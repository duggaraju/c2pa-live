use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::FragmentSigner;

type RespBody = Full<Bytes>;
const LIVE_PUBLISH_PREFIX: &str = "live";

#[derive(Clone)]
pub struct AppState {
    pub storage_root: PathBuf,
    pub signer: Arc<FragmentSigner>,
    pub no_cache: bool,
    pub trust_anchors: Option<Vec<u8>>,
    pub segment_duration: f64,
    pub playback_delay: f64,
}

pub async fn run_server(
    listener: TcpListener,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted.with_context(|| "Failed to accept TCP connection")?;
                let local_addr = stream.local_addr().ok();
                let io = TokioIo::new(stream);
                let app_state = state.clone();

                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let app_state = app_state.clone();
                        async move { handle_request(req, app_state, peer_addr, local_addr).await }
                    });

                    let mut builder = http1::Builder::new();
                    if let Err(err) = builder.half_close(true).serve_connection(io, service).await {
                        let msg = err.to_string();
                        if msg.contains("connection closed before message completed") {
                            eprintln!("HTTP connection closed by client before full message (common with live ffmpeg PUT): {msg}");
                        } else {
                            eprintln!("HTTP connection error: {msg}");
                        }
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<AppState>,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
) -> Result<Response<RespBody>, Infallible> {
    let no_cache = state.no_cache;
    let response = match *req.method() {
        Method::PUT | Method::POST | Method::DELETE => {
            let is_local_upload = peer_addr.ip().is_loopback()
                || local_addr
                    .map(|addr| addr.ip() == peer_addr.ip())
                    .unwrap_or(false);

            if !is_local_upload {
                response_with_status(
                    StatusCode::FORBIDDEN,
                    "upload endpoints are only accessible from localhost",
                )
            } else if req.method() == Method::DELETE {
                handle_delete(req, state.clone()).await
            } else {
                handle_upload(req, state.clone()).await
            }
        }
        Method::GET => handle_get(req, state.clone()).await,
        _ => response_with_status(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    };

    Ok(apply_cache_policy(response, no_cache))
}

async fn handle_delete(req: Request<Incoming>, state: Arc<AppState>) -> Response<RespBody> {
    let Some(relative) = sanitized_relative_path(req.uri().path(), LIVE_PUBLISH_PREFIX) else {
        return response_with_status(StatusCode::BAD_REQUEST, "invalid deletion path");
    };
    if relative
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(crate::representation_id_from_filename)
        .is_none()
    {
        return response_with_status(
            StatusCode::BAD_REQUEST,
            "only media segments may be deleted",
        );
    }
    for root in [&state.storage_root, &state.signer.signed_root] {
        match tokio::fs::remove_file(root.join(&relative)).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return response_with_status(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to delete media: {err}"),
                );
            }
        }
    }
    response_empty(StatusCode::NO_CONTENT)
}

async fn handle_get(req: Request<Incoming>, state: Arc<AppState>) -> Response<RespBody> {
    let uri_path = req.uri().path();
    match uri_path {
        "/" => response_redirect("/client/index.html"),
        "/client" | "/client/" => response_redirect("/client/index.html"),
        "/client/index.html" => serve_static_file("src/client/index.html", state.no_cache).await,
        "/client/script.js" => serve_static_file("src/client/script.js", state.no_cache).await,
        "/client/live.js" => serve_static_file("src/client/live.js", state.no_cache).await,
        "/favicon.ico" => response_empty(StatusCode::NO_CONTENT),
        "/api/c2pa/cert-chain.pem" => handle_cert_chain(state).await,
        "/api/live-config" => response_with_content_type(
            StatusCode::OK, "application/json",
            serde_json::json!({"segmentDuration": state.segment_duration, "playbackDelay": state.playback_delay, "protocol": "c2pa-2.4-vsi"}).to_string().into_bytes(),
        ),
        _ => {
            if let Some(relative_path) = sanitized_relative_path(uri_path, "signed") {
                return serve_signed_prefixed(&state, &relative_path).await;
            }
            handle_download(req, state).await
        }
    }
}

async fn handle_upload(req: Request<Incoming>, state: Arc<AppState>) -> Response<RespBody> {
    let Some(relative_path) = sanitized_relative_path(req.uri().path(), LIVE_PUBLISH_PREFIX) else {
        return response_with_status(StatusCode::BAD_REQUEST, "invalid upload path");
    };

    let destination = state.storage_root.join(&relative_path);
    if let Some(parent) = destination.parent()
        && let Err(err) = tokio::fs::create_dir_all(parent).await
    {
        return response_with_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to create destination directory: {err}"),
        );
    }

    let upload_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_file_name = format!(
        "{}.uploading-{}",
        destination
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("segment"),
        upload_nonce
    );
    let temp_destination = destination
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(temp_file_name);

    let mut file = match tokio::fs::File::create(&temp_destination).await {
        Ok(file) => file,
        Err(err) => {
            return response_with_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "failed to create temp file {}: {err}",
                    temp_destination.display()
                ),
            );
        }
    };

    let mut body = req.into_body();
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(err) => {
                drop(file);
                if let Err(cleanup) = tokio::fs::remove_file(&temp_destination).await {
                    eprintln!("Failed to clean aborted upload: {cleanup}");
                }
                return response_with_status(
                    StatusCode::BAD_REQUEST,
                    &format!("failed to read body frame: {err}"),
                );
            }
        };

        if let Ok(data) = frame.into_data()
            && let Err(err) = file.write_all(data.as_ref()).await
        {
            let _ = tokio::fs::remove_file(&temp_destination).await;
            return response_with_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "failed to write temp file {}: {err}",
                    temp_destination.display()
                ),
            );
        }
    }

    if let Err(err) = file.flush().await {
        let _ = tokio::fs::remove_file(&temp_destination).await;
        return response_with_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!(
                "failed to flush temp file {}: {err}",
                temp_destination.display()
            ),
        );
    }

    drop(file);

    if let Err(err) = tokio::fs::rename(&temp_destination, &destination).await {
        let _ = tokio::fs::remove_file(&temp_destination).await;
        return response_with_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!(
                "failed to finalize upload {} -> {}: {err}",
                temp_destination.display(),
                destination.display()
            ),
        );
    }

    let signer = state.signer.clone();
    let storage_root = state.storage_root.clone();
    let destination_for_signing = destination.clone();
    match tokio::task::spawn_blocking(move || {
        signer.process_upload(&storage_root, &destination_for_signing)
    })
    .await
    {
        Ok(Ok(())) => response_with_status(StatusCode::CREATED, "uploaded and signed"),
        result => {
            let error = match result {
                Ok(Err(err)) => format!("{err:#}"),
                Err(err) => format!("Signing task failed: {err}"),
                Ok(Ok(())) => unreachable!(),
            };
            eprintln!("Publication failed for {}: {error}", destination.display());
            response_with_status(StatusCode::INTERNAL_SERVER_ERROR, &error)
        }
    }
}

async fn handle_download(req: Request<Incoming>, state: Arc<AppState>) -> Response<RespBody> {
    let uri_path = req.uri().path();

    let relative_path = if let Some(path) = sanitized_relative_path(uri_path, LIVE_PUBLISH_PREFIX) {
        path
    } else if let Some(path) = sanitized_relative_path(uri_path, "") {
        path
    } else {
        return response_with_status(StatusCode::BAD_REQUEST, "invalid download path");
    };

    // /live/... and bare paths intentionally resolve to unsigned storage.
    let path = state.storage_root.join(&relative_path);

    let data = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(_) => return response_with_status(StatusCode::NOT_FOUND, "not found"),
    };

    let mime = content_type_for_path(&path);
    response_with_content_type(StatusCode::OK, mime, data)
}

async fn serve_signed_prefixed(state: &AppState, relative_path: &Path) -> Response<RespBody> {
    let signed_path = state.signer.signed_root.join(relative_path);
    if let Ok(bytes) = tokio::fs::read(&signed_path).await {
        let mime = content_type_for_path(&signed_path);
        return response_with_content_type(StatusCode::OK, mime, bytes);
    }

    response_with_status(StatusCode::NOT_FOUND, "not found")
}

async fn handle_cert_chain(state: Arc<AppState>) -> Response<RespBody> {
    let Some(pem_bytes) = state.trust_anchors.as_ref() else {
        return response_with_status(StatusCode::NOT_FOUND, "not found");
    };

    response_with_content_type(StatusCode::OK, "application/x-pem-file", pem_bytes.clone())
}

fn sanitized_relative_path(uri_path: &str, required_prefix: &str) -> Option<PathBuf> {
    let trimmed = uri_path.trim_start_matches('/');
    let without_prefix = if required_prefix.is_empty() {
        trimmed
    } else {
        let prefixed = format!("{}/", required_prefix.trim_matches('/'));
        if trimmed.starts_with(&prefixed) {
            &trimmed[prefixed.len()..]
        } else {
            return None;
        }
    };

    if without_prefix.is_empty() {
        return None;
    }

    let path = Path::new(without_prefix);
    if path.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) || matches!(c, Component::Normal(name) if name.to_str().is_none_or(|s| s.starts_with('.') || s.contains(".uploading-") || s.contains(".publishing-")))
    }) {
        return None;
    }

    Some(path.to_path_buf())
}

fn content_type_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
    {
        "mpd" => "application/dash+xml",
        "m3u8" => "application/vnd.apple.mpegurl",
        "m4s" => "video/iso.segment",
        "mp4" => "video/mp4",
        "c2pa" => "application/c2pa",
        "ts" => "video/mp2t",
        _ => "application/octet-stream",
    }
}

fn response_with_status(status: StatusCode, message: &str) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(message.to_owned())))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from_static(b"internal response error")))
        })
}

fn response_with_content_type(
    status: StatusCode,
    content_type: &str,
    bytes: Vec<u8>,
) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(bytes)))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from_static(b"internal response error")))
        })
}

fn response_redirect(location: &str) -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", location)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn response_empty(status: StatusCode) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

async fn serve_static_file(path: &str, no_cache: bool) -> Response<RespBody> {
    let service = ServeFile::new(path);
    let request = Request::builder()
        .uri("/")
        .body(Empty::<Bytes>::new())
        .unwrap_or_else(|_| Request::new(Empty::<Bytes>::new()));

    match service.oneshot(request).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            let bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            apply_cache_policy(Response::from_parts(parts, Full::new(bytes)), no_cache)
        }
        Err(err) => response_with_status(
            StatusCode::NOT_FOUND,
            &format!("failed to serve {path}: {err}"),
        ),
    }
}

fn apply_cache_policy(mut response: Response<RespBody>, no_cache: bool) -> Response<RespBody> {
    if no_cache {
        let headers = response.headers_mut();
        headers.insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
        );
        headers.insert(
            http::header::PRAGMA,
            http::HeaderValue::from_static("no-cache"),
        );
        headers.insert(http::header::EXPIRES, http::HeaderValue::from_static("0"));
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_in_progress_publications_are_not_addressable() {
        for path in [
            "/signed/.init-0.mp4.publishing-1-0",
            "/signed/chunk-0-00001.m4s.uploading-123",
            "/signed/../key.pem",
            "/signed/.c2pa-stage/fragment.m4s",
        ] {
            assert!(sanitized_relative_path(path, "signed").is_none());
        }
        assert_eq!(
            sanitized_relative_path("/signed/nested/chunk-0-00001.m4s", "signed"),
            Some(PathBuf::from("nested/chunk-0-00001.m4s"))
        );
    }
}
