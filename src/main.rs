use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use c2pa::{Context as C2paContext, SigningAlg, create_signer};
use clap::{Args, Parser};
use tokio::sync::watch;

mod ffmpeg;
use crate::ffmpeg::FfmpegArgs;
mod signer;
use crate::signer::FragmentSigner;
mod http;
use crate::http::{AppState, run_server};
mod live_emsg;
mod live_signing;

const SIGNING_FRAGMENT_FILE_PREFIX: &str = "chunk-";
const SIGNING_FRAGMENT_FILE_SUFFIX: &str = ".m4s";
const SIGNING_INIT_SEGMENT_PREFIX: &str = "init-";

#[derive(Debug, Parser, Clone)]
#[command(name = "c2pa-live")]
#[command(about = "Live CMAF ingest server with DASH/HLS generation and C2PA signing")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    #[arg(long, default_value = "live")]
    storage_dir: PathBuf,

    #[arg(
        long,
        default_value_t = false,
        help = "Disable browser caching for served assets and API responses"
    )]
    no_cache: bool,

    #[arg(long, value_parser = ffmpeg::parse_positive_duration, help = "Browser playback delay in seconds (default: three segment durations)")]
    playback_delay: Option<f64>,

    #[arg(long, value_parser = parse_public_origin,
        help = "Public HTTP(S) origin for immutable key manifests, e.g. https://stream.example.com (default: http://<listen>)")]
    public_base_url: Option<String>,

    #[command(flatten)]
    ffmpeg: FfmpegArgs,

    #[command(flatten)]
    c2pa: C2paArgs,
}

#[derive(Debug, Args, Clone)]
#[command(next_help_heading = "C2PA")]
struct C2paArgs {
    #[arg(long, default_value = "signed")]
    signed_dir: PathBuf,

    #[arg(
        long,
        help = "Optional path to C2PA settings TOML. If omitted, ./settings.toml is used when present."
    )]
    settings: Option<PathBuf>,

    #[arg(long, short = 'c', help = "C2PA signing certificate in PEM format")]
    cert: PathBuf,

    #[arg(long, short = 'k', help = "C2PA signing key in PEM format")]
    key: PathBuf,

    #[arg(
        long,
        short = 't',
        help = "Optional PEM trust anchors file for client-side validation endpoint"
    )]
    trust_anchors: Option<PathBuf>,

    #[arg(long, help = "Optional timestamp authority URL for signing")]
    timestamp_url: Option<String>,

    #[arg(long, value_parser = parse_signing_alg, default_value = "es256")]
    signing_alg: SigningAlg,

    #[arg(
        long,
        default_value_t = 300,
        help = "Session key lifetime in seconds; longer lifetimes reduce certificate/TSA operations"
    )]
    session_key_validity_secs: u32,

    #[arg(
        long,
        default_value_t = 30,
        help = "Session key overlap window (seconds) before rollover"
    )]
    session_key_overlap_secs: u32,
}

impl C2paArgs {
    fn create_context(&self) -> Result<C2paContext> {
        ensure_file_exists(&self.cert, "cert")?;
        ensure_file_exists(&self.key, "key")?;
        if let Some(path) = &self.trust_anchors {
            ensure_file_exists(path, "trust_anchors")?;
        }

        let default_settings_path = PathBuf::from("settings.toml");
        let settings_path = if let Some(path) = &self.settings {
            ensure_file_exists(path, "settings")?;
            Some(path.clone())
        } else if default_settings_path.exists() {
            Some(default_settings_path)
        } else {
            None
        };

        let mut context = C2paContext::new();
        if let Some(settings_path) = settings_path {
            let settings_toml = fs::read_to_string(&settings_path).with_context(|| {
                format!(
                    "Failed to read C2PA settings file {}",
                    settings_path.display()
                )
            })?;
            context = context
                .with_settings(settings_toml.as_str())
                .with_context(|| "Failed to apply C2PA settings to context")?;
        }

        let signer = create_signer::from_files(
            &self.cert,
            &self.key,
            self.signing_alg,
            self.timestamp_url.clone(),
        )
        .with_context(|| "Failed to create C2PA signer from cert/key files")?;
        context = context.with_signer(signer);
        Ok(context)
    }
}

fn representation_id_from_filename(file_name: &str) -> Option<&str> {
    let name = file_name.strip_suffix(SIGNING_FRAGMENT_FILE_SUFFIX)?;
    let name = name.strip_prefix(SIGNING_FRAGMENT_FILE_PREFIX)?;
    let (rep, sequence) = name.split_once('-')?;
    if rep.is_empty() || sequence.parse::<u32>().is_err() {
        return None;
    }
    Some(rep)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    ensure_file_exists(&cli.ffmpeg.input, "input")?;

    fs::create_dir_all(&cli.storage_dir)
        .with_context(|| format!("Failed to create storage dir {}", cli.storage_dir.display()))?;
    fs::create_dir_all(&cli.c2pa.signed_dir).with_context(|| {
        format!(
            "Failed to create signed dir {}",
            cli.c2pa.signed_dir.display()
        )
    })?;

    let storage_root = fs::canonicalize(&cli.storage_dir)?;
    let signed_root = fs::canonicalize(&cli.c2pa.signed_dir)?;
    anyhow::ensure!(
        !storage_root.starts_with(&signed_root) && !signed_root.starts_with(&storage_root),
        "Storage and signed directories must not overlap"
    );

    let context = cli.c2pa.create_context()?;
    let signer = Arc::new(FragmentSigner::new(
        Arc::new(context),
        signed_root,
        cli.c2pa.session_key_validity_secs,
        cli.c2pa.session_key_overlap_secs,
        cli.public_base_url
            .unwrap_or_else(|| format!("http://{}", cli.listen)),
    )?);

    let state = Arc::new(AppState {
        storage_root,
        signer,
        no_cache: cli.no_cache,
        segment_duration: cli.ffmpeg.segment_duration,
        playback_delay: cli
            .playback_delay
            .unwrap_or(cli.ffmpeg.segment_duration * 3.0),
        trust_anchors: cli
            .c2pa
            .trust_anchors
            .as_ref()
            .map(|path| {
                fs::read(path).with_context(|| {
                    format!("Failed to read trust anchors file {}", path.display())
                })
            })
            .transpose()?,
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_state = state.clone();
    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("Failed to bind HTTP server on {}", cli.listen))?;
    let server_task =
        tokio::spawn(async move { run_server(listener, server_state, shutdown_rx).await });

    println!("HTTP ingest server listening on http://{}", cli.listen);

    let ffmpeg = cli.ffmpeg.start_ffmpeg_live(cli.listen)?;

    if let Err(err) = tokio::signal::ctrl_c().await {
        eprintln!("failed to listen for Ctrl+C: {err}");
    }
    println!("received shutdown signal");

    if let Err(err) = ffmpeg.stop() {
        eprintln!("failed to stop ffmpeg gracefully: {err}");
    } else {
        println!("ffmpeg terminated gracefully");
    }

    let _ = shutdown_tx.send(true);
    match server_task.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => eprintln!("server task failed: {err:#}"),
        Err(err) => eprintln!("server join failed: {err}"),
    }

    Ok(())
}

fn ensure_file_exists(path: &Path, name: &str) -> Result<()> {
    if !path.exists() {
        bail!("{} path does not exist: {}", name, path.display());
    }
    if !path.is_file() {
        bail!("{} path is not a file: {}", name, path.display());
    }
    Ok(())
}

fn parse_signing_alg(value: &str) -> std::result::Result<SigningAlg, String> {
    match value.to_ascii_lowercase().as_str() {
        "es256" => Ok(SigningAlg::Es256),
        "ps256" => Ok(SigningAlg::Ps256),
        "ed25519" => Ok(SigningAlg::Ed25519),
        _ => Err(format!(
            "invalid signing algorithm '{value}', expected one of: es256, ps256, ed25519"
        )),
    }
}

fn parse_public_origin(value: &str) -> std::result::Result<String, String> {
    let uri: ::http::Uri = value
        .parse()
        .map_err(|_| "Invalid public origin".to_string())?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.authority().is_none()
        || uri.authority().is_some_and(|a| a.as_str().contains('@'))
        || uri.path() != "/"
        || uri.query().is_some()
        || value.contains('#')
    {
        return Err(
            "Public origin must be http(s)://host[:port] without a path, query or credentials"
                .into(),
        );
    }
    Ok(value.trim_end_matches('/').to_owned())
}

#[cfg(test)]
mod tests;
