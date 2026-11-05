use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use c2pa::{Builder, Reader};
use c2pa_cbor::Value;
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::live_emsg::{self, TrackTiming};
use crate::live_signing::{SessionKey, map, text};
use crate::{SIGNING_INIT_SEGMENT_PREFIX, representation_id_from_filename};

static PUBLICATION_ID: AtomicU64 = AtomicU64::new(0);

struct TrackState {
    init: Vec<u8>,
    timing: TrackTiming,
    session: SessionKey,
    manifest_id: String,
    manifest_uri: Value,
    last_sequence: Option<u32>,
}

pub(crate) struct FragmentSigner {
    context: Arc<c2pa::Context>,
    pub(crate) signed_root: PathBuf,
    validity_secs: u32,
    overlap_secs: u32,
    public_origin: String,
    tracks: Mutex<HashMap<PathBuf, Arc<Mutex<Option<TrackState>>>>>,
    event_id: AtomicU64,
}

impl FragmentSigner {
    pub(crate) fn new(
        context: Arc<c2pa::Context>,
        signed_root: PathBuf,
        validity_secs: u32,
        overlap_secs: u32,
        public_origin: String,
    ) -> Result<Self> {
        ensure!(
            validity_secs > 0 && overlap_secs > 0 && overlap_secs < validity_secs,
            "Session key overlap must be positive and less than validity"
        );
        Ok(Self {
            context,
            signed_root,
            validity_secs,
            overlap_secs,
            public_origin,
            tracks: Mutex::new(HashMap::new()),
            event_id: AtomicU64::new(0),
        })
    }

    pub(crate) fn process_upload(&self, storage_root: &Path, uploaded_file: &Path) -> Result<()> {
        let relative = uploaded_file
            .strip_prefix(storage_root)
            .context("Upload is outside storage root")?;
        let name = relative
            .file_name()
            .and_then(|s| s.to_str())
            .context("Invalid upload filename")?;
        let parent = relative.parent().context("Upload has no parent")?;
        let output = self.signed_root.join(relative);
        fs::create_dir_all(output.parent().context("Output has no parent")?)?;
        let extension = uploaded_file.extension().and_then(|s| s.to_str());
        if matches!(extension, Some("mpd" | "m3u8")) {
            return atomic_write(&output, &fs::read(uploaded_file)?);
        }
        let init_rep = name
            .strip_prefix(SIGNING_INIT_SEGMENT_PREFIX)
            .and_then(|s| s.strip_suffix(".mp4"));
        let media_rep = representation_id_from_filename(name);
        let rep = init_rep
            .or(media_rep)
            .context("Unsupported live upload filename")?;
        ensure!(!rep.is_empty(), "Empty representation identifier");
        let init_relative = parent.join(format!("init-{rep}.mp4"));
        let track = self
            .tracks
            .lock()
            .map_err(|_| anyhow::anyhow!("Track map lock poisoned"))?
            .entry(init_relative.clone())
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone();
        let mut guard = track
            .lock()
            .map_err(|_| anyhow::anyhow!("Track signing lock poisoned"))?;
        if init_rep.is_some() {
            let init = fs::read(uploaded_file)?;
            if let Some(state) = guard.as_ref() {
                ensure!(
                    state.init == init,
                    "Initialization changed; start a new stream path"
                );
                return Ok(());
            }
            let timing = TrackTiming::from_init(&init)?;
            let (session, manifest_id, manifest_uri) =
                self.publish_session(&init, &init_relative, 1)?;
            *guard = Some(TrackState {
                init,
                timing,
                session,
                manifest_id,
                manifest_uri,
                last_sequence: None,
            });
            return Ok(());
        }
        let state = guard
            .as_mut()
            .context("Media uploaded before initialization segment")?;
        let mut segment = fs::read(uploaded_file)?;
        let (sequence, duration) = state.timing.segment(&segment)?;
        if let Some(previous) = state.last_sequence {
            ensure!(
                previous.checked_add(1) == Some(sequence),
                "Out-of-order, repeated or missing media sequence: {previous} -> {sequence}"
            );
        }
        if state.session.needs_rotation(Utc::now(), self.overlap_secs) {
            let (session, manifest_id, manifest_uri) =
                self.publish_session(&state.init, &init_relative, sequence)?;
            state.session = session;
            state.manifest_id = manifest_id;
            state.manifest_uri = manifest_uri;
        }
        ensure!(
            live_emsg::message(&segment)?.is_none(),
            "Media already contains C2PA emsg"
        );
        let message = state.session.sign_segment(
            &segment,
            sequence,
            &state.manifest_id,
            state.manifest_uri.clone(),
            Utc::now(),
        )?;
        let event_id = u32::try_from(self.event_id.fetch_add(1, Ordering::Relaxed))
            .context("Session emsg identifiers exhausted; start a new stream")?;
        segment.extend(live_emsg::encode(
            &message,
            state.timing.timescale,
            duration,
            event_id,
        )?);
        atomic_write(&output, &segment)?;
        state.last_sequence = Some(sequence);
        Ok(())
    }

    fn publish_session(
        &self,
        init: &[u8],
        init_relative: &Path,
        min_sequence: u32,
    ) -> Result<(SessionKey, String, Value)> {
        let session = SessionKey::new(Utc::now(), self.validity_secs, min_sequence)?;
        let certs = self.context.signer()?.certs()?;
        let cert = certs
            .first()
            .context("Signer has no end-entity certificate")?;
        let mut builder = Builder::from_shared_context(&self.context).with_definition(serde_json::json!({
            "title": "Live CMAF session",
            "claim_generator_info": [{"name": "c2pa-live", "version": env!("CARGO_PKG_VERSION")}],
            "assertions": [{"label": "c2pa.actions", "data": {"actions": [{
                "action": "c2pa.created",
                "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"
            }]}}]
        }).to_string())?;
        builder.add_assertion("c2pa.session-keys", &session.assertion(cert)?)?;
        let mut signed_init = Cursor::new(Vec::new());
        let manifest = builder.sign(
            self.context.signer()?,
            "video/mp4",
            &mut Cursor::new(init),
            &mut signed_init,
        )?;
        let signed_init = signed_init.into_inner();
        let reader = Reader::from_shared_context(&self.context)
            .with_stream("video/mp4", Cursor::new(&signed_init))?;
        let manifest_id = reader
            .active_manifest()
            .and_then(|m| m.label())
            .context("Signed init has no manifest identifier")?
            .to_owned();
        let suffix: String = session
            .kid
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let file_name = format!("session-{suffix}");
        let parent = init_relative
            .parent()
            .context("Initialization has no parent")?;
        let manifest_relative = parent.join(format!("{file_name}.c2pa"));
        let path = self.signed_root.join(&manifest_relative);
        atomic_write(&path, &manifest)?;
        // Retain an immutable signed init so clients can validate the external manifest's
        // moov binding using SDKs that do not yet expose a live-video reader.
        atomic_write(
            &self
                .signed_root
                .join(parent)
                .join(format!("{file_name}.mp4")),
            &signed_init,
        )?;
        atomic_write(&self.signed_root.join(init_relative), &signed_init)?;
        let uri = format!(
            "{}/signed/{}",
            self.public_origin,
            manifest_relative
                .to_str()
                .context("Non-UTF-8 manifest path")?
        );
        ensure!(
            !uri.contains(['?', '#', '%', ' ']),
            "Stream path must be URL-safe"
        );
        let manifest_uri = map([
            ("url", text(uri)),
            ("alg", text("sha256")),
            ("hash", Value::Bytes(Sha256::digest(&manifest).to_vec())),
        ]);
        Ok((session, manifest_id, manifest_uri))
    }
}

fn atomic_write(destination: &Path, bytes: &[u8]) -> Result<()> {
    let id = PUBLICATION_ID.fetch_add(1, Ordering::Relaxed);
    let name = destination
        .file_name()
        .context("Publication has no filename")?
        .to_string_lossy();
    let temp =
        destination.with_file_name(format!(".{name}.publishing-{}-{id}", std::process::id()));
    let result: Result<()> = (|| {
        fs::write(&temp, bytes)?;
        fs::rename(&temp, destination)?;
        Ok(())
    })();
    if result.is_err()
        && let Err(err) = fs::remove_file(&temp)
    {
        eprintln!("Failed to clean publication {}: {err}", temp.display());
    }
    result.with_context(|| format!("Publishing {}", destination.display()))
}
