use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use c2pa::Builder;

use crate::{
    SIGNING_FRAGMENT_FILE_PREFIX, SIGNING_FRAGMENT_FILE_SUFFIX, SIGNING_INIT_SEGMENT_PREFIX,
    representation_id_from_filename,
};

pub(crate) struct FragmentSigner {
    context: Arc<c2pa::Context>,
    claim_generator: String,
    pub(crate) signed_root: PathBuf,
}

impl FragmentSigner {
    pub(crate) fn new(
        context: Arc<c2pa::Context>,
        signed_root: PathBuf,
        claim_generator: String,
    ) -> Self {
        Self {
            context,
            signed_root,
            claim_generator,
        }
    }

    pub(crate) fn maybe_sign_uploaded_fragment(
        &self,
        storage_root: &Path,
        uploaded_file: &Path,
    ) -> Result<()> {
        let ext = uploaded_file
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        if ext != "m4s" {
            return Ok(());
        }

        let parent = uploaded_file
            .parent()
            .context("Uploaded fragment has no parent directory")?;
        let Some(file_name) = uploaded_file.file_name().and_then(|s| s.to_str()) else {
            return Ok(());
        };

        if !file_name.starts_with(SIGNING_FRAGMENT_FILE_PREFIX)
            || !file_name.ends_with(SIGNING_FRAGMENT_FILE_SUFFIX)
        {
            return Ok(());
        }

        let Some(rep_id) = representation_id_from_filename(file_name) else {
            return Ok(());
        };

        let init_segment = self.find_init_segment(parent, rep_id)?;

        let Some(init_segment) = init_segment else {
            return Ok(());
        };

        let current_dir =
            std::env::current_dir().with_context(|| "Failed to get current working directory")?;
        let abs_parent = if parent.is_absolute() {
            parent.to_path_buf()
        } else {
            current_dir.join(parent)
        };

        let abs_init_segment = if init_segment.is_absolute() {
            init_segment.clone()
        } else {
            current_dir.join(&init_segment)
        };
        let abs_uploaded_fragment = abs_parent.join(file_name);
        if !abs_uploaded_fragment.is_file() {
            return Ok(());
        }

        let mut source_fragments: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&abs_parent)
            .with_context(|| format!("Failed to read source directory {}", abs_parent.display()))?
        {
            let entry = entry
                .with_context(|| format!("Failed to read entry in {}", abs_parent.display()))?;
            let candidate = entry.path();
            if !candidate.is_file() {
                continue;
            }

            let Some(candidate_name) = candidate.file_name().and_then(|s| s.to_str()) else {
                continue;
            };

            if !candidate_name.starts_with(&format!("{}{}-", SIGNING_FRAGMENT_FILE_PREFIX, rep_id))
                || !candidate_name.ends_with(SIGNING_FRAGMENT_FILE_SUFFIX)
            {
                continue;
            }

            source_fragments.push(candidate);
        }

        if source_fragments.is_empty() {
            return Ok(());
        }

        let stage_nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stage_dir = abs_parent.join(format!(".c2pa-stage-{stage_nonce}"));
        fs::create_dir_all(&stage_dir)
            .with_context(|| format!("Failed to create C2PA stage dir {}", stage_dir.display()))?;

        let staged_init = stage_dir.join(format!("{}{}.mp4", SIGNING_INIT_SEGMENT_PREFIX, rep_id));
        fs::copy(&abs_init_segment, &staged_init).with_context(|| {
            format!(
                "Failed to copy init segment {} to {}",
                abs_init_segment.display(),
                staged_init.display()
            )
        })?;

        for source_fragment in &source_fragments {
            let staged_fragment = stage_dir.join(
                source_fragment
                    .file_name()
                    .context("Source fragment missing file name")?,
            );
            fs::copy(source_fragment, &staged_fragment).with_context(|| {
                format!(
                    "Failed to copy fragment {} to {}",
                    source_fragment.display(),
                    staged_fragment.display()
                )
            })?;
        }

        let fragment_input = stage_dir.join(format!("chunk-{}-*.m4s", rep_id));
        let relative_parent = parent.strip_prefix(storage_root).unwrap_or(parent);
        let sign_output_dir = self.signed_root.join(relative_parent);
        fs::create_dir_all(&sign_output_dir).with_context(|| {
            format!(
                "Failed to create signed output dir {}",
                sign_output_dir.display()
            )
        })?;

        self.copy_auxiliary_playback_files(parent, &sign_output_dir)
            .with_context(|| {
                format!(
                    "Failed to copy auxiliary playback files from {} to {}",
                    parent.display(),
                    sign_output_dir.display()
                )
            })?;

        let mut builder = Builder::from_shared_context(&self.context)
            .with_definition(Self::manifest_definition(&self.claim_generator))
            .with_context(|| "Failed to construct C2PA builder")?;

        let signing_result = builder
            .sign_fragmented_files(
                self.context.signer()?,
                &staged_init,
                &fragment_input,
                &sign_output_dir,
            )
            .with_context(|| {
                format!(
                    "Failed C2PA signing for init={} fragments={} output={}",
                    staged_init.display(),
                    fragment_input.display(),
                    sign_output_dir.display()
                )
            });

        let _ = fs::remove_dir_all(&stage_dir);
        signing_result?;

        let stage_folder_name = stage_dir
            .file_name()
            .context("Failed to determine stage folder name")?;
        self.promote_signed_outputs(&sign_output_dir, stage_folder_name)
            .with_context(|| {
                format!(
                    "Failed to promote signed files from nested folder for {}",
                    sign_output_dir.display()
                )
            })?;

        println!(
            "fragment signed: {} -> {}",
            abs_uploaded_fragment.display(),
            sign_output_dir.join(file_name).display()
        );

        Ok(())
    }

    fn copy_auxiliary_playback_files(&self, source_dir: &Path, target_dir: &Path) -> Result<()> {
        for entry in fs::read_dir(source_dir)
            .with_context(|| format!("Failed to read source directory {}", source_dir.display()))?
        {
            let entry = entry
                .with_context(|| format!("Failed to read entry in {}", source_dir.display()))?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };

            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if ext != "m3u8" && ext != "mpd" {
                continue;
            }

            let destination = target_dir.join(name);
            fs::copy(&path, &destination).with_context(|| {
                format!(
                    "Failed to copy auxiliary file {} to {}",
                    path.display(),
                    destination.display()
                )
            })?;
        }

        Ok(())
    }

    fn find_init_segment(&self, dir: &Path, rep_id: &str) -> Result<Option<PathBuf>> {
        let init_segment = dir.join(format!("{}{}.mp4", SIGNING_INIT_SEGMENT_PREFIX, rep_id));
        if init_segment.is_file() {
            if let Some(init_name) = init_segment.file_name().and_then(|s| s.to_str()) {
                let expected = format!("{}{}.mp4", SIGNING_INIT_SEGMENT_PREFIX, rep_id);
                if init_name != expected {
                    return Ok(None);
                }
            }
            return Ok(Some(init_segment));
        }

        Ok(None)
    }

    fn promote_signed_outputs(
        &self,
        output_root: &Path,
        nested_dir_name: &std::ffi::OsStr,
    ) -> Result<()> {
        let nested_output_dir = output_root.join(nested_dir_name);
        if !nested_output_dir.is_dir() {
            return Ok(());
        }

        for entry in fs::read_dir(&nested_output_dir).with_context(|| {
            format!(
                "Failed to read nested output directory {}",
                nested_output_dir.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "Failed to read entry in nested output directory {}",
                    nested_output_dir.display()
                )
            })?;
            let source = entry.path();
            if !source.is_file() {
                continue;
            }

            let destination = output_root.join(entry.file_name());
            if destination.exists() {
                fs::remove_file(&destination).with_context(|| {
                    format!(
                        "Failed to remove existing output file {}",
                        destination.display()
                    )
                })?;
            }

            fs::rename(&source, &destination).with_context(|| {
                format!(
                    "Failed to move signed output {} -> {}",
                    source.display(),
                    destination.display()
                )
            })?;
        }

        fs::remove_dir_all(&nested_output_dir).with_context(|| {
            format!(
                "Failed to remove nested output directory {}",
                nested_output_dir.display()
            )
        })?;

        Ok(())
    }

    fn manifest_definition(claim_generator: &str) -> String {
        serde_json::json!({
            "title": "Live CMAF Fragment",
            "format": "video/mp4",
            "claim_generator_info": [
                {
                    "name": claim_generator,
                    "version": env!("CARGO_PKG_VERSION")
                }
            ],
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "softwareAgent": {
                                    "name": "c2pa-live"
                                }
                            }
                        ]
                    }
                }
            ]
        })
        .to_string()
    }
}
