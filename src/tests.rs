use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, ensure};
use c2pa::{Reader, SigningAlg, create_signer};
use c2pa_cbor::Value;
use chrono::{Duration, Utc};
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::live_emsg::{self, TrackTiming, make_box};
use crate::live_signing::{SessionKey, cbor_value, map, segment_hash, text};
use crate::signer::FragmentSigner;

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    let Value::Map(map) = value else {
        panic!("Expected map: {value:?}")
    };
    map.get(&text(key))
        .unwrap_or_else(|| panic!("Missing {key}"))
}

fn array(value: &Value) -> &[Value] {
    let Value::Array(values) = value else {
        panic!("Expected array")
    };
    values
}

fn bytes(value: &Value) -> &[u8] {
    let Value::Bytes(bytes) = value else {
        panic!("Expected byte string")
    };
    bytes
}

fn string(value: &Value) -> &str {
    let Value::Text(value) = value else {
        panic!("Expected string")
    };
    value
}

fn verify_signature(cose: &CoseSign1, kid: &[u8], detached: Option<&[u8]>) -> Result<()> {
    let key = VerifyingKey::from_bytes(kid.try_into()?)?;
    let verify = |signature: &[u8], data: &[u8]| -> Result<()> {
        key.verify_strict(data, &Signature::from_slice(signature)?)?;
        Ok(())
    };
    if let Some(payload) = detached {
        cose.verify_detached_signature(payload, &[], verify)?;
    } else {
        cose.verify_signature(&[], verify)?;
    }
    Ok(())
}

fn synthetic_segment() -> Result<Vec<u8>> {
    let mut mfhd = vec![0; 4];
    mfhd.extend(7u32.to_be_bytes());
    let moof = make_box(b"moof", &make_box(b"mfhd", &mfhd)?)?;
    Ok([
        make_box(b"styp", b"msdh\0\0\0\0msdhmsix")?,
        moof,
        make_box(b"mdat", &[7; 256])?,
    ]
    .concat())
}

#[test]
fn session_assertion_has_cose_key_tagged_time_and_certificate_binding() -> Result<()> {
    let now = Utc::now();
    let session = SessionKey::new(now, 300, 7)?;
    let assertion = session.assertion(b"end-entity DER certificate")?;
    let entry = &array(field(&assertion, "keys"))[0];
    assert!(matches!(field(entry, "createdAt"), Value::Tag(0, _)));
    let binding = CoseSign1::from_slice(&c2pa_cbor::to_vec(field(entry, "signerBinding"))?)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert!(binding.payload.is_none());
    verify_signature(&binding, &session.kid, Some(b"end-entity DER certificate"))?;
    assert!(verify_signature(&binding, &session.kid, Some(b"substituted certificate")).is_err());
    let encoded = c2pa_cbor::to_vec(&assertion)?;
    assert_eq!(cbor_value(&encoded)?, assertion);
    assert_eq!(field(entry, "minSequenceNumber"), &Value::Integer(7));
    assert!(!session.needs_rotation(now + Duration::seconds(269), 30));
    assert!(session.needs_rotation(now + Duration::seconds(270), 30));
    Ok(())
}

#[test]
fn vsi_signature_hash_offsets_and_tampering() -> Result<()> {
    let now = Utc::now();
    let session = SessionKey::new(now, 300, 7)?;
    let mut media = synthetic_segment()?;
    let uri = map([
        ("url", text("https://example.com/session.c2pa")),
        ("alg", text("sha256")),
        ("hash", Value::Bytes(vec![0; 32])),
    ]);
    let signed = session.sign_segment(&media, 7, "urn:c2pa:test", uri.clone(), now)?;
    assert_eq!(signed[0], 0xd2);
    let cose = CoseSign1::from_tagged_slice(&signed).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_eq!(cose.unprotected.key_id, session.kid);
    verify_signature(&cose, &session.kid, None)?;
    let payload = cbor_value(cose.payload.as_ref().unwrap())?;
    let expected = bytes(field(field(&payload, "bmffHash"), "hash"));
    let mut input = Vec::new();
    for b in live_emsg::boxes(&media)? {
        let length = b.data.len() + 8;
        input.extend((b.offset as u64).to_be_bytes());
        input.extend(&media[b.offset..b.offset + length]);
    }
    assert_eq!(expected, Sha256::digest(&input).as_slice());
    let hash: c2pa::assertions::BmffHash =
        c2pa_cbor::from_slice(&c2pa_cbor::to_vec(field(&payload, "bmffHash"))?)?;
    assert!(hash.merkle().is_none());
    assert!(
        hash.exclusions()
            .iter()
            .any(|e| e.xpath == "/emsg" && e.data.as_ref().unwrap()[0].offset == 0)
    );
    media.extend(live_emsg::encode(&signed, 1000, 1000, 0)?);
    assert_eq!(live_emsg::message(&media)?.unwrap(), signed);
    let mut recomputed = segment_hash();
    recomputed.gen_hash_from_stream(&mut Cursor::new(&media))?;
    assert_eq!(recomputed.hash().unwrap(), expected);
    let mut foreign_event = live_emsg::encode(b"foreign event", 1000, 1000, 1)?;
    foreign_event[12 + live_emsg::SCHEME.len()] = b'x';
    let mut with_foreign_event = media.clone();
    with_foreign_event.extend(foreign_event);
    recomputed.gen_hash_from_stream(&mut Cursor::new(&with_foreign_event))?;
    assert_ne!(
        recomputed.hash().unwrap(),
        expected,
        "Non-C2PA events must be hashed"
    );
    let mut tampered_cose = cose.clone();
    tampered_cose.payload.as_mut().unwrap()[0] ^= 1;
    assert!(verify_signature(&tampered_cose, &session.kid, None).is_err());
    media[80] ^= 1;
    recomputed.gen_hash_from_stream(&mut Cursor::new(&media))?;
    assert_ne!(recomputed.hash().unwrap(), expected);
    assert!(
        session
            .sign_segment(&media, 6, "id", uri.clone(), now)
            .is_err()
    );
    assert!(
        session
            .sign_segment(&media, 7, "id", uri.clone(), now + Duration::seconds(300))
            .is_err()
    );
    assert!(
        session
            .sign_segment(&media, 7, "id", uri, now - Duration::seconds(1))
            .is_err()
    );
    Ok(())
}

#[test]
fn malformed_boxes_and_duration_options_fail_explicitly() -> Result<()> {
    assert!(live_emsg::boxes(&[0; 7]).is_err());
    assert!(live_emsg::boxes(&[0, 0, 0, 1, b'm', b'd', b'a', b't']).is_err());
    assert!(live_emsg::boxes(&[0, 0, 0, 7, b'm', b'd', b'a', b't']).is_err());
    let emsg = live_emsg::encode(b"payload", 1000, 1000, 7)?;
    assert!(live_emsg::message(&[emsg.clone(), emsg].concat()).is_err());
    for invalid in ["NaN", "inf", "0", "-1", "invalid"] {
        assert!(crate::ffmpeg::parse_positive_duration(invalid).is_err());
    }
    assert_eq!(
        crate::ffmpeg::parse_positive_duration("0.25").unwrap(),
        0.25
    );
    assert!(crate::parse_public_origin("https://stream.example.com/").is_ok());
    for invalid in [
        "file:///tmp",
        "https://example.com/path",
        "https://user@example.com",
        "https://example.com/?q=1",
    ] {
        assert!(crate::parse_public_origin(invalid).is_err());
    }
    assert_eq!(
        crate::representation_id_from_filename("chunk-0-00007.m4s"),
        Some("0")
    );
    assert_eq!(
        crate::representation_id_from_filename("chunk-0-oops.m4s"),
        None
    );
    Ok(())
}

fn run(command: &mut Command) -> Result<()> {
    let output = command.output().context("Starting integration test tool")?;
    ensure!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn certificate(dir: &Path) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let root = dir.join("root.pem");
    let root_key = dir.join("root.key");
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    run(Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=C2PA Live Test Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ])
        .arg("-keyout")
        .arg(&root_key)
        .arg("-out")
        .arg(&root))?;
    let csr = dir.join("cert.csr");
    run(Command::new("openssl")
        .args([
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            "/CN=C2PA Live Test Signer",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&csr))?;
    let extensions = dir.join("extensions.cnf");
    fs::write(
        &extensions,
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=emailProtection\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
    )?;
    run(Command::new("openssl")
        .args(["x509", "-req", "-days", "1", "-sha256"])
        .arg("-in")
        .arg(csr)
        .arg("-CA")
        .arg(&root)
        .arg("-CAkey")
        .arg(root_key)
        .arg("-CAcreateserial")
        .arg("-extfile")
        .arg(extensions)
        .arg("-out")
        .arg(&cert))?;
    let chain = [fs::read(&cert)?, fs::read(&root)?].concat();
    fs::write(&cert, chain)?;
    Ok((cert, key))
}

struct CountingSigner {
    inner: c2pa::BoxedSigner,
    count: Arc<AtomicUsize>,
}

impl c2pa::Signer for CountingSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.inner.alg()
    }
    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        self.inner.certs()
    }
    fn reserve_size(&self) -> usize {
        self.inner.reserve_size()
    }
}

fn assertion_cbor(manifest: &[u8], label: &str) -> Result<Option<Value>> {
    for b in live_emsg::boxes(manifest)? {
        if b.kind != b"jumb" {
            continue;
        }
        let children = live_emsg::boxes(b.data)?;
        if let Some(description) = children.iter().find(|b| b.kind == b"jumd") {
            let label_bytes = description.data.get(17..).context("Missing JUMBF label")?;
            if label_bytes.split(|byte| *byte == 0).next() == Some(label.as_bytes()) {
                let cbor = children
                    .iter()
                    .find(|b| b.kind == b"cbor")
                    .context("Missing assertion CBOR")?;
                return Ok(Some(cbor_value(cbor.data)?));
            }
        }
        if let Some(value) = assertion_cbor(b.data, label)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

#[test]
fn ffmpeg_live_init_media_rotation_and_sdk_validation() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = temp.path().join("live");
    let signed = temp.path().join("signed");
    fs::create_dir(&source)?;
    fs::create_dir(&signed)?;
    run(Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=128x72:rate=10",
            "-f",
            "lavfi",
            "-i",
            "sine=sample_rate=48000",
            "-t",
            "3",
            "-c:v",
            "libx264",
            "-threads",
            "1",
            "-force_key_frames",
            "expr:if(isnan(prev_forced_t),1,gte(t,prev_forced_t+0.25-0.000001))",
            "-bf",
            "0",
            "-c:a",
            "aac",
            "-f",
            "dash",
            "-seg_duration",
            "0.25",
            "-use_timeline",
            "1",
            "-init_seg_name",
            "init-$RepresentationID$.mp4",
            "-media_seg_name",
            "chunk-$RepresentationID$-$Number%05d$.m4s",
        ])
        .arg(source.join("manifest.mpd")))?;
    let (cert, key) = certificate(temp.path())?;
    let count = Arc::new(AtomicUsize::new(0));
    let context = Arc::new(c2pa::Context::new().with_settings("[verify]\nverify_trust = false\nverify_after_sign = true\nverify_after_sign_hash = true\n")?
        .with_signer(Box::new(CountingSigner {
            inner: create_signer::from_files(cert, key, SigningAlg::Es256, None)?,
            count: count.clone(),
        })));
    let signer = FragmentSigner::new(
        context.clone(),
        signed.clone(),
        300,
        30,
        "http://127.0.0.1:8080".into(),
    )?;
    let mut init_ids = Vec::new();
    for rep in ["0", "1"] {
        let init_path = source.join(format!("init-{rep}.mp4"));
        let init = fs::read(&init_path)?;
        let timing = TrackTiming::from_init(&init)?;
        signer.process_upload(&source, &init_path)?;
        let signed_init = fs::read(signed.join(format!("init-{rep}.mp4")))?;
        let reader = Reader::from_shared_context(&context)
            .with_stream("video/mp4", Cursor::new(&signed_init))?;
        assert_ne!(reader.validation_state(), c2pa::ValidationState::Invalid);
        let manifest_id = reader
            .active_manifest()
            .and_then(|m| m.label())
            .unwrap()
            .to_owned();
        init_ids.push(manifest_id.clone());
        for sequence in 1..=3 {
            let path = source.join(format!("chunk-{rep}-{sequence:05}.m4s"));
            let raw = fs::read(&path)?;
            let (mfhd_sequence, duration) = timing.segment(&raw)?;
            assert_eq!(mfhd_sequence, sequence);
            assert!(duration > 0);
            let seconds = f64::from(duration) / f64::from(timing.timescale);
            let packet = if rep == "0" { 0.1 } else { 1024.0 / 48000.0 };
            assert!(
                seconds <= 0.25 + packet + 0.001,
                "Requested subsecond duration was not respected: {seconds}"
            );
            signer.process_upload(&source, &path)?;
            let output = fs::read(signed.join(path.file_name().unwrap()))?;
            let message = live_emsg::message(&output)?.context("Missing VSI")?;
            let cose =
                CoseSign1::from_tagged_slice(message).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            verify_signature(&cose, &cose.unprotected.key_id, None)?;
            let info = cbor_value(cose.payload.as_ref().unwrap())?;
            assert_eq!(string(field(&info, "manifestId")), manifest_id);
            let mut hash = segment_hash();
            hash.gen_hash_from_stream(&mut Cursor::new(&output))?;
            assert_eq!(
                bytes(field(field(&info, "bmffHash"), "hash")),
                hash.hash().unwrap()
            );
            let uri = field(&info, "manifestUri");
            let url = string(field(uri, "url"));
            let file = signed.join(url.rsplit('/').next().unwrap());
            let raw_manifest = fs::read(&file)?;
            assert_eq!(
                bytes(field(uri, "hash")),
                Sha256::digest(&raw_manifest).as_slice()
            );
            let assertion = assertion_cbor(&raw_manifest, "c2pa.session-keys")?
                .context("Missing session assertion")?;
            let entry = &array(field(&assertion, "keys"))[0];
            assert!(matches!(field(entry, "createdAt"), Value::Tag(0, _)));
            let binding = CoseSign1::from_slice(&c2pa_cbor::to_vec(field(entry, "signerBinding"))?)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            verify_signature(
                &binding,
                &cose.unprotected.key_id,
                Some(&context.signer()?.certs()?[0]),
            )?;
            // Both the UUID manifest and the mutable init stay unchanged between rotations.
            assert_eq!(
                fs::read(signed.join(format!("init-{rep}.mp4")))?,
                signed_init
            );
        }
        assert!(
            signer
                .process_upload(&source, &source.join(format!("chunk-{rep}-00003.m4s")))
                .is_err()
        );
    }
    assert_ne!(init_ids[0], init_ids[1]);
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "One certificate signature per track, not per segment"
    );
    signer.process_upload(&source, &source.join("manifest.mpd"))?;
    assert_eq!(
        fs::read(source.join("manifest.mpd"))?,
        fs::read(signed.join("manifest.mpd"))?
    );
    let rotation_output = temp.path().join("rotation");
    fs::create_dir(&rotation_output)?;
    let rotating = FragmentSigner::new(
        context,
        rotation_output.clone(),
        10,
        9,
        "http://127.0.0.1:8080".into(),
    )?;
    rotating.process_upload(&source, &source.join("init-0.mp4"))?;
    let first_init = fs::read(rotation_output.join("init-0.mp4"))?;
    std::thread::sleep(std::time::Duration::from_millis(1100));
    rotating.process_upload(&source, &source.join("chunk-0-00001.m4s"))?;
    assert_ne!(fs::read(rotation_output.join("init-0.mp4"))?, first_init);
    let manifests: Vec<_> = fs::read_dir(&rotation_output)?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(
        manifests
            .iter()
            .filter(|e| e.path().extension().is_some_and(|s| s == "c2pa"))
            .count(),
        2
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        4,
        "One additional certificate signature at rollover"
    );
    Ok(())
}
