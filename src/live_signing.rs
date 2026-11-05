use std::io::Cursor;

use anyhow::{Context, Result, ensure};
use c2pa::assertions::{BmffHash, DataMap, ExclusionsMap};
use c2pa_cbor::Value;
use chrono::{DateTime, Utc};
use coset::{
    CborSerializable, CoseKeyBuilder, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable, iana,
};
use ed25519_dalek::{Signer, SigningKey};

use crate::live_emsg::SCHEME;

pub(crate) fn map(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::Text(key.into()), value))
            .collect(),
    )
}

pub(crate) fn text(value: impl Into<String>) -> Value {
    Value::Text(value.into())
}

pub(crate) fn cbor_value(bytes: &[u8]) -> Result<Value> {
    Ok(Value::from_tagged_slice(bytes)?)
}

pub(crate) struct SessionKey {
    key: SigningKey,
    pub kid: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub validity_secs: u32,
    pub min_sequence: u32,
}

impl SessionKey {
    pub fn new(now: DateTime<Utc>, validity_secs: u32, min_sequence: u32) -> Result<Self> {
        ensure!(validity_secs > 0, "Session key validity must be positive");
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).context("Failed to generate session key")?;
        let key = SigningKey::from_bytes(&secret);
        secret.fill(0);
        let kid = key.verifying_key().to_bytes().to_vec();
        Ok(Self {
            key,
            kid,
            created_at: DateTime::from_timestamp(now.timestamp(), 0)
                .context("Session creation time is outside the supported range")?,
            validity_secs,
            min_sequence,
        })
    }

    pub fn needs_rotation(&self, now: DateTime<Utc>, overlap_secs: u32) -> bool {
        now.signed_duration_since(self.created_at).num_seconds()
            >= i64::from(self.validity_secs - overlap_secs)
    }

    pub fn assertion(&self, certificate: &[u8]) -> Result<Value> {
        let public_key = CoseKeyBuilder::new_okp_key()
            .param(
                iana::OkpKeyParameter::Crv as i64,
                coset::cbor::value::Value::from(iana::EllipticCurve::Ed25519 as u64),
            )
            .param(
                iana::OkpKeyParameter::X as i64,
                coset::cbor::value::Value::Bytes(self.kid.clone()),
            )
            .key_id(self.kid.clone())
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        let binding = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(iana::Algorithm::EdDSA)
                    .build(),
            )
            .create_detached_signature(certificate, &[], |data| {
                self.key.sign(data).to_bytes().to_vec()
            })
            .build();
        Ok(map([(
            "keys",
            Value::Array(vec![map([
                (
                    "key",
                    cbor_value(&public_key.to_vec().context("Encoding COSE public key")?)?,
                ),
                (
                    "minSequenceNumber",
                    Value::Integer(i64::from(self.min_sequence)),
                ),
                (
                    "createdAt",
                    Value::Tag(
                        0,
                        Box::new(text(
                            self.created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        )),
                    ),
                ),
                (
                    "validityPeriod",
                    Value::Integer(i64::from(self.validity_secs)),
                ),
                (
                    "signerBinding",
                    cbor_value(&binding.to_vec().context("Encoding signer binding")?)?,
                ),
            ])]),
        )]))
    }

    pub fn sign_segment(
        &self,
        segment: &[u8],
        sequence: u32,
        manifest_id: &str,
        manifest_uri: Value,
        now: DateTime<Utc>,
    ) -> Result<Vec<u8>> {
        ensure!(
            sequence >= self.min_sequence,
            "Sequence precedes session key"
        );
        ensure!(
            now >= self.created_at
                && now < self.created_at + chrono::Duration::seconds(i64::from(self.validity_secs)),
            "Session key is not currently valid"
        );
        let mut hash = segment_hash();
        hash.gen_hash_from_stream(&mut Cursor::new(segment))?;
        let payload = map([
            ("sequenceNumber", Value::Integer(i64::from(sequence))),
            ("manifestId", text(manifest_id)),
            ("manifestUri", manifest_uri),
            ("bmffHash", cbor_value(&c2pa_cbor::to_vec(&hash)?)?),
        ]);
        let mut protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        // RFC 8392's iat is a CWT claim in the protected header, not a COSE parameter.
        protected.rest.push((
            coset::Label::Text("iat".into()),
            coset::cbor::value::Value::from(now.timestamp()),
        ));
        CoseSign1Builder::new()
            .protected(protected)
            .unprotected(HeaderBuilder::new().key_id(self.kid.clone()).build())
            .payload(c2pa_cbor::to_vec(&payload)?)
            .create_signature(&[], |data| self.key.sign(data).to_bytes().to_vec())
            .build()
            .to_tagged_vec()
            .context("Encoding VSI COSE_Sign1")
    }
}

pub(crate) fn segment_hash() -> BmffHash {
    let mut hash = BmffHash::new("Live media segment", "sha256", None);
    // Section 19.4 requires offset 0. The SDK matches offsets from the box header,
    // so also exclude the physical scheme location in a version-0 FullBox.
    for offset in [0, 12] {
        let mut exclusion = ExclusionsMap::new("/emsg".into());
        let mut value = SCHEME.as_bytes().to_vec();
        if offset == 12 {
            value.push(0);
        }
        exclusion.data = Some(vec![DataMap { offset, value }]);
        hash.exclusions_mut().push(exclusion);
    }
    hash
}
