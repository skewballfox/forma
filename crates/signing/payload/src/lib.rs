//! The signature Podman's `sigstoreSigned` policy verifies.
//!
//! Podman checks a cosign "simple signing" payload: a small JSON document
//! that names an image and the digest of its manifest. The signature is an
//! ECDSA P-256 signature over that payload. In a `dir:` layout, both sit in
//! a signature file next to the image (`docs/architecture.md` 5.5).
//!
//! This library builds the payload, encodes and decodes the signature
//! file, and verifies a signature. It does no input or output and holds no
//! private key: the caller signs [`Payload::to_bytes`] with whatever key it
//! has, and hands the signature to [`SignatureFile::new`].
//!
//! The formats follow `containers/container-libs`:
//! `image/signature/internal/sigstore_payload.go` for the payload, and
//! `image/internal/signature/sigstore.go` and `signature.go` for the file.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// The `critical.type` of every payload Podman accepts.
pub const SIGNATURE_TYPE: &str = "cosign container image signature";
/// The media type of the payload.
pub const PAYLOAD_MIME_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
/// The annotation that holds the signature, in base64.
pub const SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
/// What a signature file starts with: a zero byte, the format's name, a newline.
pub const FILE_MAGIC: &[u8] = b"\x00sigstore-json\n";

/// Something about a payload, a signature file or a signature is wrong.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    /// A manifest digest is not `sha256:` and 64 lower-case hex digits.
    #[error("manifest digest {0:?} is not sha256: followed by 64 lower-case hex digits")]
    Digest(String),
    /// An image reference is empty or holds a control character.
    #[error("image reference {0:?} is empty or holds a control character")]
    Reference(String),
    /// A signature file does not start with the sigstore marker.
    #[error("the signature file does not start with the sigstore-json marker")]
    Magic,
    /// A signature file or payload is not the JSON forma expects.
    #[error("the {what} cannot be read: {message}")]
    Json {
        /// `signature file` or `payload`.
        what: &'static str,
        /// What the parser said.
        message: String,
    },
    /// A payload has another type than Podman accepts.
    #[error("the payload has type {0:?}, not \"cosign container image signature\"")]
    Type(String),
    /// A signature file has another media type, or no signature annotation.
    #[error("the signature file {0}")]
    File(&'static str),
    /// A public key is not a P-256 key in PEM.
    #[error("the public key cannot be read: {0}")]
    PublicKey(String),
    /// The signature is not valid base64 or not an ASN.1 ECDSA signature.
    #[error("the signature is not an ASN.1 ECDSA signature in base64")]
    SignatureEncoding,
    /// No given key made the signature over this payload.
    #[error("the signature was not made by a trusted key, or the payload was changed after it was signed")]
    BadSignature,
    /// The signature is good, and it is for another image.
    #[error("the signature is for image {signed}, not {expected}")]
    WrongReference {
        /// The reference in the payload.
        signed: String,
        /// The reference the caller expects.
        expected: String,
    },
    /// The signature is good, and it is for another manifest.
    #[error("the signature is for manifest {signed}, not {expected}")]
    WrongDigest {
        /// The digest in the payload.
        signed: String,
        /// The digest of the manifest at hand.
        expected: String,
    },
}

/// The digest of an image manifest: `sha256:` and 64 hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ManifestDigest(String);

impl ManifestDigest {
    /// Computes the digest of manifest bytes. The signature covers these
    /// exact bytes, so nothing may convert the manifest afterwards.
    #[must_use]
    pub fn of(manifest: &[u8]) -> Self {
        let hash = Sha256::digest(manifest);
        let mut text = String::with_capacity(7 + 64);
        text.push_str("sha256:");
        for byte in hash {
            text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            text.push(char::from_digit(u32::from(byte & 0xf), 16).unwrap_or('0'));
        }
        Self(text)
    }

    /// Checks a digest written as text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Digest`] unless the text is `sha256:` and 64
    /// lower-case hex digits.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let hex = text
            .strip_prefix("sha256:")
            .ok_or_else(|| Error::Digest(text.to_owned()))?;
        if hex.len() == 64 && hex.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(text.to_owned()))
        } else {
            Err(Error::Digest(text.to_owned()))
        }
    }

    /// Returns the digest as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ManifestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a signature says: this reference names the image with this manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// The image reference, such as `localhost/moonshine/steam:latest`.
    /// Podman compares it with the `signedIdentity` of the policy.
    pub reference: String,
    /// The digest of the image's manifest.
    pub digest: ManifestDigest,
    /// Who made the signature. Not checked by anyone; for people.
    pub creator: Option<String>,
    /// When the signature was made, in seconds since 1970. Not checked.
    pub timestamp: Option<i64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawImage {
    #[serde(rename = "docker-manifest-digest")]
    digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    #[serde(rename = "docker-reference")]
    reference: String,
}

// Field order is the order Go's encoder writes a map in: by key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCritical {
    identity: RawIdentity,
    image: RawImage,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Serialize, Deserialize, Default)]
struct RawOptional {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    creator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timestamp: Option<i64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPayload {
    critical: RawCritical,
    // Podman accepts `null` here, and keys it does not know.
    optional: Option<RawOptional>,
}

impl Payload {
    /// Builds a payload for an image.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Reference`] if the reference is empty or holds a
    /// control character.
    pub fn new(reference: &str, digest: ManifestDigest) -> Result<Self, Error> {
        if reference.is_empty() || reference.chars().any(char::is_control) {
            return Err(Error::Reference(reference.to_owned()));
        }
        Ok(Self {
            reference: reference.to_owned(),
            digest,
            creator: None,
            timestamp: None,
        })
    }

    /// Returns the bytes to sign. The signature is over exactly these
    /// bytes, so store them as they are: encoding the payload again may
    /// give other bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let raw = RawPayload {
            critical: RawCritical {
                identity: RawIdentity {
                    reference: self.reference.clone(),
                },
                image: RawImage {
                    digest: self.digest.0.clone(),
                },
                kind: SIGNATURE_TYPE.to_owned(),
            },
            optional: Some(RawOptional {
                creator: self.creator.clone(),
                timestamp: self.timestamp,
            }),
        };
        serde_json::to_vec(&raw).unwrap_or_else(|_| unreachable!("a payload holds only strings and numbers"))
    }

    /// Reads a payload. It is as strict as Podman: `critical` may hold no
    /// key it does not know.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Json`], [`Error::Type`], [`Error::Digest`] or
    /// [`Error::Reference`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let raw: RawPayload = serde_json::from_slice(bytes).map_err(|error| Error::Json {
            what: "payload",
            message: error.to_string(),
        })?;
        if raw.critical.kind != SIGNATURE_TYPE {
            return Err(Error::Type(raw.critical.kind));
        }
        let optional = raw.optional.unwrap_or_default();
        Ok(Self {
            creator: optional.creator,
            timestamp: optional.timestamp,
            ..Self::new(
                &raw.critical.identity.reference,
                ManifestDigest::parse(&raw.critical.image.digest)?,
            )?
        })
    }
}

#[derive(Serialize, Deserialize)]
struct RawFile {
    #[serde(rename = "mimeType")]
    mime_type: String,
    // Go writes a byte slice as base64.
    payload: String,
    annotations: BTreeMap<String, String>,
}

/// A signature as Podman stores it next to an image in a `dir:` layout,
/// in a file named `signature-1`, `signature-2` and so on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFile {
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl SignatureFile {
    /// Pairs the signed bytes with their signature.
    ///
    /// `payload` is what [`Payload::to_bytes`] returned, and `signature`
    /// the ECDSA P-256 signature over it, with SHA-256, in ASN.1 DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SignatureEncoding`] if `signature` is not ASN.1 DER.
    pub fn new(payload: Vec<u8>, signature: &[u8]) -> Result<Self, Error> {
        Signature::from_der(signature).map_err(|_| Error::SignatureEncoding)?;
        Ok(Self {
            payload,
            signature: signature.to_vec(),
        })
    }

    /// Returns the signed bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the file's contents.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let raw = RawFile {
            mime_type: PAYLOAD_MIME_TYPE.to_owned(),
            payload: STANDARD.encode(&self.payload),
            annotations: BTreeMap::from([(SIGNATURE_ANNOTATION.to_owned(), STANDARD.encode(&self.signature))]),
        };
        let mut bytes = FILE_MAGIC.to_vec();
        bytes.extend(serde_json::to_vec(&raw).unwrap_or_else(|_| unreachable!("a signature file holds only strings")));
        bytes
    }

    /// Reads a file's contents. Annotations forma does not know are dropped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Magic`], [`Error::Json`], [`Error::File`] or
    /// [`Error::SignatureEncoding`].
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let json = bytes.strip_prefix(FILE_MAGIC).ok_or(Error::Magic)?;
        let raw: RawFile = serde_json::from_slice(json).map_err(|error| Error::Json {
            what: "signature file",
            message: error.to_string(),
        })?;
        if raw.mime_type != PAYLOAD_MIME_TYPE {
            return Err(Error::File("has another media type than a simple-signing payload"));
        }
        let signature = raw
            .annotations
            .get(SIGNATURE_ANNOTATION)
            .ok_or(Error::File("has no signature annotation"))?;
        let signature = STANDARD.decode(signature).map_err(|_| Error::SignatureEncoding)?;
        let payload = STANDARD
            .decode(&raw.payload)
            .map_err(|_| Error::File("has a payload that is not base64"))?;
        Self::new(payload, &signature)
    }

    /// Checks the signature the way Podman does for `sigstoreSigned` with
    /// `exactReference`: one of `keys` made it over the stored bytes, and
    /// the payload names this reference and this manifest.
    ///
    /// The signature is checked before the payload is read, so an
    /// untrusted payload is never parsed as if it were trusted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadSignature`], [`Error::WrongReference`],
    /// [`Error::WrongDigest`], or an error from reading the payload.
    pub fn verify(&self, keys: &[PublicKey], reference: &str, digest: &ManifestDigest) -> Result<Payload, Error> {
        let signature = Signature::from_der(&self.signature).map_err(|_| Error::SignatureEncoding)?;
        if !keys.iter().any(|key| key.0.verify(&self.payload, &signature).is_ok()) {
            return Err(Error::BadSignature);
        }
        let payload = Payload::from_bytes(&self.payload)?;
        if payload.digest != *digest {
            return Err(Error::WrongDigest {
                signed: payload.digest.0,
                expected: digest.0.clone(),
            });
        }
        if payload.reference != reference {
            return Err(Error::WrongReference {
                signed: payload.reference,
                expected: reference.to_owned(),
            });
        }
        Ok(payload)
    }
}

/// A P-256 public key that verifies signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Reads a public key from PEM (`-----BEGIN PUBLIC KEY-----`), the
    /// form Podman's `keyPath` takes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PublicKey`] if the text is not a P-256 public key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        VerifyingKey::from_public_key_pem(pem)
            .map(Self)
            .map_err(|error| Error::PublicKey(error.to_string()))
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(key: VerifyingKey) -> Self {
        Self(key)
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer as _;

    use super::*;

    const REFERENCE: &str = "localhost/moonshine/steam:latest";

    /// A fixed test key. Signing with it is deterministic (RFC 6979).
    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn public(seed: u8) -> PublicKey {
        PublicKey::from(*key(seed).verifying_key())
    }

    fn digest() -> ManifestDigest {
        ManifestDigest::of(b"{\"schemaVersion\":2}")
    }

    fn signed(seed: u8) -> SignatureFile {
        let payload = Payload::new(REFERENCE, digest()).unwrap().to_bytes();
        let signature: Signature = key(seed).sign(&payload);
        SignatureFile::new(payload, signature.to_der().as_bytes()).unwrap()
    }

    #[test]
    fn a_digest_is_sha256_of_the_manifest_bytes() {
        // sha256 of the empty input.
        assert_eq!(
            ManifestDigest::of(b"").as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(ManifestDigest::parse(digest().as_str()).unwrap(), digest());
        for bad in [
            "",
            "sha256:",
            "sha256:E3B0",
            "sha512:00",
            &format!("sha256:{}", "g".repeat(64)),
            &"0".repeat(64),
        ] {
            assert!(ManifestDigest::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_payload_is_the_json_podman_writes() {
        let mut payload = Payload::new(REFERENCE, ManifestDigest::of(b"")).unwrap();
        assert_eq!(
            String::from_utf8(payload.to_bytes()).unwrap(),
            "{\"critical\":{\"identity\":{\"docker-reference\":\"localhost/moonshine/steam:latest\"},\
             \"image\":{\"docker-manifest-digest\":\
             \"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"},\
             \"type\":\"cosign container image signature\"},\"optional\":{}}"
        );
        payload.creator = Some("forma 0.1.0".into());
        payload.timestamp = Some(1_763_164_800);
        let text = String::from_utf8(payload.to_bytes()).unwrap();
        assert!(
            text.ends_with("\"optional\":{\"creator\":\"forma 0.1.0\",\"timestamp\":1763164800}}"),
            "{text}"
        );
        assert_eq!(Payload::from_bytes(text.as_bytes()).unwrap(), payload);
    }

    #[test]
    fn a_payload_from_cosign_or_podman_reads() {
        // cosign writes `"optional": null`; Podman adds keys of its own.
        let digest = digest();
        for optional in [
            "null",
            "{\"creator\":\"containers/image 5.36\",\"timestamp\":1,\"other\":[1]}",
        ] {
            let text = format!(
                "{{\"critical\":{{\"type\":\"cosign container image signature\",\"image\":\
                 {{\"docker-manifest-digest\":\"{digest}\"}},\"identity\":{{\"docker-reference\":\"{REFERENCE}\"}}}},\
                 \"optional\":{optional}}}"
            );
            let payload = Payload::from_bytes(text.as_bytes()).unwrap();
            assert_eq!(
                (payload.reference.as_str(), &payload.digest),
                (REFERENCE, &digest),
                "{optional}"
            );
        }
    }

    #[test]
    fn a_payload_with_unknown_critical_keys_or_another_type_is_refused() {
        let digest = digest();
        let payload = |critical: &str| {
            format!(
                "{{\"critical\":{{{critical}\"image\":{{\"docker-manifest-digest\":\"{digest}\"}},\
                     \"identity\":{{\"docker-reference\":\"{REFERENCE}\"}}}},\"optional\":null}}"
            )
        };
        let good = payload("\"type\":\"cosign container image signature\",");
        assert!(Payload::from_bytes(good.as_bytes()).is_ok());
        let extra = payload("\"type\":\"cosign container image signature\",\"extra\":1,");
        assert!(matches!(Payload::from_bytes(extra.as_bytes()), Err(Error::Json { .. })));
        let other = payload("\"type\":\"atomic container signature\",");
        assert!(matches!(Payload::from_bytes(other.as_bytes()), Err(Error::Type(_))));
        assert!(matches!(Payload::from_bytes(b"{}"), Err(Error::Json { .. })));
        assert!(Payload::new("", digest.clone()).is_err());
        assert!(Payload::new("a\nb", digest).is_err());
    }

    #[test]
    fn the_file_is_the_marker_then_three_json_keys() {
        let file = signed(7);
        let bytes = file.encode();
        assert!(bytes.starts_with(b"\x00sigstore-json\n{"));
        let json: serde_json::Value = serde_json::from_slice(&bytes[FILE_MAGIC.len()..]).unwrap();
        let object = json.as_object().unwrap();
        let mut keys: Vec<&String> = object.keys().collect();
        keys.sort();
        assert_eq!(keys, ["annotations", "mimeType", "payload"]);
        assert_eq!(object["mimeType"], PAYLOAD_MIME_TYPE);
        assert_eq!(
            STANDARD.decode(object["payload"].as_str().unwrap()).unwrap(),
            file.payload()
        );
        assert!(object["annotations"][SIGNATURE_ANNOTATION].is_string());
        assert_eq!(SignatureFile::decode(&bytes).unwrap(), file);
    }

    #[test]
    fn a_good_signature_verifies_and_returns_what_was_signed() {
        let file = SignatureFile::decode(&signed(7).encode()).unwrap();
        let payload = file.verify(&[public(7)], REFERENCE, &digest()).unwrap();
        assert_eq!(payload.reference, REFERENCE);
        // During a key rotation the policy lists both keys; either may have signed.
        assert!(file.verify(&[public(8), public(7)], REFERENCE, &digest()).is_ok());
    }

    #[test]
    fn another_key_a_changed_payload_or_another_image_fail() {
        let file = signed(7);
        assert_eq!(
            file.verify(&[public(8)], REFERENCE, &digest()),
            Err(Error::BadSignature)
        );
        assert_eq!(file.verify(&[], REFERENCE, &digest()), Err(Error::BadSignature));

        let other_reference = file.verify(&[public(7)], "localhost/moonshine/steam:other", &digest());
        assert!(
            matches!(other_reference, Err(Error::WrongReference { .. })),
            "{other_reference:?}"
        );
        let other_manifest = file.verify(&[public(7)], REFERENCE, &ManifestDigest::of(b"changed manifest"));
        assert!(
            matches!(other_manifest, Err(Error::WrongDigest { .. })),
            "{other_manifest:?}"
        );

        // The same signature over a payload for another image.
        let forged = Payload::new("localhost/evil:latest", digest()).unwrap().to_bytes();
        let signature: Signature = key(7).sign(file.payload());
        let moved = SignatureFile::new(forged, signature.to_der().as_bytes()).unwrap();
        assert_eq!(
            moved.verify(&[public(7)], "localhost/evil:latest", &digest()),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn broken_files_are_refused() {
        let good = signed(7).encode();
        assert_eq!(SignatureFile::decode(&good[1..]), Err(Error::Magic));
        assert_eq!(SignatureFile::decode(b"\x00simple-signing\n"), Err(Error::Magic));
        assert!(matches!(
            SignatureFile::decode(b"\x00sigstore-json\nnot json"),
            Err(Error::Json { .. })
        ));
        let text = String::from_utf8(good[FILE_MAGIC.len()..].to_vec()).unwrap();
        let with = |from: &str, to: &str| {
            let mut bytes = FILE_MAGIC.to_vec();
            bytes.extend(text.replace(from, to).into_bytes());
            SignatureFile::decode(&bytes)
        };
        assert!(matches!(with(PAYLOAD_MIME_TYPE, "text/plain"), Err(Error::File(_))));
        assert!(matches!(
            with(SIGNATURE_ANNOTATION, "other/annotation"),
            Err(Error::File(_))
        ));
        assert!(SignatureFile::new(Vec::new(), b"not der").is_err());
    }

    #[test]
    fn a_public_key_reads_from_pem() {
        use p256::pkcs8::EncodePublicKey as _;
        let pem = key(7)
            .verifying_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(PublicKey::from_pem(&pem).unwrap(), public(7));
        assert!(PublicKey::from_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n").is_err());
        assert!(PublicKey::from_pem("").is_err());
    }
}
