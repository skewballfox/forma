//! Signs the image in a `dir:` layout with a throwaway key, for spike 0(a)
//! of `docs/architecture.md`: does Podman accept a signature forma wrote?
//!
//! ```text
//! cargo run -p forma-signing-payload --example sign_dir -- <dir> <reference> <public key out>
//! ```
//!
//! It reads `<dir>/manifest.json`, writes `<dir>/signature-1`, and writes
//! the public key as PEM. The private key is fixed and public: never use
//! this to sign an image anyone will trust.

use std::path::Path;

use forma_signing_payload::{ManifestDigest, Payload, SignatureFile};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey as _;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [directory, reference, public_key] = arguments.as_slice() else {
        return Err("usage: sign_dir <dir> <reference> <public key out>".into());
    };
    let directory = Path::new(directory);
    let manifest = std::fs::read(directory.join("manifest.json"))?;
    let digest = ManifestDigest::of(&manifest);

    let key = SigningKey::from_slice(&[7; 32])?;
    let payload = Payload::new(reference, digest.clone())?.to_bytes();
    let signature: Signature = key.sign(&payload);
    let file = SignatureFile::new(payload, signature.to_der().as_bytes())?;

    std::fs::write(directory.join("signature-1"), file.encode())?;
    std::fs::write(public_key, key.verifying_key().to_public_key_pem(p256::pkcs8::LineEnding::LF)?)?;
    println!("signed {reference} with manifest {digest}");
    Ok(())
}
