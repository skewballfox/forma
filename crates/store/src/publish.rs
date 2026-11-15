//! The signer's half: publish a signed image into an account's directory
//! (architecture 5.7, "Publish").
//!
//! 1. Copy the image from staging to `<image-name>.new/`, add the
//!    signature, and sync it.
//! 2. Swap it into place with `renameat2(RENAME_EXCHANGE)`, or
//!    `RENAME_NOREPLACE` for an image's first publish.
//! 3. Touch `.published`.
//! 4. Delete the old copy, now at `<image-name>.new/`.
//!
//! Steps 2 to 4 run with `.lock` held exclusively, which differs from the
//! order in 5.7 (lock only for step 4). Podman's `dir:` transport opens
//! the manifest, the signature and each blob by path, one after another,
//! so a swap during a load would hand it an old manifest and new blobs.
//! Podman's digest checks would refuse the mix, but the load would fail.
//! With the lock taken before the swap, a publish waits for the loads in
//! progress, and a load never sees a swap. Copying (step 1) does not hold
//! the lock, so loads are blocked only for the swap and the removal.
//!
//! New directories are not chmodded: they must keep the set-group-ID bit
//! they inherit from the account directory (`<signer>:<account> 2750`), so
//! the files in them get the account's group. A signer outside that group
//! could not set the bit again. Run the signer with umask `027`; a
//! directory created with another mode is an error.
//!
//! The signature is checked against the copy, not against staging: the
//! builder owns staging and could change it after the signer read it. A
//! signature whose manifest digest or reference does not match the copy
//! is refused, so the store never holds an image its signature does not
//! sign. Blob digests are checked by Podman when the account loads.
//!
//! One signer publishes to an account at a time; forma's own lock
//! (`/run/forma/lock`) is expected to see to that.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use forma_signing_payload::{ManifestDigest, Payload, SignatureFile};
use rustix::fs::{self, FlockOperation};
use rustix::io::Errno;

use crate::{Error, ImageName, LOCK, PUBLISHED, SIGNATURE, fsx, io};

/// Mode of an image directory in the store. The account directory is
/// set-group-ID, so the group is the account's.
const DIR_MODE: u32 = 0o750;
/// Mode of each file in the store.
const FILE_MODE: u32 = 0o640;
/// `S_ISGID`.
const SET_GROUP_ID: u32 = 0o2000;
/// The manifest of a `dir:` layout.
const MANIFEST: &str = "manifest.json";

/// One publish.
#[derive(Debug, Clone, Copy)]
pub struct Publish<'a> {
    /// The staging root, `/var/lib/forma/staging`.
    pub staging: &'a Path,
    /// The account's directory, `/var/lib/forma/store/<account>`.
    pub account_dir: &'a Path,
    /// The image.
    pub image: &'a ImageName,
    /// The reference the signature must name, such as
    /// `localhost/moonshine/steam:latest`.
    pub reference: &'a str,
    /// The encoded `signature-1` file, as
    /// [`SignatureFile::encode`] writes it.
    pub signature: &'a [u8],
}

/// What a publish replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Published {
    /// The image was not in the store before.
    First,
    /// An older copy was replaced and removed.
    Replaced,
}

/// Publishes one image. On an error before the swap, the store is as it
/// was; on an error after it, the new image is in place and a later
/// publish removes what is left over.
///
/// # Errors
///
/// Returns [`Error::Staging`] if staging holds anything but regular files
/// (or holds a signature, which only the signer writes),
/// [`Error::Signature`] if the signature does not sign the copy, and
/// [`Error::Io`] for a failed system call.
pub fn publish(request: &Publish<'_>) -> Result<Published, Error> {
    let image = request.image;
    let new = image.new_copy();
    let account_text = request.account_dir.display().to_string();
    let account = fsx::open_root(request.account_dir).map_err(io(format!("open {account_text}")))?;
    let account = account.as_fd();
    let lock = fsx::open_lock(account, LOCK, FILE_MODE, true).map_err(io(format!("open {account_text}/{LOCK}")))?;

    // A copy left by a publish that stopped part way: possibly an old copy a load still holds the lock for.
    match fsx::kind(account, &new) {
        Err(Errno::NOENT) => {}
        _ => with_exclusive(&lock, || fsx::remove_flat_dir(account, &new))
            .map_err(io(format!("remove {account_text}/{new}")))?,
    }

    let staging_text = request.staging.display().to_string();
    let staging_root = fsx::open_root(request.staging).map_err(io(format!("open {staging_text}")))?;
    let source =
        fsx::open_dir(staging_root.as_fd(), image.as_str()).map_err(io(format!("open {staging_text}/{image}")))?;

    let account_mode = fs::fstat(account)
        .map_err(io(format!("look at {account_text}")))?
        .st_mode;
    let expected = DIR_MODE | (account_mode & SET_GROUP_ID);
    let (target, found) = fsx::make_dir(account, &new, DIR_MODE).map_err(io(format!("create {account_text}/{new}")))?;
    if found != expected {
        let _ = fsx::remove_flat_dir(account, &new);
        return Err(Error::DirMode {
            path: format!("{account_text}/{new}"),
            found,
            expected,
        });
    }
    if let Err(error) = fill(request, source.as_fd(), target.as_fd(), &account_text) {
        // Best effort: the next publish removes it too.
        let _ = fsx::remove_flat_dir(account, &new);
        return Err(error);
    }
    drop(target);

    // Held until this function returns: the swap, the stamp and the removal of the old copy.
    fs::flock(&lock, FlockOperation::LockExclusive).map_err(io(format!("lock {account_text}/{LOCK}")))?;
    let published = match fsx::exchange(account, &new, image.as_str()) {
        Ok(()) => Published::Replaced,
        Err(Errno::NOENT) => {
            fsx::rename_new(account, &new, image.as_str())
                .map_err(io(format!("move {account_text}/{new} into place")))?;
            Published::First
        }
        Err(error) => {
            return Err(Error::Io {
                what: format!("swap {account_text}/{new} into place"),
                source: error,
            });
        }
    };
    fs::fsync(account).map_err(io(format!("sync {account_text}")))?;

    let mut stamp = fsx::open_write(account, PUBLISHED, FILE_MODE, false)
        .map_err(io(format!("open {account_text}/{PUBLISHED}")))?;
    std::io::Write::write_all(&mut stamp, format!("{image}\n").as_bytes())
        .and_then(|()| stamp.sync_all())
        .map_err(|error| Error::Io {
            what: format!("write {account_text}/{PUBLISHED}"),
            source: Errno::from_io_error(&error).unwrap_or(Errno::IO),
        })?;

    if published == Published::Replaced {
        fsx::remove_flat_dir(account, &new).map_err(io(format!("remove the old copy {account_text}/{new}")))?;
    }
    Ok(published)
}

/// Copies the staged files into `target`, adds the signature, checks it
/// against the copy, and syncs the directory.
fn fill(
    request: &Publish<'_>,
    source: BorrowedFd<'_>,
    target: BorrowedFd<'_>,
    account_text: &str,
) -> Result<(), Error> {
    let image = request.image;
    let staging_error = |entry: &str, reason: &'static str| Error::Staging {
        image: image.clone(),
        entry: entry.to_owned(),
        reason,
    };
    let staged = fsx::names(source).map_err(io(format!("list staged image {image}")))?;
    if !staged.iter().any(|name| name == MANIFEST) {
        return Err(staging_error(MANIFEST, "is missing"));
    }
    let mut manifest = None;
    for name in &staged {
        if name.starts_with("signature-") {
            return Err(staging_error(name, "is a signature; only the signer writes one"));
        }
        if name.starts_with('.') || name.contains(char::REPLACEMENT_CHARACTER) {
            return Err(staging_error(name, "is not a name buildah writes"));
        }
        let from = match fsx::open_regular(source, name) {
            Ok(file) => file,
            Err(Errno::LOOP | Errno::INVAL | Errno::ISDIR | Errno::NXIO) => {
                return Err(staging_error(name, "is not a regular file"));
            }
            Err(error) => {
                return Err(Error::Io {
                    what: format!("open staged {image}/{name}"),
                    source: error,
                });
            }
        };
        let mut to = fsx::open_write(target, name, FILE_MODE, true)
            .map_err(io(format!("create {account_text}/{}/{name}", image.new_copy())))?;
        let kept = fsx::copy(from, &mut to, name == MANIFEST).map_err(|error| Error::Io {
            what: format!("copy {image}/{name}"),
            source: Errno::from_io_error(&error).unwrap_or(Errno::IO),
        })?;
        if kept.is_some() {
            manifest = kept;
        }
    }
    let manifest = manifest.unwrap_or_default();
    check_signature(request, &manifest)?;

    let mut file = fsx::open_write(target, SIGNATURE, FILE_MODE, true)
        .map_err(io(format!("create {account_text}/{}/{SIGNATURE}", image.new_copy())))?;
    std::io::Write::write_all(&mut file, request.signature)
        .and_then(|()| file.sync_all())
        .map_err(|error| Error::Io {
            what: format!("write the signature of {image}"),
            source: Errno::from_io_error(&error).unwrap_or(Errno::IO),
        })?;
    fs::fsync(target).map_err(io(format!("sync {account_text}/{}", image.new_copy())))
}

fn check_signature(request: &Publish<'_>, manifest: &[u8]) -> Result<(), Error> {
    let refuse = |reason: String| Error::Signature {
        image: request.image.clone(),
        reason,
    };
    let file = SignatureFile::decode(request.signature).map_err(|error| refuse(error.to_string()))?;
    let payload = Payload::from_bytes(file.payload()).map_err(|error| refuse(error.to_string()))?;
    let digest = ManifestDigest::of(manifest);
    if payload.digest != digest {
        return Err(refuse(format!(
            "it signs manifest {}, but the copied manifest is {digest}",
            payload.digest
        )));
    }
    if payload.reference != request.reference {
        return Err(refuse(format!(
            "it names {}, not {}",
            payload.reference, request.reference
        )));
    }
    Ok(())
}

fn with_exclusive<T>(lock: &OwnedFd, work: impl FnOnce() -> Result<T, Errno>) -> Result<T, Errno> {
    fs::flock(lock, FlockOperation::LockExclusive)?;
    let result = work();
    fs::flock(lock, FlockOperation::Unlock)?;
    result
}
