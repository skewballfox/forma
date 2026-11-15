//! The account's half: load published images (architecture 5.7, "Load").
//!
//! Take `<account>/.lock` shared, then `podman pull dir:<path>` with the
//! account's verifying policy. A publish that swaps an image in meanwhile
//! waits for the shared lock before it removes the old copy, so the copy
//! being pulled stays whole.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::path::Path;
//! use forma_process::Rootless;
//!
//! let account_dir = Path::new("/var/lib/forma/store/moonshine");
//! let rootless = Rootless { home: "/var/home/moonshine".into(), runtime_dir: "/run/user/1001".into() };
//! let lock = forma_store::lock_shared(account_dir)?;
//! for image in forma_store::images(account_dir)? {
//!     forma_store::pull_command(&lock, &image, &rootless, None)?.run()?;
//! }
//! drop(lock);
//! # Ok(())
//! # }
//! ```

use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use forma_process::{Command, Rootless, podman};
use rustix::fs::{self, FileType, FlockOperation};
use rustix::io::Errno;

use crate::{Error, ImageName, LOCK, fsx, io};

/// A shared hold on an account directory's `.lock`. While it lives, no
/// publish removes an image copy. Dropping it releases the lock.
#[derive(Debug)]
pub struct LoadLock {
    directory: OwnedFd,
    path: PathBuf,
    // Closing the descriptor releases the lock.
    _lock: OwnedFd,
}

/// Takes the account directory's lock shared, waiting for a publish that
/// holds it exclusively.
///
/// # Errors
///
/// Returns [`Error::NothingPublished`] if the directory has no lock file,
/// and [`Error::Io`] for a failed system call.
pub fn lock_shared(account_dir: &Path) -> Result<LoadLock, Error> {
    let text = account_dir.display().to_string();
    let directory = fsx::open_root(account_dir).map_err(io(format!("open {text}")))?;
    let lock = match fsx::open_lock(directory.as_fd(), LOCK, 0, false) {
        Ok(lock) => lock,
        Err(Errno::NOENT) => return Err(Error::NothingPublished(text)),
        Err(error) => {
            return Err(Error::Io {
                what: format!("open {text}/{LOCK}"),
                source: error,
            });
        }
    };
    fs::flock(&lock, FlockOperation::LockShared).map_err(io(format!("lock {text}/{LOCK}")))?;
    Ok(LoadLock {
        directory,
        path: account_dir.to_path_buf(),
        _lock: lock,
    })
}

/// Lists the images published in an account directory: its
/// subdirectories with a valid image name. Copies in the middle of a
/// publish (`.new`) and the lock and stamp files are left out.
///
/// # Errors
///
/// Returns [`Error::Io`] if the directory cannot be read.
pub fn images(account_dir: &Path) -> Result<Vec<ImageName>, Error> {
    let text = account_dir.display().to_string();
    let directory = fsx::open_root(account_dir).map_err(io(format!("open {text}")))?;
    let mut images = Vec::new();
    for name in fsx::names(directory.as_fd()).map_err(io(format!("list {text}")))? {
        let Ok(image) = ImageName::new(&name) else { continue };
        match fsx::kind(directory.as_fd(), &name) {
            Ok(FileType::Directory) => images.push(image),
            // Removed meanwhile, or not a directory: not an image.
            Ok(_) | Err(Errno::NOENT) => {}
            Err(error) => {
                return Err(Error::Io {
                    what: format!("look at {text}/{name}"),
                    source: error,
                });
            }
        }
    }
    Ok(images)
}

/// Builds the `podman pull dir:<path>` that loads one image, checked
/// against `policy` (or the account's own `policy.json` when `None`). Run
/// it while `lock` is held.
///
/// # Errors
///
/// Returns [`Error::NotPublished`] if the image is not a directory in the
/// store, and [`Error::Command`] if the command cannot be built.
pub fn pull_command(
    lock: &LoadLock,
    image: &ImageName,
    rootless: &Rootless,
    policy: Option<&Path>,
) -> Result<Command, Error> {
    match fsx::open_dir(lock.directory.as_fd(), image.as_str()) {
        Ok(_) => {}
        Err(Errno::NOENT | Errno::LOOP | Errno::NOTDIR) => {
            return Err(Error::NotPublished {
                image: image.clone(),
                account_dir: lock.path.display().to_string(),
            });
        }
        Err(error) => {
            return Err(Error::Io {
                what: format!("open {}/{image}", lock.path.display()),
                source: error,
            });
        }
    }
    Ok(podman::pull_from_dir(
        rootless,
        policy,
        &lock.path.join(image.as_str()),
    )?)
}
