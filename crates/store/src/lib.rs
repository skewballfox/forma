//! Forma's local image store (architecture 5.7).
//!
//! ```text
//! /var/lib/forma/staging/<image-name>/     builder writes, signer reads
//! /var/lib/forma/store/<account>/          signer owns, account reads
//!     .lock                                shared by loads, exclusive for cleanup
//!     .published                           touched after each publish
//!     <image-name>/                        one dir: layout per image
//!         manifest.json, <blobs>, signature-1
//! ```
//!
//! [`publish`] is the signer's half, [`load`] the account's. Both run
//! unprivileged. Every file inside the staging and store directories is
//! opened with `openat2`, `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`, so
//! a builder or an account that plants a link cannot send the signer or
//! another account elsewhere.
//!
//! Creating the directories, their owners and ACLs is the `admin` part of
//! 5.7. It goes through `forma_user::admin` and needs root, so it belongs
//! with the executor and is not here.

use std::fmt;

use forma_config::types::ImageRef;
use rustix::io::Errno;

mod fsx;
pub mod load;
pub mod publish;

pub use load::{LoadLock, images, lock_shared, pull_command};
pub use publish::{Publish, Published, publish};

/// The lock file of an account directory.
pub const LOCK: &str = ".lock";
/// The stamp of the last publish: `forma load`, which the account's
/// `forma-load.timer` starts, compares it with what it loaded last.
pub const PUBLISHED: &str = ".published";
/// The one signature of a published image.
pub const SIGNATURE: &str = "signature-1";
/// Where a new copy is written, and where the old one waits for removal.
const NEW_SUFFIX: &str = ".new";

/// The name of an image's directory in staging and in the store, such as
/// `moonshine_steam_latest`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImageName(String);

impl ImageName {
    /// Checks a directory name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Name`] for a name that is empty, hidden, holds
    /// anything but `a-z`, `0-9`, `.`, `_` and `-`, or ends in `.new`.
    pub fn new(name: &str) -> Result<Self, Error> {
        let reason = if name.is_empty() || name.len() > 200 {
            Some("it must be 1 to 200 characters")
        } else if name.starts_with('.') {
            Some("it must not start with '.'")
        } else if name.ends_with(NEW_SUFFIX) {
            Some("it must not end in .new, which the store uses while publishing")
        } else if !name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-'))
        {
            Some("it may hold only a-z, 0-9, '.', '_' and '-'")
        } else {
            None
        };
        match reason {
            Some(reason) => Err(Error::Name {
                name: name.to_owned(),
                reason,
            }),
            None => Ok(Self(name.to_owned())),
        }
    }

    /// The name of an image forma builds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Name`] if the reference gives no usable name, which
    /// a reference `forma-config` accepted does not.
    pub fn of(image: &ImageRef) -> Result<Self, Error> {
        Self::new(&image.dir_name())
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn new_copy(&self) -> String {
        format!("{}{NEW_SUFFIX}", self.0)
    }
}

impl fmt::Display for ImageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A system call failed.
    #[error("cannot {what}: {source}")]
    Io {
        /// What forma was doing, with the path.
        what: String,
        /// The error.
        #[source]
        source: Errno,
    },
    /// An image name is not usable as a directory name.
    #[error("{name:?} is not an image name for the store: {reason}")]
    Name {
        /// The name.
        name: String,
        /// Why.
        reason: &'static str,
    },
    /// The staged image holds something a `dir:` layout from
    /// `buildah push` does not.
    #[error("staged image {image}: {entry:?} {reason}")]
    Staging {
        /// The image.
        image: ImageName,
        /// The entry.
        entry: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The signature does not sign the image as it was copied.
    #[error("the signature for {image} does not fit the image: {reason}")]
    Signature {
        /// The image.
        image: ImageName,
        /// Why.
        reason: String,
    },
    /// A directory the signer made does not have the mode the account
    /// needs to read it.
    #[error(
        "{path} was created with mode {found:04o}, not {expected:04o}; run the signer with umask 027 \
         and keep the account directory set-group-ID"
    )]
    DirMode {
        /// The directory.
        path: String,
        /// Its mode.
        found: u32,
        /// The mode it needs.
        expected: u32,
    },
    /// The account directory has no lock file, so nothing was published.
    #[error("{0} holds no {LOCK}: nothing has been published for this account")]
    NothingPublished(String),
    /// The image is not in the store.
    #[error("{image} is not published in {account_dir}")]
    NotPublished {
        /// The image.
        image: ImageName,
        /// The account directory.
        account_dir: String,
    },
    /// The `podman pull` command could not be built.
    #[error(transparent)]
    Command(#[from] forma_process::Error),
}

fn io(what: impl Into<String>) -> impl FnOnce(Errno) -> Error {
    let what = what.into();
    move |source| Error::Io { what, source }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_names_are_single_safe_directory_names() {
        let image = ImageRef::new("moonshine/steam:latest").unwrap();
        assert_eq!(ImageName::of(&image).unwrap().as_str(), "moonshine_steam_latest");
        assert_eq!(ImageName::new("a.b-c_1").unwrap().to_string(), "a.b-c_1");
        for bad in ["", ".lock", "..", "a/b", "A", "a.new", "a b", &"a".repeat(201)] {
            assert!(ImageName::new(bad).is_err(), "{bad:?}");
        }
    }
}
