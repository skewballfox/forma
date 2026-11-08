//! Checked absolute and relative paths.
//!
//! Both types hold only normal path parts: no `.`, no `..`, no repeated or
//! trailing `/`. So a checked path always names the place it seems to name,
//! before symlinks are considered. The crate refuses symlinks separately,
//! when it opens the path.

use std::ffi::OsStr;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// An absolute, normalised path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsPath(PathBuf);

impl AbsPath {
    /// Checks an absolute path.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] if the path is relative, holds `.`, `..`, a
    /// repeated or trailing `/`, or a NUL byte.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, PathError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(PathError::NotAbsolute(path));
        }
        check_normal(&path, true)?;
        Ok(Self(path))
    }

    /// The root directory, `/`.
    #[must_use]
    pub fn root() -> Self {
        Self(PathBuf::from("/"))
    }

    /// Returns the path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Returns the path relative to `/`, or `None` for `/` itself.
    #[must_use]
    pub fn relative(&self) -> Option<RelPath> {
        let rel = self.0.strip_prefix("/").ok()?;
        (!rel.as_os_str().is_empty()).then(|| RelPath(rel.to_path_buf()))
    }

    /// Returns the parent directory, or `None` for `/`.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        self.0.parent().map(|parent| Self(parent.to_path_buf()))
    }

    /// Returns the last part of the path, or `None` for `/`.
    #[must_use]
    pub fn file_name(&self) -> Option<&OsStr> {
        self.0.file_name()
    }

    /// Says whether `base` is this path or one of its ancestors.
    #[must_use]
    pub fn is_under(&self, base: &Self) -> bool {
        self.0.starts_with(&base.0)
    }

    /// Returns a path with `name` added as a new last part.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] if `name` is not a single normal part.
    pub fn join(&self, name: &OsStr) -> Result<Self, PathError> {
        let joined = self.0.join(name);
        if Path::new(name).components().count() != 1 {
            return Err(PathError::NotNormal(joined));
        }
        Self::new(joined)
    }

    /// Returns every ancestor directory, starting at `/` and ending at the
    /// parent. Returns nothing for `/`.
    #[must_use]
    pub fn ancestors(&self) -> Vec<Self> {
        let mut ancestors: Vec<Self> = self
            .0
            .ancestors()
            .skip(1)
            .map(|path| Self(path.to_path_buf()))
            .collect();
        ancestors.reverse();
        ancestors
    }
}

impl fmt::Display for AbsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display().fmt(f)
    }
}

impl AsRef<Path> for AbsPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// A relative, normalised, non-empty path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(PathBuf);

impl RelPath {
    /// Checks a relative path.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] if the path is absolute, empty, or holds
    /// `.`, `..`, a repeated or trailing `/`, or a NUL byte.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, PathError> {
        let path = path.into();
        if path.is_absolute() {
            return Err(PathError::NotRelative(path));
        }
        if path.as_os_str().is_empty() {
            return Err(PathError::Empty);
        }
        check_normal(&path, false)?;
        Ok(Self(path))
    }

    /// Returns the path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Returns a path with `name` added as a new last part.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] if `name` is not a single normal part.
    pub fn join(&self, name: &OsStr) -> Result<Self, PathError> {
        if Path::new(name).components().count() != 1 {
            return Err(PathError::NotNormal(self.0.join(name)));
        }
        Self::new(self.0.join(name))
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display().fmt(f)
    }
}

impl AsRef<Path> for RelPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// Checks that `path` holds only normal parts and is written in its
/// shortest form.
fn check_normal(path: &Path, absolute: bool) -> Result<(), PathError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) {
        return Err(PathError::Nul(path.to_path_buf()));
    }
    let mut rebuilt = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir if absolute => rebuilt.push("/"),
            Component::Normal(part) => rebuilt.push(part),
            _ => return Err(PathError::NotNormal(path.to_path_buf())),
        }
    }
    // `components()` hides "//", "/./" and a trailing "/". Comparing the
    // bytes catches them.
    if rebuilt.as_os_str().as_bytes() != bytes {
        return Err(PathError::NotNormal(path.to_path_buf()));
    }
    Ok(())
}

/// A path failed a check.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathError {
    /// An absolute path was needed.
    #[error("path {} is not absolute", .0.display())]
    NotAbsolute(PathBuf),
    /// A relative path was needed.
    #[error("path {} is not relative", .0.display())]
    NotRelative(PathBuf),
    /// The path is empty.
    #[error("path is empty")]
    Empty,
    /// The path holds `.`, `..`, a repeated or trailing `/`.
    #[error("path {} is not normalised: it holds '.', '..', '//' or a trailing '/'", .0.display())]
    NotNormal(PathBuf),
    /// The path holds a NUL byte.
    #[error("path {} holds a NUL byte", .0.display())]
    Nul(PathBuf),
}
