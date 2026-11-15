//! Reads Quadlet and systemd unit files, checks them against forma's
//! rules, and renders the few units forma installs itself.
//!
//! See `docs/architecture.md` 5.10. This library changes nothing on the
//! host and needs no privilege.

pub mod check;
pub mod reader;
pub mod units;

use std::path::{Path, PathBuf};

pub use check::{Account, Code, Finding, ImageRole, ImageUse, UnitFile, UnitKind, check, images, kind_of};
pub use reader::{Entry, entries};

/// A unit file read from a component's staged copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedUnit {
    /// The file's path inside the component, such as `app.container`.
    pub name: String,
    /// The file's text.
    pub text: String,
}

impl StagedUnit {
    /// Returns the file in the form the checks take.
    #[must_use]
    pub fn as_unit_file(&self) -> UnitFile<'_> {
        UnitFile {
            name: &self.name,
            text: &self.text,
        }
    }
}

/// A component's staged copy could not be read.
#[derive(Debug)]
pub struct ReadError {
    /// The file or directory.
    pub path: PathBuf,
    /// Why.
    pub source: std::io::Error,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot read {}: {}", self.path.display(), self.source)
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Reads every unit file of a component's staged copy, by name.
///
/// Root owns the staged copy and the account can only read it
/// (architecture 2.4), so plain file access is safe here. Files that are
/// not units, and symbolic links, are left out.
///
/// # Errors
///
/// Returns [`ReadError`] if a directory or unit file cannot be read.
pub fn read_staged(directory: &Path) -> Result<Vec<StagedUnit>, ReadError> {
    let mut units = Vec::new();
    let mut pending = vec![(directory.to_path_buf(), String::new())];
    while let Some((path, prefix)) = pending.pop() {
        let error = |source| ReadError {
            path: path.clone(),
            source,
        };
        for entry in std::fs::read_dir(&path).map_err(error)? {
            let entry = entry.map_err(error)?;
            let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
            let kind = entry.file_type().map_err(error)?;
            if kind.is_dir() {
                pending.push((entry.path(), format!("{name}/")));
            } else if kind.is_file() && kind_of(&name).is_some() {
                let text = std::fs::read_to_string(entry.path()).map_err(|source| ReadError {
                    path: entry.path(),
                    source,
                })?;
                units.push(StagedUnit { name, text });
            }
        }
    }
    units.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(units)
}
