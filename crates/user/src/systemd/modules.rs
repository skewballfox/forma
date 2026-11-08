//! `modules-load.d` files and their rendering. Nothing here touches the host.

use std::fmt::Write as _;

use thiserror::Error;

use crate::ownership::MarkerTag;
use crate::udev::is_file_stem;

/// Longest kernel module name (`MODULE_NAME_LEN` is 56, with the NUL).
const MAX_MODULE_NAME_LEN: usize = 55;

/// A kernel module name, such as `uinput`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleName(String);

impl ModuleName {
    /// Checks a module name: `[A-Za-z0-9_-]+`, at most 55 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ModulesError::ModuleName`] otherwise.
    pub fn new(name: impl Into<String>) -> Result<Self, ModulesError> {
        let name = name.into();
        let valid = !name.is_empty()
            && name.len() <= MAX_MODULE_NAME_LEN
            && name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
        if !valid {
            return Err(ModulesError::ModuleName(name));
        }
        Ok(Self(name))
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The name of a `modules-load.d` file: `name.conf`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModulesLoadFileName(String);

impl ModulesLoadFileName {
    /// Checks a name: `[a-z0-9][a-z0-9_-]*`, at most 64 bytes, without `.conf`.
    ///
    /// # Errors
    ///
    /// Returns [`ModulesError::FileName`] otherwise.
    pub fn new(name: impl Into<String>) -> Result<Self, ModulesError> {
        let name = name.into();
        if !is_file_stem(&name) {
            return Err(ModulesError::FileName(name));
        }
        Ok(Self(name))
    }

    /// Returns the file name, such as `moonshine.conf`.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!("{}.conf", self.0)
    }
}

/// A `modules-load.d` file: its name and the modules it loads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModulesLoadFile {
    name: ModulesLoadFileName,
    modules: Vec<ModuleName>,
}

impl ModulesLoadFile {
    /// Builds a file.
    ///
    /// # Errors
    ///
    /// Returns [`ModulesError::Empty`] if there are no modules.
    pub fn new(name: ModulesLoadFileName, modules: Vec<ModuleName>) -> Result<Self, ModulesError> {
        if modules.is_empty() {
            return Err(ModulesError::Empty);
        }
        Ok(Self { name, modules })
    }

    /// Returns the file's name.
    #[must_use]
    pub fn name(&self) -> &ModulesLoadFileName {
        &self.name
    }

    /// Renders the file. The first line is the managed-file header for `tag`.
    #[must_use]
    pub fn render(&self, tag: &MarkerTag) -> String {
        let mut out = format!("{}\n", tag.header_line());
        for module in &self.modules {
            // Writing to a String cannot fail.
            let _ = writeln!(out, "{}", module.as_str());
        }
        out
    }
}

/// A module name or file failed a check.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ModulesError {
    /// The module name is not allowed.
    #[error("kernel module name {0:?} is not allowed")]
    ModuleName(String),
    /// The file name is not allowed.
    #[error("modules-load.d file name {0:?} is not allowed: use [a-z0-9][a-z0-9_-]*")]
    FileName(String),
    /// The file lists no modules.
    #[error("a modules-load.d file needs at least one module")]
    Empty,
}
