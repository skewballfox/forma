//! What materia installed on this host (architecture 2.2).
//!
//! Forma reads materia's installed state, not the repository. Every file
//! read here is owned by root.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;

use crate::materia::MateriaConfig;
use crate::raw::{self, SyntaxError, Value};
use crate::schema::{self, COMPONENT_VERSION_FIELDS};
use crate::types::ComponentName;

/// The only `.component_version` format forma knows.
pub const KNOWN_VERSION: i64 = 1;

/// The directories that hold materia's installed state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPaths {
    /// `<materia_dir>/components`: one record per component.
    pub components_dir: PathBuf,
    /// `quadlet_dir`: one directory per component, with `.materia_managed`.
    pub quadlet_dir: PathBuf,
    /// `executor.delegate_dir`: what root materia staged for each account.
    pub delegate_dir: PathBuf,
}

impl From<&MateriaConfig> for InstalledPaths {
    fn from(config: &MateriaConfig) -> Self {
        Self {
            components_dir: config.components_dir(),
            quadlet_dir: config.quadlet_dir.clone(),
            delegate_dir: config.delegate_dir.clone(),
        }
    }
}

/// One installed component, as input for [`crate::load`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentInput {
    /// The component's name.
    pub name: ComponentName,
    /// The account materia delegated the component to: `User` in
    /// `.component_version`, exactly as written.
    pub user: Option<String>,
    /// The installed `MANIFEST.toml`.
    pub manifest: PathBuf,
    /// The component's staged copy, if it is delegated and staged.
    pub staged: Option<PathBuf>,
}

/// Why forma leaves a component alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// Materia stopped part way through installing it. The value names the
    /// file that is missing.
    Incomplete(&'static str),
    /// Its `.component_version` has a version forma does not know.
    UnknownVersion(i64),
    /// Its `.component_version` cannot be read as one.
    BadVersionFile(String),
    /// Its directory name is not a component name.
    InvalidName(&'static str),
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete(missing) => {
                write!(f, "materia did not finish installing it: {missing} is missing")
            }
            Self::UnknownVersion(version) => {
                write!(
                    f,
                    "its format version is {version}, and forma knows only version {KNOWN_VERSION}"
                )
            }
            Self::BadVersionFile(why) => write!(f, "its .component_version cannot be used: {why}"),
            Self::InvalidName(why) => write!(f, "its directory name is not a component name: {why}"),
        }
    }
}

/// A component forma found and does not act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The directory name.
    pub name: String,
    /// The account its `.component_version` names, when that could be read.
    /// Pruning keeps such an account (delegation 9).
    pub user: Option<String>,
    /// Why forma skips it.
    pub reason: SkipReason,
}

/// The components materia manages on this host.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Installed {
    /// Components that are fully installed, by name.
    pub components: Vec<ComponentInput>,
    /// Components forma skips and reports. Forma never prunes for these: a
    /// component that is not fully installed has not declared "nothing".
    pub skipped: Vec<Skipped>,
}

/// Materia's installed state could not be read.
#[derive(Debug, Error)]
pub enum InstalledError {
    /// A directory or file could not be read.
    #[error("cannot read {}: {source}", path.display())]
    Read {
        /// The path.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
}

/// What a `.component_version` file says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VersionFile {
    pub(crate) version: i64,
    pub(crate) user: Option<String>,
}

pub(crate) fn parse_version_file(text: &str, path: &Path) -> Result<VersionFile, String> {
    let file: Arc<Path> = Arc::from(path);
    let table = raw::parse(text, &file).map_err(|SyntaxError { message, .. }| message)?;
    let table = schema::canonical(&table, COMPONENT_VERSION_FIELDS, false, "").map_err(|error| error.to_string())?;
    let version = match table.get("Version").map(|node| &node.value) {
        Some(Value::Integer(version)) => *version,
        Some(other) => return Err(format!("Version is {}, not a number", other.kind())),
        None => return Err("it has no Version".to_owned()),
    };
    let user = match table.get("User").map(|node| &node.value) {
        None => None,
        // Materia writes no key for a component that is not delegated.
        Some(Value::String(user)) if user.is_empty() => None,
        Some(Value::String(user)) => Some(user.clone()),
        Some(other) => return Err(format!("User is {}, not a string", other.kind())),
    };
    Ok(VersionFile { version, user })
}

fn exists(path: &Path) -> Result<bool, InstalledError> {
    path.try_exists().map_err(|source| InstalledError::Read {
        path: path.to_path_buf(),
        source,
    })
}

/// Finds the components materia manages.
///
/// A component is installed when its Quadlet directory holds
/// `.materia_managed`, and its record holds a `.component_version` with
/// version 1 and a `MANIFEST.toml`. A directory without `.materia_managed`
/// is not materia's, and is ignored.
///
/// A missing `quadlet_dir` means nothing is installed.
///
/// # Errors
///
/// Returns [`InstalledError`] if a directory or file cannot be read.
pub fn scan(paths: &InstalledPaths) -> Result<Installed, InstalledError> {
    let read_error = |path: &Path| {
        let path = path.to_path_buf();
        move |source| InstalledError::Read { path, source }
    };
    let entries = match std::fs::read_dir(&paths.quadlet_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Installed::default()),
        Err(source) => return Err(read_error(&paths.quadlet_dir)(source)),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(read_error(&paths.quadlet_dir))?;
        if exists(&entry.path().join(".materia_managed"))? {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();

    let mut installed = Installed::default();
    for name in names {
        let record = paths.components_dir.join(&name);
        let version_path = record.join(".component_version");
        let manifest = record.join("MANIFEST.toml");
        let mut skip = |user: Option<String>, reason: SkipReason| {
            installed.skipped.push(Skipped {
                name: name.clone(),
                user,
                reason,
            });
        };
        let component = match ComponentName::new(name.as_str()) {
            Ok(component) => component,
            Err(why) => {
                skip(None, SkipReason::InvalidName(why));
                continue;
            }
        };
        let version_text = match std::fs::read_to_string(&version_path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                skip(None, SkipReason::Incomplete(".component_version"));
                continue;
            }
            Err(source) => return Err(read_error(&version_path)(source)),
        };
        let version = match parse_version_file(&version_text, &version_path) {
            Ok(version) => version,
            Err(why) => {
                skip(None, SkipReason::BadVersionFile(why));
                continue;
            }
        };
        if version.version != KNOWN_VERSION {
            skip(version.user, SkipReason::UnknownVersion(version.version));
            continue;
        }
        if !exists(&manifest)? {
            skip(version.user, SkipReason::Incomplete("MANIFEST.toml"));
            continue;
        }
        // The account name becomes a directory name only after the same
        // check an account name gets; `load` reports a bad one.
        let staged = match version.user.as_deref().map(crate::types::AccountName::new) {
            Some(Ok(account)) => {
                let staged = paths
                    .delegate_dir
                    .join("accounts")
                    .join(account.as_str())
                    .join("components")
                    .join(&name);
                exists(&staged)?.then_some(staged)
            }
            _ => None,
        };
        installed.components.push(ComponentInput {
            name: component,
            user: version.user,
            manifest,
            staged,
        });
    }
    Ok(installed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> InstalledPaths {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/installed/moonshine");
        InstalledPaths {
            components_dir: base.join("data"),
            quadlet_dir: base.join("quadlets"),
            delegate_dir: base.join("delegate"),
        }
    }

    #[test]
    fn the_fixture_has_two_installed_components() {
        let paths = fixture();
        let installed = scan(&paths).unwrap();
        let names: Vec<&str> = installed
            .components
            .iter()
            .map(|component| component.name.as_str())
            .collect();
        assert_eq!(names, ["moonshine", "nvidia-driver"]);
        for component in &installed.components {
            assert_eq!(component.user.as_deref(), Some("moonshine"));
            assert!(component.manifest.is_file());
            let staged = component.staged.as_ref().expect("delegated components are staged");
            assert!(staged.starts_with(paths.delegate_dir.join("accounts/moonshine/components")));
        }
    }

    #[test]
    fn a_half_installed_component_is_skipped_and_reported() {
        let installed = scan(&fixture()).unwrap();
        assert_eq!(
            installed.skipped,
            [Skipped {
                name: "half-installed".into(),
                user: None,
                reason: SkipReason::Incomplete(".component_version"),
            }]
        );
    }

    #[test]
    fn a_directory_materia_does_not_manage_is_ignored() {
        let installed = scan(&fixture()).unwrap();
        let all: Vec<&str> = installed
            .components
            .iter()
            .map(|component| component.name.as_str())
            .chain(installed.skipped.iter().map(|skipped| skipped.name.as_str()))
            .collect();
        assert!(!all.contains(&"hand-made"));
    }

    fn host(components: &[(&str, Option<&str>, bool)]) -> (tempfile::TempDir, InstalledPaths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = InstalledPaths {
            components_dir: dir.path().join("data"),
            quadlet_dir: dir.path().join("quadlets"),
            delegate_dir: dir.path().join("delegate"),
        };
        for (name, version, manifest) in components {
            std::fs::create_dir_all(paths.quadlet_dir.join(name)).unwrap();
            std::fs::write(paths.quadlet_dir.join(name).join(".materia_managed"), "").unwrap();
            std::fs::create_dir_all(paths.components_dir.join(name)).unwrap();
            if let Some(version) = version {
                std::fs::write(paths.components_dir.join(name).join(".component_version"), version).unwrap();
            }
            if *manifest {
                std::fs::write(paths.components_dir.join(name).join("MANIFEST.toml"), "").unwrap();
            }
        }
        (dir, paths)
    }

    #[test]
    fn a_version_file_without_a_manifest_is_incomplete_and_keeps_its_user() {
        let (_dir, paths) = host(&[("app", Some("Version = 1\nUser = \"svc\"\n"), false)]);
        let installed = scan(&paths).unwrap();
        assert_eq!(installed.components, []);
        assert_eq!(installed.skipped[0].reason, SkipReason::Incomplete("MANIFEST.toml"));
        assert_eq!(installed.skipped[0].user.as_deref(), Some("svc"));
    }

    #[test]
    fn an_unknown_version_is_skipped_and_the_rest_still_load() {
        let (_dir, paths) = host(&[
            ("new", Some("Version = 2\n"), true),
            ("ok", Some("Version = 1\n"), true),
            ("broken", Some("Version = \"one\"\n"), true),
            ("bad.name", Some("Version = 1\n"), true),
        ]);
        let installed = scan(&paths).unwrap();
        assert_eq!(installed.components.len(), 1);
        assert_eq!(installed.components[0].name.as_str(), "ok");
        assert_eq!(installed.components[0].user, None);
        assert_eq!(installed.components[0].staged, None);
        let reasons: Vec<(&str, &SkipReason)> = installed
            .skipped
            .iter()
            .map(|skipped| (skipped.name.as_str(), &skipped.reason))
            .collect();
        assert_eq!(reasons[0].0, "bad.name");
        assert!(matches!(reasons[0].1, SkipReason::InvalidName(_)));
        assert!(matches!(reasons[1], ("broken", SkipReason::BadVersionFile(_))));
        assert_eq!(reasons[2], ("new", &SkipReason::UnknownVersion(2)));
    }

    #[test]
    fn a_delegated_component_that_is_not_staged_yet_has_no_staged_copy() {
        let (_dir, paths) = host(&[("app", Some("Version = 1\nUser = \"svc\"\n"), true)]);
        let installed = scan(&paths).unwrap();
        assert_eq!(installed.components[0].user.as_deref(), Some("svc"));
        assert_eq!(installed.components[0].staged, None);
    }

    #[test]
    fn a_user_that_is_not_an_account_name_never_becomes_a_path() {
        let (_dir, paths) = host(&[("app", Some("Version = 1\nUser = \"../../etc\"\n"), true)]);
        let installed = scan(&paths).unwrap();
        assert_eq!(installed.components[0].user.as_deref(), Some("../../etc"));
        assert_eq!(installed.components[0].staged, None);
    }

    #[test]
    fn no_quadlet_directory_means_nothing_installed() {
        let dir = tempfile::tempdir().unwrap();
        let paths = InstalledPaths {
            components_dir: dir.path().join("data"),
            quadlet_dir: dir.path().join("missing"),
            delegate_dir: dir.path().join("delegate"),
        };
        assert_eq!(scan(&paths).unwrap(), Installed::default());
    }

    #[test]
    fn version_files_match_keys_as_materia_does() {
        let path = Path::new(".component_version");
        assert_eq!(
            parse_version_file("version = 1\nuser = \"svc\"\n", path).unwrap(),
            VersionFile {
                version: 1,
                user: Some("svc".into())
            }
        );
        assert_eq!(
            parse_version_file("Version = 1\nUser = \"\"\n", path).unwrap().user,
            None
        );
        assert!(parse_version_file("User = \"svc\"\n", path).is_err());
        assert!(parse_version_file("Version = 1\nUser = 5\n", path).is_err());
    }
}
