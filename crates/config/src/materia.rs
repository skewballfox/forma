//! The parts of materia's configuration that forma reads: its paths, its
//! host name and its lock (architecture 2.2 and 2.3).
//!
//! Forma follows materia's loader (`pkg/config/loader.go`): the file, then
//! `MATERIA_*` variables with `__` between levels. Defaults are the ones
//! materia uses for root (`pkg/dirs`).

use std::path::{Path, PathBuf};

use forma_user::path::AbsPath;

use crate::flat::{ConfigError, Flat, Source};
use crate::types::AccountName;

/// Materia's default configuration file.
pub const DEFAULT_FILE: &str = "/etc/materia/config.toml";

/// How materia keeps two runs apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockKind {
    /// No lock. Forma can take only its own.
    None,
    /// `flock` on `<materia_dir>/lockfile`.
    File,
    /// Materia's D-Bus locker.
    Dbus,
}

/// What forma reads from materia's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MateriaConfig {
    /// The host name materia is told to use, if any.
    pub hostname: Option<String>,
    /// Materia's data directory. Default: `/var/lib/materia`.
    pub materia_dir: PathBuf,
    /// Where root materia installs Quadlets. Default: `/etc/containers/systemd`.
    pub quadlet_dir: PathBuf,
    /// Materia's copy of the repository. Default: `<materia_dir>/source`.
    pub source_dir: PathBuf,
    /// The directory inside the repository that holds the manifest, if set.
    pub source_subpath: Option<PathBuf>,
    /// Where root materia stages delegated components. Default: `<materia_dir>/delegate`.
    pub delegate_dir: PathBuf,
    /// Materia's lock.
    pub lock: LockKind,
}

impl MateriaConfig {
    /// Loads materia's configuration from `file` and `environment`.
    ///
    /// A missing file is not an error: materia's defaults for root apply.
    /// Keys forma does not read are ignored.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if the file cannot be read or parsed, or a
    /// value forma reads is not usable.
    pub fn load<I>(file: &Path, environment: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut flat = Flat::read(file)?;
        flat.overlay_env("MATERIA", environment, &["config"]);
        Self::from_flat(&flat)
    }

    /// Loads materia's configuration from TOML text.
    ///
    /// # Errors
    ///
    /// As [`MateriaConfig::load`].
    pub fn parse<I>(text: &str, file: &Path, environment: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut flat = Flat::parse(text, file)?;
        flat.overlay_env("MATERIA", environment, &["config"]);
        Self::from_flat(&flat)
    }

    fn from_flat(flat: &Flat) -> Result<Self, ConfigError> {
        let invalid = |key: &str, source: &Source, message: String| ConfigError::Invalid {
            key: key.to_owned(),
            from: source.clone(),
            message,
        };
        // Materia treats an empty string as "not set" (`cmp.Or`).
        let text = |key: &str| Ok::<_, ConfigError>(flat.text(key)?.filter(|setting| !setting.value.is_empty()));
        let directory = |key: &str| -> Result<Option<PathBuf>, ConfigError> {
            let Some(setting) = text(key)? else {
                return Ok(None);
            };
            AbsPath::new(setting.value.as_str())
                .map(|path| Some(path.as_path().to_path_buf()))
                .map_err(|error| invalid(key, &setting.source, format!("is not a usable directory: {error}")))
        };
        let materia_dir = directory("materia_dir")?.unwrap_or_else(|| PathBuf::from("/var/lib/materia"));
        let source_subpath = match text("source_subpath")? {
            Some(setting) => {
                let path = forma_user::path::RelPath::new(setting.value.as_str())
                    .map_err(|error| invalid("source_subpath", &setting.source, format!("is not usable: {error}")))?;
                Some(path.as_path().to_path_buf())
            }
            None => None,
        };
        let lock = match text("lock")? {
            None => LockKind::None,
            Some(setting) => match setting.value.as_str() {
                "file" => LockKind::File,
                "dbus" => LockKind::Dbus,
                other => {
                    return Err(invalid(
                        "lock",
                        &setting.source,
                        format!("is {other:?}; forma knows \"file\" and \"dbus\""),
                    ));
                }
            },
        };
        Ok(Self {
            hostname: text("hostname")?.map(|setting| setting.value),
            quadlet_dir: directory("quadlet_dir")?.unwrap_or_else(|| PathBuf::from("/etc/containers/systemd")),
            source_dir: directory("source_dir")?.unwrap_or_else(|| materia_dir.join("source")),
            source_subpath,
            delegate_dir: directory("executor.delegate_dir")?.unwrap_or_else(|| materia_dir.join("delegate")),
            materia_dir,
            lock,
        })
    }

    /// Returns the directory that holds one record per installed component.
    #[must_use]
    pub fn components_dir(&self) -> PathBuf {
        self.materia_dir.join("components")
    }

    /// Returns the repository manifest in materia's source cache.
    #[must_use]
    pub fn repository_manifest(&self) -> PathBuf {
        match &self.source_subpath {
            Some(subpath) => self.source_dir.join(subpath).join("MANIFEST.toml"),
            None => self.source_dir.join("MANIFEST.toml"),
        }
    }

    /// Returns the file materia locks when `lock` is `file`.
    #[must_use]
    pub fn lock_file(&self) -> PathBuf {
        self.materia_dir.join("lockfile")
    }

    /// Returns the staging directory of one account.
    #[must_use]
    pub fn staging_dir(&self, account: &AccountName) -> PathBuf {
        self.delegate_dir.join("accounts").join(account.as_str())
    }

    /// Returns the host name the way materia finds it: its configured name
    /// (`MATERIA_HOSTNAME`, then `hostname` in the file), then the system's.
    ///
    /// # Errors
    ///
    /// Returns an error if the system host name is needed and cannot be read.
    pub fn resolve_hostname(&self) -> std::io::Result<String> {
        match &self.hostname {
            Some(name) => Ok(name.clone()),
            None => Ok(std::fs::read_to_string("/proc/sys/kernel/hostname")?.trim().to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn defaults_are_materias_for_root() {
        let config = MateriaConfig::load(Path::new("/nonexistent/materia.toml"), []).unwrap();
        assert_eq!(config.materia_dir, Path::new("/var/lib/materia"));
        assert_eq!(config.quadlet_dir, Path::new("/etc/containers/systemd"));
        assert_eq!(config.source_dir, Path::new("/var/lib/materia/source"));
        assert_eq!(config.delegate_dir, Path::new("/var/lib/materia/delegate"));
        assert_eq!(config.components_dir(), Path::new("/var/lib/materia/components"));
        assert_eq!(
            config.repository_manifest(),
            Path::new("/var/lib/materia/source/MANIFEST.toml")
        );
        assert_eq!(config.lock_file(), Path::new("/var/lib/materia/lockfile"));
        assert_eq!(config.lock, LockKind::None);
        assert_eq!(config.hostname, None);
        assert_eq!(
            config.staging_dir(&AccountName::new("moonshine").unwrap()),
            Path::new("/var/lib/materia/delegate/accounts/moonshine")
        );
    }

    #[test]
    fn paths_follow_materia_dir_unless_set() {
        let text = "hostname = \"forge\"\nmateria_dir = \"/srv/materia\"\nlock = \"file\"\nsource_subpath = \"hosts/a\"\n\
                    debug = true\n[executor]\ndelegate_dir = \"/srv/delegate\"\ndelegate_timeout = 60\n[age]\nkeyfile = \"/k\"\n";
        let config = MateriaConfig::parse(text, Path::new("config.toml"), []).unwrap();
        assert_eq!(config.source_dir, Path::new("/srv/materia/source"));
        assert_eq!(config.delegate_dir, Path::new("/srv/delegate"));
        assert_eq!(
            config.repository_manifest(),
            Path::new("/srv/materia/source/hosts/a/MANIFEST.toml")
        );
        assert_eq!(config.lock, LockKind::File);
        assert_eq!(config.resolve_hostname().unwrap(), "forge");
    }

    #[test]
    fn variables_win_as_in_materias_loader() {
        let config = MateriaConfig::parse(
            "hostname = \"file-name\"\n",
            Path::new("config.toml"),
            env(&[
                ("MATERIA_HOSTNAME", "env-name"),
                ("MATERIA_EXECUTOR__DELEGATE_DIR", "/d"),
                ("MATERIA_LOCK", "dbus"),
                ("MATERIA_CONFIG", "/ignored"),
            ]),
        )
        .unwrap();
        assert_eq!(config.hostname.as_deref(), Some("env-name"));
        assert_eq!(config.delegate_dir, Path::new("/d"));
        assert_eq!(config.lock, LockKind::Dbus);
    }

    #[test]
    fn unusable_values_are_refused() {
        let path = Path::new("config.toml");
        assert!(MateriaConfig::parse("materia_dir = \"relative\"\n", path, []).is_err());
        assert!(MateriaConfig::parse("lock = \"etcd\"\n", path, []).is_err());
        assert!(MateriaConfig::parse("source_subpath = \"../up\"\n", path, []).is_err());
        assert!(
            MateriaConfig::parse("materia_dir = \"\"\n", path, []).is_ok(),
            "empty means not set"
        );
    }

    #[test]
    fn the_system_host_name_is_the_fallback() {
        let config = MateriaConfig::load(Path::new("/nonexistent/materia.toml"), []).unwrap();
        assert_ne!(config.resolve_hostname().unwrap(), "");
    }
}
