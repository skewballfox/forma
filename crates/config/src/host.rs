//! Forma's host configuration, `/etc/forma/config.toml`.
//!
//! It holds the limits the repository may not set (architecture 7, rule 1).
//! Keys are exact snake case. Each can be set with `FORMA_<KEY>`, with `__`
//! between levels. Values load in materia's order: defaults, file,
//! environment.

use std::path::{Path, PathBuf};

use forma_user::id::IdRange;
use forma_user::path::AbsPath;

use crate::flat::{ConfigError, Flat, Setting, Source};

/// The default host configuration file.
pub const DEFAULT_FILE: &str = "/etc/forma/config.toml";
/// The variable that names another host configuration file.
pub const FILE_VARIABLE: &str = "FORMA_CONFIG";

const KNOWN: &[&str] = &[
    "paths.allowed_roots",
    "accounts.id_range.start",
    "accounts.id_range.end",
    "accounts.home_base",
    "selinux.allow_modules",
    "selinux.priority",
    "materia.config_file",
    "notify.triggers.default",
    "notify.triggers.update",
    "notify.triggers.failure",
    "base_images.host_policy",
];

/// Whether the host-wide `policy.json` applies to base image pulls.
///
/// Only the host configuration yields this type, so repository code cannot
/// build an `Ignore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HostPolicyMode {
    /// The host policy applies to every base image pull.
    #[default]
    Respect,
    /// The host policy does not apply to base image pulls.
    Ignore,
}

impl HostPolicyMode {
    /// Returns the mode as the configuration writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Respect => "respect",
            Self::Ignore => "ignore",
        }
    }
}

/// Webhooks, one per kind of event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Webhooks {
    /// Used when an event has no webhook of its own.
    pub default: Option<Setting<String>>,
    /// A build succeeded.
    pub update: Option<Setting<String>>,
    /// A run failed.
    pub failure: Option<Setting<String>>,
}

/// The host configuration, with the source of each value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    /// Absolute paths from the repository must sit under one of these.
    /// Default: `/var/lib/forma`.
    pub allowed_roots: Setting<Vec<AbsPath>>,
    /// The user and group IDs forma may allocate. Default: none set, which
    /// means the system range of `login.defs`.
    pub id_range: Option<Setting<IdRange>>,
    /// The directory that holds service account homes. Default: `/var/home`.
    pub home_base: Setting<AbsPath>,
    /// Whether the repository may install SELinux modules. Default: no.
    pub selinux_allow_modules: Setting<bool>,
    /// The priority forma installs SELinux modules at. Default: 350.
    pub selinux_priority: Setting<u16>,
    /// Materia's configuration file. Default: `/etc/materia/config.toml`.
    pub materia_config_file: Setting<PathBuf>,
    /// Webhooks for reports.
    pub webhooks: Webhooks,
    /// Whether the host-wide `policy.json` applies to base image pulls.
    /// Default: `respect`.
    pub host_policy: Setting<HostPolicyMode>,
}

impl HostConfig {
    /// Returns the built-in defaults.
    #[must_use]
    pub fn defaults() -> Self {
        let abs = |path: &str| AbsPath::new(path).unwrap_or_else(|_| unreachable!("the default is a normal path"));
        Self {
            allowed_roots: Setting::default(vec![abs("/var/lib/forma")]),
            id_range: None,
            home_base: Setting::default(abs("/var/home")),
            selinux_allow_modules: Setting::default(false),
            selinux_priority: Setting::default(350),
            materia_config_file: Setting::default(PathBuf::from(crate::materia::DEFAULT_FILE)),
            webhooks: Webhooks {
                default: None,
                update: None,
                failure: None,
            },
            host_policy: Setting::default(HostPolicyMode::Respect),
        }
    }

    /// Loads the configuration from `file` and `environment`.
    ///
    /// A missing file is not an error: the defaults apply.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if the file cannot be read or parsed, if a
    /// key or a `FORMA_*` variable is unknown, or if a value is not allowed.
    pub fn load<I>(file: &Path, environment: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut flat = Flat::read(file)?;
        flat.overlay_env("FORMA", environment, &["config", "debug"]);
        Self::from_flat(&flat)
    }

    /// Loads the configuration from TOML text, as [`HostConfig::load`] does
    /// from a file.
    ///
    /// # Errors
    ///
    /// As [`HostConfig::load`].
    pub fn parse<I>(text: &str, file: &Path, environment: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut flat = Flat::parse(text, file)?;
        flat.overlay_env("FORMA", environment, &["config", "debug"]);
        Self::from_flat(&flat)
    }

    fn from_flat(flat: &Flat) -> Result<Self, ConfigError> {
        flat.check_known(KNOWN)?;
        let mut config = Self::defaults();
        if let Some(roots) = flat.list("paths.allowed_roots")? {
            let value = roots
                .value
                .iter()
                .map(|root| abs("paths.allowed_roots", root, &roots.source))
                .collect::<Result<Vec<_>, _>>()?;
            if value.iter().any(|root| *root == AbsPath::root()) {
                return Err(invalid("paths.allowed_roots", &roots.source, "must not hold /"));
            }
            config.allowed_roots = Setting {
                value,
                source: roots.source,
            };
        }
        if let Some(base) = flat.text("accounts.home_base")? {
            config.home_base = Setting {
                value: abs("accounts.home_base", &base.value, &base.source)?,
                source: base.source,
            };
        }
        config.id_range = id_range(flat)?;
        if let Some(allow) = flat.boolean("selinux.allow_modules")? {
            config.selinux_allow_modules = allow;
        }
        if let Some(priority) = flat.integer("selinux.priority")? {
            let value = u16::try_from(priority.value)
                .ok()
                .filter(|value| (1..=999).contains(value))
                .ok_or_else(|| invalid("selinux.priority", &priority.source, "must be between 1 and 999"))?;
            config.selinux_priority = Setting {
                value,
                source: priority.source,
            };
        }
        if let Some(file) = flat.text("materia.config_file")? {
            abs("materia.config_file", &file.value, &file.source)?;
            config.materia_config_file = Setting {
                value: PathBuf::from(file.value),
                source: file.source,
            };
        }
        config.webhooks = Webhooks {
            default: webhook(flat, "notify.triggers.default")?,
            update: webhook(flat, "notify.triggers.update")?,
            failure: webhook(flat, "notify.triggers.failure")?,
        };
        if let Some(mode) = flat.text("base_images.host_policy")? {
            let value = match mode.value.as_str() {
                "respect" => HostPolicyMode::Respect,
                "ignore" => HostPolicyMode::Ignore,
                other => {
                    return Err(invalid(
                        "base_images.host_policy",
                        &mode.source,
                        format!("is {other:?}; use \"respect\" or \"ignore\""),
                    ));
                }
            };
            config.host_policy = Setting {
                value,
                source: mode.source,
            };
        }
        Ok(config)
    }

    /// Returns every setting as text, with its source, in a fixed order.
    /// `forma config` prints this.
    #[must_use]
    pub fn entries(&self) -> Vec<(&'static str, String, Source)> {
        let roots = self
            .allowed_roots
            .value
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let webhook = |name: &'static str, hook: &Option<Setting<String>>| match hook {
            Some(hook) => (name, hook.value.clone(), hook.source.clone()),
            None => (name, "(not set)".to_owned(), Source::Default),
        };
        vec![
            ("paths.allowed_roots", roots, self.allowed_roots.source.clone()),
            match &self.id_range {
                Some(range) => (
                    "accounts.id_range",
                    format!("{} to {}", range.value.first(), range.value.last()),
                    range.source.clone(),
                ),
                None => (
                    "accounts.id_range",
                    "(the system range of login.defs)".to_owned(),
                    Source::Default,
                ),
            },
            (
                "accounts.home_base",
                self.home_base.value.to_string(),
                self.home_base.source.clone(),
            ),
            (
                "selinux.allow_modules",
                self.selinux_allow_modules.value.to_string(),
                self.selinux_allow_modules.source.clone(),
            ),
            (
                "selinux.priority",
                self.selinux_priority.value.to_string(),
                self.selinux_priority.source.clone(),
            ),
            (
                "materia.config_file",
                self.materia_config_file.value.display().to_string(),
                self.materia_config_file.source.clone(),
            ),
            webhook("notify.triggers.default", &self.webhooks.default),
            webhook("notify.triggers.update", &self.webhooks.update),
            webhook("notify.triggers.failure", &self.webhooks.failure),
            (
                "base_images.host_policy",
                self.host_policy.value.as_str().to_owned(),
                self.host_policy.source.clone(),
            ),
        ]
    }
}

fn invalid(key: &str, source: &Source, message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        key: key.to_owned(),
        from: source.clone(),
        message: message.into(),
    }
}

fn abs(key: &str, text: &str, source: &Source) -> Result<AbsPath, ConfigError> {
    AbsPath::new(text).map_err(|error| invalid(key, source, format!("holds a path that is not allowed: {error}")))
}

fn id_range(flat: &Flat) -> Result<Option<Setting<IdRange>>, ConfigError> {
    match (
        flat.integer("accounts.id_range.start")?,
        flat.integer("accounts.id_range.end")?,
    ) {
        (None, None) => Ok(None),
        (Some(start), Some(end)) => {
            let range = u32::try_from(start.value)
                .ok()
                .zip(u32::try_from(end.value).ok())
                .filter(|(first, _)| *first > 0)
                .and_then(|(first, last)| IdRange::new(first, last).ok())
                .ok_or_else(|| {
                    invalid(
                        "accounts.id_range",
                        &start.source,
                        format!(
                            "must run from a start above 0 to an end not below it, not {} to {}",
                            start.value, end.value
                        ),
                    )
                })?;
            Ok(Some(Setting {
                value: range,
                source: start.source,
            }))
        }
        (Some(one), None) | (None, Some(one)) => {
            Err(invalid("accounts.id_range", &one.source, "needs both start and end"))
        }
    }
}

fn webhook(flat: &Flat, key: &str) -> Result<Option<Setting<String>>, ConfigError> {
    let Some(url) = flat.text(key)? else {
        return Ok(None);
    };
    let ok = (url.value.starts_with("https://") || url.value.starts_with("http://"))
        && !url.value.chars().any(|ch| ch.is_control() || ch.is_whitespace());
    if ok {
        Ok(Some(url))
    } else {
        Err(invalid(key, &url.source, "must be an http:// or https:// URL"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (String, PathBuf) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/host/config.toml");
        (std::fs::read_to_string(&path).unwrap(), path)
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn the_fixture_loads() {
        let (text, path) = fixture();
        let config = HostConfig::parse(&text, &path, []).unwrap();
        let roots: Vec<String> = config.allowed_roots.value.iter().map(ToString::to_string).collect();
        assert_eq!(roots, ["/var/lib/forma", "/var/home", "/etc/moonshine"]);
        let range = config.id_range.unwrap().value;
        assert_eq!((range.first(), range.last()), (900, 999));
        assert!(config.selinux_allow_modules.value);
        assert_eq!(config.selinux_priority.value, 350);
        assert_eq!(config.materia_config_file.value, Path::new("/etc/materia/config.toml"));
        assert_eq!(
            config.webhooks.failure.unwrap().value,
            "https://hooks.example.invalid/forma-alerts"
        );
        assert!(config.webhooks.update.is_none());
        assert_eq!(config.host_policy.value, HostPolicyMode::Respect);
    }

    #[test]
    fn a_missing_file_gives_the_defaults() {
        let config = HostConfig::load(Path::new("/nonexistent/forma.toml"), []).unwrap();
        assert_eq!(config, HostConfig::defaults());
        assert!(
            !config.selinux_allow_modules.value,
            "modules from the repository are off by default"
        );
    }

    #[test]
    fn variables_override_the_file_and_show_as_the_source() {
        let (text, path) = fixture();
        let config = HostConfig::parse(
            &text,
            &path,
            env(&[
                ("FORMA_SELINUX__PRIORITY", "360"),
                ("FORMA_BASE_IMAGES__HOST_POLICY", "ignore"),
                ("FORMA_PATHS__ALLOWED_ROOTS", "/srv/forma,/var/lib/forma"),
                ("FORMA_CONFIG", "/elsewhere.toml"),
                ("FORMA_DEBUG", "1"),
            ]),
        )
        .unwrap();
        assert_eq!(config.selinux_priority.value, 360);
        assert_eq!(config.host_policy.value, HostPolicyMode::Ignore);
        assert_eq!(config.allowed_roots.value.len(), 2);
        let entries = config.entries();
        let priority = entries.iter().find(|(key, _, _)| *key == "selinux.priority").unwrap();
        assert_eq!(priority.2.to_string(), "environment variable FORMA_SELINUX__PRIORITY");
    }

    #[test]
    fn bad_values_and_unknown_keys_are_refused() {
        let path = Path::new("config.toml");
        for text in [
            "[paths]\nallowed_roots = [\"/\"]\n",
            "[paths]\nallowed_roots = [\"relative\"]\n",
            "[paths]\nallowed_roots = [\"/var/../etc\"]\n",
            "[accounts]\nid_range = { start = 0, end = 10 }\n",
            "[accounts]\nid_range = { start = 20, end = 10 }\n",
            "[accounts]\nid_range = { start = 20 }\n",
            "[selinux]\npriority = 0\n",
            "[selinux]\npriority = 1000\n",
            "[selinux]\nallow_modules = \"yes\"\n",
            "[base_images]\nhost_policy = \"Ignore\"\n",
            "[base_images]\nHostPolicy = \"ignore\"\n",
            "[notify.triggers]\ndefault = \"file:///etc/passwd\"\n",
            "[notify.triggers]\nother = \"https://x.invalid\"\n",
            "[Paths]\nallowed_roots = []\n",
        ] {
            assert!(HostConfig::parse(text, path, []).is_err(), "should be refused:\n{text}");
        }
        assert!(HostConfig::parse("", path, env(&[("FORMA_NO_SUCH_KEY", "1")])).is_err());
    }
}
