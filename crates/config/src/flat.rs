//! Configuration as dotted keys, layered the way materia layers its own:
//! built-in defaults, then a TOML file, then environment variables.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use thiserror::Error;

use crate::raw::{self, Origin, SyntaxError, Table, Value};

/// Where a configuration value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Forma's built-in default.
    Default,
    /// The configuration file.
    File(Origin),
    /// An environment variable.
    Env(String),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("default"),
            Self::File(origin) => write!(f, "{origin}"),
            Self::Env(variable) => write!(f, "environment variable {variable}"),
        }
    }
}

/// A configuration value and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting<T> {
    /// The value.
    pub value: T,
    /// Where it came from.
    pub source: Source,
}

impl<T> Setting<T> {
    pub(crate) fn default(value: T) -> Self {
        Self {
            value,
            source: Source::Default,
        }
    }
}

/// A configuration file or variable could not be used.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read {}: {source}", path.display())]
    Read {
        /// The file.
        path: std::path::PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// The file is not valid TOML.
    #[error(transparent)]
    Syntax(#[from] SyntaxError),
    /// A key is not one forma knows. Keys are exact, in snake case.
    #[error("{from}: unknown setting {key:?}")]
    UnknownKey {
        /// The key, with dots between levels.
        key: String,
        /// Where it was set.
        from: Source,
    },
    /// A value cannot be read as its setting needs.
    #[error("{from}: {key} {message}")]
    Invalid {
        /// The key, with dots between levels.
        key: String,
        /// Where it was set.
        from: Source,
        /// What is wrong, as the rest of a sentence that starts with the key.
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FlatValue {
    Text(String),
    Integer(i64),
    Bool(bool),
    List(Vec<String>),
}

/// Values by dotted key.
#[derive(Debug, Default)]
pub(crate) struct Flat {
    values: BTreeMap<String, (FlatValue, Source)>,
}

impl Flat {
    /// Reads a TOML file. A missing file gives no values.
    pub(crate) fn read(path: &Path) -> Result<Self, ConfigError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        Self::parse(&text, path)
    }

    pub(crate) fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        let file: Arc<Path> = Arc::from(path);
        let table = raw::parse(text, &file)?;
        let mut flat = Self::default();
        flat.add_table(&table, "")?;
        Ok(flat)
    }

    fn add_table(&mut self, table: &Table, prefix: &str) -> Result<(), ConfigError> {
        for entry in &table.entries {
            let key = if prefix.is_empty() {
                entry.key.clone()
            } else {
                format!("{prefix}.{}", entry.key)
            };
            let source = Source::File(entry.node.at.clone());
            let value = match &entry.node.value {
                Value::Table(inner) => {
                    self.add_table(inner, &key)?;
                    continue;
                }
                Value::String(text) => FlatValue::Text(text.clone()),
                Value::Integer(number) => FlatValue::Integer(*number),
                Value::Bool(flag) => FlatValue::Bool(*flag),
                Value::Array(items) => FlatValue::List(
                    items
                        .iter()
                        .map(|item| match &item.value {
                            Value::String(text) => Ok(text.clone()),
                            other => Err(ConfigError::Invalid {
                                key: key.clone(),
                                from: Source::File(item.at.clone()),
                                message: format!("must be a list of strings, but holds {}", other.kind()),
                            }),
                        })
                        .collect::<Result<_, _>>()?,
                ),
                Value::Other(kind) => {
                    return Err(ConfigError::Invalid {
                        key,
                        from: source,
                        message: format!("cannot be {kind}"),
                    });
                }
            };
            self.values.insert(key, (value, source));
        }
        Ok(())
    }

    /// Lays environment variables over the file, as materia's loader does:
    /// `<PREFIX>_A__B` sets `a.b`. Variables named in `skip` (without the
    /// prefix, lower case) are not settings.
    pub(crate) fn overlay_env<I>(&mut self, prefix: &str, variables: I, skip: &[&str])
    where
        I: IntoIterator<Item = (String, String)>,
    {
        for (name, value) in variables {
            let Some(rest) = name.strip_prefix(prefix).and_then(|rest| rest.strip_prefix('_')) else {
                continue;
            };
            let key = rest.to_lowercase().replace("__", ".");
            if key.is_empty() || skip.contains(&key.as_str()) {
                continue;
            }
            self.values.insert(key, (FlatValue::Text(value), Source::Env(name)));
        }
    }

    /// Fails if a key is not in `known`. A known key that ends in `.*`
    /// allows any key below it.
    pub(crate) fn check_known(&self, known: &[&str]) -> Result<(), ConfigError> {
        for (key, (_, source)) in &self.values {
            let ok = known.iter().any(|known| match known.strip_suffix(".*") {
                Some(prefix) => key.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('.')),
                None => known == key,
            });
            if !ok {
                return Err(ConfigError::UnknownKey {
                    key: key.clone(),
                    from: source.clone(),
                });
            }
        }
        Ok(())
    }

    fn invalid(key: &str, source: &Source, message: impl Into<String>) -> ConfigError {
        ConfigError::Invalid {
            key: key.to_owned(),
            from: source.clone(),
            message: message.into(),
        }
    }

    pub(crate) fn text(&self, key: &str) -> Result<Option<Setting<String>>, ConfigError> {
        match self.values.get(key) {
            None => Ok(None),
            Some((FlatValue::Text(text), source)) => Ok(Some(Setting {
                value: text.clone(),
                source: source.clone(),
            })),
            Some((_, source)) => Err(Self::invalid(key, source, "must be a string")),
        }
    }

    pub(crate) fn boolean(&self, key: &str) -> Result<Option<Setting<bool>>, ConfigError> {
        let (value, source) = match self.values.get(key) {
            None => return Ok(None),
            Some((FlatValue::Bool(flag), source)) => (*flag, source),
            Some((FlatValue::Text(text), source @ Source::Env(_))) => match text.as_str() {
                "true" | "1" => (true, source),
                "false" | "0" => (false, source),
                _ => return Err(Self::invalid(key, source, "must be true or false")),
            },
            Some((_, source)) => return Err(Self::invalid(key, source, "must be true or false")),
        };
        Ok(Some(Setting {
            value,
            source: source.clone(),
        }))
    }

    pub(crate) fn integer(&self, key: &str) -> Result<Option<Setting<i64>>, ConfigError> {
        let (value, source) = match self.values.get(key) {
            None => return Ok(None),
            Some((FlatValue::Integer(number), source)) => (*number, source),
            Some((FlatValue::Text(text), source @ Source::Env(_))) => match text.parse() {
                Ok(number) => (number, source),
                Err(_) => return Err(Self::invalid(key, source, "must be a whole number")),
            },
            Some((_, source)) => return Err(Self::invalid(key, source, "must be a whole number")),
        };
        Ok(Some(Setting {
            value,
            source: source.clone(),
        }))
    }

    /// Reads a list of strings. An environment variable holds the items
    /// separated by commas.
    pub(crate) fn list(&self, key: &str) -> Result<Option<Setting<Vec<String>>>, ConfigError> {
        let (value, source) = match self.values.get(key) {
            None => return Ok(None),
            Some((FlatValue::List(items), source)) => (items.clone(), source),
            Some((FlatValue::Text(text), source @ Source::Env(_))) => (
                text.split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_owned)
                    .collect(),
                source,
            ),
            Some((_, source)) => return Err(Self::invalid(key, source, "must be a list of strings")),
        };
        Ok(Some(Setting {
            value,
            source: source.clone(),
        }))
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
    fn the_environment_overrides_the_file() {
        let mut flat = Flat::parse("[selinux]\npriority = 350\nallow_modules = true\n", Path::new("c.toml")).unwrap();
        flat.overlay_env(
            "FORMA",
            env(&[
                ("FORMA_SELINUX__PRIORITY", "360"),
                ("FORMA_CONFIG", "/x"),
                ("FORMAT", "y"),
                ("OTHER_A", "b"),
            ]),
            &["config"],
        );
        let priority = flat.integer("selinux.priority").unwrap().unwrap();
        assert_eq!(priority.value, 360);
        assert_eq!(priority.source, Source::Env("FORMA_SELINUX__PRIORITY".into()));
        assert!(matches!(
            flat.boolean("selinux.allow_modules").unwrap().unwrap().source,
            Source::File(_)
        ));
        flat.check_known(&["selinux.priority", "selinux.allow_modules"])
            .unwrap();
    }

    #[test]
    fn unknown_keys_are_named_with_their_source() {
        let flat = Flat::parse("[paths]\nallowed_root = []\n", Path::new("c.toml")).unwrap();
        let error = flat
            .check_known(&["paths.allowed_roots", "notify.triggers.*"])
            .unwrap_err();
        assert_eq!(error.to_string(), "c.toml:2:16: unknown setting \"paths.allowed_root\"");
        let flat = Flat::parse("[notify.triggers]\nupdate = \"u\"\n", Path::new("c.toml")).unwrap();
        flat.check_known(&["notify.triggers.*"]).unwrap();
    }

    #[test]
    fn lists_come_from_arrays_or_comma_separated_variables() {
        let mut flat = Flat::parse("roots = [\"/a\", \"/b\"]\n", Path::new("c.toml")).unwrap();
        assert_eq!(flat.list("roots").unwrap().unwrap().value, ["/a", "/b"]);
        flat.overlay_env("X", env(&[("X_ROOTS", "/c, /d,")]), &[]);
        assert_eq!(flat.list("roots").unwrap().unwrap().value, ["/c", "/d"]);
    }

    #[test]
    fn wrong_types_are_errors() {
        let flat = Flat::parse("a = 1\nb = \"x\"\nc = [1]\n", Path::new("c.toml"));
        assert!(flat.is_err(), "a list of numbers is refused");
        let flat = Flat::parse("a = 1\nb = \"true\"\n", Path::new("c.toml")).unwrap();
        assert!(flat.text("a").is_err());
        assert!(flat.boolean("b").is_err(), "a string in the file is not a boolean");
        assert!(flat.integer("b").is_err());
    }

    #[test]
    fn a_missing_file_is_empty() {
        let flat = Flat::read(Path::new("/nonexistent/forma/config.toml")).unwrap();
        assert!(flat.text("x").unwrap().is_none());
    }
}
