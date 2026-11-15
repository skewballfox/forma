//! A parsed TOML document that remembers where each key and value came from.
//!
//! Forma merges tables from two files (a component's manifest and the
//! repository manifest), so each value carries its own [`Origin`]. Errors
//! then point at the file and line that hold the bad value.

use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use toml::de::{DeTable, DeValue};

/// Where a key or value sits in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// The file.
    pub file: Arc<Path>,
    /// The line, counted from 1.
    pub line: u32,
    /// The column, counted from 1, in characters.
    pub column: u32,
}

impl Origin {
    /// An origin for a whole file, used when a file as a whole is at fault.
    #[must_use]
    pub fn file(file: &Arc<Path>) -> Self {
        Self {
            file: Arc::clone(file),
            line: 1,
            column: 1,
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file.display(), self.line, self.column)
    }
}

/// A TOML file could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{at}: {message}")]
pub struct SyntaxError {
    /// Where parsing stopped.
    pub at: Origin,
    /// What the parser said.
    pub message: String,
}

/// One value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    String(String),
    Integer(i64),
    Bool(bool),
    Array(Vec<Node>),
    Table(Table),
    /// A type forma never reads: a float or a date. Holds the type's name.
    Other(&'static str),
}

impl Value {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::String(_) => "a string",
            Self::Integer(_) => "an integer",
            Self::Bool(_) => "a boolean",
            Self::Array(_) => "an array",
            Self::Table(_) => "a table",
            Self::Other(kind) => kind,
        }
    }
}

/// A value and where it came from.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Node {
    pub(crate) value: Value,
    pub(crate) at: Origin,
}

impl Node {
    /// Compares two values and ignores where they came from.
    pub(crate) fn same_value(&self, other: &Self) -> bool {
        match (&self.value, &other.value) {
            (Value::Array(a), Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a.same_value(b)),
            (Value::Table(a), Value::Table(b)) => {
                a.entries.len() == b.entries.len()
                    && a.entries
                        .iter()
                        .all(|entry| b.get(&entry.key).is_some_and(|node| node.same_value(&entry.node)))
            }
            (Value::Table(_) | Value::Array(_), _) | (_, Value::Table(_) | Value::Array(_)) => false,
            (a, b) => a == b,
        }
    }
}

/// One key of a table, with its value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Entry {
    pub(crate) key: String,
    pub(crate) key_at: Origin,
    pub(crate) node: Node,
}

/// A table. Keys keep the spelling of the file until
/// [`crate::schema::canonical`] renames them.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Table {
    pub(crate) entries: Vec<Entry>,
}

impl Table {
    /// Returns the value of `key`, matched exactly.
    pub(crate) fn get(&self, key: &str) -> Option<&Node> {
        self.entry(key).map(|entry| &entry.node)
    }

    pub(crate) fn entry(&self, key: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.key == key)
    }

    pub(crate) fn get_mut(&mut self, key: &str) -> Option<&mut Node> {
        self.entries
            .iter_mut()
            .find(|entry| entry.key == key)
            .map(|entry| &mut entry.node)
    }

    /// Returns the value of `key` the way materia's decoder finds it: an
    /// exact match first, then the first match that ignores case.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn get_ignore_case(&self, key: &str) -> Option<&Node> {
        self.get(key).or_else(|| {
            self.entries
                .iter()
                .find(|entry| entry.key.eq_ignore_ascii_case(key))
                .map(|entry| &entry.node)
        })
    }

    /// Sets `key`, replacing a value it already has.
    pub(crate) fn set(&mut self, entry: Entry) {
        match self.entries.iter_mut().find(|old| old.key == entry.key) {
            Some(old) => *old = entry,
            None => self.entries.push(entry),
        }
    }
}

/// Turns byte offsets into lines and columns.
struct Lines<'a> {
    text: &'a str,
    starts: Vec<usize>,
    file: Arc<Path>,
}

impl<'a> Lines<'a> {
    fn new(text: &'a str, file: &Arc<Path>) -> Self {
        let starts = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(at, _)| at + 1))
            .collect();
        Self {
            text,
            starts,
            file: Arc::clone(file),
        }
    }

    fn origin(&self, span: &Range<usize>) -> Origin {
        let start = span.start.min(self.text.len());
        let line = self.starts.partition_point(|&line_start| line_start <= start).max(1);
        let line_start = self.starts[line - 1];
        let column = self
            .text
            .get(line_start..start)
            .map_or(start - line_start, |before| before.chars().count())
            + 1;
        // A manifest with more than four thousand million lines does not exist.
        Origin {
            file: Arc::clone(&self.file),
            line: u32::try_from(line).unwrap_or(u32::MAX),
            column: u32::try_from(column).unwrap_or(u32::MAX),
        }
    }
}

/// Parses a TOML document.
pub(crate) fn parse(text: &str, file: &Arc<Path>) -> Result<Table, SyntaxError> {
    let lines = Lines::new(text, file);
    let parsed = DeTable::parse(text).map_err(|error| SyntaxError {
        at: lines.origin(&error.span().unwrap_or(0..0)),
        message: error.message().to_owned(),
    })?;
    Ok(table(parsed.get_ref(), &lines))
}

fn table(source: &DeTable<'_>, lines: &Lines<'_>) -> Table {
    let mut entries: Vec<Entry> = source
        .iter()
        .map(|(key, value)| Entry {
            key: key.get_ref().to_string(),
            key_at: lines.origin(&key.span()),
            node: Node {
                value: convert(value.get_ref(), lines),
                at: lines.origin(&value.span()),
            },
        })
        .collect();
    // The parser sorts keys by name. File order gives steadier messages.
    entries.sort_by_key(|entry| (entry.key_at.line, entry.key_at.column));
    Table { entries }
}

fn convert(value: &DeValue<'_>, lines: &Lines<'_>) -> Value {
    match value {
        DeValue::String(text) => Value::String(text.to_string()),
        DeValue::Integer(integer) => i64::from_str_radix(integer.as_str(), integer.radix())
            .map_or(Value::Other("an integer out of range"), Value::Integer),
        DeValue::Boolean(flag) => Value::Bool(*flag),
        DeValue::Float(_) => Value::Other("a float"),
        DeValue::Datetime(_) => Value::Other("a date or time"),
        DeValue::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| Node {
                    value: convert(item.get_ref(), lines),
                    at: lines.origin(&item.span()),
                })
                .collect(),
        ),
        DeValue::Table(inner) => Value::Table(table(inner, lines)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> Arc<Path> {
        Arc::from(Path::new("MANIFEST.toml"))
    }

    #[test]
    fn values_remember_their_line_and_column() {
        let parsed = parse("[Forma.Account]\nName = \"app\"\n  Linger = true\n", &file()).unwrap();
        let Value::Table(forma) = &parsed.get("Forma").unwrap().value else {
            panic!("Forma is a table");
        };
        let Value::Table(account) = &forma.get("Account").unwrap().value else {
            panic!("Account is a table");
        };
        let name = account.entry("Name").unwrap();
        assert_eq!((name.key_at.line, name.key_at.column), (2, 1));
        assert_eq!((name.node.at.line, name.node.at.column), (2, 8));
        let linger = account.entry("Linger").unwrap();
        assert_eq!((linger.key_at.line, linger.key_at.column), (3, 3));
        assert_eq!(name.node.at.to_string(), "MANIFEST.toml:2:8");
    }

    #[test]
    fn a_syntax_error_names_the_line() {
        let error = parse("[Forma]\nName = \n", &file()).unwrap_err();
        assert_eq!(error.at.line, 2);
    }

    #[test]
    fn lookups_prefer_the_exact_key() {
        let parsed = parse("hosts = 1\nHosts = 2\n", &file()).unwrap();
        assert_eq!(parsed.get_ignore_case("Hosts").unwrap().value, Value::Integer(2));
        assert_eq!(parsed.get_ignore_case("HOSTS").unwrap().value, Value::Integer(1));
    }

    #[test]
    fn same_value_ignores_origin_and_key_order() {
        let a = parse("x = { a = 1, b = [\"y\"] }\n", &file()).unwrap();
        let b = parse("\n\nx = { b = [\"y\"], a = 1 }\n", &file()).unwrap();
        assert!(a.get("x").unwrap().same_value(b.get("x").unwrap()));
        let c = parse("x = { a = 1, b = [\"z\"] }\n", &file()).unwrap();
        assert!(!a.get("x").unwrap().same_value(c.get("x").unwrap()));
    }
}
