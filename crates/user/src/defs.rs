//! Parsers for the account files this crate reads.
//!
//! Every parser is a pure function over the file's text. None of them reads
//! a file. Lookups of accounts and groups go through NSS instead (see
//! [`crate::lookup`]); these parsers answer what NSS cannot, such as which
//! file an entry came from.

use std::path::PathBuf;

use thiserror::Error;

use crate::id::{IdError, IdRange, SubIdRange};

/// The ID ranges from `login.defs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginDefs {
    /// `UID_MIN..=UID_MAX`: user IDs for people.
    pub uid: IdRange,
    /// `SYS_UID_MIN..=SYS_UID_MAX`: user IDs for system accounts.
    pub sys_uid: IdRange,
    /// `GID_MIN..=GID_MAX`: group IDs for people.
    pub gid: IdRange,
    /// `SYS_GID_MIN..=SYS_GID_MAX`: group IDs for system groups.
    pub sys_gid: IdRange,
    /// `SUB_UID_MIN`, `SUB_UID_MAX` and `SUB_UID_COUNT`.
    pub sub_uid: SubIdLimits,
    /// `SUB_GID_MIN`, `SUB_GID_MAX` and `SUB_GID_COUNT`.
    pub sub_gid: SubIdLimits,
}

/// Where sub-ID ranges may be allocated, and their default size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubIdLimits {
    /// Sub-IDs in `min..=max` may be allocated.
    pub range: IdRange,
    /// The size shadow-utils gives a new account by default.
    pub count: u32,
}

impl LoginDefs {
    /// Parses `login.defs`.
    ///
    /// Keys that are missing get shadow-utils' built-in defaults. Numbers are
    /// read as shadow-utils reads them: `0x` means hexadecimal and a leading
    /// `0` means octal.
    ///
    /// # Errors
    ///
    /// Returns [`DefsError::Value`] if a key this crate uses holds something
    /// other than a number, and [`DefsError::Range`] if a range is empty.
    pub fn parse(text: &str) -> Result<Self, DefsError> {
        let get = |key: &str| -> Result<Option<u32>, DefsError> {
            // Shadow-utils uses the last line that sets a key.
            let value = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.starts_with('#'))
                .filter_map(|line| {
                    let mut parts = line.split_whitespace();
                    (parts.next() == Some(key)).then(|| parts.next().unwrap_or(""))
                })
                .next_back();
            value
                .map(|value| {
                    parse_c_number(value).ok_or_else(|| DefsError::Value {
                        key: key.to_owned(),
                        value: value.to_owned(),
                    })
                })
                .transpose()
        };

        let uid_min = get("UID_MIN")?.unwrap_or(1000);
        let gid_min = get("GID_MIN")?.unwrap_or(1000);
        let range = |first: u32, last: u32| IdRange::new(first, last).map_err(DefsError::Range);
        Ok(Self {
            uid: range(uid_min, get("UID_MAX")?.unwrap_or(60_000))?,
            sys_uid: range(
                get("SYS_UID_MIN")?.unwrap_or(101),
                get("SYS_UID_MAX")?.unwrap_or(uid_min.saturating_sub(1)),
            )?,
            gid: range(gid_min, get("GID_MAX")?.unwrap_or(60_000))?,
            sys_gid: range(
                get("SYS_GID_MIN")?.unwrap_or(101),
                get("SYS_GID_MAX")?.unwrap_or(gid_min.saturating_sub(1)),
            )?,
            sub_uid: SubIdLimits {
                range: range(
                    get("SUB_UID_MIN")?.unwrap_or(100_000),
                    get("SUB_UID_MAX")?.unwrap_or(600_100_000),
                )?,
                count: get("SUB_UID_COUNT")?.unwrap_or(65_536),
            },
            sub_gid: SubIdLimits {
                range: range(
                    get("SUB_GID_MIN")?.unwrap_or(100_000),
                    get("SUB_GID_MAX")?.unwrap_or(600_100_000),
                )?,
                count: get("SUB_GID_COUNT")?.unwrap_or(65_536),
            },
        })
    }
}

/// Reads a number the way C's `strtoul` does with base 0.
fn parse_c_number(text: &str) -> Option<u32> {
    match text.as_bytes() {
        [b'0', b'x' | b'X', rest @ ..] if !rest.is_empty() => u32::from_str_radix(&text[2..], 16).ok(),
        [b'0', rest @ ..] if !rest.is_empty() => u32::from_str_radix(&text[1..], 8).ok(),
        _ => text.parse().ok(),
    }
}

/// One line of `/etc/subuid` or `/etc/subgid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubIdEntry {
    /// The owner, as written: a user name or a user ID.
    pub owner: String,
    /// The range.
    pub range: SubIdRange,
}

/// Parses `/etc/subuid` or `/etc/subgid`.
///
/// # Errors
///
/// Returns [`DefsError::Line`] for a line that is not `owner:start:count`.
pub fn parse_subids(file: &'static str, text: &str) -> Result<Vec<SubIdEntry>, DefsError> {
    records(text)
        .map(|(number, line)| {
            let bad = |reason| DefsError::Line { file, number, reason };
            let mut fields = line.split(':');
            let (Some(owner), Some(start), Some(count), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(bad("expected owner:start:count"));
            };
            if owner.is_empty() {
                return Err(bad("owner is empty"));
            }
            let start = start.parse().map_err(|_| bad("start is not a number"))?;
            let count = count.parse().map_err(|_| bad("count is not a number"))?;
            let range = SubIdRange::from_parts(start, count).ok_or_else(|| bad("range is empty or too large"))?;
            Ok(SubIdEntry { owner: owner.to_owned(), range })
        })
        .collect()
}

/// Where NSS gets sub-ID ranges from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubIdBackend {
    /// `/etc/subuid` and `/etc/subgid`. Also used when `nsswitch.conf` has no
    /// `subid:` line.
    Files,
    /// Another source, such as `sss`. Writing the files would have no effect.
    Other(String),
}

/// Finds the `subid:` line in `nsswitch.conf`.
#[must_use]
pub fn subid_backend(nsswitch: &str) -> SubIdBackend {
    let source = nsswitch
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .find_map(|line| line.strip_prefix("subid:"))
        .and_then(|sources| sources.split_whitespace().next());
    match source {
        None | Some("files") => SubIdBackend::Files,
        Some(other) => SubIdBackend::Other(other.to_owned()),
    }
}

/// One line of a `passwd` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    /// User name.
    pub name: String,
    /// User ID.
    pub uid: u32,
    /// Primary group ID.
    pub gid: u32,
    /// Home directory.
    pub home: PathBuf,
}

/// Parses `/etc/passwd` or `/usr/lib/passwd`.
///
/// Skips the old NIS lines that start with `+` or `-`.
///
/// # Errors
///
/// Returns [`DefsError::Line`] for a line without seven fields, or with
/// IDs that are not numbers.
pub fn parse_passwd(file: &'static str, text: &str) -> Result<Vec<PasswdEntry>, DefsError> {
    records(text)
        .filter(|(_, line)| !line.starts_with(['+', '-']))
        .map(|(number, line)| {
            let bad = |reason| DefsError::Line { file, number, reason };
            let fields: Vec<&str> = line.split(':').collect();
            let [name, _, uid, gid, _, home, _] = fields[..] else {
                return Err(bad("expected 7 fields"));
            };
            Ok(PasswdEntry {
                name: name.to_owned(),
                uid: uid.parse().map_err(|_| bad("user ID is not a number"))?,
                gid: gid.parse().map_err(|_| bad("group ID is not a number"))?,
                home: PathBuf::from(home),
            })
        })
        .collect()
}

/// One line of a `group` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    /// Group name.
    pub name: String,
    /// Group ID.
    pub gid: u32,
    /// Names of the accounts that have this as a supplementary group.
    pub members: Vec<String>,
}

/// Parses `/etc/group` or `/usr/lib/group`.
///
/// Skips the old NIS lines that start with `+` or `-`.
///
/// # Errors
///
/// Returns [`DefsError::Line`] for a line without four fields, or with a
/// group ID that is not a number.
pub fn parse_group(file: &'static str, text: &str) -> Result<Vec<GroupEntry>, DefsError> {
    records(text)
        .filter(|(_, line)| !line.starts_with(['+', '-']))
        .map(|(number, line)| {
            let bad = |reason| DefsError::Line { file, number, reason };
            let fields: Vec<&str> = line.split(':').collect();
            let [name, _, gid, members] = fields[..] else {
                return Err(bad("expected 4 fields"));
            };
            Ok(GroupEntry {
                name: name.to_owned(),
                gid: gid.parse().map_err(|_| bad("group ID is not a number"))?,
                members: members
                    .split(',')
                    .filter(|member| !member.is_empty())
                    .map(str::to_owned)
                    .collect(),
            })
        })
        .collect()
}

/// Yields each line that is not blank or a `#` comment, with its 1-based
/// line number.
fn records(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line))
        .filter(|(_, line)| !line.trim().is_empty() && !line.starts_with('#'))
}

/// A file could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DefsError {
    /// A line has the wrong shape.
    #[error("{file} line {number}: {reason}")]
    Line {
        /// The file, such as `/etc/subuid`.
        file: &'static str,
        /// The 1-based line number.
        number: usize,
        /// What is wrong.
        reason: &'static str,
    },
    /// A `login.defs` key holds something other than a number.
    #[error("login.defs: {key} is {value:?}, not a number")]
    Value {
        /// The key.
        key: String,
        /// The value found.
        value: String,
    },
    /// A `login.defs` range is empty.
    #[error("login.defs: {0}")]
    Range(IdError),
}
