//! Typed udev rules and their rendering. Nothing here touches the host.
//!
//! A rule is a list of typed matches and typed assignments. The model has
//! no `RUN`, `PROGRAM` or `IMPORT` keys, because those run code or read
//! files as root.

use std::fmt::{self, Write as _};

use thiserror::Error;

use crate::name::GroupName;
use crate::ownership::MarkerTag;

/// Longest value the crate writes into a rule.
const MAX_VALUE_LEN: usize = 256;

/// A value inside a rule's quotes.
///
/// It holds no `"`, `\`, newline or other control character, so it cannot
/// close its quotes or start a new key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdevValue(String);

impl UdevValue {
    /// Checks a value. Glob characters such as `*` and `?` are allowed.
    ///
    /// # Errors
    ///
    /// Returns [`UdevError::Value`] if the value is empty, too long, or holds
    /// a character that is not allowed.
    pub fn new(value: impl Into<String>) -> Result<Self, UdevError> {
        let value = value.into();
        let bad = value.chars().any(|ch| ch == '"' || ch == '\\' || ch.is_control());
        if value.is_empty() || value.len() > MAX_VALUE_LEN || bad {
            return Err(UdevError::Value(value));
        }
        Ok(Self(value))
    }

    /// Returns the value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The name of a rules file: `NN-name.rules`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RulesFileName {
    priority: u8,
    name: String,
}

impl RulesFileName {
    /// Checks a priority (`0` to `99`) and a name (`[a-z0-9][a-z0-9_-]*`, at
    /// most 64 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`UdevError::FileName`] if either is not allowed.
    pub fn new(priority: u8, name: impl Into<String>) -> Result<Self, UdevError> {
        let name = name.into();
        if priority > 99 || !is_file_stem(&name) {
            return Err(UdevError::FileName { priority, name });
        }
        Ok(Self { priority, name })
    }

    /// Returns the file name, such as `85-moonshine.rules`.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!("{:02}-{}.rules", self.priority, self.name)
    }
}

/// Says whether `name` is a safe file name stem: `[a-z0-9][a-z0-9_-]*`, at
/// most 64 bytes.
pub(crate) fn is_file_stem(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('a'..='z' | '0'..='9'))
        && chars.all(|ch| matches!(ch, 'a'..='z' | '0'..='9' | '_' | '-'))
        && name.len() <= 64
}

/// A device node mode a rule may set. Never writable by others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceMode(u32);

impl DeviceMode {
    /// Checks a mode, such as `0o660`.
    ///
    /// # Errors
    ///
    /// Returns [`UdevError::Mode`] if the mode has bits outside `0o777` or the
    /// write bit for others.
    pub const fn new(mode: u32) -> Result<Self, UdevError> {
        if mode & !0o777 != 0 || mode & 0o002 != 0 {
            return Err(UdevError::Mode(mode));
        }
        Ok(Self(mode))
    }
}

/// A seat name, such as `seat9`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeatName(String);

impl SeatName {
    /// Checks a seat name: `seat` followed by `[a-z0-9_-]*`.
    ///
    /// # Errors
    ///
    /// Returns [`UdevError::Seat`] otherwise.
    pub fn new(name: impl Into<String>) -> Result<Self, UdevError> {
        let name = name.into();
        let valid = name
            .strip_prefix("seat")
            .is_some_and(|rest| rest.chars().all(|ch| matches!(ch, 'a'..='z' | '0'..='9' | '_' | '-')));
        if !valid || name.len() > 64 {
            return Err(UdevError::Seat(name));
        }
        Ok(Self(name))
    }
}

/// A condition a device must meet for the rule to apply. Always `==`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Match {
    /// `KERNEL==`: the device's kernel name.
    Kernel(UdevValue),
    /// `SUBSYSTEM==`: the device's subsystem.
    Subsystem(UdevValue),
    /// `KERNELS==`: the kernel name of the device or a parent.
    Kernels(UdevValue),
    /// `DEVPATH==`: the device's path under `/sys`.
    Devpath(UdevValue),
}

/// A change the rule makes to the device.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Assign {
    /// `GROUP=`: the device node's group. The group must exist when the
    /// file is written.
    Group(GroupName),
    /// `MODE=`: the device node's mode.
    Mode(DeviceMode),
    /// `OPTIONS+="static_node=…"`: apply the rule to a static node at boot.
    StaticNode(UdevValue),
    /// `ENV{ID_SEAT}=`: put the device on a seat.
    Seat(SeatName),
}

/// One rule: matches, then assignments.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rule {
    matches: Vec<Match>,
    assigns: Vec<Assign>,
}

impl Rule {
    /// Builds a rule.
    ///
    /// # Errors
    ///
    /// Returns [`UdevError::EmptyRule`] if either list is empty. A rule with
    /// no match would apply to every device.
    pub fn new(matches: Vec<Match>, assigns: Vec<Assign>) -> Result<Self, UdevError> {
        if matches.is_empty() || assigns.is_empty() {
            return Err(UdevError::EmptyRule);
        }
        Ok(Self { matches, assigns })
    }

    /// Returns the groups the rule assigns.
    pub fn groups(&self) -> impl Iterator<Item = &GroupName> {
        self.assigns.iter().filter_map(|assign| match assign {
            Assign::Group(group) => Some(group),
            _ => None,
        })
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let matches = self.matches.iter().map(|m| match m {
            Match::Kernel(value) => format!("KERNEL==\"{}\"", value.as_str()),
            Match::Subsystem(value) => format!("SUBSYSTEM==\"{}\"", value.as_str()),
            Match::Kernels(value) => format!("KERNELS==\"{}\"", value.as_str()),
            Match::Devpath(value) => format!("DEVPATH==\"{}\"", value.as_str()),
        });
        let assigns = self.assigns.iter().map(|a| match a {
            Assign::Group(group) => format!("GROUP=\"{group}\""),
            Assign::Mode(DeviceMode(mode)) => format!("MODE=\"{mode:04o}\""),
            Assign::StaticNode(value) => format!("OPTIONS+=\"static_node={}\"", value.as_str()),
            Assign::Seat(SeatName(seat)) => format!("ENV{{ID_SEAT}}=\"{seat}\""),
        });
        let parts: Vec<String> = matches.chain(assigns).collect();
        f.write_str(&parts.join(", "))
    }
}

/// A rules file: its name and its rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RulesFile {
    name: RulesFileName,
    rules: Vec<Rule>,
}

impl RulesFile {
    /// Builds a rules file.
    ///
    /// # Errors
    ///
    /// Returns [`UdevError::EmptyFile`] if there are no rules.
    pub fn new(name: RulesFileName, rules: Vec<Rule>) -> Result<Self, UdevError> {
        if rules.is_empty() {
            return Err(UdevError::EmptyFile);
        }
        Ok(Self { name, rules })
    }

    /// Returns the file's name.
    #[must_use]
    pub fn name(&self) -> &RulesFileName {
        &self.name
    }

    /// Returns the rules.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Renders the file. The first line is the managed-file header for `tag`.
    #[must_use]
    pub fn render(&self, tag: &MarkerTag) -> String {
        let mut out = format!("{}\n", tag.header_line());
        for rule in &self.rules {
            // Writing to a String cannot fail.
            let _ = writeln!(out, "{rule}");
        }
        out
    }
}

/// A udev value or rule failed a check.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UdevError {
    /// A value is empty, too long, or holds `"`, `\` or a control character.
    #[error("udev value {0:?} is not allowed")]
    Value(String),
    /// A rules file name is not allowed.
    #[error("udev rules file {priority:02}-{name}.rules is not allowed: priority must be 0-99, name [a-z0-9][a-z0-9_-]*")]
    FileName {
        /// The priority given.
        priority: u8,
        /// The name given.
        name: String,
    },
    /// A device mode has bits outside `0o777`, or lets others write.
    #[error("device mode {0:#o} is not allowed: only 0o777 without write for others")]
    Mode(u32),
    /// A seat name is not allowed.
    #[error("seat name {0:?} is not allowed")]
    Seat(String),
    /// A rule has no matches or no assignments.
    #[error("a udev rule needs at least one match and one assignment")]
    EmptyRule,
    /// A file has no rules.
    #[error("a udev rules file needs at least one rule")]
    EmptyFile,
}
