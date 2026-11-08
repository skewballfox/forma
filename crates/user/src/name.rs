//! Checked user names, group names and account comments.

use std::fmt;

use thiserror::Error;

/// Longest user or group name shadow-utils accepts by default.
const MAX_NAME_LEN: usize = 32;

/// Names the crate never creates, changes or looks up.
const RESERVED_NAMES: &[&str] = &["root", "nobody"];

/// Longest account comment the crate writes.
const MAX_COMMENT_LEN: usize = 255;

/// A user name that is safe to pass to shadow-utils.
///
/// It matches `[a-z_][a-z0-9_-]{0,31}` and is not a reserved name. It can
/// never start with `-`, so a tool cannot read it as an option.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserName(String);

impl UserName {
    /// Checks a user name.
    ///
    /// # Errors
    ///
    /// Returns a [`NameError`] that says which rule the name breaks.
    pub fn new(name: impl Into<String>) -> Result<Self, NameError> {
        let name = name.into();
        check_name(&name)?;
        Ok(Self(name))
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for UserName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A group name that is safe to pass to shadow-utils.
///
/// Same rules as [`UserName`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupName(String);

impl GroupName {
    /// Checks a group name.
    ///
    /// # Errors
    ///
    /// Returns a [`NameError`] that says which rule the name breaks.
    pub fn new(name: impl Into<String>) -> Result<Self, NameError> {
        let name = name.into();
        check_name(&name)?;
        Ok(Self(name))
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GroupName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for GroupName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

fn check_name(name: &str) -> Result<(), NameError> {
    let mut chars = name.chars();
    match chars.next() {
        None => return Err(NameError::Empty),
        Some('a'..='z' | '_') => {}
        Some(_) => return Err(NameError::InvalidStart(name.to_owned())),
    }
    if let Some(ch) = chars.find(|ch| !matches!(ch, 'a'..='z' | '0'..='9' | '_' | '-')) {
        return Err(NameError::InvalidChar { name: name.to_owned(), ch });
    }
    if name.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong(name.to_owned()));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(NameError::Reserved(name.to_owned()));
    }
    Ok(())
}

/// The comment (GECOS) field of an account.
///
/// It holds no `:`, newline or other control character, so it cannot break
/// the line format of `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Comment(String);

impl Comment {
    /// Checks a comment.
    ///
    /// # Errors
    ///
    /// Returns [`NameError::InvalidComment`] if the text holds `:` or a
    /// control character, or is longer than 255 bytes.
    pub fn new(text: impl Into<String>) -> Result<Self, NameError> {
        let text = text.into();
        match text.chars().find(|&ch| ch == ':' || ch.is_control()) {
            Some(ch) => Err(NameError::InvalidComment { text, ch: Some(ch) }),
            None if text.len() > MAX_COMMENT_LEN => Err(NameError::InvalidComment { text, ch: None }),
            None => Ok(Self(text)),
        }
    }

    /// Returns the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Comment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A name or comment failed a check.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NameError {
    /// The name is empty.
    #[error("name is empty")]
    Empty,
    /// The name does not start with a lower-case letter or `_`.
    #[error("name {0:?} must start with a lower-case letter or '_'")]
    InvalidStart(String),
    /// The name holds a character outside `a-z`, `0-9`, `_` and `-`.
    #[error("name {name:?} holds {ch:?}; only a-z, 0-9, '_' and '-' are allowed")]
    InvalidChar {
        /// The name given.
        name: String,
        /// The first character that is not allowed.
        ch: char,
    },
    /// The name is longer than 32 bytes.
    #[error("name {0:?} is longer than {MAX_NAME_LEN} bytes")]
    TooLong(String),
    /// The name is reserved for the operating system.
    #[error("name {0:?} is reserved")]
    Reserved(String),
    /// The comment holds a character that would break `/etc/passwd`, or is too long.
    #[error("comment {text:?} is not allowed: {}", match ch {
        Some(ch) => format!("it holds {ch:?}"),
        None => format!("it is longer than {MAX_COMMENT_LEN} bytes"),
    })]
    InvalidComment {
        /// The text given.
        text: String,
        /// The character that is not allowed, or `None` if the text is too long.
        ch: Option<char>,
    },
}
