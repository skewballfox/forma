//! How a caller adds its own rules: the [`Ownership`] and [`Journal`] traits.
//!
//! [`crate::admin::System`] is generic over both. It asks [`Ownership`]
//! before it changes or removes anything that already exists, and tells
//! [`Journal`] before and after each change. The crate never holds a
//! caller's rules itself.

use std::convert::Infallible;
use std::fmt;

use thiserror::Error;

use crate::id::{Gid, SubIdRange, Uid};
use crate::lookup::{self, LocalGroup, LookupError, User};
use crate::name::{GroupName, UserName};
use crate::path::AbsPath;
use crate::perm::{Acl, AclEntry, FileMode};
use crate::spec::HomePolicy;

/// A tag that marks what one caller manages, such as `forma`.
///
/// Files the crate writes start with `# managed-by: <tag>`. Accounts it
/// creates have `managed-by=<tag>` in their comment. It is `=`, not `:`,
/// because `:` separates the fields of `/etc/passwd` and no comment may hold it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MarkerTag(String);

impl MarkerTag {
    /// Checks a tag: `[a-z0-9][a-z0-9._-]*`, at most 64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MarkerError`] otherwise.
    pub fn new(tag: impl Into<String>) -> Result<Self, MarkerError> {
        let tag = tag.into();
        let mut chars = tag.chars();
        let valid = matches!(chars.next(), Some('a'..='z' | '0'..='9'))
            && chars.all(|ch| matches!(ch, 'a'..='z' | '0'..='9' | '.' | '_' | '-'))
            && tag.len() <= 64;
        if !valid {
            return Err(MarkerError(tag));
        }
        Ok(Self(tag))
    }

    /// Returns the tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the first line of every managed file.
    #[must_use]
    pub fn header_line(&self) -> String {
        format!("# managed-by: {}", self.0)
    }

    /// Returns the text added to the comment of every account created.
    #[must_use]
    pub fn comment_marker(&self) -> String {
        format!("managed-by={}", self.0)
    }
}

impl fmt::Display for MarkerTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A marker tag failed its check.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("marker tag {0:?} is not allowed: use [a-z0-9][a-z0-9._-]*, at most 64 bytes")]
pub struct MarkerError(String);

/// Something that exists and that an operation wants to change or remove.
#[derive(Debug, Clone, Copy)]
pub enum Item<'a> {
    /// An account.
    User(&'a User),
    /// A group.
    Group(&'a LocalGroup),
    /// One account's membership in one group.
    Membership {
        /// The account.
        user: &'a User,
        /// The group.
        group: &'a LocalGroup,
    },
    /// A sub-ID range of an account.
    SubIds {
        /// The account.
        user: &'a User,
        /// The range.
        range: SubIdRange,
    },
    /// A file. `header` is its first line, if it has one.
    File {
        /// The file.
        path: &'a AbsPath,
        /// Its first line.
        header: Option<&'a str>,
    },
    /// A named ACL entry on a file.
    AclEntry {
        /// The file.
        path: &'a AbsPath,
        /// The entry.
        entry: AclEntry,
    },
}

impl fmt::Display for Item<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(user) => write!(f, "user {} ({})", user.name(), user.uid()),
            Self::Group(group) => write!(f, "group {} ({})", group.info().name(), group.info().gid()),
            Self::Membership { user, group } => {
                write!(f, "membership of {} in {}", user.name(), group.info().name())
            }
            Self::SubIds { user, range } => write!(f, "sub-IDs {range} of {}", user.name()),
            Self::File { path, .. } => write!(f, "file {path}"),
            Self::AclEntry { path, entry } => write!(f, "ACL entry {entry} on {path}"),
        }
    }
}

/// Decides which existing items the caller may change or remove.
pub trait Ownership {
    /// The error `claims` can return.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Says whether the caller may change or remove `item`.
    ///
    /// # Errors
    ///
    /// Returns `Self::Error` if the answer cannot be found. The operation
    /// then fails without changing anything.
    fn claims(&self, item: &Item<'_>) -> Result<bool, Self::Error>;
}

/// Claims items that carry its [`MarkerTag`].
///
/// | Item | Claimed when |
/// |---|---|
/// | Account | Its comment holds `managed-by=<tag>`. |
/// | Group | A claimed account has the group's name and uses it as its primary group. |
/// | Membership, sub-IDs | The account is claimed. |
/// | File | Its first line is `# managed-by: <tag>`. |
/// | ACL entry | Never. Use your own [`Ownership`] to change ACLs. |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    /// The tag to look for.
    pub tag: MarkerTag,
}

impl Marker {
    fn claims_user(&self, user: &User) -> bool {
        user.comment().contains(&self.tag.comment_marker())
    }
}

impl Ownership for Marker {
    type Error = LookupError;

    fn claims(&self, item: &Item<'_>) -> Result<bool, Self::Error> {
        match item {
            Item::User(user) | Item::Membership { user, .. } | Item::SubIds { user, .. } => {
                Ok(self.claims_user(user))
            }
            Item::Group(group) => {
                let Ok(name) = UserName::new(group.info().name().as_str()) else {
                    return Ok(false);
                };
                Ok(lookup::user(&name)?
                    .is_some_and(|user| self.claims_user(&user) && user.gid() == group.info().gid()))
            }
            Item::File { header, .. } => Ok(*header == Some(self.tag.header_line().as_str())),
            Item::AclEntry { .. } => Ok(false),
        }
    }
}

/// Claims nothing. Every change to an existing item fails. Useful for
/// programs that only create.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClaimNothing;

impl Ownership for ClaimNothing {
    type Error = Infallible;

    fn claims(&self, _item: &Item<'_>) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

/// One change to the host, with what is needed to undo it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// An account is created.
    CreateUser {
        /// Its name.
        name: UserName,
    },
    /// An account is deleted.
    DeleteUser {
        /// The account as it was.
        user: User,
        /// What happens to its home.
        home: HomePolicy,
    },
    /// A group is created.
    CreateGroup {
        /// Its name.
        name: GroupName,
    },
    /// A group is deleted.
    DeleteGroup {
        /// The group as it was.
        group: LocalGroup,
    },
    /// An account joins a group.
    AddMember {
        /// The account.
        user: UserName,
        /// The group.
        group: GroupName,
    },
    /// An account leaves a group.
    RemoveMember {
        /// The account.
        user: UserName,
        /// The group.
        group: GroupName,
    },
    /// A range is added to both `/etc/subuid` and `/etc/subgid`.
    AddSubIds {
        /// The account.
        user: UserName,
        /// The range.
        range: SubIdRange,
    },
    /// Ranges are removed.
    RemoveSubIds {
        /// The account.
        user: UserName,
        /// Ranges removed from `/etc/subuid`.
        uids: Vec<SubIdRange>,
        /// Ranges removed from `/etc/subgid`.
        gids: Vec<SubIdRange>,
    },
    /// Linger is turned on or off.
    ///
    /// Only produced with the `systemd` feature. The variant exists in every
    /// build so that code matching on `Change` is the same in all of them.
    SetLinger {
        /// The account.
        user: UserName,
        /// The new state.
        enable: bool,
    },
    /// A managed file is written.
    WriteFile {
        /// The file.
        path: AbsPath,
        /// Its contents before, or `None` if it did not exist.
        previous: Option<Vec<u8>>,
    },
    /// A managed file is removed.
    RemoveFile {
        /// The file.
        path: AbsPath,
        /// Its contents.
        contents: Vec<u8>,
    },
    /// A directory is created.
    CreateDir {
        /// The directory.
        path: AbsPath,
        /// Its owner.
        owner: Uid,
        /// Its group.
        group: Gid,
        /// Its mode.
        mode: FileMode,
    },
    /// A file's owner and group change.
    SetOwner {
        /// The file.
        path: AbsPath,
        /// Owner and group before.
        previous: (Uid, Gid),
        /// Owner and group after.
        new: (Uid, Gid),
    },
    /// A file's mode changes.
    SetMode {
        /// The file.
        path: AbsPath,
        /// Mode bits before (`0o7777`).
        previous: u32,
        /// Mode after.
        new: FileMode,
    },
    /// A file's ACL changes.
    SetAcl {
        /// The file.
        path: AbsPath,
        /// ACL before.
        previous: Acl,
        /// ACL after.
        new: Acl,
    },
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateUser { name } => write!(f, "create user {name}"),
            Self::DeleteUser { user, .. } => write!(f, "delete user {}", user.name()),
            Self::CreateGroup { name } => write!(f, "create group {name}"),
            Self::DeleteGroup { group } => write!(f, "delete group {}", group.info().name()),
            Self::AddMember { user, group } => write!(f, "add {user} to {group}"),
            Self::RemoveMember { user, group } => write!(f, "remove {user} from {group}"),
            Self::AddSubIds { user, range } => write!(f, "add sub-IDs {range} to {user}"),
            Self::RemoveSubIds { user, .. } => write!(f, "remove sub-IDs of {user}"),
            Self::SetLinger { user, enable } => write!(f, "set linger of {user} to {enable}"),
            Self::WriteFile { path, .. } => write!(f, "write {path}"),
            Self::RemoveFile { path, .. } => write!(f, "remove {path}"),
            Self::CreateDir { path, .. } => write!(f, "create directory {path}"),
            Self::SetOwner { path, .. } => write!(f, "set owner of {path}"),
            Self::SetMode { path, new, .. } => write!(f, "set mode of {path} to {new}"),
            Self::SetAcl { path, .. } => write!(f, "set ACL of {path}"),
        }
    }
}

/// What the crate learned while making a change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// The user ID of a new account.
    pub uid: Option<Uid>,
    /// The group ID of a new group or account's primary group.
    pub gid: Option<Gid>,
    /// Where an account's home was moved to.
    pub archived_home: Option<AbsPath>,
}

/// Records each change, before and after it is made.
pub trait Journal {
    /// The error the methods can return.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Called before a change. If this fails, the change is not made.
    ///
    /// # Errors
    ///
    /// Returns `Self::Error` if the intent cannot be recorded.
    fn intent(&mut self, change: &Change) -> Result<(), Self::Error>;

    /// Called after a change succeeds, with what was learned.
    ///
    /// # Errors
    ///
    /// Returns `Self::Error` if the result cannot be recorded. The change
    /// has already been made.
    fn applied(&mut self, change: &Change, facts: &Facts) -> Result<(), Self::Error>;
}

/// Records nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NoJournal;

impl Journal for NoJournal {
    type Error = Infallible;

    fn intent(&mut self, _change: &Change) -> Result<(), Self::Error> {
        Ok(())
    }

    fn applied(&mut self, _change: &Change, _facts: &Facts) -> Result<(), Self::Error> {
        Ok(())
    }
}
