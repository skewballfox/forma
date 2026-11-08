//! Read-only lookups of accounts and groups. None of these need root.
//!
//! Accounts and groups are found through NSS, so entries in
//! `/usr/lib/passwd` (nss-altfiles) and in sssd count as existing. The crate
//! then reads the files to learn where each entry came from.

use std::ffi::CString;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::defs::{self, DefsError, GroupEntry, PasswdEntry};
use crate::id::{Gid, Uid};
use crate::name::{GroupName, NameError, UserName};

pub(crate) const ETC_PASSWD: &str = "/etc/passwd";
pub(crate) const VENDOR_PASSWD: &str = "/usr/lib/passwd";
pub(crate) const ETC_GROUP: &str = "/etc/group";
pub(crate) const VENDOR_GROUP: &str = "/usr/lib/group";

/// Where an account or group entry lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// `/etc/passwd` or `/etc/group`. Shadow-utils can change it.
    Local,
    /// Only `/usr/lib/passwd` or `/usr/lib/group`. It cannot be changed.
    Vendor,
    /// Another NSS source, such as sssd. Shadow-utils cannot change it.
    Other,
}

/// An account, as NSS reported it when it was looked up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    name: UserName,
    uid: Uid,
    gid: Gid,
    home: PathBuf,
    shell: PathBuf,
    comment: String,
    source: Source,
}

impl User {
    /// Returns the user name.
    #[must_use]
    pub fn name(&self) -> &UserName {
        &self.name
    }

    /// Returns the user ID.
    #[must_use]
    pub fn uid(&self) -> Uid {
        self.uid
    }

    /// Returns the primary group ID.
    #[must_use]
    pub fn gid(&self) -> Gid {
        self.gid
    }

    /// Returns the home directory, as written in the password database.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Returns the login shell.
    #[must_use]
    pub fn shell(&self) -> &Path {
        &self.shell
    }

    /// Returns the comment (GECOS) field.
    #[must_use]
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Returns where the entry lives.
    #[must_use]
    pub fn source(&self) -> Source {
        self.source
    }
}

/// The fields every group has, whatever its source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    name: GroupName,
    gid: Gid,
    members: Vec<String>,
}

impl GroupInfo {
    /// Returns the group name.
    #[must_use]
    pub fn name(&self) -> &GroupName {
        &self.name
    }

    /// Returns the group ID.
    #[must_use]
    pub fn gid(&self) -> Gid {
        self.gid
    }

    /// Returns the names of the accounts that have this as a supplementary group.
    #[must_use]
    pub fn members(&self) -> &[String] {
        &self.members
    }

    /// Says whether `user` is a supplementary member.
    #[must_use]
    pub fn has_member(&self, user: &UserName) -> bool {
        self.members.iter().any(|member| member == user.as_str())
    }
}

/// A group with an entry in `/etc/group`. Shadow-utils can change its members.
///
/// Only a lookup, or a copy of a vendor group, makes one. So code that holds
/// a `LocalGroup` knows the group can take members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalGroup(GroupInfo);

impl LocalGroup {
    /// Returns the group's fields.
    #[must_use]
    pub fn info(&self) -> &GroupInfo {
        &self.0
    }
}

/// A group that exists only in `/usr/lib/group`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorGroup(GroupInfo);

impl VendorGroup {
    /// Returns the group's fields.
    #[must_use]
    pub fn info(&self) -> &GroupInfo {
        &self.0
    }
}

/// A group from another NSS source, such as sssd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteGroup(GroupInfo);

impl RemoteGroup {
    /// Returns the group's fields.
    #[must_use]
    pub fn info(&self) -> &GroupInfo {
        &self.0
    }
}

/// A group, by where it lives. Each source allows different uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Group {
    /// In `/etc/group`.
    Local(LocalGroup),
    /// Only in `/usr/lib/group`.
    Vendor(VendorGroup),
    /// In another NSS source.
    Other(RemoteGroup),
}

impl Group {
    /// Returns the group's fields.
    #[must_use]
    pub fn info(&self) -> &GroupInfo {
        match self {
            Self::Local(LocalGroup(info)) | Self::Vendor(VendorGroup(info)) | Self::Other(RemoteGroup(info)) => info,
        }
    }

    /// Returns where the group lives.
    #[must_use]
    pub fn source(&self) -> Source {
        match self {
            Self::Local(_) => Source::Local,
            Self::Vendor(_) => Source::Vendor,
            Self::Other(_) => Source::Other,
        }
    }
}

/// Looks up an account by name.
///
/// # Errors
///
/// Returns a [`LookupError`] if NSS fails, or a password file cannot be read
/// or parsed.
pub fn user(name: &UserName) -> Result<Option<User>, LookupError> {
    let found = nix::unistd::User::from_name(name.as_str()).map_err(|source| LookupError::Nss {
        what: format!("user {name}"),
        source,
    })?;
    found.map(from_nss_user).transpose()
}

/// Looks up an account by user ID.
///
/// # Errors
///
/// Returns a [`LookupError`] if NSS fails, a password file cannot be read,
/// or the account's name fails the checks in [`UserName`].
pub fn user_by_uid(uid: Uid) -> Result<Option<User>, LookupError> {
    let found = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid.as_raw())).map_err(|source| {
        LookupError::Nss {
            what: format!("user ID {uid}"),
            source,
        }
    })?;
    found.map(from_nss_user).transpose()
}

fn from_nss_user(user: nix::unistd::User) -> Result<User, LookupError> {
    let name = UserName::new(user.name.clone()).map_err(|source| LookupError::InvalidName {
        name: user.name.clone(),
        source,
    })?;
    let source = user_source(name.as_str())?;
    Ok(User {
        name,
        uid: Uid::from_raw(user.uid.as_raw()),
        gid: Gid::from_raw(user.gid.as_raw()),
        home: user.dir,
        shell: user.shell,
        comment: user.gecos.to_string_lossy().into_owned(),
        source,
    })
}

/// Looks up a group by name.
///
/// # Errors
///
/// Returns a [`LookupError`] if NSS fails, or a group file cannot be read
/// or parsed.
pub fn group(name: &GroupName) -> Result<Option<Group>, LookupError> {
    let found = nix::unistd::Group::from_name(name.as_str()).map_err(|source| LookupError::Nss {
        what: format!("group {name}"),
        source,
    })?;
    found.map(from_nss_group).transpose()
}

/// Looks up a group by group ID.
///
/// # Errors
///
/// Returns a [`LookupError`] if NSS fails, a group file cannot be read, or
/// the group's name fails the checks in [`GroupName`].
pub fn group_by_gid(gid: Gid) -> Result<Option<Group>, LookupError> {
    let found = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid.as_raw())).map_err(|source| {
        LookupError::Nss {
            what: format!("group ID {gid}"),
            source,
        }
    })?;
    found.map(from_nss_group).transpose()
}

fn from_nss_group(group: nix::unistd::Group) -> Result<Group, LookupError> {
    let name = GroupName::new(group.name.clone()).map_err(|source| LookupError::InvalidName {
        name: group.name.clone(),
        source,
    })?;
    let info = GroupInfo {
        name,
        gid: Gid::from_raw(group.gid.as_raw()),
        members: group.mem,
    };
    Ok(match group_source(info.name.as_str())? {
        Source::Local => Group::Local(LocalGroup(info)),
        Source::Vendor => Group::Vendor(VendorGroup(info)),
        Source::Other => Group::Other(RemoteGroup(info)),
    })
}

/// Returns every group ID the account has: its primary group and its
/// supplementary groups.
///
/// # Errors
///
/// Returns [`LookupError::Nss`] if NSS fails.
pub fn group_ids(user: &User) -> Result<Vec<Gid>, LookupError> {
    // A checked user name never holds a NUL byte.
    let name = CString::new(user.name.as_str()).map_err(|_| LookupError::InvalidName {
        name: user.name.as_str().to_owned(),
        source: NameError::Empty,
    })?;
    let gids = nix::unistd::getgrouplist(&name, nix::unistd::Gid::from_raw(user.gid.as_raw())).map_err(|source| {
        LookupError::Nss {
            what: format!("groups of {}", user.name),
            source,
        }
    })?;
    Ok(gids.into_iter().map(|gid| Gid::from_raw(gid.as_raw())).collect())
}

fn user_source(name: &str) -> Result<Source, LookupError> {
    if passwd_file(ETC_PASSWD)?.iter().any(|entry| entry.name == name) {
        return Ok(Source::Local);
    }
    if passwd_file(VENDOR_PASSWD)?.iter().any(|entry| entry.name == name) {
        return Ok(Source::Vendor);
    }
    Ok(Source::Other)
}

fn group_source(name: &str) -> Result<Source, LookupError> {
    if group_file(ETC_GROUP)?.iter().any(|entry| entry.name == name) {
        return Ok(Source::Local);
    }
    if group_file(VENDOR_GROUP)?.iter().any(|entry| entry.name == name) {
        return Ok(Source::Vendor);
    }
    Ok(Source::Other)
}

/// Reads and parses a password file. A missing file counts as empty.
pub(crate) fn passwd_file(path: &'static str) -> Result<Vec<PasswdEntry>, LookupError> {
    read_optional(path)
        .map(Option::unwrap_or_default)
        .and_then(|text| defs::parse_passwd(path, &text).map_err(LookupError::Defs))
}

/// Reads and parses a group file. A missing file counts as empty.
pub(crate) fn group_file(path: &'static str) -> Result<Vec<GroupEntry>, LookupError> {
    read_optional(path)
        .map(Option::unwrap_or_default)
        .and_then(|text| defs::parse_group(path, &text).map_err(LookupError::Defs))
}

fn read_optional(path: &'static str) -> Result<Option<String>, LookupError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(LookupError::Read {
            path: PathBuf::from(path),
            source,
        }),
    }
}

/// A lookup failed.
#[derive(Debug, Error)]
pub enum LookupError {
    /// NSS returned an error.
    #[error("NSS lookup of {what} failed")]
    Nss {
        /// What was looked up.
        what: String,
        /// The error NSS returned.
        source: nix::errno::Errno,
    },
    /// A file could not be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The error.
        source: io::Error,
    },
    /// A file could not be parsed.
    #[error(transparent)]
    Defs(#[from] DefsError),
    /// NSS returned a name this crate does not accept.
    #[error("NSS returned the name {name:?}, which this crate does not accept")]
    InvalidName {
        /// The name.
        name: String,
        /// The rule it breaks.
        source: NameError,
    },
}
