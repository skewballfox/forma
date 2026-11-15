//! What the ledger holds.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The ledger format this forma writes.
pub const VERSION: u32 = 1;

/// The name under which the host itself needs an item, in place of a
/// component. The builder, the signer and the store are needed this way.
/// No component can have this name: a component name does not start with `@`.
pub const HOST: &str = "@host";

/// How far a change has come (architecture 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Status {
    /// Forma was about to make the item. It may or may not exist.
    Pending,
    /// Forma made the item.
    Applied,
    /// Forma was about to remove the item. It may or may not still exist.
    Removing,
}

/// Something forma made, with what is needed to recognise and undo it.
///
/// IDs are optional because forma learns them only after the change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Item {
    /// A group forma created.
    Group {
        /// Its name.
        name: String,
        /// Its group ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gid: Option<u32>,
    },
    /// An account forma created.
    User {
        /// Its name.
        name: String,
        /// Its user ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uid: Option<u32>,
        /// The ID of its primary group.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gid: Option<u32>,
    },
    /// An account's membership in a group. Forma may not own the group.
    Membership {
        /// The account.
        user: String,
        /// The group.
        group: String,
    },
    /// A sub-ID range forma added for both user and group IDs.
    SubIds {
        /// The account.
        user: String,
        /// The first ID.
        start: u32,
        /// How many IDs.
        count: u32,
    },
    /// Linger that forma turned on.
    Linger {
        /// The account.
        user: String,
    },
    /// A directory forma created.
    Directory {
        /// The directory.
        path: PathBuf,
    },
    /// A file forma wrote and owns whole. Undo deletes it.
    File {
        /// The file.
        path: PathBuf,
        /// The SHA-256 of what forma wrote, in hex, when forma checks the
        /// file for changes (architecture 5.9, "Detection").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
    },
    /// An owner and group forma set on a file it did not create.
    Owner {
        /// The file.
        path: PathBuf,
        /// The user ID before forma's first change.
        previous_uid: u32,
        /// The group ID before forma's first change.
        previous_gid: u32,
        /// The user ID forma set.
        uid: u32,
        /// The group ID forma set.
        gid: u32,
    },
    /// A mode forma set on a file it did not create.
    Mode {
        /// The file.
        path: PathBuf,
        /// The mode bits before forma's first change.
        previous: u32,
        /// The mode bits forma set.
        mode: u32,
    },
    /// A named ACL entry forma added.
    AclGrant {
        /// The file.
        path: PathBuf,
        /// `user` or `group`.
        who: AclWho,
        /// The user or group ID.
        id: u32,
        /// The permission bits (`rwx` = 7).
        perms: u8,
    },
    /// A home directory forma kept when it deleted the account (decision D6).
    ArchivedHome {
        /// Where the home is now.
        path: PathBuf,
        /// The account it belonged to.
        user: String,
    },
    /// An SELinux module forma installed.
    SeLinuxModule {
        /// Its name.
        name: String,
        /// The priority it is installed at.
        priority: u16,
        /// The SHA-256 of its source, in hex.
        sha256: String,
    },
    /// A mapping from a login to an SELinux user.
    SeLinuxLogin {
        /// The account.
        user: String,
        /// The SELinux user, such as `user_u`.
        selinux_user: String,
    },
    /// A base-image trust key an administrator approved (architecture 5.6).
    TrustKey {
        /// Where forma installed the key.
        path: PathBuf,
        /// The key's SHA-256 fingerprint, in hex.
        fingerprint: String,
    },
}

/// Whether an ACL entry names a user or a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AclWho {
    /// A named user.
    User,
    /// A named group.
    Group,
}

/// What identifies an item. Two items with the same key are the same item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key(String);

impl Key {
    /// Returns the key as text, such as `user:moonshine`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The key of a group.
    #[must_use]
    pub fn group(name: &str) -> Self {
        Self(format!("group:{name}"))
    }

    /// The key of an account.
    #[must_use]
    pub fn user(name: &str) -> Self {
        Self(format!("user:{name}"))
    }

    /// The key of a membership.
    #[must_use]
    pub fn membership(user: &str, group: &str) -> Self {
        Self(format!("member:{user}:{group}"))
    }

    /// The key of an account's sub-ID range.
    #[must_use]
    pub fn sub_ids(user: &str) -> Self {
        Self(format!("subids:{user}"))
    }

    /// The key of an account's linger setting.
    #[must_use]
    pub fn linger(user: &str) -> Self {
        Self(format!("linger:{user}"))
    }

    /// The key of a directory or file forma created.
    #[must_use]
    pub fn path(path: &std::path::Path) -> Self {
        Self(format!("path:{}", path.display()))
    }

    /// The key of an owner forma set.
    #[must_use]
    pub fn owner(path: &std::path::Path) -> Self {
        Self(format!("owner:{}", path.display()))
    }

    /// The key of a mode forma set.
    #[must_use]
    pub fn mode(path: &std::path::Path) -> Self {
        Self(format!("mode:{}", path.display()))
    }

    /// The key of a named ACL entry.
    #[must_use]
    pub fn acl_grant(path: &std::path::Path, who: AclWho, id: u32) -> Self {
        let who = match who {
            AclWho::User => 'u',
            AclWho::Group => 'g',
        };
        Self(format!("acl:{who}:{id}:{}", path.display()))
    }

    /// The key of an SELinux module.
    #[must_use]
    pub fn selinux_module(name: &str) -> Self {
        Self(format!("semodule:{name}"))
    }

    /// The key of an SELinux login mapping.
    #[must_use]
    pub fn selinux_login(user: &str) -> Self {
        Self(format!("selogin:{user}"))
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Item {
    /// Returns what identifies the item.
    #[must_use]
    pub fn key(&self) -> Key {
        match self {
            Self::Group { name, .. } => Key::group(name),
            Self::User { name, .. } => Key::user(name),
            Self::Membership { user, group } => Key::membership(user, group),
            Self::SubIds { user, .. } => Key::sub_ids(user),
            Self::Linger { user } => Key::linger(user),
            Self::Directory { path } | Self::File { path, .. } | Self::ArchivedHome { path, .. } => Key::path(path),
            Self::Owner { path, .. } => Key::owner(path),
            Self::Mode { path, .. } => Key::mode(path),
            Self::AclGrant { path, who, id, .. } => Key::acl_grant(path, *who, *id),
            Self::SeLinuxModule { name, .. } => Key::selinux_module(name),
            Self::SeLinuxLogin { user, .. } => Key::selinux_login(user),
            Self::TrustKey { path, .. } => Key(format!("trustkey:{}", path.display())),
        }
    }
}

impl fmt::Display for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id = |id: &Option<u32>| id.map_or_else(|| "ID not known".to_owned(), |id| id.to_string());
        match self {
            Self::Group { name, gid } => write!(f, "group {name} ({})", id(gid)),
            Self::User { name, uid, .. } => write!(f, "user {name} ({})", id(uid)),
            Self::Membership { user, group } => write!(f, "membership of {user} in {group}"),
            Self::SubIds { user, start, count } => write!(f, "sub-IDs {start}+{count} of {user}"),
            Self::Linger { user } => write!(f, "linger for {user}"),
            Self::Directory { path } => write!(f, "directory {}", path.display()),
            Self::File { path, .. } => write!(f, "file {}", path.display()),
            Self::Owner { path, uid, gid, .. } => write!(f, "owner {uid}:{gid} of {}", path.display()),
            Self::Mode { path, mode, .. } => write!(f, "mode {mode:04o} of {}", path.display()),
            Self::AclGrant { path, who, id, perms } => {
                let who = match who {
                    AclWho::User => "user",
                    AclWho::Group => "group",
                };
                write!(f, "ACL entry {who}:{id}:{perms:o} on {}", path.display())
            }
            Self::ArchivedHome { path, user } => write!(f, "kept home of {user} at {}", path.display()),
            Self::SeLinuxModule { name, priority, .. } => write!(f, "SELinux module {name} (priority {priority})"),
            Self::SeLinuxLogin { user, selinux_user } => write!(f, "SELinux login {user} as {selinux_user}"),
            Self::TrustKey { path, .. } => write!(f, "trust key {}", path.display()),
        }
    }
}

/// One item and its state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// How far the change has come.
    pub status: Status,
    /// The components that need the item, and [`HOST`] if the host itself
    /// does. Forma removes the item only when this is empty (architecture 4.4).
    #[serde(default)]
    pub needed_by: BTreeSet<String>,
    /// The item.
    pub item: Item,
}

/// The whole ledger, as it is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// The format version.
    pub version: u32,
    /// The entries, in the order forma made them. Undo runs in reverse.
    #[serde(default, rename = "entry")]
    pub entries: Vec<Entry>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            version: VERSION,
            entries: Vec::new(),
        }
    }
}
