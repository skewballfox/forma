//! Operations that need root or a Linux capability.
//!
//! Every public function here takes a [`System`], the root handle. The only
//! way to get one is [`System::open`], which checks that the process runs as
//! root. The crate never gains privilege itself.
//!
//! Each function lists the capabilities it uses in a `# Capabilities`
//! section. These are the expected values; spike 0(d) in the architecture
//! plan confirms them.

mod file;
pub mod group;
pub mod perm;
pub mod subid;
#[cfg(feature = "systemd")]
pub mod systemd;
mod tool;
pub mod udev;
pub mod user;

use std::io;
use std::path::Path;
use std::time::Duration;

use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{self as rfs, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use thiserror::Error;

pub use tool::ToolError;

use crate::defs::{DefsError, LoginDefs};
use crate::id::{Gid, SubIdRange, Uid};
use crate::lookup::LookupError;
use crate::name::{GroupName, NameError, UserName};
use crate::ownership::{Change, Facts, Item, Journal, MarkerTag, Ownership};
use crate::path::{AbsPath, PathError, RelPath};
use crate::perm::PermError;
use crate::subid::SubIdError;
use tool::{Invocation, Tools};

const LOGIN_DEFS: &[&str] = &["/etc/login.defs", "/usr/etc/login.defs"];
const CONTAINER_MARKERS: &[&str] = &["/run/.containerenv", "/.dockerenv"];

/// The settings a caller controls. There is no default: set every field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemConfig {
    /// Homes may be created and removed, and owners, modes and ACLs changed,
    /// only under these directories.
    pub allowed_bases: Vec<AbsPath>,
    /// Allow changes to accounts and groups whose IDs are outside the system
    /// range in `login.defs`. Leave `false` unless you manage human accounts.
    pub allow_ids_outside_system_range: bool,
    /// The file every operation locks. Callers that must not run at the same
    /// time use the same path. Its directory must exist.
    pub lock_file: AbsPath,
    /// The tag written into managed files and new accounts' comments.
    pub marker: MarkerTag,
    /// How long one shadow-utils command may run.
    pub tool_timeout: Duration,
    /// How long to wait for a systemd unit or user manager to stop or start.
    #[cfg(feature = "systemd")]
    pub unit_timeout: Duration,
}

/// The root handle. Every operation in [`crate::admin`] takes one.
///
/// `O` decides what the caller may change or remove, and `J` records each
/// change (see [`crate::ownership`]).
pub struct System<O: Ownership, J: Journal> {
    root: OwnedFd,
    config: SystemConfig,
    defs: LoginDefs,
    tools: Tools,
    ownership: O,
    journal: J,
}

impl<O: Ownership, J: Journal> System<O, J> {
    /// Opens the root handle.
    ///
    /// Checks that the effective user ID is 0 and that the process is not
    /// in a container, opens `/`, reads `login.defs`, and checks that each
    /// shadow-utils tool is owned by root and not writable by others.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotRoot`], [`Error::InContainer`], or an error from
    /// reading `login.defs` or checking the tools.
    pub fn open(config: SystemConfig, ownership: O, journal: J) -> Result<Self, Error> {
        let euid = rustix::process::geteuid();
        if !euid.is_root() {
            return Err(Error::NotRoot(Uid::from_raw(euid.as_raw())));
        }
        if let Some(marker) = CONTAINER_MARKERS.iter().find(|marker| Path::new(marker).exists()) {
            return Err(Error::InContainer(marker));
        }
        let root = rfs::open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
            .map_err(|source| Error::sys("open /", source))?;
        let defs = read_login_defs()?;
        let tools = Tools::resolve()?;
        Ok(Self {
            root,
            config,
            defs,
            tools,
            ownership,
            journal,
        })
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &SystemConfig {
        &self.config
    }

    /// Returns the ID ranges read from `login.defs`.
    #[must_use]
    pub fn login_defs(&self) -> &LoginDefs {
        &self.defs
    }

    /// Returns the caller's ownership rules.
    #[must_use]
    pub fn ownership(&self) -> &O {
        &self.ownership
    }

    /// Returns the caller's journal.
    #[must_use]
    pub fn journal(&self) -> &J {
        &self.journal
    }

    /// Closes the handle and returns the ownership rules and journal.
    #[must_use]
    pub fn into_parts(self) -> (O, J) {
        (self.ownership, self.journal)
    }

    pub(crate) fn root(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }

    /// Takes the crate's lock until the guard is dropped.
    pub(crate) fn lock(&self) -> Result<LockGuard, Error> {
        let path = &self.config.lock_file;
        let rel = path.relative().ok_or_else(|| Error::LockFile(path.clone()))?;
        let fd = rfs::openat2(
            self.root(),
            rel.as_path(),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            crate::fs::RESOLVE,
        )
        .map_err(|source| Error::sys(format!("open lock file {path}"), source))?;
        rfs::flock(&fd, FlockOperation::LockExclusive)
            .map_err(|source| Error::sys(format!("lock {path}"), source))?;
        Ok(LockGuard(fd))
    }

    /// Fails with [`Error::NotOwned`] unless the caller's [`Ownership`] claims `item`.
    pub(crate) fn require_claim(&self, item: &Item<'_>) -> Result<(), Error> {
        match self.ownership.claims(item) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::NotOwned(item.to_string())),
            Err(source) => Err(Error::Ownership {
                item: item.to_string(),
                source: Box::new(source),
            }),
        }
    }

    pub(crate) fn intent(&mut self, change: &Change) -> Result<(), Error> {
        self.journal.intent(change).map_err(|source| Error::Journal {
            change: change.to_string(),
            source: Box::new(source),
        })
    }

    pub(crate) fn applied(&mut self, change: &Change, facts: &Facts) -> Result<(), Error> {
        self.journal.applied(change, facts).map_err(|source| Error::Journal {
            change: change.to_string(),
            source: Box::new(source),
        })
    }

    /// Fails unless `path` is under one of the allowed bases.
    pub(crate) fn check_allowed(&self, path: &AbsPath) -> Result<(), Error> {
        if self.config.allowed_bases.iter().any(|base| path.is_under(base)) {
            return Ok(());
        }
        Err(Error::Refused {
            what: path.to_string(),
            reason: Refusal::OutsideAllowedBases,
        })
    }

    /// Fails for user ID 0, and for IDs outside the system range unless allowed.
    pub(crate) fn check_uid(&self, uid: Uid, what: &str) -> Result<(), Error> {
        self.check_id(uid.as_raw(), self.defs.sys_uid, what)
    }

    /// Fails for group ID 0, and for IDs outside the system range unless allowed.
    pub(crate) fn check_gid(&self, gid: Gid, what: &str) -> Result<(), Error> {
        self.check_id(gid.as_raw(), self.defs.sys_gid, what)
    }

    fn check_id(&self, id: u32, range: crate::id::IdRange, what: &str) -> Result<(), Error> {
        let reason = match id {
            0 => Refusal::Root,
            id if !range.contains(id) && !self.config.allow_ids_outside_system_range => Refusal::OutsideSystemRange,
            _ => return Ok(()),
        };
        Err(Error::Refused {
            what: what.to_owned(),
            reason,
        })
    }

    pub(crate) fn run(&self, invocation: &Invocation) -> Result<(), ToolError> {
        self.tools.run(invocation, self.config.tool_timeout)
    }
}

/// The result of an `ensure` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ensured<T, D> {
    /// It did not exist, and was created.
    Created(T),
    /// It exists, the caller owns it, and it matches the spec.
    Matches(T),
    /// It exists and the caller owns it, but it differs from the spec.
    /// Nothing was changed.
    Conflict {
        /// What exists.
        existing: T,
        /// How it differs.
        diff: D,
    },
}

/// Holds the crate's lock. Dropping it closes the file, which releases the lock.
pub(crate) struct LockGuard(#[allow(dead_code, reason = "held only to keep the lock")] OwnedFd);

fn read_login_defs() -> Result<LoginDefs, Error> {
    for path in LOGIN_DEFS {
        match std::fs::read_to_string(path) {
            Ok(text) => return LoginDefs::parse(&text).map_err(Error::Defs),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(Error::io(format!("read {path}"), source)),
        }
    }
    // No file: shadow-utils' built-in defaults.
    LoginDefs::parse("").map_err(Error::Defs)
}

/// Reads a configuration file, following symlinks. `None` if it is missing.
///
/// Only for files the crate reads and never writes, such as
/// `nsswitch.conf`, which authselect makes a symlink.
pub(crate) fn read_config(path: &str) -> Result<Option<String>, Error> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::io(format!("read {path}"), source)),
    }
}

/// Converts a known absolute path to a relative one for `openat2`.
pub(crate) fn rel(path: &AbsPath) -> Result<RelPath, Error> {
    path.relative().ok_or_else(|| Error::Refused {
        what: path.to_string(),
        reason: Refusal::RootDirectory,
    })
}

/// Why the crate refused an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The ID is 0.
    Root,
    /// The ID is outside the system range, and the configuration does not allow that.
    OutsideSystemRange,
    /// The entry lives only in `/usr/lib` and cannot be changed.
    Vendor,
    /// The entry comes from another NSS source, such as sssd.
    Remote,
    /// The account is the one that started this process.
    CallerLogin,
    /// The account has login sessions, listed by ID.
    ActiveSessions(Vec<String>),
    /// The group is this account's primary group.
    PrimaryGroupOf(String),
    /// A managed udev rule names the group.
    UsedByUdevRule(AbsPath),
    /// The path is outside every allowed base.
    OutsideAllowedBases,
    /// The path is `/`.
    RootDirectory,
    /// The home is a mount point.
    HomeIsMountPoint,
    /// The home is owned by another user ID.
    HomeOwnedBy(Uid),
    /// Another account has the same home.
    HomeShared(String),
    /// The account has no home to archive or remove.
    NoHome,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => f.write_str("it is root"),
            Self::OutsideSystemRange => f.write_str("its ID is outside the system range"),
            Self::Vendor => f.write_str("it lives only in /usr/lib and cannot be changed"),
            Self::Remote => f.write_str("it comes from an NSS source shadow-utils cannot change"),
            Self::CallerLogin => f.write_str("it is the account that started this process"),
            Self::ActiveSessions(ids) => write!(f, "it has login sessions: {}", ids.join(", ")),
            Self::PrimaryGroupOf(user) => write!(f, "it is the primary group of {user}"),
            Self::UsedByUdevRule(path) => write!(f, "the managed udev rule {path} names it"),
            Self::OutsideAllowedBases => f.write_str("it is outside every allowed base"),
            Self::RootDirectory => f.write_str("it is /"),
            Self::HomeIsMountPoint => f.write_str("its home is a mount point"),
            Self::HomeOwnedBy(uid) => write!(f, "its home is owned by user ID {uid}"),
            Self::HomeShared(user) => write!(f, "its home is also the home of {user}"),
            Self::NoHome => f.write_str("it has no home"),
        }
    }
}

/// A privileged operation failed.
#[derive(Debug, Error)]
pub enum Error {
    /// The process does not run as root.
    #[error("this needs root, but the effective user ID is {0}")]
    NotRoot(Uid),
    /// The process runs in a container.
    #[error("refusing to change the host from inside a container ({0} exists)")]
    InContainer(&'static str),
    /// The lock file path is `/`.
    #[error("lock file {0} is not a file path")]
    LockFile(AbsPath),
    /// A file operation failed.
    #[error("cannot {action}")]
    Io {
        /// What was being done.
        action: String,
        /// The error.
        source: io::Error,
    },
    /// A system call failed.
    #[error("cannot {action}")]
    Sys {
        /// What was being done.
        action: String,
        /// The error.
        source: Errno,
    },
    /// A call to logind or systemd failed.
    #[cfg(feature = "systemd")]
    #[error(transparent)]
    Systemd(#[from] systemd::SystemdError),
    /// A file could not be parsed.
    #[error(transparent)]
    Defs(#[from] DefsError),
    /// A lookup failed.
    #[error(transparent)]
    Lookup(#[from] LookupError),
    /// A name or comment failed a check.
    #[error(transparent)]
    Name(#[from] NameError),
    /// A path failed a check.
    #[error(transparent)]
    Path(#[from] PathError),
    /// A shadow-utils command failed.
    #[error(transparent)]
    Tool(#[from] ToolError),
    /// A permission operation failed.
    #[error(transparent)]
    Perm(#[from] PermError),
    /// No sub-ID range could be found.
    #[error(transparent)]
    SubIds(#[from] SubIdError),
    /// The caller's [`Ownership`] does not claim the item.
    #[error("{0} is not owned by the caller")]
    NotOwned(String),
    /// The caller's [`Ownership`] failed.
    #[error("cannot check ownership of {item}")]
    Ownership {
        /// The item.
        item: String,
        /// The caller's error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The caller's [`Journal`] failed.
    #[error("cannot record \"{change}\" in the journal")]
    Journal {
        /// The change.
        change: String,
        /// The caller's error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The crate refused the operation.
    #[error("refusing to change {what}: {reason}")]
    Refused {
        /// What the operation would change.
        what: String,
        /// Why it was refused.
        reason: Refusal,
    },
    /// An account with this name exists.
    #[error("user {0} already exists")]
    UserExists(UserName),
    /// An account with this user ID exists.
    #[error("user ID {0} is already in use")]
    UidInUse(Uid),
    /// A group with this name exists.
    #[error("group {0} already exists")]
    GroupExists(GroupName),
    /// A group with this group ID exists.
    #[error("group ID {0} is already in use")]
    GidInUse(Gid),
    /// The spec asks for a new primary group, but a group with the
    /// account's name exists.
    #[error("group {0} already exists; use PrimaryGroup::Existing to make it the primary group")]
    PrimaryGroupExists(GroupName),
    /// A group the operation needs does not exist.
    #[error("group {0} does not exist")]
    GroupMissing(GroupName),
    /// A group is not in `/etc/group`, so it cannot take members.
    #[error("group {0} is not in /etc/group")]
    NotLocal(GroupName),
    /// The account or group changed since it was looked up.
    #[error("{0} changed since it was looked up")]
    Changed(String),
    /// The account, group or file no longer exists.
    #[error("{0} no longer exists")]
    Gone(String),
    /// A path that must be new already exists.
    #[error("{0} already exists")]
    AlreadyExists(AbsPath),
    /// NSS takes sub-IDs from a source other than the files.
    #[error("nsswitch.conf takes sub-IDs from {0:?}, so /etc/subuid has no effect")]
    SubIdBackend(String),
    /// A sub-ID range overlaps another owner's.
    #[error("sub-ID range {range} overlaps the range of {owner}")]
    SubIdOverlap {
        /// The range.
        range: SubIdRange,
        /// The other owner.
        owner: String,
    },
    /// The account already has sub-ID ranges.
    #[error("{user} already has sub-ID ranges")]
    HasSubIds {
        /// The account.
        user: UserName,
        /// Its ranges in `/etc/subuid`.
        uids: Vec<SubIdRange>,
        /// Its ranges in `/etc/subgid`.
        gids: Vec<SubIdRange>,
    },
}

impl Error {
    pub(crate) fn io(action: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            action: action.into(),
            source,
        }
    }

    pub(crate) fn sys(action: impl Into<String>, source: Errno) -> Self {
        Self::Sys {
            action: action.into(),
            source,
        }
    }
}
