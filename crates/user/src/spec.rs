//! What an account or group should look like, and how one differs from it.
//!
//! These types describe; they change nothing. [`crate::admin::user`] and
//! [`crate::admin::group`] act on them.

use std::path::Path;

use crate::id::{Gid, SystemGid, SystemUid, Uid};
use crate::lookup::{Group, LocalGroup, User};
use crate::name::{Comment, GroupName, UserName};
use crate::path::AbsPath;

/// The login shell for accounts that must not log in.
pub const NOLOGIN: &str = "/usr/sbin/nologin";

/// The home field of accounts without a home, as `systemd-sysusers` writes it.
pub const NO_HOME: &str = "/";

/// How a new account gets its user ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UidChoice {
    /// Let `useradd` pick a free ID in the system range.
    Allocate,
    /// Use this ID.
    Fixed(SystemUid),
}

/// How a new group gets its group ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GidChoice {
    /// Let `groupadd` pick a free ID in the system range.
    Allocate,
    /// Use this ID.
    Fixed(SystemGid),
}

/// The primary group of a new account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimaryGroup {
    /// Create a group with the account's name. Fails if one exists.
    New,
    /// Use a group that already exists, from any source. It is not changed.
    Existing(Group),
}

/// The home directory of a new account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeSpec {
    /// No home. The password database records `/`.
    None,
    /// Create this directory. It must not exist yet, and must be under an
    /// allowed base.
    Create(AbsPath),
}

/// The login shell of a new account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shell {
    /// `/usr/sbin/nologin`.
    NoLogin,
    /// A shell that allows logins.
    Login(AbsPath),
}

/// Every setting of a new system account. Nothing falls back to
/// `login.defs` or `/etc/default/useradd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSpec {
    /// The account's name.
    pub name: UserName,
    /// How it gets its user ID.
    pub uid: UidChoice,
    /// Its primary group.
    pub primary_group: PrimaryGroup,
    /// Its supplementary groups. Each must be in `/etc/group`.
    pub supplementary: Vec<LocalGroup>,
    /// Its home directory.
    pub home: HomeSpec,
    /// Its login shell.
    pub shell: Shell,
    /// Its comment. The crate adds its ownership marker after this text.
    pub comment: Option<Comment>,
}

/// How an existing account differs from a [`UserSpec`]. Each field holds
/// `(expected, actual)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserDiff {
    /// The user ID differs.
    pub uid: Option<(Uid, Uid)>,
    /// The primary group differs. `expected` is `None` when the spec asks
    /// for a new group and no group with the account's name exists.
    pub primary_gid: Option<(Option<Gid>, Gid)>,
    /// Supplementary groups the spec lists but the account lacks.
    pub missing_groups: Vec<GroupName>,
    /// The home differs.
    pub home: Option<(String, String)>,
    /// The shell differs.
    pub shell: Option<(String, String)>,
}

impl UserDiff {
    /// Says whether the account matches the spec.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

impl UserSpec {
    /// Compares the spec with an existing account.
    ///
    /// `gids` must hold every group ID the account has (see
    /// [`crate::lookup::group_ids`]). `own_group` is the ID of the group with
    /// the account's name, if one exists; it is used when the spec asks for
    /// [`PrimaryGroup::New`].
    #[must_use]
    pub fn diff(&self, user: &User, gids: &[Gid], own_group: Option<Gid>) -> UserDiff {
        let uid = match self.uid {
            UidChoice::Fixed(fixed) if fixed.uid() != user.uid() => Some((fixed.uid(), user.uid())),
            _ => None,
        };
        let expected_gid = match &self.primary_group {
            PrimaryGroup::New => own_group,
            PrimaryGroup::Existing(group) => Some(group.info().gid()),
        };
        let primary_gid = (expected_gid != Some(user.gid())).then_some((expected_gid, user.gid()));
        let missing_groups = self
            .supplementary
            .iter()
            .filter(|group| !gids.contains(&group.info().gid()))
            .map(|group| group.info().name().clone())
            .collect();
        let expected_home = match &self.home {
            HomeSpec::None => Path::new(NO_HOME),
            HomeSpec::Create(path) => path.as_path(),
        };
        let home = (user.home() != expected_home).then(|| {
            (
                expected_home.display().to_string(),
                user.home().display().to_string(),
            )
        });
        let shell_matches = match &self.shell {
            // Merged-/usr systems reach nologin by several paths.
            Shell::NoLogin => user.shell().file_name().is_some_and(|name| name == "nologin"),
            Shell::Login(path) => user.shell() == path.as_path(),
        };
        let shell = (!shell_matches).then(|| {
            let expected = match &self.shell {
                Shell::NoLogin => NOLOGIN.to_owned(),
                Shell::Login(path) => path.to_string(),
            };
            (expected, user.shell().display().to_string())
        });
        UserDiff {
            uid,
            primary_gid,
            missing_groups,
            home,
            shell,
        }
    }
}

/// Every setting of a new system group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSpec {
    /// The group's name.
    pub name: GroupName,
    /// How it gets its group ID.
    pub gid: GidChoice,
}

/// How an existing group differs from a [`GroupSpec`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupDiff {
    /// The group ID differs: `(expected, actual)`.
    pub gid: Option<(Gid, Gid)>,
}

impl GroupDiff {
    /// Says whether the group matches the spec.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

impl GroupSpec {
    /// Compares the spec with an existing group.
    #[must_use]
    pub fn diff(&self, group: &LocalGroup) -> GroupDiff {
        let actual = group.info().gid();
        GroupDiff {
            gid: match self.gid {
                GidChoice::Fixed(fixed) if fixed.gid() != actual => Some((fixed.gid(), actual)),
                _ => None,
            },
        }
    }
}

/// What happens to an account's home when the account is deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomePolicy {
    /// Leave it as it is.
    Keep,
    /// Rename it to `<home>.removed-<seconds since 1970>`, owned by root,
    /// mode `0700`.
    Archive,
    /// Remove it, without following symlinks.
    Remove,
}

/// What happens when the account to delete has login sessions.
///
/// With the `systemd` feature, sessions come from logind. Without it, the
/// crate cannot see sessions; `userdel` refuses an account that has running
/// processes, and that refusal is reported as active sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPolicy {
    /// Fail with an error.
    Refuse,
    /// End them with logind.
    #[cfg(feature = "systemd")]
    Terminate,
}

/// Options for deleting an account. Neither has a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteOptions {
    /// What happens to the home.
    pub home: HomePolicy,
    /// What happens to login sessions.
    pub sessions: SessionPolicy,
}
