//! Creating and deleting system accounts.
//!
//! [`crate::spec::UserSpec`] describes an account, and
//! [`crate::spec::UserSpec::diff`] compares one, without root.

use std::ffi::OsString;
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::fs::{self as rfs, Gid as RGid, Mode, RenameFlags, Uid as RUid};

use super::tool::{Invocation, Tool};
use super::{Ensured, Error, Refusal, System, file, group, perm};
use crate::id::{Gid, Uid};
use crate::lookup::{self, Group, LookupError, Source, User, ETC_PASSWD, VENDOR_PASSWD};
use crate::name::{Comment, GroupName};
use crate::ownership::{Change, Facts, Item, Journal, Ownership};
use crate::path::AbsPath;
use crate::spec::{
    DeleteOptions, HomePolicy, HomeSpec, NO_HOME, NOLOGIN, PrimaryGroup, Shell, UidChoice, UserDiff,
    UserSpec,
};

/// `useradd` exit code: the user ID is in use.
const USERADD_UID_IN_USE: i32 = 4;
/// `useradd` exit code: the user name is in use.
const USERADD_NAME_IN_USE: i32 = 9;
/// `userdel` exit code: the account is logged in.
const USERDEL_LOGGED_IN: i32 = 8;
/// The audit login ID of a process that no login started.
const LOGINUID_UNSET: u32 = u32::MAX;

/// Creates a system account. Fails if an account with that name or user ID
/// exists. Groups that already exist are fine (see [`PrimaryGroup`]).
///
/// Every `useradd` setting is passed explicitly, so `login.defs` and
/// `/etc/default/useradd` cannot change the result. The account's comment
/// ends with the ownership marker from the configuration.
///
/// # Errors
///
/// Returns [`Error::UserExists`] or [`Error::UidInUse`] if the name or ID
/// is taken, [`Error::PrimaryGroupExists`] if the spec asks for a new
/// primary group and one with that name exists, [`Error::Changed`] or
/// [`Error::Gone`] if a group in the spec changed since it was looked up,
/// [`Error::Refused`] or [`Error::AlreadyExists`] for a home outside the
/// allowed bases or one that exists, and [`Error::Tool`] if `useradd`
/// fails.
///
/// # Capabilities
///
/// `CAP_DAC_OVERRIDE`, `CAP_CHOWN` and `CAP_FOWNER` for `useradd` to write
/// the account files and create the home, and `CAP_AUDIT_WRITE` for its
/// audit record.
pub fn create<O: Ownership, J: Journal>(system: &mut System<O, J>, spec: &UserSpec) -> Result<User, Error> {
    let _lock = system.lock()?;
    create_unlocked(system, spec)
}

/// Creates the account if it does not exist. If it exists, compares it with
/// the spec and changes nothing.
///
/// # Errors
///
/// Returns [`Error::NotOwned`] if the account exists and the caller's
/// `Ownership` does not claim it. Otherwise the errors of [`create`].
///
/// # Capabilities
///
/// The same as [`create`].
pub fn ensure<O: Ownership, J: Journal>(system: &mut System<O, J>, spec: &UserSpec) -> Result<Ensured<User, UserDiff>, Error> {
    let _lock = system.lock()?;
    let Some(user) = lookup::user(&spec.name)? else {
        return create_unlocked(system, spec).map(Ensured::Created);
    };
    system.require_claim(&Item::User(&user))?;
    let gids = lookup::group_ids(&user)?;
    let own_group = match GroupName::new(spec.name.as_str()) {
        Ok(name) => lookup::group(&name)?.map(|group| group.info().gid()),
        Err(_) => None,
    };
    let diff = spec.diff(&user, &gids, own_group);
    Ok(if diff.is_empty() {
        Ensured::Matches(user)
    } else {
        Ensured::Conflict { existing: user, diff }
    })
}

fn create_unlocked<O: Ownership, J: Journal>(system: &mut System<O, J>, spec: &UserSpec) -> Result<User, Error> {
    if lookup::user(&spec.name)?.is_some() {
        return Err(Error::UserExists(spec.name.clone()));
    }
    let invocation = useradd(system, spec)?;
    let change = Change::CreateUser { name: spec.name.clone() };
    system.intent(&change)?;
    system.run(&invocation).map_err(|error| match error.exit_code() {
        Some(USERADD_UID_IN_USE) => match spec.uid {
            UidChoice::Fixed(uid) => Error::UidInUse(uid.uid()),
            UidChoice::Allocate => Error::Tool(error),
        },
        Some(USERADD_NAME_IN_USE) => Error::UserExists(spec.name.clone()),
        _ => Error::Tool(error),
    })?;
    let user = lookup::user(&spec.name)?.ok_or_else(|| Error::Gone(format!("user {}", spec.name)))?;
    system.applied(
        &change,
        &Facts {
            uid: Some(user.uid()),
            gid: Some(user.gid()),
            ..Facts::default()
        },
    )?;
    Ok(user)
}

/// Checks the spec against the host and builds the `useradd` command line.
fn useradd<O: Ownership, J: Journal>(system: &System<O, J>, spec: &UserSpec) -> Result<Invocation, Error> {
    let mut invocation = Invocation::new(Tool::Useradd).flag("--system");

    if let UidChoice::Fixed(uid) = spec.uid {
        if uid_in_use(uid.uid())? {
            return Err(Error::UidInUse(uid.uid()));
        }
        invocation = invocation.value("--uid", uid.uid().to_string());
    }

    invocation = match &spec.primary_group {
        PrimaryGroup::New => {
            let name = GroupName::new(spec.name.as_str())?;
            if lookup::group(&name)?.is_some() {
                return Err(Error::PrimaryGroupExists(name));
            }
            invocation.flag("--user-group")
        }
        PrimaryGroup::Existing(group) => {
            let gid = still_there(group)?;
            invocation.flag("--no-user-group").value("--gid", gid.to_string())
        }
    };

    if !spec.supplementary.is_empty() {
        let mut names = Vec::with_capacity(spec.supplementary.len());
        for wanted in &spec.supplementary {
            let now = group::current(wanted.info().name())?;
            if now.info().gid() != wanted.info().gid() {
                return Err(Error::Changed(format!("group {}", wanted.info().name())));
            }
            names.push(now.info().name().as_str().to_owned());
        }
        invocation = invocation.value("--groups", names.join(","));
    }

    invocation = match &spec.home {
        HomeSpec::None => invocation.flag("--no-create-home").value("--home-dir", NO_HOME),
        HomeSpec::Create(path) => {
            system.check_allowed(path)?;
            if perm::stat(system, path)?.is_some() {
                return Err(Error::AlreadyExists(path.clone()));
            }
            invocation
                .flag("--create-home")
                .value("--home-dir", OsString::from(path.as_path()))
        }
    };

    invocation = match &spec.shell {
        Shell::NoLogin => invocation.value("--shell", NOLOGIN),
        Shell::Login(path) => invocation.value("--shell", OsString::from(path.as_path())),
    };

    let marker = system.config().marker.comment_marker();
    let comment = match &spec.comment {
        Some(comment) => Comment::new(format!("{comment} {marker}"))?,
        None => Comment::new(marker)?,
    };
    // An empty expiry date turns expiry off, whatever /etc/default/useradd says.
    Ok(invocation
        .value("--comment", comment.as_str())
        .value("--expiredate", "")
        .arg(spec.name.as_str()))
}

/// Checks that a group from the spec still exists with the same ID.
fn still_there(group: &Group) -> Result<Gid, Error> {
    let name = group.info().name();
    match lookup::group(name)? {
        Some(now) if now.info().gid() == group.info().gid() => Ok(now.info().gid()),
        Some(_) => Err(Error::Changed(format!("group {name}"))),
        None => Err(Error::Gone(format!("group {name}"))),
    }
}

fn uid_in_use(uid: Uid) -> Result<bool, Error> {
    match lookup::user_by_uid(uid) {
        Ok(found) => Ok(found.is_some()),
        // An account with a name this crate rejects still holds the ID.
        Err(LookupError::InvalidName { .. }) => Ok(true),
        Err(error) => Err(error.into()),
    }
}

/// Deletes an account. Returns where the home was archived, if it was.
///
/// Steps, in order:
///
/// 1. Look the account up again. Stop if its user ID or home changed.
/// 2. Ask the caller's `Ownership`, and check the refusals: root, IDs
///    outside the system range, vendor and remote entries, the account that
///    started this process, and (for `Archive` and `Remove`) a home that is
///    outside the allowed bases, a mount point, owned by another ID, or
///    shared with another account.
/// 3. With the `systemd` feature: check for login sessions, and refuse if
///    the options say so.
/// 4. With the `systemd` feature: turn linger off, end the account's
///    sessions with logind, and wait for `user@<uid>.service` to stop.
/// 5. Run `userdel`, without `-r` and without `-f`. It refuses an account
///    with running processes, which is reported as active sessions.
/// 6. Keep, archive or remove the home.
///
/// # Errors
///
/// Returns [`Error::Changed`] or [`Error::Gone`] if the account changed,
/// [`Error::NotOwned`] if the caller does not own it, [`Error::Refused`]
/// for the refusals above, `Error::Systemd` (feature `systemd`) if the
/// user manager does not stop, and [`Error::Tool`] if `userdel` fails.
///
/// # Capabilities
///
/// `CAP_DAC_OVERRIDE` and `CAP_AUDIT_WRITE` for `userdel`. `CAP_CHOWN` and
/// `CAP_FOWNER` to archive or remove the home. Ending sessions and turning
/// linger off need user ID 0 (polkit).
pub fn delete<O: Ownership, J: Journal>(
    system: &mut System<O, J>,
    user: &User,
    options: DeleteOptions,
) -> Result<Option<AbsPath>, Error> {
    let _lock = system.lock()?;
    let name = user.name().clone();
    let what = format!("user {name}");
    let now = lookup::user(&name)?.ok_or_else(|| Error::Gone(what.clone()))?;
    if (now.uid(), now.home()) != (user.uid(), user.home()) {
        return Err(Error::Changed(what));
    }
    system.require_claim(&Item::User(&now))?;
    system.check_uid(now.uid(), &what)?;
    match now.source() {
        Source::Local => {}
        Source::Vendor => return refused(what, Refusal::Vendor),
        Source::Other => return refused(what, Refusal::Remote),
    }
    if caller_loginuid()? == Some(now.uid()) {
        return refused(what, Refusal::CallerLogin);
    }
    let home = match options.home {
        HomePolicy::Keep => None,
        HomePolicy::Archive | HomePolicy::Remove => checked_home(system, &now)?,
    };

    #[cfg(feature = "systemd")]
    if options.sessions == crate::spec::SessionPolicy::Refuse {
        let sessions = super::systemd::login_sessions(&now)?;
        if !sessions.is_empty() {
            return refused(what, Refusal::ActiveSessions(sessions));
        }
    }

    let change = Change::DeleteUser {
        user: now.clone(),
        home: options.home,
    };
    system.intent(&change)?;
    #[cfg(feature = "systemd")]
    super::systemd::stop_user_manager(&now, system.config().unit_timeout)?;

    system
        .run(&Invocation::new(Tool::Userdel).arg(name.as_str()))
        .map_err(|error| match error.exit_code() {
            Some(USERDEL_LOGGED_IN) => Error::Refused {
                what: format!("user {name}"),
                reason: Refusal::ActiveSessions(Vec::new()),
            },
            _ => Error::Tool(error),
        })?;

    let archived = match (options.home, home) {
        (HomePolicy::Archive, Some(home)) => Some(archive_home(system, &home)?),
        (HomePolicy::Remove, Some(home)) => {
            perm::remove_tree(system, &home)?;
            None
        }
        _ => None,
    };
    system.applied(
        &change,
        &Facts {
            archived_home: archived.clone(),
            ..Facts::default()
        },
    )?;
    Ok(archived)
}

fn refused<T>(what: String, reason: Refusal) -> Result<T, Error> {
    Err(Error::Refused { what, reason })
}

/// Checks that the account's home may be archived or removed. Returns
/// `None` if the account has a home path but nothing exists there.
fn checked_home<O: Ownership, J: Journal>(system: &System<O, J>, user: &User) -> Result<Option<AbsPath>, Error> {
    let what = format!("home of {}", user.name());
    let Ok(home) = AbsPath::new(user.home()) else {
        return refused(what, Refusal::NoHome);
    };
    if home == AbsPath::root() {
        return refused(what, Refusal::NoHome);
    }
    system.check_allowed(&home)?;
    let Some(stat) = perm::stat(system, &home)? else {
        return Ok(None);
    };
    if stat.owner != user.uid() {
        return refused(what, Refusal::HomeOwnedBy(stat.owner));
    }
    if perm::is_mount_point(system, &home)? {
        return refused(what, Refusal::HomeIsMountPoint);
    }
    for file in [ETC_PASSWD, VENDOR_PASSWD] {
        let shared = lookup::passwd_file(file)?
            .into_iter()
            .find(|entry| entry.home == home.as_path() && entry.name != user.name().as_str());
        if let Some(entry) = shared {
            return refused(what, Refusal::HomeShared(entry.name));
        }
    }
    Ok(Some(home))
}

/// Renames a home to `<home>.removed-<seconds>`, owned by root, mode `0700`.
fn archive_home<O: Ownership, J: Journal>(system: &System<O, J>, home: &AbsPath) -> Result<AbsPath, Error> {
    let (parent, name) = file::open_parent(system, home)?;
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
    let mut new_name = name.to_owned();
    new_name.push(format!(".removed-{seconds}"));
    let archived = home.parent().unwrap_or_else(AbsPath::root).join(&new_name)?;
    rfs::renameat_with(&parent, name, &parent, &new_name, RenameFlags::NOREPLACE)
        .map_err(|source| Error::sys(format!("rename {home} to {archived}"), source))?;

    let rel = super::rel(&archived)?;
    let dir = crate::fs::open_dir(system.root(), Some(&rel))
        .map_err(|source| Error::sys(format!("open {archived}"), source))?;
    rfs::fchown(&dir, Some(RUid::ROOT), Some(RGid::ROOT))
        .map_err(|source| Error::sys(format!("give {archived} to root"), source))?;
    rfs::fchmod(&dir, Mode::from_raw_mode(0o700))
        .map_err(|source| Error::sys(format!("set the mode of {archived}"), source))?;
    Ok(archived)
}

/// Returns the user ID of the login that started this process, if any.
fn caller_loginuid() -> Result<Option<Uid>, Error> {
    let Some(text) = super::read_config("/proc/self/loginuid")? else {
        return Ok(None);
    };
    Ok(text
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|&uid| uid != LOGINUID_UNSET)
        .map(Uid::from_raw))
}
