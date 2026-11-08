//! Creating and deleting groups, and changing their members.
//!
//! To put an account in a group that already exists, use
//! [`add_member`] or the account's spec. Neither needs the caller to own
//! the group.

use super::tool::{Invocation, Tool};
use super::{Ensured, Error, Refusal, System, udev};
use crate::id::Gid;
use crate::lookup::{self, Group, LocalGroup, LookupError, Source, User, ETC_PASSWD, VENDOR_PASSWD};
use crate::name::GroupName;
use crate::ownership::{Change, Facts, Item, Journal, Ownership};
use crate::spec::{GidChoice, GroupDiff, GroupSpec};

/// `groupadd` exit code: the group ID is in use.
const GROUPADD_GID_IN_USE: i32 = 4;
/// `groupadd` exit code: the group name is in use.
const GROUPADD_NAME_IN_USE: i32 = 9;
/// `groupdel` exit code: the group is some account's primary group.
const GROUPDEL_PRIMARY: i32 = 8;

/// Creates a system group. Fails if a group with that name or ID exists.
///
/// # Errors
///
/// Returns [`Error::GroupExists`] or [`Error::GidInUse`] if the name or ID
/// is taken, and [`Error::Tool`] if `groupadd` fails.
///
/// # Capabilities
///
/// `CAP_DAC_OVERRIDE` for `groupadd` to write `/etc/group` and
/// `/etc/gshadow`, and `CAP_AUDIT_WRITE` for its audit record.
pub fn create<O: Ownership, J: Journal>(system: &mut System<O, J>, spec: &GroupSpec) -> Result<LocalGroup, Error> {
    let _lock = system.lock()?;
    create_unlocked(system, spec)
}

/// Creates the group if it does not exist. If it exists, compares it with
/// the spec and changes nothing.
///
/// # Errors
///
/// Returns [`Error::NotOwned`] if the group exists and the caller's
/// `Ownership` does not claim it, and [`Error::Refused`] if it exists
/// outside `/etc/group`. Otherwise the errors of [`create`].
///
/// # Capabilities
///
/// The same as [`create`].
pub fn ensure<O: Ownership, J: Journal>(
    system: &mut System<O, J>,
    spec: &GroupSpec,
) -> Result<Ensured<LocalGroup, GroupDiff>, Error> {
    let _lock = system.lock()?;
    match lookup::group(&spec.name)? {
        None => create_unlocked(system, spec).map(Ensured::Created),
        Some(Group::Local(group)) => {
            system.require_claim(&Item::Group(&group))?;
            let diff = spec.diff(&group);
            Ok(if diff.is_empty() {
                Ensured::Matches(group)
            } else {
                Ensured::Conflict { existing: group, diff }
            })
        }
        Some(other) => Err(not_local(&other)),
    }
}

fn create_unlocked<O: Ownership, J: Journal>(system: &mut System<O, J>, spec: &GroupSpec) -> Result<LocalGroup, Error> {
    if lookup::group(&spec.name)?.is_some() {
        return Err(Error::GroupExists(spec.name.clone()));
    }
    let mut invocation = Invocation::new(Tool::Groupadd).flag("--system");
    if let GidChoice::Fixed(gid) = spec.gid {
        if gid_in_use(gid.gid())? {
            return Err(Error::GidInUse(gid.gid()));
        }
        invocation = invocation.value("--gid", gid.gid().to_string());
    }
    let invocation = invocation.arg(spec.name.as_str());

    let change = Change::CreateGroup { name: spec.name.clone() };
    system.intent(&change)?;
    system.run(&invocation).map_err(|error| match error.exit_code() {
        Some(GROUPADD_GID_IN_USE) => match spec.gid {
            GidChoice::Fixed(gid) => Error::GidInUse(gid.gid()),
            GidChoice::Allocate => Error::Tool(error),
        },
        Some(GROUPADD_NAME_IN_USE) => Error::GroupExists(spec.name.clone()),
        _ => Error::Tool(error),
    })?;
    let group = current(&spec.name)?;
    system.applied(
        &change,
        &Facts {
            gid: Some(group.info().gid()),
            ..Facts::default()
        },
    )?;
    Ok(group)
}

/// Deletes a group the caller owns.
///
/// # Errors
///
/// Returns [`Error::Changed`] if the group's ID changed since it was looked
/// up, [`Error::NotOwned`] if the caller's `Ownership` does not claim it,
/// and [`Error::Refused`] if it is root's group, outside the system range,
/// an account's primary group, or named in a managed udev rule.
///
/// # Capabilities
///
/// `CAP_DAC_OVERRIDE` for `groupdel` to write `/etc/group` and
/// `/etc/gshadow`, and `CAP_AUDIT_WRITE` for its audit record.
pub fn delete<O: Ownership, J: Journal>(system: &mut System<O, J>, group: &LocalGroup) -> Result<(), Error> {
    let _lock = system.lock()?;
    let name = group.info().name().clone();
    let now = current(&name)?;
    if now.info().gid() != group.info().gid() {
        return Err(Error::Changed(format!("group {name}")));
    }
    system.require_claim(&Item::Group(&now))?;
    let what = format!("group {name}");
    system.check_gid(now.info().gid(), &what)?;

    let gid = now.info().gid().as_raw();
    for file in [ETC_PASSWD, VENDOR_PASSWD] {
        if let Some(entry) = lookup::passwd_file(file)?.into_iter().find(|entry| entry.gid == gid) {
            return Err(Error::Refused {
                what,
                reason: Refusal::PrimaryGroupOf(entry.name),
            });
        }
    }
    if let Some(rules) = udev::files_naming(system, &name)?.into_iter().next() {
        return Err(Error::Refused {
            what,
            reason: Refusal::UsedByUdevRule(rules),
        });
    }

    let change = Change::DeleteGroup { group: now };
    system.intent(&change)?;
    system
        .run(&Invocation::new(Tool::Groupdel).arg(name.as_str()))
        .map_err(|error| match error.exit_code() {
            Some(GROUPDEL_PRIMARY) => Error::Refused {
                what: format!("group {name}"),
                reason: Refusal::PrimaryGroupOf("an account".to_owned()),
            },
            _ => Error::Tool(error),
        })?;
    system.applied(&change, &Facts::default())
}

/// Adds one account to one group. The group may be any group in
/// `/etc/group`; the caller does not need to own it. Returns `false` if the
/// account was already a member.
///
/// # Errors
///
/// Returns [`Error::Gone`] or [`Error::NotLocal`] if the group is no longer
/// in `/etc/group`, and [`Error::Tool`] if `gpasswd` fails.
///
/// # Capabilities
///
/// `CAP_DAC_OVERRIDE` for `gpasswd` to write `/etc/group` and
/// `/etc/gshadow`.
pub fn add_member<O: Ownership, J: Journal>(
    system: &mut System<O, J>,
    user: &User,
    group: &LocalGroup,
) -> Result<bool, Error> {
    let _lock = system.lock()?;
    let now = current(group.info().name())?;
    if now.info().has_member(user.name()) {
        return Ok(false);
    }
    let change = Change::AddMember {
        user: user.name().clone(),
        group: now.info().name().clone(),
    };
    system.intent(&change)?;
    system.run(
        &Invocation::new(Tool::Gpasswd)
            .value("--add", user.name().as_str())
            .arg(now.info().name().as_str()),
    )?;
    system.applied(&change, &Facts::default())?;
    Ok(true)
}

/// Removes one account from one group, if the caller's `Ownership` claims
/// that membership. Returns `false` if the account was not a member.
///
/// # Errors
///
/// Returns [`Error::NotOwned`] if the caller's `Ownership` does not claim
/// the membership, and [`Error::Tool`] if `gpasswd` fails.
///
/// # Capabilities
///
/// `CAP_DAC_OVERRIDE` for `gpasswd` to write `/etc/group` and
/// `/etc/gshadow`.
pub fn remove_member<O: Ownership, J: Journal>(
    system: &mut System<O, J>,
    user: &User,
    group: &LocalGroup,
) -> Result<bool, Error> {
    let _lock = system.lock()?;
    let now = current(group.info().name())?;
    if !now.info().has_member(user.name()) {
        return Ok(false);
    }
    system.require_claim(&Item::Membership { user, group: &now })?;
    let change = Change::RemoveMember {
        user: user.name().clone(),
        group: now.info().name().clone(),
    };
    system.intent(&change)?;
    system.run(
        &Invocation::new(Tool::Gpasswd)
            .value("--delete", user.name().as_str())
            .arg(now.info().name().as_str()),
    )?;
    system.applied(&change, &Facts::default())?;
    Ok(true)
}

/// Looks a group up again and requires it to be in `/etc/group`.
pub(crate) fn current(name: &GroupName) -> Result<LocalGroup, Error> {
    match lookup::group(name)? {
        Some(Group::Local(group)) => Ok(group),
        Some(other) => Err(not_local(&other)),
        None => Err(Error::Gone(format!("group {name}"))),
    }
}

fn not_local(group: &Group) -> Error {
    let reason = match group.source() {
        Source::Vendor => Refusal::Vendor,
        Source::Other | Source::Local => Refusal::Remote,
    };
    Error::Refused {
        what: format!("group {}", group.info().name()),
        reason,
    }
}

/// Says whether any group has this ID, whatever its name.
pub(crate) fn gid_in_use(gid: Gid) -> Result<bool, Error> {
    match lookup::group_by_gid(gid) {
        Ok(found) => Ok(found.is_some()),
        // A group with a name this crate rejects still holds the ID.
        Err(LookupError::InvalidName { .. }) => Ok(true),
        Err(error) => Err(error.into()),
    }
}
