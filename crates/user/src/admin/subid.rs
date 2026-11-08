//! Assigning and removing sub-ID ranges.
//!
//! [`crate::subid`] finds free ranges without root. Ranges are written with
//! `usermod --add-subuids` and `--add-subgids`, which take shadow-utils'
//! lock on the files.

use super::tool::{Invocation, Tool};
use super::{Error, System, read_config};
use crate::defs::{self, SubIdBackend, SubIdEntry, SubIdLimits};
use crate::id::{IdRange, SubIdCount, SubIdRange};
use crate::lookup::User;
use crate::ownership::{Change, Facts, Item, Journal, Ownership};
use crate::subid;

const SUBUID: &str = "/etc/subuid";
const SUBGID: &str = "/etc/subgid";
const NSSWITCH: &str = "/etc/nsswitch.conf";

/// The current contents of `/etc/subuid` and `/etc/subgid`.
struct Files {
    uids: Vec<SubIdEntry>,
    gids: Vec<SubIdEntry>,
}

fn read_files() -> Result<Files, Error> {
    let parse = |path: &'static str| -> Result<Vec<SubIdEntry>, Error> {
        let text = read_config(path)?.unwrap_or_default();
        defs::parse_subids(path, &text).map_err(Error::Defs)
    };
    Ok(Files {
        uids: parse(SUBUID)?,
        gids: parse(SUBGID)?,
    })
}

fn check_backend() -> Result<(), Error> {
    match defs::subid_backend(&read_config(NSSWITCH)?.unwrap_or_default()) {
        SubIdBackend::Files => Ok(()),
        SubIdBackend::Other(source) => Err(Error::SubIdBackend(source)),
    }
}

/// Finds a free range and assigns it to the account, in both `/etc/subuid`
/// and `/etc/subgid`. This is what `useradd` does for a new person's
/// account, done here for a system account.
///
/// The range is the lowest one free in both files, inside the `SUB_UID_*`
/// and `SUB_GID_*` limits of `login.defs`, and clear of the ID ranges for
/// people.
///
/// # Errors
///
/// Returns [`Error::HasSubIds`] if the account already has a range,
/// [`Error::SubIdBackend`] if NSS does not read the files, and
/// [`Error::SubIds`] if no range is free.
///
/// # Capabilities
///
/// `CAP_DAC_OVERRIDE` for `usermod` to write `/etc/subuid` and
/// `/etc/subgid`.
pub fn allocate<O: Ownership, J: Journal>(
    system: &mut System<O, J>,
    user: &User,
    count: SubIdCount,
) -> Result<SubIdRange, Error> {
    let _lock = system.lock()?;
    check_backend()?;
    let files = read_files()?;
    let (uids, gids) = (subid::ranges_of(&files.uids, user), subid::ranges_of(&files.gids, user));
    if !uids.is_empty() || !gids.is_empty() {
        return Err(Error::HasSubIds {
            user: user.name().clone(),
            uids,
            gids,
        });
    }
    let defs = system.login_defs();
    let limits = shared_limits(defs.sub_uid, defs.sub_gid)?;
    let taken: Vec<SubIdRange> = files.uids.iter().chain(&files.gids).map(|entry| entry.range).collect();
    let range = subid::find_free_range(&taken, &[defs.uid, defs.gid], limits, count)?;
    add_unlocked(system, user, range)?;
    Ok(range)
}

/// Assigns a given range to the account, in both `/etc/subuid` and
/// `/etc/subgid`.
///
/// # Errors
///
/// Returns [`Error::SubIdOverlap`] if the range overlaps another owner's,
/// and [`Error::SubIdBackend`] if NSS does not read the files.
///
/// # Capabilities
///
/// `CAP_DAC_OVERRIDE` for `usermod` to write `/etc/subuid` and
/// `/etc/subgid`.
pub fn add<O: Ownership, J: Journal>(system: &mut System<O, J>, user: &User, range: SubIdRange) -> Result<(), Error> {
    let _lock = system.lock()?;
    check_backend()?;
    check_free(&read_files()?, user, range)?;
    add_unlocked(system, user, range)
}

fn check_free(files: &Files, user: &User, range: SubIdRange) -> Result<(), Error> {
    let conflicts = subid::conflicts(&files.uids, range, user)
        .into_iter()
        .chain(subid::conflicts(&files.gids, range, user));
    match conflicts.into_iter().next() {
        Some(entry) => Err(Error::SubIdOverlap {
            range,
            owner: entry.owner.clone(),
        }),
        None => Ok(()),
    }
}

fn add_unlocked<O: Ownership, J: Journal>(system: &mut System<O, J>, user: &User, range: SubIdRange) -> Result<(), Error> {
    let change = Change::AddSubIds {
        user: user.name().clone(),
        range,
    };
    system.intent(&change)?;
    let text = range.to_string();
    system.run(
        &Invocation::new(Tool::Usermod)
            .value("--add-subuids", text.clone())
            .value("--add-subgids", text.clone())
            .arg(user.name().as_str()),
    )?;

    // Another program may have added an overlapping range since the files
    // were read. If so, take ours back out.
    if let Err(error) = check_free(&read_files()?, user, range) {
        system.run(
            &Invocation::new(Tool::Usermod)
                .value("--del-subuids", text.clone())
                .value("--del-subgids", text)
                .arg(user.name().as_str()),
        )?;
        return Err(error);
    }
    system.applied(&change, &Facts::default())
}

/// Removes every sub-ID range of the account, from both files. Returns the
/// ranges removed from `/etc/subuid` and from `/etc/subgid`.
///
/// # Errors
///
/// Returns [`Error::NotOwned`] if the caller's `Ownership` does not claim a
/// range, and [`Error::SubIdBackend`] if NSS does not read the files.
///
/// # Capabilities
///
/// `CAP_DAC_OVERRIDE` for `usermod` to write `/etc/subuid` and
/// `/etc/subgid`.
pub fn remove<O: Ownership, J: Journal>(
    system: &mut System<O, J>,
    user: &User,
) -> Result<(Vec<SubIdRange>, Vec<SubIdRange>), Error> {
    let _lock = system.lock()?;
    check_backend()?;
    let files = read_files()?;
    let (uids, gids) = (subid::ranges_of(&files.uids, user), subid::ranges_of(&files.gids, user));
    if uids.is_empty() && gids.is_empty() {
        return Ok((uids, gids));
    }
    for &range in uids.iter().chain(&gids) {
        system.require_claim(&Item::SubIds { user, range })?;
    }
    let change = Change::RemoveSubIds {
        user: user.name().clone(),
        uids: uids.clone(),
        gids: gids.clone(),
    };
    system.intent(&change)?;
    let mut invocation = Invocation::new(Tool::Usermod);
    for range in &uids {
        invocation = invocation.value("--del-subuids", range.to_string());
    }
    for range in &gids {
        invocation = invocation.value("--del-subgids", range.to_string());
    }
    system.run(&invocation.arg(user.name().as_str()))?;
    system.applied(&change, &Facts::default())?;
    Ok((uids, gids))
}

/// Returns the limits that both the user and group sub-ID settings allow.
fn shared_limits(uid: SubIdLimits, gid: SubIdLimits) -> Result<SubIdLimits, Error> {
    let first = uid.range.first().max(gid.range.first());
    let last = uid.range.last().min(gid.range.last());
    let range = IdRange::new(first, last).map_err(|error| Error::Defs(defs::DefsError::Range(error)))?;
    Ok(SubIdLimits {
        range,
        count: uid.count.max(gid.count),
    })
}
