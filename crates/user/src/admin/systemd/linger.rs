//! Turning linger on and off.
//!
//! [`crate::systemd::linger`] reads the state without root, and
//! [`crate::systemd::set_own_linger`] sets it for the process's own account;
//! these set it for another account, which needs root.

use super::{bus, wait_manager_gone};
use crate::admin::{Error, System};
use crate::lookup::User;
use crate::ownership::{Change, Facts, Item, Journal, Ownership};

/// Turns linger on or off for an account, and records the change. Returns
/// `false` if it was already in that state.
///
/// Wraps the call [`crate::systemd::set_own_linger`] makes, for an account
/// other than the process's own.
///
/// Turning it off needs the caller's `Ownership` to claim the account.
///
/// # Errors
///
/// Returns [`Error::NotOwned`] when turning linger off for an account the
/// caller does not own, and [`Error::Systemd`] if logind refuses.
///
/// # Capabilities
///
/// None. Needs user ID 0: logind asks polkit, which checks the user ID.
/// Calls `org.freedesktop.login1.Manager.SetUserLinger` on the system bus.
pub fn set<O: Ownership, J: Journal>(system: &mut System<O, J>, user: &User, enable: bool) -> Result<bool, Error> {
    let _lock = system.lock()?;
    if !enable {
        system.require_claim(&Item::User(user))?;
    }
    if crate::systemd::linger(user)? == enable {
        return Ok(false);
    }
    let change = Change::SetLinger {
        user: user.name().clone(),
        enable,
    };
    system.intent(&change)?;
    crate::systemd::set_linger_of(user.uid().as_raw(), enable)?;
    system.applied(&change, &Facts::default())?;
    Ok(true)
}

/// Turns linger off and waits until the account's user manager has stopped
/// and logind has let the account go. Returns `false` if linger was already
/// off (it still waits, for a manager that was stopping).
///
/// [`set`] returns as soon as logind has the new setting; the manager stops
/// some time after, and until it has, its processes keep `usermod` and
/// `userdel` from changing the account. Forma's `DisableLinger` uses this.
///
/// An account with a login session keeps its manager, so the wait ends at
/// the system's unit timeout with an error. Service accounts have none.
///
/// # Errors
///
/// As [`set`], and [`Error::Systemd`] if the manager has not stopped
/// within the unit timeout.
///
/// # Capabilities
///
/// None, as [`set`].
pub fn disable_and_wait<O: Ownership, J: Journal>(system: &mut System<O, J>, user: &User) -> Result<bool, Error> {
    let changed = set(system, user, false)?;
    wait_manager_gone(&bus()?, user.uid().as_raw(), system.config().unit_timeout)?;
    Ok(changed)
}
