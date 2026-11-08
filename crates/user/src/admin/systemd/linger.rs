//! Turning linger on and off.
//!
//! [`crate::systemd::linger`] reads the state without root.

use super::{bus, dbus};
use crate::admin::{Error, System};
use crate::lookup::User;
use crate::ownership::{Change, Facts, Item, Journal, Ownership};

/// Turns linger on or off for an account. Returns `false` if it was
/// already in that state.
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
    dbus::set_linger(&bus()?, user.uid().as_raw(), enable)?;
    system.applied(&change, &Facts::default())?;
    Ok(true)
}
