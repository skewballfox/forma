//! Privileged parts that depend on systemd. Feature `systemd`.
//!
//! [`crate::systemd`] holds the parts that need no root, and the D-Bus
//! calls these wrap.

pub mod linger;
pub mod modules;

use std::time::Duration;

use zbus::blocking::Connection;

pub use crate::systemd::SystemdError;
use crate::lookup::User;
use crate::systemd::{bus, dbus};

/// Returns the IDs of an account's login sessions, leaving out the sessions
/// logind makes for user managers.
pub(crate) fn login_sessions(user: &User) -> Result<Vec<String>, SystemdError> {
    dbus::login_sessions(&bus()?, user.uid().as_raw())
}

/// Turns linger off, ends the account's sessions, and waits for its user
/// manager, runtime directory and slice to stop, and for logind to forget the
/// account. logind stops the runtime directory and slice after the manager and
/// drops its record last, and an account that reuses the ID must not start
/// while any of that is still going on.
pub(crate) fn stop_user_manager(user: &User, timeout: Duration) -> Result<(), super::Error> {
    let bus = bus()?;
    let uid = user.uid().as_raw();
    if crate::systemd::linger(user)? {
        dbus::set_linger(&bus, uid, false)?;
    }
    dbus::terminate_user(&bus, uid)?;
    wait_manager_gone(&bus, uid, timeout)
}

/// Waits for an account's user manager, runtime directory and slice to
/// stop, in the order logind stops them, and then for logind to forget the
/// account. Returns at once for an account with none of them running.
fn wait_manager_gone(bus: &Connection, uid: u32, timeout: Duration) -> Result<(), super::Error> {
    for unit in [
        format!("user@{uid}.service"),
        format!("user-runtime-dir@{uid}.service"),
        format!("user-{uid}.slice"),
    ] {
        dbus::wait_stopped(bus, &unit, timeout)?;
    }
    dbus::wait_user_gone(bus, uid, timeout)?;
    Ok(())
}
