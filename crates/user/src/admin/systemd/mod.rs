//! Privileged parts that depend on systemd. Feature `systemd`.
//!
//! [`crate::systemd`] holds the parts that need no root.

mod dbus;
pub mod linger;
pub mod modules;

use std::time::Duration;

use thiserror::Error;
use zbus::blocking::Connection;

use crate::lookup::User;

/// Connects to the system bus.
fn bus() -> Result<Connection, SystemdError> {
    Connection::system().map_err(|source| SystemdError::bus("connect to the system bus", source))
}

/// Returns the IDs of an account's login sessions, leaving out the sessions
/// logind makes for user managers.
pub(crate) fn login_sessions(user: &User) -> Result<Vec<String>, SystemdError> {
    dbus::login_sessions(&bus()?, user.uid().as_raw())
}

/// Turns linger off, ends the account's sessions, and waits for its user
/// manager to stop.
pub(crate) fn stop_user_manager(user: &User, timeout: Duration) -> Result<(), super::Error> {
    let bus = bus()?;
    let uid = user.uid().as_raw();
    if crate::systemd::linger(user)? {
        dbus::set_linger(&bus, uid, false)?;
    }
    dbus::terminate_user(&bus, uid)?;
    dbus::wait_stopped(&bus, &format!("user@{uid}.service"), timeout)?;
    Ok(())
}

/// A call to logind or systemd failed.
#[derive(Debug, Error)]
pub enum SystemdError {
    /// A D-Bus call failed.
    #[error("cannot {action}")]
    Bus {
        /// What was being done.
        action: String,
        /// The error.
        source: Box<zbus::Error>,
    },
    /// Waiting for a unit took too long.
    #[error("timed out waiting for {0}")]
    Timeout(String),
    /// A unit did not end up active.
    #[error("unit {unit} is {state} after restarting")]
    UnitFailed {
        /// The unit.
        unit: String,
        /// Its state.
        state: String,
    },
}

impl SystemdError {
    fn bus(action: impl Into<String>, source: zbus::Error) -> Self {
        Self::Bus {
            action: action.into(),
            source: Box::new(source),
        }
    }
}
