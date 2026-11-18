//! Unprivileged parts that depend on systemd. Feature `systemd`.
//!
//! [`crate::admin::systemd`] holds the parts that need root.

pub(crate) mod dbus;
pub mod modules;

use std::io;
use std::path::Path;

use thiserror::Error;
use zbus::blocking::Connection;

use crate::lookup::{LookupError, User};

/// Where logind records which accounts linger.
const LINGER_DIR: &str = "/var/lib/systemd/linger";

/// Says whether linger is on for the account.
///
/// Reads logind's state directory, `/var/lib/systemd/linger`, so it needs
/// no D-Bus connection.
///
/// # Errors
///
/// Returns [`LookupError::Read`] if the state cannot be read.
pub fn linger(user: &User) -> Result<bool, LookupError> {
    let path = Path::new(LINGER_DIR).join(user.name().as_str());
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(LookupError::Read { path, source }),
    }
}

/// Turns linger on or off for the account the process runs as. An account
/// may do this for itself without root: logind asks polkit, whose
/// `org.freedesktop.login1.set-self-linger` allows it. Does nothing if
/// linger is already in that state.
///
/// [`crate::admin::systemd::linger::set`] does the same for another
/// account, which needs root, and records the change.
///
/// # Errors
///
/// Returns [`SystemdError::Bus`] if the system bus cannot be reached or
/// logind refuses.
pub fn set_own_linger(enable: bool) -> Result<(), SystemdError> {
    set_linger_of(rustix::process::getuid().as_raw(), enable)
}

/// Asks logind to turn linger on or off for a user ID. polkit allows it
/// for the caller's own ID; for another, only for root.
pub(crate) fn set_linger_of(uid: u32, enable: bool) -> Result<(), SystemdError> {
    dbus::set_linger(&bus()?, uid, enable)
}

/// Connects to the system bus.
pub(crate) fn bus() -> Result<Connection, SystemdError> {
    Connection::system().map_err(|source| SystemdError::bus("connect to the system bus", source))
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
