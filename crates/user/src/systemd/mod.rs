//! Unprivileged parts that depend on systemd. Feature `systemd`.
//!
//! [`crate::admin::systemd`] holds the parts that need root.

pub mod modules;

use std::io;
use std::path::Path;

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
