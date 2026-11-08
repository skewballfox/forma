//! Writing and removing `modules-load.d` files, and loading the modules.
//!
//! [`crate::systemd::modules`] builds and renders the files without root.

use std::path::Path;

use super::{SystemdError, bus, dbus};
use crate::admin::{Error, System, file};
use crate::systemd::modules::{ModulesLoadFile, ModulesLoadFileName};
use crate::ownership::{Journal, Ownership};
use crate::path::AbsPath;

/// Where the crate writes `modules-load.d` files.
pub const MODULES_DIR: &str = "/etc/modules-load.d";

/// The unit that loads the modules listed in `modules-load.d`.
const MODULES_UNIT: &str = "systemd-modules-load.service";

fn modules_path(name: &ModulesLoadFileName) -> Result<AbsPath, Error> {
    AbsPath::new(Path::new(MODULES_DIR).join(name.file_name())).map_err(|_| Error::Gone(name.file_name()))
}

/// Writes a `modules-load.d` file, then restarts
/// `systemd-modules-load.service` so the modules load now as well as at
/// boot. Returns `false` if the file already had these contents; the
/// service is then not restarted.
///
/// # Errors
///
/// Returns [`Error::NotOwned`] if a file with that name exists and the
/// caller's `Ownership` does not claim it, and [`SystemdError::UnitFailed`] if the
/// service fails, which usually means a module could not be loaded.
///
/// # Capabilities
///
/// None if root owns `/etc/modules-load.d`. Restarting the unit needs user
/// ID 0 (polkit). The unit itself loads the modules with `CAP_SYS_MODULE`.
/// Calls `org.freedesktop.systemd1.Manager.RestartUnit` on the system bus.
pub fn write<O: Ownership, J: Journal>(system: &mut System<O, J>, modules: &ModulesLoadFile) -> Result<bool, Error> {
    let _lock = system.lock()?;
    let path = modules_path(modules.name())?;
    let contents = modules.render(&system.config().marker);
    if !file::write(system, &path, contents.as_bytes())? {
        return Ok(false);
    }
    let state = dbus::restart_and_wait(&bus()?, MODULES_UNIT, system.config().unit_timeout)?;
    if state != "active" {
        return Err(SystemdError::UnitFailed {
            unit: MODULES_UNIT.to_owned(),
            state,
        }
        .into());
    }
    Ok(true)
}

/// Removes a `modules-load.d` file. Returns `false` if it did not exist.
/// Modules already loaded stay loaded.
///
/// # Errors
///
/// Returns [`Error::NotOwned`] if the caller's `Ownership` does not claim
/// the file.
///
/// # Capabilities
///
/// None if root owns `/etc/modules-load.d`.
pub fn remove<O: Ownership, J: Journal>(system: &mut System<O, J>, name: &ModulesLoadFileName) -> Result<bool, Error> {
    let _lock = system.lock()?;
    let path = modules_path(name)?;
    file::remove(system, &path)
}
