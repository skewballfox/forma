//! Writing, removing and triggering udev rules.
//!
//! [`crate::udev`] builds and renders rules without root.

use std::io::Write as _;
use std::path::Path;

use rustix::fs::{self as rfs, Mode, OFlags, ResolveFlags};

use super::{Error, System, file};
use crate::fs;
use crate::lookup;
use crate::name::GroupName;
use crate::ownership::{Journal, Ownership};
use crate::path::{AbsPath, PathError, RelPath};
use crate::udev::{RulesFile, RulesFileName};

/// Where the crate writes rules files.
pub const RULES_DIR: &str = "/etc/udev/rules.d";

/// The `f_type` of sysfs.
const SYSFS_MAGIC: i128 = 0x6265_6572;

/// A device under `/sys`, such as `class/misc/uinput`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SysfsDevice(RelPath);

impl SysfsDevice {
    /// Names a device by its path relative to `/sys`.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] if the path is not a normalised relative path.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Result<Self, PathError> {
        RelPath::new(path).map(Self)
    }
}

fn rules_path(name: &RulesFileName) -> Result<AbsPath, Error> {
    AbsPath::new(Path::new(RULES_DIR).join(name.file_name())).map_err(|_| Error::Gone(name.file_name()))
}

/// Writes a rules file to `/etc/udev/rules.d`. Returns `false` if the file
/// already had these contents.
///
/// udevd reads changed rules before it handles the next event, so no
/// reload is needed. Use [`trigger`] to send that event.
///
/// # Errors
///
/// Returns [`Error::GroupMissing`] if a rule names a group that does not
/// exist, and [`Error::NotOwned`] if a file with that name exists and the
/// caller's `Ownership` does not claim it.
///
/// # Capabilities
///
/// None if root owns `/etc/udev/rules.d`. Writes one file there.
pub fn write<O: Ownership, J: Journal>(system: &mut System<O, J>, rules: &RulesFile) -> Result<bool, Error> {
    let _lock = system.lock()?;
    for group in rules.rules().iter().flat_map(crate::udev::Rule::groups) {
        if lookup::group(group)?.is_none() {
            return Err(Error::GroupMissing(group.clone()));
        }
    }
    let path = rules_path(rules.name())?;
    let contents = rules.render(&system.config().marker);
    file::write(system, &path, contents.as_bytes())
}

/// Removes a rules file. Returns `false` if it did not exist.
///
/// # Errors
///
/// Returns [`Error::NotOwned`] if the caller's `Ownership` does not claim
/// the file.
///
/// # Capabilities
///
/// None if root owns `/etc/udev/rules.d`.
pub fn remove<O: Ownership, J: Journal>(system: &mut System<O, J>, name: &RulesFileName) -> Result<bool, Error> {
    let _lock = system.lock()?;
    let path = rules_path(name)?;
    file::remove(system, &path)
}

/// Asks udevd to process a device again, by writing `change` to its
/// `uevent` file.
///
/// The path is resolved beneath `/sys`. Symlinks are allowed there, because
/// sysfs uses them for classes, but they cannot lead out of `/sys`.
///
/// # Errors
///
/// Returns [`Error::Sys`] if `/sys` is not sysfs, or the device cannot be
/// reached.
///
/// # Capabilities
///
/// None. Needs user ID 0: `uevent` files are writable only by root.
pub fn trigger<O: Ownership, J: Journal>(system: &System<O, J>, device: &SysfsDevice) -> Result<(), Error> {
    let sys_rel = RelPath::new("sys").map_err(|_| Error::Gone("/sys".to_owned()))?;
    let sys = fs::open_dir(system.root(), Some(&sys_rel)).map_err(|source| Error::sys("open /sys", source))?;
    let statfs = rfs::fstatfs(&sys).map_err(|source| Error::sys("read the file system of /sys", source))?;
    if i128::from(statfs.f_type) != SYSFS_MAGIC {
        return Err(Error::sys("use /sys, which is not sysfs", rustix::io::Errno::NODEV));
    }
    let uevent = device.0.as_path().join("uevent");
    let fd = rfs::openat2(
        &sys,
        &uevent,
        OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(|source| Error::sys(format!("open /sys/{}", uevent.display()), source))?;
    std::fs::File::from(fd)
        .write_all(b"change")
        .map_err(|source| Error::io(format!("trigger /sys/{}", device.0), source))
}

/// Returns the managed rules files that assign `group`.
pub(crate) fn files_naming<O: Ownership, J: Journal>(
    system: &System<O, J>,
    group: &GroupName,
) -> Result<Vec<AbsPath>, Error> {
    let entries = match std::fs::read_dir(RULES_DIR) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(Error::io(format!("list {RULES_DIR}"), source)),
    };
    let header = system.config().marker.header_line();
    let needle = format!("GROUP=\"{group}\"");
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| Error::io(format!("list {RULES_DIR}"), source))?;
        let Ok(path) = AbsPath::new(entry.path()) else { continue };
        let Some(bytes) = file::read(system, &path)? else { continue };
        let text = String::from_utf8_lossy(&bytes);
        if file::header(&bytes) == Some(header.as_str()) && text.contains(&needle) {
            found.push(path);
        }
    }
    Ok(found)
}
