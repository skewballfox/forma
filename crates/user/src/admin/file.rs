//! Writing and removing managed files. Private to [`crate::admin`].
//!
//! A write goes to a temporary file in the same directory, which is
//! `fsync`ed and renamed into place; then the directory is `fsync`ed. A
//! crash leaves either the old file or the new one.

use std::io::Write as _;

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self as rfs, AtFlags, Mode, OFlags};
use rustix::io::Errno;

use super::{Error, System, rel};
use crate::fs::{self, OpenError};
use crate::ownership::{Change, Facts, Item, Journal, Ownership};
use crate::path::AbsPath;
use crate::perm::PermError;

/// Returns the first line of a file, if it is text.
pub(crate) fn header(bytes: &[u8]) -> Option<&str> {
    let line = bytes.split(|&byte| byte == b'\n').next()?;
    std::str::from_utf8(line).ok()
}

/// Reads a file without following symlinks. `None` if it does not exist.
pub(crate) fn read<O: Ownership, J: Journal>(system: &System<O, J>, path: &AbsPath) -> Result<Option<Vec<u8>>, Error> {
    let rel = rel(path)?;
    let fd = fs::open_file(system.root(), &rel).map_err(|error| PermError::open(path, error))?;
    fd.map(|fd| fs::read_all(fd).map_err(|source| Error::io(format!("read {path}"), source)))
        .transpose()
}

/// Writes a managed file. Returns `false` if it already had these contents.
///
/// An existing file is replaced only if the caller's `Ownership` claims it.
pub(crate) fn write<O: Ownership, J: Journal>(
    system: &mut System<O, J>,
    path: &AbsPath,
    contents: &[u8],
) -> Result<bool, Error> {
    let previous = read(system, path)?;
    if let Some(previous) = &previous {
        if previous == contents {
            return Ok(false);
        }
        system.require_claim(&Item::File {
            path,
            header: header(previous),
        })?;
    }

    let (dir, name) = open_parent(system, path)?;
    let temp = format!(".{}.tmp", name.to_string_lossy());
    let change = Change::WriteFile {
        path: path.clone(),
        previous,
    };
    system.intent(&change)?;

    let sys = |action: &str, source: Errno| Error::sys(format!("{action} {path}"), source);
    // A temporary file left by a crash is ours to replace.
    match rfs::unlinkat(&dir, temp.as_str(), AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(source) => return Err(sys("clear the temporary file for", source)),
    }
    let fd = rfs::openat(
        &dir,
        temp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )
    .map_err(|source| sys("create the temporary file for", source))?;
    // The umask may have removed bits; set the mode outright.
    rfs::fchmod(&fd, Mode::from_raw_mode(0o644)).map_err(|source| sys("set the mode of", source))?;
    let mut file = std::fs::File::from(fd);
    file.write_all(contents)
        .map_err(|source| Error::io(format!("write {path}"), source))?;
    rfs::fsync(&file).map_err(|source| sys("sync", source))?;
    rfs::renameat(&dir, temp.as_str(), &dir, name).map_err(|source| sys("rename into place", source))?;
    rfs::fsync(&dir).map_err(|source| sys("sync the directory of", source))?;

    system.applied(&change, &Facts::default())?;
    Ok(true)
}

/// Removes a managed file. Returns `false` if it did not exist.
pub(crate) fn remove<O: Ownership, J: Journal>(system: &mut System<O, J>, path: &AbsPath) -> Result<bool, Error> {
    let Some(contents) = read(system, path)? else {
        return Ok(false);
    };
    system.require_claim(&Item::File {
        path,
        header: header(&contents),
    })?;
    let (dir, name) = open_parent(system, path)?;
    let change = Change::RemoveFile {
        path: path.clone(),
        contents,
    };
    system.intent(&change)?;
    rfs::unlinkat(&dir, name, AtFlags::empty()).map_err(|source| Error::sys(format!("remove {path}"), source))?;
    rfs::fsync(&dir).map_err(|source| Error::sys(format!("sync the directory of {path}"), source))?;
    system.applied(&change, &Facts::default())?;
    Ok(true)
}

/// Opens the directory that holds `path`, and returns it with the file name.
pub(crate) fn open_parent<'p, O: Ownership, J: Journal>(
    system: &System<O, J>,
    path: &'p AbsPath,
) -> Result<(OwnedFd, &'p std::ffi::OsStr), Error> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(Error::Refused {
            what: path.to_string(),
            reason: super::Refusal::RootDirectory,
        });
    };
    let dir = fs::open_dir(system.root().as_fd(), parent.relative().as_ref())
        .map_err(|error| PermError::open(&parent, OpenError::Io(error)))?;
    Ok((dir, name))
}
