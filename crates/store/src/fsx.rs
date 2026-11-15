//! File access beneath a directory handle. Every open uses `openat2` with
//! `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS` and `RESOLVE_NO_MAGICLINKS`,
//! and `O_NOFOLLOW` for the last part.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, RenameFlags, ResolveFlags};
use rustix::io::Errno;

const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Opens a directory forma trusts by its path: the staging or store root,
/// or an account directory, whose ancestors only root can change.
pub(crate) fn open_root(path: &Path) -> Result<OwnedFd, Errno> {
    fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Opens the directory `name` beneath `base`.
pub(crate) fn open_dir(base: BorrowedFd<'_>, name: &str) -> Result<OwnedFd, Errno> {
    fs::openat2(
        base,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE,
    )
}

/// Opens the regular file `name` beneath `base` for reading. A FIFO or a
/// device is refused without blocking on it.
pub(crate) fn open_regular(base: BorrowedFd<'_>, name: &str) -> Result<File, Errno> {
    let fd = fs::openat2(
        base,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE,
    )?;
    if FileType::from_raw_mode(fs::fstat(&fd)?.st_mode) != FileType::RegularFile {
        return Err(Errno::INVAL);
    }
    Ok(File::from(fd))
}

/// Opens `name` beneath `base` for writing, creating it with exactly `mode`
/// if it is missing. `truncate` empties a file that exists.
pub(crate) fn open_write(base: BorrowedFd<'_>, name: &str, mode: u32, exclusive: bool) -> Result<File, Errno> {
    let mut flags = OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if exclusive {
        flags |= OFlags::EXCL;
    } else {
        flags |= OFlags::TRUNC;
    }
    let fd = fs::openat2(base, name, flags, Mode::from_raw_mode(mode), RESOLVE)?;
    if FileType::from_raw_mode(fs::fstat(&fd)?.st_mode) != FileType::RegularFile {
        return Err(Errno::INVAL);
    }
    // The umask may have taken bits away.
    fs::fchmod(&fd, Mode::from_raw_mode(mode))?;
    Ok(File::from(fd))
}

/// Opens `name` beneath `base` for locking, creating it with `mode` when
/// `create` is set.
pub(crate) fn open_lock(base: BorrowedFd<'_>, name: &str, mode: u32, create: bool) -> Result<OwnedFd, Errno> {
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    if create {
        flags |= OFlags::CREATE;
    }
    let fd = fs::openat2(base, name, flags, Mode::from_raw_mode(mode), RESOLVE)?;
    if FileType::from_raw_mode(fs::fstat(&fd)?.st_mode) != FileType::RegularFile {
        return Err(Errno::INVAL);
    }
    Ok(fd)
}

/// Makes the directory `name` beneath `base` and returns it with its mode.
///
/// It is not chmodded: in a set-group-ID directory the new directory
/// inherits the bit, and a chmod by an owner outside the group would clear
/// it, so files created later would get the creator's group. The caller
/// checks the returned mode instead.
pub(crate) fn make_dir(base: BorrowedFd<'_>, name: &str, mode: u32) -> Result<(OwnedFd, u32), Errno> {
    fs::mkdirat(base, name, Mode::from_raw_mode(mode))?;
    let fd = open_dir(base, name)?;
    let found = fs::fstat(&fd)?.st_mode & 0o7777;
    Ok((fd, found))
}

/// The kind of an entry, without following a link.
pub(crate) fn kind(base: BorrowedFd<'_>, name: &str) -> Result<FileType, Errno> {
    let stat = fs::statat(base, name, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(FileType::from_raw_mode(stat.st_mode))
}

/// The names in a directory, without `.` and `..`, sorted.
pub(crate) fn names(dir: BorrowedFd<'_>) -> Result<Vec<String>, Errno> {
    let mut names = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        // Names that are not UTF-8 are kept lossily: they are refused later as unexpected.
        names.push(String::from_utf8_lossy(name).into_owned());
    }
    names.sort_unstable();
    Ok(names)
}

/// Removes the directory `name` beneath `base` and the files in it. A
/// `dir:` layout holds no subdirectories; if one is there, the removal
/// stops with `ENOTEMPTY` and leaves it for an administrator.
pub(crate) fn remove_flat_dir(base: BorrowedFd<'_>, name: &str) -> Result<(), Errno> {
    let dir = match open_dir(base, name) {
        Ok(dir) => dir,
        Err(Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in names(dir.as_fd())? {
        if kind(dir.as_fd(), &entry)? != FileType::Directory {
            fs::unlinkat(&dir, entry.as_str(), AtFlags::empty())?;
        }
    }
    fs::fsync(&dir)?;
    fs::unlinkat(base, name, AtFlags::REMOVEDIR)
}

/// Copies a regular file and syncs the copy. Returns the bytes when `keep`
/// is set, so the caller can check what was copied rather than what is in
/// the source now.
pub(crate) fn copy(mut from: File, to: &mut File, keep: bool) -> Result<Option<Vec<u8>>, std::io::Error> {
    if keep {
        let mut bytes = Vec::new();
        from.read_to_end(&mut bytes)?;
        to.write_all(&bytes)?;
        to.sync_all()?;
        Ok(Some(bytes))
    } else {
        std::io::copy(&mut from, to)?;
        to.sync_all()?;
        Ok(None)
    }
}

/// Swaps two entries of one directory.
pub(crate) fn exchange(dir: BorrowedFd<'_>, a: &str, b: &str) -> Result<(), Errno> {
    fs::renameat_with(dir, a, dir, b, RenameFlags::EXCHANGE)
}

/// Renames an entry, failing if the new name exists.
pub(crate) fn rename_new(dir: BorrowedFd<'_>, from: &str, to: &str) -> Result<(), Errno> {
    fs::renameat_with(dir, from, dir, to, RenameFlags::NOREPLACE)
}
