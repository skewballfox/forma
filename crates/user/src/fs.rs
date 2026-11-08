//! Opening paths without following symlinks. Crate-private.
//!
//! Every path is opened beneath a directory handle with `openat2`,
//! `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`. A symlink anywhere in the
//! path fails with `ELOOP`, and a path that would leave the directory fails
//! with `EXDEV`.

use std::os::fd::AsRawFd;
use std::path::Path;

use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags, Stat};
use rustix::io::Errno;

use crate::path::RelPath;

/// How every path in this crate is resolved.
pub(crate) const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// The kinds of file the crate changes. Others, such as device nodes, are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Dir,
    File,
}

/// An open file or directory, with its status at the time it was opened.
pub(crate) struct Node {
    pub(crate) fd: OwnedFd,
    pub(crate) kind: Kind,
    pub(crate) stat: Stat,
}

/// Why a path could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenError {
    /// A system call failed. `ELOOP` means a symlink was in the path.
    Io(Errno),
    /// The path names something other than a file or directory.
    UnsupportedKind,
    /// The path changed between the two opens.
    Replaced,
}

impl From<Errno> for OpenError {
    fn from(errno: Errno) -> Self {
        Self::Io(errno)
    }
}

fn as_path(path: Option<&RelPath>) -> &Path {
    path.map_or(Path::new("."), RelPath::as_path)
}

/// Opens a directory beneath `base`. `None` opens `base` itself.
pub(crate) fn open_dir(base: BorrowedFd<'_>, path: Option<&RelPath>) -> Result<OwnedFd, Errno> {
    fs::openat2(
        base,
        as_path(path),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE,
    )
}

/// Opens a file or directory beneath `base` for reading its attributes and
/// changing its owner, mode or ACL. `None` opens `base` itself.
///
/// The path is first opened with `O_PATH`, which never runs a device
/// driver's open. Only after the kind is known is it opened for real:
/// a directory with `O_DIRECTORY`, a regular file through its
/// `/proc/self/fd` entry, which reopens the same inode.
pub(crate) fn open_node(base: BorrowedFd<'_>, path: Option<&RelPath>) -> Result<Node, OpenError> {
    let probe = fs::openat2(
        base,
        as_path(path),
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE,
    )?;
    let stat = fs::fstat(&probe)?;
    let (fd, kind) = match FileType::from_raw_mode(stat.st_mode) {
        FileType::Directory => (open_dir(base, path)?, Kind::Dir),
        FileType::RegularFile => {
            let proc_path = format!("/proc/self/fd/{}", probe.as_raw_fd());
            let fd = fs::open(proc_path, OFlags::RDONLY | OFlags::NOCTTY | OFlags::CLOEXEC, Mode::empty())?;
            (fd, Kind::File)
        }
        // `O_PATH | O_NOFOLLOW` opens a trailing symlink itself, rather than
        // failing as `RESOLVE_NO_SYMLINKS` does for the other parts.
        FileType::Symlink => return Err(OpenError::Io(Errno::LOOP)),
        _ => return Err(OpenError::UnsupportedKind),
    };
    let reopened = fs::fstat(&fd)?;
    if (reopened.st_dev, reopened.st_ino) != (stat.st_dev, stat.st_ino) {
        return Err(OpenError::Replaced);
    }
    Ok(Node { fd, kind, stat: reopened })
}

/// Opens a regular file beneath `base` for reading. Returns `None` if it
/// does not exist.
pub(crate) fn open_file(base: BorrowedFd<'_>, path: &RelPath) -> Result<Option<OwnedFd>, OpenError> {
    match open_node(base, Some(path)) {
        Ok(Node { fd, kind: Kind::File, .. }) => Ok(Some(fd)),
        Ok(Node { kind: Kind::Dir, .. }) => Err(OpenError::UnsupportedKind),
        Err(OpenError::Io(Errno::NOENT)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Reads a whole file through an open descriptor.
pub(crate) fn read_all(fd: impl AsFd) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut file = std::fs::File::from(fd.as_fd().try_clone_to_owned()?);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
