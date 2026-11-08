//! File modes and POSIX ACLs.
//!
//! The model, the kernel encoding and [`can_traverse`] are pure. The
//! functions that touch files work only on files the process owns, so they
//! need no root. [`crate::admin::perm`] does the same for any file.
//!
//! ACLs are read and written as the `system.posix_acl_access` extended
//! attribute, on an open file descriptor. The format is a version number
//! followed by fixed-size entries; the kernel checks it on write.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use cap_std::fs::Dir;
use rustix::fd::AsFd;
use rustix::fs::{self as rfs, Mode, Stat, XattrFlags};
use rustix::io::Errno;
use thiserror::Error;

use crate::fs::{self, Kind, Node, OpenError};
use crate::id::{Gid, Uid};
use crate::path::RelPath;

const ACL_XATTR: &str = "system.posix_acl_access";
const ACL_VERSION: u32 = 2;
const TAG_USER_OBJ: u16 = 0x01;
const TAG_USER: u16 = 0x02;
const TAG_GROUP_OBJ: u16 = 0x04;
const TAG_GROUP: u16 = 0x08;
const TAG_MASK: u16 = 0x10;
const TAG_OTHER: u16 = 0x20;
const UNDEFINED_ID: u32 = u32::MAX;

/// Read, write and execute permission bits for one ACL entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Perms(u8);

impl Perms {
    /// No permission.
    pub const NONE: Self = Self(0);
    /// Execute, or traverse for a directory.
    pub const EXECUTE: Self = Self(1);
    /// Write.
    pub const WRITE: Self = Self(2);
    /// Read.
    pub const READ: Self = Self(4);

    /// Builds permissions from the low three bits (`rwx` = `0o7`).
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits > 0o7 {
            return None;
        }
        Some(Self(bits))
    }

    /// Returns the bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Says whether every bit in `other` is set here.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the bits set in either.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the bits set in both.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    fn from_mode_bits(bits: u32) -> Self {
        // Masked to three bits, so the cast cannot truncate.
        Self((bits & 0o7) as u8)
    }
}

impl fmt::Display for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bit = |flag: Self, ch| if self.contains(flag) { ch } else { '-' };
        write!(f, "{}{}{}", bit(Self::READ, 'r'), bit(Self::WRITE, 'w'), bit(Self::EXECUTE, 'x'))
    }
}

/// Who a named ACL entry is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Qualifier {
    /// A named user.
    User(Uid),
    /// A named group.
    Group(Gid),
}

/// A named ACL entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AclEntry {
    /// Who the entry is for.
    pub qualifier: Qualifier,
    /// What it grants, before the mask applies.
    pub perms: Perms,
}

impl fmt::Display for AclEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.qualifier {
            Qualifier::User(uid) => write!(f, "u:{uid}:{}", self.perms),
            Qualifier::Group(gid) => write!(f, "g:{gid}:{}", self.perms),
        }
    }
}

/// An access ACL: the owner, owning group and other entries, the mask, and
/// any named entries.
///
/// A file without an ACL has a minimal one, built from its mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    owner: Perms,
    owning_group: Perms,
    other: Perms,
    mask: Option<Perms>,
    users: BTreeMap<Uid, Perms>,
    groups: BTreeMap<Gid, Perms>,
}

impl Acl {
    /// Builds the minimal ACL that a mode stands for.
    #[must_use]
    pub fn from_mode(mode: u32) -> Self {
        Self {
            owner: Perms::from_mode_bits(mode >> 6),
            owning_group: Perms::from_mode_bits(mode >> 3),
            other: Perms::from_mode_bits(mode),
            mask: None,
            users: BTreeMap::new(),
            groups: BTreeMap::new(),
        }
    }

    /// Returns the owner's permissions.
    #[must_use]
    pub fn owner(&self) -> Perms {
        self.owner
    }

    /// Returns the owning group's permissions, before the mask applies.
    #[must_use]
    pub fn owning_group(&self) -> Perms {
        self.owning_group
    }

    /// Returns the permissions for everyone else.
    #[must_use]
    pub fn other(&self) -> Perms {
        self.other
    }

    /// Returns the mask, which limits the owning group and named entries.
    #[must_use]
    pub fn mask(&self) -> Option<Perms> {
        self.mask
    }

    /// Returns the permissions of a named entry, before the mask applies.
    #[must_use]
    pub fn entry(&self, qualifier: Qualifier) -> Option<Perms> {
        match qualifier {
            Qualifier::User(uid) => self.users.get(&uid).copied(),
            Qualifier::Group(gid) => self.groups.get(&gid).copied(),
        }
    }

    /// Returns every named entry: users first, then groups, each by ID.
    pub fn entries(&self) -> impl Iterator<Item = AclEntry> + '_ {
        let users = self.users.iter().map(|(&uid, &perms)| AclEntry {
            qualifier: Qualifier::User(uid),
            perms,
        });
        let groups = self.groups.iter().map(|(&gid, &perms)| AclEntry {
            qualifier: Qualifier::Group(gid),
            perms,
        });
        users.chain(groups)
    }

    /// Says whether the ACL is just a mode: no named entries and no mask.
    #[must_use]
    pub fn is_minimal(&self) -> bool {
        self.mask.is_none() && self.users.is_empty() && self.groups.is_empty()
    }

    /// Returns the nine permission bits the file's mode shows. With a mask,
    /// the group bits show the mask.
    #[must_use]
    pub fn mode_bits(&self) -> u32 {
        let group = self.mask.unwrap_or(self.owning_group);
        u32::from(self.owner.bits()) << 6 | u32::from(group.bits()) << 3 | u32::from(self.other.bits())
    }

    /// Returns a copy with `entry` added, or replacing the entry for the
    /// same user or group.
    ///
    /// No other entry's effective permissions change. The old mask is first
    /// applied to the owning group and named entries, then a new mask is
    /// computed that covers them and the new entry.
    #[must_use]
    pub fn with_entry(&self, entry: AclEntry) -> Self {
        let mut acl = self.with_mask_applied();
        match entry.qualifier {
            Qualifier::User(uid) => acl.users.insert(uid, entry.perms),
            Qualifier::Group(gid) => acl.groups.insert(gid, entry.perms),
        };
        acl.recompute_mask();
        acl
    }

    /// Returns a copy without the named entry for `qualifier`.
    ///
    /// No other entry's effective permissions change.
    #[must_use]
    pub fn without_entry(&self, qualifier: Qualifier) -> Self {
        let mut acl = self.with_mask_applied();
        match qualifier {
            Qualifier::User(uid) => acl.users.remove(&uid),
            Qualifier::Group(gid) => acl.groups.remove(&gid),
        };
        acl.recompute_mask();
        acl
    }

    fn with_mask_applied(&self) -> Self {
        let mut acl = self.clone();
        if let Some(mask) = acl.mask {
            acl.owning_group = acl.owning_group.intersection(mask);
            acl.users.values_mut().for_each(|perms| *perms = perms.intersection(mask));
            acl.groups.values_mut().for_each(|perms| *perms = perms.intersection(mask));
        }
        acl
    }

    fn recompute_mask(&mut self) {
        self.mask = (!self.users.is_empty() || !self.groups.is_empty()).then(|| {
            self.users
                .values()
                .chain(self.groups.values())
                .fold(self.owning_group, |mask, &perms| mask.union(perms))
        });
    }

    /// Encodes the ACL in the kernel's `system.posix_acl_access` format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let count = 3 + usize::from(self.mask.is_some()) + self.users.len() + self.groups.len();
        let mut out = Vec::with_capacity(4 + 8 * count);
        out.extend_from_slice(&ACL_VERSION.to_le_bytes());
        let mut push = |tag: u16, perms: Perms, id: u32| {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&u16::from(perms.bits()).to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
        };
        push(TAG_USER_OBJ, self.owner, UNDEFINED_ID);
        for (uid, &perms) in &self.users {
            push(TAG_USER, perms, uid.as_raw());
        }
        push(TAG_GROUP_OBJ, self.owning_group, UNDEFINED_ID);
        for (gid, &perms) in &self.groups {
            push(TAG_GROUP, perms, gid.as_raw());
        }
        if let Some(mask) = self.mask {
            push(TAG_MASK, mask, UNDEFINED_ID);
        }
        push(TAG_OTHER, self.other, UNDEFINED_ID);
        out
    }

    /// Decodes the kernel's `system.posix_acl_access` format.
    ///
    /// # Errors
    ///
    /// Returns an [`AclError`] if the version, length or entries are not
    /// valid.
    pub fn decode(bytes: &[u8]) -> Result<Self, AclError> {
        let (version, body) = bytes.split_first_chunk::<4>().ok_or(AclError::Length(bytes.len()))?;
        if u32::from_le_bytes(*version) != ACL_VERSION {
            return Err(AclError::Version(u32::from_le_bytes(*version)));
        }
        if body.len() % 8 != 0 {
            return Err(AclError::Length(bytes.len()));
        }

        let (mut owner, mut owning_group, mut other, mut mask) = (None, None, None, None);
        let (mut users, mut groups) = (BTreeMap::new(), BTreeMap::new());
        for &[t0, t1, p0, p1, i0, i1, i2, i3] in body.as_chunks::<8>().0 {
            let tag = u16::from_le_bytes([t0, t1]);
            let raw_perms = u16::from_le_bytes([p0, p1]);
            let id = u32::from_le_bytes([i0, i1, i2, i3]);
            let perms = u8::try_from(raw_perms)
                .ok()
                .and_then(Perms::from_bits)
                .ok_or(AclError::Perms(raw_perms))?;
            let once = |slot: &mut Option<Perms>| match slot.replace(perms) {
                None => Ok(()),
                Some(_) => Err(AclError::Duplicate(tag)),
            };
            match tag {
                TAG_USER_OBJ => once(&mut owner)?,
                TAG_GROUP_OBJ => once(&mut owning_group)?,
                TAG_OTHER => once(&mut other)?,
                TAG_MASK => once(&mut mask)?,
                TAG_USER if users.insert(Uid::from_raw(id), perms).is_some() => return Err(AclError::Duplicate(tag)),
                TAG_GROUP if groups.insert(Gid::from_raw(id), perms).is_some() => return Err(AclError::Duplicate(tag)),
                TAG_USER | TAG_GROUP => {}
                tag => return Err(AclError::Tag(tag)),
            }
        }

        let (Some(owner), Some(owning_group), Some(other)) = (owner, owning_group, other) else {
            return Err(AclError::Missing);
        };
        if mask.is_none() && !(users.is_empty() && groups.is_empty()) {
            return Err(AclError::MissingMask);
        }
        Ok(Self {
            owner,
            owning_group,
            other,
            mask,
            users,
            groups,
        })
    }
}

/// What kind of file a [`FileStat`] describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// A directory.
    Directory,
    /// A regular file.
    File,
}

/// The owner, group and mode of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    /// The owner.
    pub owner: Uid,
    /// The owning group.
    pub group: Gid,
    /// Permission bits, including setuid, setgid and sticky (`0o7777`).
    pub mode: u32,
    /// The kind of file.
    pub kind: FileKind,
}

impl FileStat {
    pub(crate) fn from_node(node: &Node) -> Self {
        Self {
            owner: Uid::from_raw(node.stat.st_uid),
            group: Gid::from_raw(node.stat.st_gid),
            mode: node.stat.st_mode & 0o7777,
            kind: match node.kind {
                Kind::Dir => FileKind::Directory,
                Kind::File => FileKind::File,
            },
        }
    }
}

/// Says whether an account can pass through a directory.
///
/// Follows the kernel's ACL check: the owner entry, then a named user entry,
/// then every group entry that matches (if one matches but none grants
/// `x`, access is denied), then other. The mask limits everything except
/// the owner and other entries. Root can always pass through.
///
/// `gids` must hold the account's primary group and every supplementary
/// group.
#[must_use]
pub fn can_traverse(stat: &FileStat, acl: &Acl, uid: Uid, gids: &[Gid]) -> bool {
    if uid == Uid::ROOT {
        return true;
    }
    if uid == stat.owner {
        return acl.owner.contains(Perms::EXECUTE);
    }
    let effective = |perms: Perms| acl.mask.map_or(perms, |mask| perms.intersection(mask));
    if let Some(&perms) = acl.users.get(&uid) {
        return effective(perms).contains(Perms::EXECUTE);
    }
    let owning = gids.contains(&stat.group).then_some(acl.owning_group);
    let named = acl
        .groups
        .iter()
        .filter(|(gid, _)| gids.contains(gid))
        .map(|(_, &perms)| perms);
    let mut matched = owning.into_iter().chain(named).peekable();
    if matched.peek().is_some() {
        return matched.any(|perms| effective(perms).contains(Perms::EXECUTE));
    }
    acl.other.contains(Perms::EXECUTE)
}

/// A mode the crate may set: permission bits, setgid and sticky.
///
/// It never has the setuid bit, and never gives others write access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileMode(u32);

impl FileMode {
    /// Checks a mode, such as `0o2750`.
    ///
    /// # Errors
    ///
    /// Returns [`PermError::Mode`] if the mode has bits outside `0o3777`
    /// or the write bit for others.
    pub const fn new(mode: u32) -> Result<Self, PermError> {
        if mode & !0o3777 != 0 || mode & 0o002 != 0 {
            return Err(PermError::Mode(mode));
        }
        Ok(Self(mode))
    }

    /// Returns the mode bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl fmt::Display for FileMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04o}", self.0)
    }
}

/// Reads a file's owner, mode and ACL.
///
/// # Errors
///
/// Returns a [`PermError`] if the path holds a symlink, leaves `dir`, names
/// something other than a file or directory, or cannot be read.
pub fn read(dir: &Dir, path: &RelPath) -> Result<(FileStat, Acl), PermError> {
    let node = fs::open_node(dir.as_fd(), Some(path)).map_err(|error| PermError::open(path, error))?;
    let acl = read_acl(&node).map_err(|source| PermError::io(path, source))?;
    Ok((FileStat::from_node(&node), acl))
}

/// Sets the ACL of a file the process owns.
///
/// # Errors
///
/// Returns [`PermError::NotOwner`] if the process does not own the file, and
/// the errors of [`read`] for the path.
pub fn set_owned_acl(dir: &Dir, path: &RelPath, acl: &Acl) -> Result<(), PermError> {
    let node = open_owned(dir, path)?;
    write_acl(&node, acl).map_err(|source| PermError::io(path, source))
}

/// Sets the mode of a file the process owns.
///
/// # Errors
///
/// Returns [`PermError::NotOwner`] if the process does not own the file, and
/// the errors of [`read`] for the path.
pub fn set_owned_mode(dir: &Dir, path: &RelPath, mode: FileMode) -> Result<(), PermError> {
    let node = open_owned(dir, path)?;
    write_mode(&node, mode).map_err(|source| PermError::io(path, source))
}

fn open_owned(dir: &Dir, path: &RelPath) -> Result<Node, PermError> {
    let node = fs::open_node(dir.as_fd(), Some(path)).map_err(|error| PermError::open(path, error))?;
    let euid = rustix::process::geteuid().as_raw();
    if node.stat.st_uid != euid {
        return Err(PermError::NotOwner {
            path: path.as_path().to_path_buf(),
            owner: Uid::from_raw(node.stat.st_uid),
        });
    }
    Ok(node)
}

/// Reads the ACL of an open file. A file without one gets its mode's ACL.
pub(crate) fn read_acl(node: &Node) -> Result<Acl, Errno> {
    let mut buf = vec![0_u8; 256];
    loop {
        match rfs::fgetxattr(&node.fd, ACL_XATTR, &mut buf[..]) {
            Ok(len) => return Acl::decode(&buf[..len]).map_err(|_| Errno::INVAL),
            Err(Errno::RANGE) if buf.len() < 1 << 20 => buf.resize(buf.len() * 4, 0),
            Err(Errno::NODATA | Errno::OPNOTSUPP) => return Ok(Acl::from_mode(node.stat.st_mode)),
            Err(errno) => return Err(errno),
        }
    }
}

/// Writes the ACL of an open file. A minimal ACL is written as a mode.
pub(crate) fn write_acl(node: &Node, acl: &Acl) -> Result<(), Errno> {
    if acl.is_minimal() {
        match rfs::fremovexattr(&node.fd, ACL_XATTR) {
            Ok(()) | Err(Errno::NODATA | Errno::OPNOTSUPP) => {}
            Err(errno) => return Err(errno),
        }
        return rfs::fchmod(&node.fd, Mode::from_raw_mode(special_bits(&node.stat) | acl.mode_bits()));
    }
    rfs::fsetxattr(&node.fd, ACL_XATTR, &acl.encode(), XattrFlags::empty())
}

/// Sets the mode of an open file.
pub(crate) fn write_mode(node: &Node, mode: FileMode) -> Result<(), Errno> {
    rfs::fchmod(&node.fd, Mode::from_raw_mode(mode.bits()))
}

fn special_bits(stat: &Stat) -> u32 {
    stat.st_mode & 0o7000
}

/// An ACL in the kernel format could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AclError {
    /// The data is not a version number followed by 8-byte entries.
    #[error("ACL data has {0} bytes, which is not a valid length")]
    Length(usize),
    /// The version is not 2.
    #[error("ACL version {0} is not supported")]
    Version(u32),
    /// An entry has an unknown tag.
    #[error("ACL entry has unknown tag {0:#x}")]
    Tag(u16),
    /// An entry has bits outside `rwx`.
    #[error("ACL entry has permission bits {0:#o}")]
    Perms(u16),
    /// An entry appears twice.
    #[error("ACL has a repeated entry with tag {0:#x}")]
    Duplicate(u16),
    /// The owner, owning group or other entry is missing.
    #[error("ACL lacks an owner, owning group or other entry")]
    Missing,
    /// Named entries exist but the mask is missing.
    #[error("ACL has named entries but no mask")]
    MissingMask,
}

/// A permission operation failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PermError {
    /// The mode has bits the crate never sets.
    #[error("mode {0:#o} is not allowed: only 0o3777 without write for others")]
    Mode(u32),
    /// A symlink is in the path.
    #[error("path {} goes through a symlink", .0.display())]
    Symlink(PathBuf),
    /// The path leaves the directory it is relative to.
    #[error("path {} leaves its base directory", .0.display())]
    Escapes(PathBuf),
    /// The path names something other than a file or directory.
    #[error("path {} is not a regular file or directory", .0.display())]
    UnsupportedKind(PathBuf),
    /// The path changed while it was being opened.
    #[error("path {} changed while it was being opened", .0.display())]
    Replaced(PathBuf),
    /// The process does not own the file.
    #[error("{} is owned by user ID {owner}, not by this process", path.display())]
    NotOwner {
        /// The file.
        path: PathBuf,
        /// Its owner.
        owner: Uid,
    },
    /// A system call failed.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The error.
        source: Errno,
    },
}

impl PermError {
    pub(crate) fn open(path: impl AsRef<std::path::Path>, error: OpenError) -> Self {
        let path = path.as_ref().to_path_buf();
        match error {
            OpenError::Io(Errno::LOOP) => Self::Symlink(path),
            OpenError::Io(Errno::XDEV) => Self::Escapes(path),
            OpenError::Io(source) => Self::Io { path, source },
            OpenError::UnsupportedKind => Self::UnsupportedKind(path),
            OpenError::Replaced => Self::Replaced(path),
        }
    }

    pub(crate) fn io(path: impl AsRef<std::path::Path>, source: Errno) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }
}
