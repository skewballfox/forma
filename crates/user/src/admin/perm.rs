//! Owners, modes and ACLs on any file.
//!
//! [`crate::perm`] does the same for files the process owns, without root.
//! Every function here changes files only under an allowed base, except
//! [`grant_traverse`] and [`revoke_traverse`], which add and remove `x`-only
//! entries on the directories above one.

use rustix::fs::{self as rfs, AtFlags, Gid as RGid, Mode, Uid as RUid};
use rustix::io::Errno;

use super::{Error, System, file, rel};
use crate::fs::{self, Node, OpenError};
use crate::id::{Gid, Uid};
use crate::lookup::{self, User};
use crate::ownership::{Change, Facts, Item, Journal, Ownership};
use crate::path::AbsPath;
use crate::perm::{self, Acl, AclEntry, FileMode, FileStat, PermError, Perms, Qualifier};

fn open<O: Ownership, J: Journal>(system: &System<O, J>, path: &AbsPath) -> Result<Node, Error> {
    let rel = path.relative();
    fs::open_node(system.root(), rel.as_ref()).map_err(|error| Error::Perm(PermError::open(path, error)))
}

fn perm_io(path: &AbsPath) -> impl Fn(Errno) -> Error + '_ {
    move |source| Error::Perm(PermError::io(path, source))
}

/// Sets the ACL of a file or directory under an allowed base.
///
/// # Errors
///
/// Returns [`Error::Refused`] outside the allowed bases, [`Error::NotOwned`]
/// if the caller's `Ownership` does not claim the file, and [`Error::Perm`]
/// if the path holds a symlink or cannot be changed.
///
/// # Capabilities
///
/// `CAP_FOWNER`, unless root owns the file.
pub fn set_acl<O: Ownership, J: Journal>(system: &mut System<O, J>, path: &AbsPath, acl: &Acl) -> Result<(), Error> {
    let _lock = system.lock()?;
    system.check_allowed(path)?;
    let node = open(system, path)?;
    system.require_claim(&Item::File { path, header: None })?;
    let previous = perm::read_acl(&node).map_err(perm_io(path))?;
    let change = Change::SetAcl {
        path: path.clone(),
        previous,
        new: acl.clone(),
    };
    system.intent(&change)?;
    perm::write_acl(&node, acl).map_err(perm_io(path))?;
    system.applied(&change, &Facts::default())
}

/// Sets the mode of a file or directory under an allowed base.
///
/// # Errors
///
/// The same as [`set_acl`].
///
/// # Capabilities
///
/// `CAP_FOWNER`, unless root owns the file.
pub fn set_mode<O: Ownership, J: Journal>(system: &mut System<O, J>, path: &AbsPath, mode: FileMode) -> Result<(), Error> {
    let _lock = system.lock()?;
    system.check_allowed(path)?;
    let node = open(system, path)?;
    system.require_claim(&Item::File { path, header: None })?;
    let change = Change::SetMode {
        path: path.clone(),
        previous: node.stat.st_mode & 0o7777,
        new: mode,
    };
    system.intent(&change)?;
    perm::write_mode(&node, mode).map_err(perm_io(path))?;
    system.applied(&change, &Facts::default())
}

/// Sets the owner and group of a file or directory under an allowed base.
///
/// # Errors
///
/// The same as [`set_acl`].
///
/// # Capabilities
///
/// `CAP_CHOWN`.
pub fn set_owner<O: Ownership, J: Journal>(
    system: &mut System<O, J>,
    path: &AbsPath,
    owner: Uid,
    group: Gid,
) -> Result<(), Error> {
    let _lock = system.lock()?;
    system.check_allowed(path)?;
    let node = open(system, path)?;
    system.require_claim(&Item::File { path, header: None })?;
    let change = Change::SetOwner {
        path: path.clone(),
        previous: (Uid::from_raw(node.stat.st_uid), Gid::from_raw(node.stat.st_gid)),
        new: (owner, group),
    };
    system.intent(&change)?;
    chown(&node, owner, group).map_err(perm_io(path))?;
    system.applied(&change, &Facts::default())
}

fn chown(node: &Node, owner: Uid, group: Gid) -> Result<(), Errno> {
    rfs::fchown(
        &node.fd,
        Some(RUid::from_raw(owner.as_raw())),
        Some(RGid::from_raw(group.as_raw())),
    )
}

/// Creates a directory under an allowed base, with its owner and mode set
/// before anyone else can use it.
///
/// The directory is created as root with mode `0700`, then opened, checked,
/// and given its owner and mode through the open handle.
///
/// # Errors
///
/// Returns [`Error::AlreadyExists`] if the path exists, [`Error::Refused`]
/// outside the allowed bases, and [`Error::Perm`] if the parent path holds a
/// symlink.
///
/// # Capabilities
///
/// `CAP_CHOWN` to give the directory away. `CAP_FOWNER` is not needed,
/// because root owns the directory until the last step.
pub fn create_dir<O: Ownership, J: Journal>(
    system: &mut System<O, J>,
    path: &AbsPath,
    owner: Uid,
    group: Gid,
    mode: FileMode,
) -> Result<(), Error> {
    let _lock = system.lock()?;
    system.check_allowed(path)?;
    let (parent, name) = file::open_parent(system, path)?;
    let change = Change::CreateDir {
        path: path.clone(),
        owner,
        group,
        mode,
    };
    system.intent(&change)?;
    match rfs::mkdirat(&parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => {}
        Err(Errno::EXIST) => return Err(Error::AlreadyExists(path.clone())),
        Err(source) => return Err(perm_io(path)(source)),
    }
    let node = open(system, path)?;
    // Another process could have swapped the new directory before it was
    // opened. Only root can write the parent's entries if the base is safe,
    // but check anyway.
    if node.stat.st_uid != 0 {
        return Err(Error::Perm(PermError::Replaced(path.as_path().to_path_buf())));
    }
    chown(&node, owner, group).map_err(perm_io(path))?;
    perm::write_mode(&node, mode).map_err(perm_io(path))?;
    system.applied(&change, &Facts::default())
}

/// Lets one account reach `path`, by adding a traverse-only (`x`) entry for
/// it on each directory above `path` that it cannot already pass through.
/// Returns the directories that changed.
///
/// No other entry's effective permissions change (see [`Acl::with_entry`]).
/// Directories the account can already pass through, such as `/var` with
/// mode `0755`, are left alone. Each change goes to the journal with the
/// ACL it replaced.
///
/// # Errors
///
/// Returns [`Error::Refused`] if `path` is outside the allowed bases, and
/// [`Error::Perm`] if a directory above it is a symlink.
///
/// # Capabilities
///
/// `CAP_FOWNER`, for directories root does not own.
pub fn grant_traverse<O: Ownership, J: Journal>(
    system: &mut System<O, J>,
    path: &AbsPath,
    user: &User,
) -> Result<Vec<AbsPath>, Error> {
    let _lock = system.lock()?;
    system.check_allowed(path)?;
    let gids = lookup::group_ids(user)?;
    let mut changed = Vec::new();
    for dir in path.ancestors() {
        let node = open(system, &dir)?;
        let acl = perm::read_acl(&node).map_err(perm_io(&dir))?;
        if perm::can_traverse(&FileStat::from_node(&node), &acl, user.uid(), &gids) {
            continue;
        }
        let qualifier = Qualifier::User(user.uid());
        let perms = acl.entry(qualifier).unwrap_or(Perms::NONE).union(Perms::EXECUTE);
        let new = acl.with_entry(AclEntry { qualifier, perms });
        let change = Change::SetAcl {
            path: dir.clone(),
            previous: acl,
            new: new.clone(),
        };
        system.intent(&change)?;
        perm::write_acl(&node, &new).map_err(perm_io(&dir))?;
        system.applied(&change, &Facts::default())?;
        changed.push(dir);
    }
    Ok(changed)
}

/// Removes the traverse-only entries [`grant_traverse`] added for `user` on
/// the directories above `path`. Returns the directories that changed.
///
/// An entry is removed only if it grants exactly `x` and the caller's
/// `Ownership` claims it. Entries that grant more were not made by
/// `grant_traverse`, and are left alone.
///
/// # Errors
///
/// Returns [`Error::NotOwned`] if the caller's `Ownership` does not claim an
/// entry, and [`Error::Perm`] if a directory above `path` is a symlink.
///
/// # Capabilities
///
/// `CAP_FOWNER`, for directories root does not own.
pub fn revoke_traverse<O: Ownership, J: Journal>(
    system: &mut System<O, J>,
    path: &AbsPath,
    user: &User,
) -> Result<Vec<AbsPath>, Error> {
    let _lock = system.lock()?;
    let qualifier = Qualifier::User(user.uid());
    let mut changed = Vec::new();
    for dir in path.ancestors() {
        let node = match open(system, &dir) {
            Ok(node) => node,
            // A directory removed since the grant has no entry left to remove.
            Err(Error::Perm(PermError::Io { source: Errno::NOENT, .. })) => continue,
            Err(error) => return Err(error),
        };
        let acl = perm::read_acl(&node).map_err(perm_io(&dir))?;
        if acl.entry(qualifier) != Some(Perms::EXECUTE) {
            continue;
        }
        let entry = AclEntry {
            qualifier,
            perms: Perms::EXECUTE,
        };
        system.require_claim(&Item::AclEntry { path: &dir, entry })?;
        let new = acl.without_entry(qualifier);
        let change = Change::SetAcl {
            path: dir.clone(),
            previous: acl,
            new: new.clone(),
        };
        system.intent(&change)?;
        perm::write_acl(&node, &new).map_err(perm_io(&dir))?;
        system.applied(&change, &Facts::default())?;
        changed.push(dir);
    }
    Ok(changed)
}

/// Removes a directory tree under an allowed base, without following
/// symlinks. Crate-private: used for account homes.
pub(crate) fn remove_tree<O: Ownership, J: Journal>(system: &System<O, J>, path: &AbsPath) -> Result<(), Error> {
    system.check_allowed(path)?;
    let (parent, name) = file::open_parent(system, path)?;
    let parent = cap_std::fs::Dir::from(parent);
    parent
        .remove_dir_all(name)
        .map_err(|source| Error::io(format!("remove {path}"), source))
}

/// Says whether `path` is the root of a mount.
pub(crate) fn is_mount_point<O: Ownership, J: Journal>(system: &System<O, J>, path: &AbsPath) -> Result<bool, Error> {
    let rel = rel(path)?;
    let node = fs::open_node(system.root(), Some(&rel)).map_err(|error| PermError::open(path, error))?;
    let statx = rfs::statx(
        &node.fd,
        "",
        AtFlags::EMPTY_PATH,
        rfs::StatxFlags::BASIC_STATS,
    )
    .map_err(perm_io(path))?;
    if !statx.stx_attributes_mask.contains(rfs::StatxAttributes::MOUNT_ROOT) {
        // The kernel cannot say. Refuse rather than guess.
        return Ok(true);
    }
    Ok(statx.stx_attributes.contains(rfs::StatxAttributes::MOUNT_ROOT))
}

/// Opens a file or directory for the crate's own checks.
pub(crate) fn stat<O: Ownership, J: Journal>(system: &System<O, J>, path: &AbsPath) -> Result<Option<FileStat>, Error> {
    let rel = path.relative();
    match fs::open_node(system.root(), rel.as_ref()) {
        Ok(node) => Ok(Some(FileStat::from_node(&node))),
        Err(OpenError::Io(Errno::NOENT)) => Ok(None),
        Err(error) => Err(Error::Perm(PermError::open(path, error))),
    }
}
