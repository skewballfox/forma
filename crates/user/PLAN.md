# `forma-user` plan

Status: **in progress.** Sections 4.1, 4.2 and 4.4 to 4.8 are implemented,
with the virtual machine tests in `tests/vm/` (section 10.3). Most unit
tests (10.1) are not written.
Vendor groups (4.3) wait on question U3, and
`trigger_subsystem` (feature `udev-enumerate`) is not written yet.

## About this document

**Who this is for.** People who will build, review or use `forma-user`. You
should know Linux users and groups, file permissions, shadow-utils, udev,
systemd-logind and Rust.

**What it covers.** What the crate does, what it refuses to do, how it is
split between unprivileged code and its `admin` module, its types and
operations, how it runs external tools, and how we test it.

**How it relates to `docs/architecture.md`.** This document sits under
the architecture plan. That plan keeps a short summary of this crate
(section 5.10) and links here for the details.

### Terms used in this document

| Term | Meaning |
|---|---|
| **Account** | A user entry in the password database. |
| **System account** | An account whose user ID is in `SYS_UID_MIN..=SYS_UID_MAX` from `login.defs`. |
| **Vendor entry** | A user or group that exists only in `/usr/lib/passwd` or `/usr/lib/group` (nss-altfiles). Fedora Atomic and secureblue ship these. |
| **Local group** | A group with an entry in `/etc/group`. Shadow-utils can change its members. |
| **Sub-ID range** | A range of subordinate user or group IDs in `/etc/subuid` or `/etc/subgid`. Rootless Podman needs one per account. |
| **Linger** | A logind setting that starts an account's systemd user manager at boot, without a login. |
| **ACL** | A POSIX access control list. It adds entries for named users and groups to a file's owner, group and other permission bits. |
| **Traverse** | Pass through a directory to reach a path inside it. Needs the `x` bit, not `r`. |
| **Managed file** | A file this crate wrote. It starts with a header that marks it as managed. |
| **Root handle** | The `admin::System` value that every privileged operation takes (5.1). |
| **Owner** | The caller's own rule for which accounts, groups and files it may change or remove. The crate asks it through the `Ownership` trait (section 6). |

## 1. What the crate does

The crate manages Linux users, groups and the permissions that go with
them:

1. Create and delete system accounts.
2. Create and delete groups. Add and remove one account's membership in one group.
3. Copy a vendor group into `/etc/group`, so accounts can join it.
4. Allocate and assign sub-ID ranges.
5. Turn linger on and off.
6. Write, remove and trigger udev rules.
7. Write and remove `modules-load.d` entries, and load the listed modules.
8. Read and set file owners, modes and ACLs, including traverse-only access
   to a directory for one account.

The crate is a general utility library. Nothing in it knows about forma,
materia, components or the ledger. Any program that manages accounts and
their permissions can use it.

Where a caller needs its own behaviour, the crate takes it through a generic
parameter, not through code written for that caller. Section 6 defines the
two such parameters: `Ownership` decides what the caller may change or
remove, and `Journal` records each change. Forma implements both with its
ledger. Other callers can use the implementations the crate ships.

## 2. What the crate does not do

- **No privilege escalation.** The crate never calls `sudo`, `run0`, `pkexec`
  or polkit to gain privilege. Privileged operations need a process that
  already runs as root. The crate checks this once, when the root handle is
  opened (5.1).
- **No storage of its own.** The crate keeps no record of what it created.
  It asks the caller's `Ownership` and tells the caller's `Journal`
  (section 6).
- **No passwords.** No operation takes a password. Accounts stay locked.
- **No shell.** The crate never runs `sh -c` or anything like it.
- **No adoption.** The crate never takes over an existing account, group or
  file that the caller's `Ownership` does not claim. Using an existing
  group is not adoption: an account may have any existing group as its
  primary or supplementary group (4.1). The crate adds the account to it and
  changes nothing else about the group.
- **No direct writes to `passwd`, `shadow`, `group` or `gshadow`.** Shadow-utils
  does this (section 8). The one exception is copying a vendor group line,
  which shadow-utils cannot do (4.3).

## 3. Crate layout: unprivileged code and `admin`

### 3.1 The rule

A function goes in the `admin` module only if it needs root or a Linux
capability. Everything a normal user can run stays outside `admin`. This
includes pure logic (checks, parsing, planning, rendering) and actions that
a user can take on their own files.

If only one step of an operation needs privilege, only that step goes in
`admin`. An `admin` function may be a thin wrapper that calls the
unprivileged function. Example: a user can set an ACL on a file they own,
so `perm::set_owned_acl` is unprivileged. Setting an ACL on someone else's
file needs `CAP_FOWNER`, so `admin::perm::set_acl` exists too, and calls the
same code without the owner check.

**No two functions share a name.** An unprivileged function and its `admin`
counterpart get different names (`set_owned_acl` and `set_acl`), so the
import path never decides what a call does.

**Signatures.** Operations that change the host take `&mut System`, because
they write to the caller's `Journal`. In the tables below, `&System` is
short for that. All `admin` functions return one error type,
`admin::Error`: they share most failure modes (lookups, tools, D-Bus,
ownership, journal), so `admin` counts as one module for the "one error
type per module" rule.

Every public `admin` function takes `&admin::System` (5.1). Code that has
no `System` cannot call one. Each has a `# Capabilities` section in its
documentation, as the architecture plan requires (3.3 there).

### 3.2 Modules

```
forma_user
├── name        checked names, IDs and values (5.2)
├── defs        parsers: login.defs, nsswitch.conf, /etc/subuid, /etc/group
├── lookup      NSS lookups: User, Group, LocalGroup, VendorGroup (5.3)
├── subid       range allocation, as a pure function (4.4)
├── systemd     feature `systemd`: reading linger (4.5), and
│   └── modules modules-load.d model and rendering (4.7)
├── udev        rule model and rendering (4.6)
├── perm        modes and ACLs: model, encoding, read, and set on files the
│               process owns (4.8)
├── ownership   the Ownership and Journal traits and the implementations
│               the crate ships (section 6)
└── admin       everything that needs root or a capability
    ├── System, SystemConfig (5.1)
    ├── user, group, vendor, subid, udev, perm
    ├── systemd feature `systemd`: linger, modules, and the logind and
    │           systemd D-Bus calls account deletion uses
    └── tool    private: the shadow-utils runner (section 8)
```

None of the modules outside `admin` change anything outside files the
process owns.

### 3.3 Feature `systemd`

On by default. Everything that needs systemd lives in two modules,
`systemd` and `admin::systemd`, so turning the feature off removes them
and the `zbus` dependency with few `#[cfg]` lines elsewhere. They hold:

- linger, read from logind's state and set over D-Bus (4.5);
- `modules-load.d` files and `systemd-modules-load.service` (4.7);
- the session check and user-manager stop that account deletion uses
  (4.1, steps 3 to 5).

udev rules stay outside the feature: eudev reads the same
`/etc/udev/rules.d`, and a trigger is a plain sysfs write.

Without the feature, `SessionPolicy` has only `Refuse`, and account
deletion relies on `userdel`, which refuses an account with running
processes. `SystemConfig::unit_timeout` exists only with the feature.

## 4. Operations

Each table shows the full path, so it is clear which functions need root.

### 4.1 Accounts

| Operation | Does |
|---|---|
| `admin::user::create(&System, &UserSpec)` | Creates a system account. Fails if an account with that name or user ID exists. Existing groups are fine (see below). |
| `admin::user::ensure(&System, &UserSpec)` | Returns `Created`, `Matches` or `Conflict(UserDiff)`. Never changes an existing account. Returns `NotOwned` if the account exists and `Ownership` does not claim it. |
| `admin::user::delete(&System, &User, DeleteOptions)` | Deletes an account with the steps below. `DeleteOptions` holds a `HomePolicy` and a `SessionPolicy` (refuse or terminate); neither has a default. |
| `UserSpec::diff(&self, &User) -> UserDiff` | Unprivileged. Compares a spec with an existing account. |

`UserSpec` holds every setting explicitly. No field falls back to
`login.defs` or `/etc/default/useradd`:

- name (`UserName`);
- user ID: `Allocate` in the system range, or a fixed `SystemUid`;
- primary group, one of:
  - `PrimaryGroup::New`: create a group with the account's name
    (`useradd -U`). Fails if a group with that name exists, and says to use
    `Existing` instead;
  - `PrimaryGroup::Existing(GroupRef)`: use a group that already exists.
    Any group works: a standard one such as `users`, a vendor group, or one
    the caller created earlier. The group is not changed;
- supplementary groups: a list of `LocalGroup` values (5.3). These can be
  standard groups such as `render` or `video`. A vendor group must be
  copied to `/etc/group` first (4.3). The type system enforces this;
- home: `None`, or `Create { path }` under an allowed base;
- shell: `NoLogin` unless the spec names a `LoginShell`;
- comment (GECOS): optional, validated, no `:` or newline.

Each group in the spec must exist when `create` runs, except a
`PrimaryGroup::New` group. The crate never creates a group as a side effect
of `Existing` or of a supplementary group.

**Delete steps.** `delete` takes a `User` from a lookup (5.3), not a name.
It runs these steps in order:

1. Take the crate's lock and look the account up again. Stop if the name,
   user ID or home differ from the `User` value.
2. Ask `Ownership` whether the caller owns the account. Check the refusals
   in section 7.
3. Turn linger off.
4. End the account's sessions with logind `TerminateUser`.
5. Wait until `user@<uid>.service` has stopped, with a timeout.
6. Run `userdel` without `-r` and without `-f`.
7. Apply the `HomePolicy`. It has no default; the caller must choose:
   - `Keep`: leave the home as it is.
   - `Archive`: rename it to `<home>.removed-<timestamp>` and set
     mode `0700`, owner root.
   - `Remove`: remove it with `cap-std`'s `remove_dir_all`, which does not
     follow symlinks. Only after these checks pass:
     - the home is under an allowed base;
     - the top directory is owned by the account's user ID (only the top:
       rootless storage holds files owned by sub-IDs);
     - it is not a mount point;
     - no other account uses it as a home.

Corectl uses `pkill -u`, ignores every error, and falls back to
`rm -rf /var/home/<user>`. These steps replace that.

### 4.2 Groups

| Operation | Does |
|---|---|
| `admin::group::create(&System, &GroupSpec)` | Creates a system group. Fails if it exists. |
| `admin::group::ensure(&System, &GroupSpec)` | `Created`, `Matches` or `Conflict(GroupDiff)`. `NotOwned` if the group exists and `Ownership` does not claim it. |
| `admin::group::delete(&System, &LocalGroup)` | Deletes a group the caller owns, after the checks in section 7. |
| `admin::group::add_member(&System, &User, &LocalGroup)` | Adds one account to one group. The group may be any local group, owned or not. |
| `admin::group::remove_member(&System, &User, &LocalGroup)` | Removes one account from one group, if `Ownership` claims that membership. |

`create` and `ensure` are for groups the caller wants to create. To put an
account in a group that already exists, use `PrimaryGroup::Existing`, the
supplementary list in `UserSpec`, or `add_member`. None of these need the
caller to own the group.

The crate never replaces an account's whole group list (`usermod -G`).
Corectl's `wolf::setup-user` does this, which strips groups from any existing
account with the same name.

### 4.3 Vendor groups

On Fedora Atomic and secureblue, groups such as `render` exist only in
`/usr/lib/group`. `usermod -aG` and `gpasswd -a` edit only `/etc/group`, so
they fail for these groups.

`admin::vendor::materialize(&System, VendorGroup) -> (LocalGroup, Copied)`
copies the line from `/usr/lib/group` into `/etc/group`. `Copied` says
whether this call made the copy, so the caller can undo only its own copy.
`admin::vendor::dematerialize` removes the line only if `Ownership` claims
the copy, `/etc/group` still matches what was copied, and the group has no
members left.

Because `add_member` and `UserSpec` take a `LocalGroup`, code that tries to
add an account to a vendor group without copying it first does not compile.

This is the only place the crate writes a database file itself. It uses
shadow's lock protocol (`/etc/group.lock`, created with `link()`), writes a
temporary file, `fsync`s it, renames it into place, and keeps the file's
SELinux label. Fedora's own documentation for atomic desktops gives the
same fix: copy the line from `/usr/lib/group` into `/etc/group`.

`groupadd` cannot do this. It looks the name up through NSS, finds the
vendor entry, and fails with "group already exists". Question U3 lists the
other options.

### 4.4 Sub-ID ranges

| Operation | Does |
|---|---|
| `subid::find_free_range(taken, avoid, limits, count) -> SubIdRange` | Unprivileged and pure. Finds the lowest free range, as shadow-utils' `find_free_range` does. |
| `admin::subid::allocate(&mut System, &User, SubIdCount)` | Reads the files, calls `find_free_range`, and adds the range for both user and group IDs. |
| `admin::subid::add(&mut System, &User, SubIdRange)` | Adds a given range (`usermod --add-subuids`). Fails if it overlaps another owner's range. |
| `admin::subid::remove(&mut System, &User)` | Removes the account's ranges (`usermod --del-subuids`). |

Names follow shadow-utils: it *finds* a free range, and `usermod` *adds* and
*deletes* sub-IDs. No two functions share a name, so the import path never
decides what a call does.

Rules:

- Read `SUB_UID_MIN`, `SUB_UID_MAX` and `SUB_UID_COUNT` (and the `GID`
  ones) from `login.defs`. Corectl starts at 100000. This host's
  `login.defs` says 524288, so corectl allocates outside the range shadow uses.
- Never overlap another range. Never overlap the normal user ID range.
- Refuse if `nsswitch.conf` has a `subid:` line with a source other than
  `files`. Writing to `/etc/subuid` would then have no effect.
- `usermod --add-subuids` and `--add-subgids` write the range, because they
  take shadow's lock.
- Reading, allocating and writing can race with another program. So after
  the write, read both files again and check that the new range overlaps
  nothing. If it does, remove the range and fail.

### 4.5 Linger

| Operation | Does |
|---|---|
| `systemd::linger(&User) -> bool` | Unprivileged. Reads the state from logind. |
| `systemd::set_own_linger(bool)` | Unprivileged. Calls logind's `SetUserLinger` for the process's own account, which polkit allows any account. |
| `admin::systemd::linger::set(&System, &User, bool)` | Wraps the same call for another account, which needs root, and records the change. |

Rootless Quadlets do not start at boot without linger.

### 4.6 udev rules

| Operation | Does |
|---|---|
| `udev::RulesFile::render(&self) -> String` | Unprivileged. Renders the file. |
| `admin::udev::write(&System, &RulesFile)` | Writes a managed rules file to `/etc/udev/rules.d`. |
| `admin::udev::remove(&System, &RulesFileName)` | Removes a managed rules file. |
| `admin::udev::trigger(&System, &SysfsDevice)` | Writes `change` to the device's `uevent` file. |
| `admin::udev::trigger_subsystem(&System, &Subsystem)` | Feature `udev-enumerate`: triggers every device in a subsystem. |

**File names.** `RulesFileName` has the form `NN-name.rules`: a two-digit
priority, then a validated name. Files go only in `/etc/udev/rules.d`.

**Managed files.** Each file starts with a header line that marks it as
managed. `write` refuses to overwrite an existing file, and `remove`
refuses to delete one, unless `Ownership` claims it. The crate's `Marker`
ownership (6.2) claims a file when the header carries its tag.

**Typed rules.** A rule is a list of typed matches and typed assignments.
It is not a raw string. Version 1 covers what corectl uses:

| Kind | Keys |
|---|---|
| Match | `KERNEL`, `SUBSYSTEM`, `KERNELS`, `DEVPATH` (with `==` only) |
| Assign | `GROUP`, `MODE`, `OPTIONS+="static_node=…"`, `ENV{ID_SEAT}` |

The typed API has no `RUN`, `PROGRAM`, `IMPORT{program}` or `IMPORT{file}`.
These run code or read files as root. `MODE` can never give write access to
others. A `GROUP` must exist when the file is written. Otherwise udev logs an
error and leaves the node owned by root.

Values are checked so they cannot close a quote or start a new key.

**Writes** use a temporary file, `fsync` and a rename. udevd reloads changed
rules before it handles the next event, so no `udevadm control --reload`
is needed. `trigger` sends that event. Corectl does the same, because `run0`
cannot run `udevadm` on secureblue.

### 4.7 Kernel modules

| Operation | Does |
|---|---|
| `systemd::modules::ModulesLoadFile::render(&self) -> String` | Unprivileged. Renders the file. |
| `admin::systemd::modules::write(&System, &ModulesLoadFile)` | Writes a managed file to `/etc/modules-load.d`, then restarts `systemd-modules-load.service` over D-Bus, so the modules load now as well as at boot. |
| `admin::systemd::modules::remove(&System, &ModulesLoadFileName)` | Removes a file that `Ownership` claims. Does not unload modules. |

`ModuleName` is validated. The uinput and uhid rules do nothing unless their
modules are loaded, so this belongs with udev rules.

### 4.8 Owners, modes and ACLs

**Why this crate.** File owners, modes and ACLs decide which accounts can
reach which files. Changing them for other accounts' files needs root, so
it sits with the other account utilities. Other crates, such as
`forma-store`, build their directory layouts from these functions.

**Unprivileged (`perm`):**

| Operation | Does |
|---|---|
| `Acl`, `AclEntry`, `Perms` | A typed ACL: owner, owning group, named users, named groups, mask, other. |
| `Acl::encode` and `Acl::decode` | Pure. Convert to and from the kernel's `system.posix_acl_access` format. |
| `Acl::with_entry`, `Acl::without_entry` | Pure. Return a new ACL and recompute the mask, as `setfacl` does. |
| `perm::can_traverse(&Metadata, &Acl, &User, &[Gid]) -> bool` | Pure. Says whether an account can already pass through a directory. |
| `perm::read(&Dir, &RelPath) -> (Metadata, Acl)` | Reads owner, mode and ACL. |
| `perm::set_owned_acl(&Dir, &RelPath, &Acl)` | Sets the ACL on a file the process owns. Fails with `NotOwner` otherwise. |
| `perm::set_owned_mode(&Dir, &RelPath, FileMode)` | Sets the mode on a file the process owns. |

**Privileged (`admin::perm`):**

| Operation | Does | Needs |
|---|---|---|
| `admin::perm::set_acl(&System, &Path, &Acl)` | Sets the ACL on any file under an allowed base. Calls the code behind `perm::set_owned_acl` without the owner check. | `CAP_FOWNER` |
| `admin::perm::set_mode(&System, &Path, FileMode)` | Same, for the mode. | `CAP_FOWNER` |
| `admin::perm::set_owner(&System, &Path, Owner)` | Sets owner and group. | `CAP_CHOWN` |
| `admin::perm::create_dir(&System, &Path, Owner, FileMode)` | Creates a directory with its owner and mode set before anyone else can open it. | `CAP_CHOWN`, `CAP_FOWNER` |
| `admin::perm::grant_traverse(&System, &Path, &User)` | Lets one account reach a path, with the steps below. | `CAP_FOWNER` |
| `admin::perm::revoke_traverse(&System, &Path, &User)` | Removes only the entries `grant_traverse` added. | `CAP_FOWNER` |

**`grant_traverse` steps.** Corectl's `prepare-user-dir` does this with
`setfacl -m u:<user>:x` on every ancestor. This crate does it with less:

1. Walk from `/` to the path, one directory at a time.
2. For each directory, compute `can_traverse`. Skip directories the account
   can already pass through. Corectl adds entries to `/var` and `/var/lib`,
   which are already `0755`.
3. For each other directory, add one named-user entry with only `x`.
4. Tell the `Journal` about each entry, with the ACL it replaced, so it can
   be undone.

`revoke_traverse` removes only that account's named entry, and only where
`Ownership` claims it. Corectl never removes its entries.

**Rules:**

- Every file is opened through the root `Dir` without following symlinks.
  ACLs, modes and owners are set on the open file descriptor (`fsetxattr`,
  `fchmod`, `fchown`), so a path cannot be swapped between the check and
  the change.
- `admin::perm` changes files only under an allowed base from
  `SystemConfig`. The one exception is `grant_traverse`, which may add
  `x`-only named-user entries to the directories above an allowed base.
- `FileMode` has no setuid bit. Setgid and sticky are allowed. Others never
  get write access.
- Version 1 handles access ACLs only. Default ACLs (inherited by new files)
  are left for later. Corectl uses a setgid directory instead.

**How ACLs are written.** The crate encodes the ACL itself and writes it
with `rustix`'s `fsetxattr`. The format is a version number followed by
fixed-size entries, and the kernel checks it on write. Section 11 says why
the crate does not use `exacl`.

## 5. Types

### 5.1 Root handle

`admin::System::open(SystemConfig, O, J) -> Result<System<O, J>, OpenError>`
is the only way to get a `System`. `O` is the caller's `Ownership` and `J`
its `Journal` (section 6). It:

1. checks that the effective user ID is 0;
2. checks that the process does not run in a container (`/run/.containerenv`,
   `/.dockerenv`);
3. opens `/` as a `cap_std::fs::Dir`;
4. reads `login.defs` (`/etc/login.defs`, then `/usr/etc/login.defs`);
5. checks each external tool (section 8).

`SystemConfig` holds the settings the caller controls: allowed bases for
homes and file changes, whether user IDs outside the system range are
allowed, the lock file path (section 9), and timeouts. It has no `Default`:
the caller sets each value.

Tests open the handle against a temporary directory instead of `/`
(section 10). That constructor exists only under `cfg(test)` and the
`vm-tests` feature.

### 5.2 Checked values

| Type | Checked when built |
|---|---|
| `UserName`, `GroupName` | `[a-z_][a-z0-9_-]{0,31}`. Not all digits. Does not start with `-`. Not a reserved name (`root`, `nobody` and others). |
| `SystemUid`, `SystemGid` | Not 0. Inside the system range from `login.defs`, unless `SystemConfig` allows otherwise. |
| `SubIdCount` | 65536 to 2^31. |
| `SubIdRange` | Start and count. Does not wrap past `u32::MAX`. |
| `HomePath` | Absolute, normalised, under an allowed base. |
| `RelPath` | Relative, normalised, no `..`. |
| `Comment` | No `:`, newline or control characters. |
| `RulesFileName`, `ModulesLoadFileName`, `ModuleName` | See 4.6 and 4.7. |
| `UdevValue` | No `"`, `\`, newline or control characters. |
| `FileMode` | Permission bits, setgid and sticky only. No setuid. No write bit for others. |
| `Perms` | Any of `r`, `w`, `x`. |

These types have no public constructor other than their checked one, and
they do not implement `Default`. They live outside `admin`, so unprivileged
code can check input before it asks for privilege.

### 5.3 Lookups

`lookup::user(&UserName) -> Option<User>` and `lookup::group` go through NSS
(`nix::unistd::User::from_name`). So vendor entries and sssd entries count
as existing. Lookups need no root.

`User` records the name, user ID, home and source. `lookup::group` returns
an enum, so the caller must handle each source:

| Variant | Source | Can be used as |
|---|---|---|
| `Group::Local(LocalGroup)` | `/etc/group` | Primary group, supplementary group, `add_member`, `admin::group::delete`. |
| `Group::Vendor(VendorGroup)` | `/usr/lib/group` only | Primary group. Supplementary only after `admin::vendor::materialize` (4.3). |
| `Group::Other(RemoteGroup)` | Another NSS source, such as sssd | Primary group only. Shadow-utils cannot change its members. |

`GroupRef` (used by `PrimaryGroup::Existing`) accepts any of the three.

Delete operations take these values, so a caller cannot delete something it
has not looked at.

## 6. Caller behaviour: `Ownership` and `Journal`

`admin::System<O, J>` is generic over two traits. These are how a caller
adds its own rules. The crate never contains a caller's rules directly. The
traits live in the `ownership` module, outside `admin`, because they need
no privilege.

### 6.1 `Ownership`

```rust
// Sketch only. Not final API.
pub trait Ownership {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Says whether the caller may change or remove this item.
    fn claims(&self, item: &Item<'_>) -> Result<bool, Self::Error>;
}

pub enum Item<'a> {
    User(&'a User),
    Group(&'a LocalGroup),
    Membership { user: &'a User, group: &'a LocalGroup },
    SubIds { user: &'a User, range: SubIdRange },
    VendorGroupCopy(&'a LocalGroup),
    File { path: &'a Path, header: Option<&'a str> },
    AclEntry { path: &'a Path, entry: &'a AclEntry },
}
```

The crate asks `claims` before every operation that changes or removes
something that already exists: delete, `ensure` on an existing item,
`remove_member`, `admin::subid::remove`, turning linger off, overwriting
or removing a managed file, changing the owner, mode or ACL of an existing
file, `revoke_traverse`, and `admin::vendor::dematerialize`. If `claims`
returns `false`, the operation fails with `NotOwned` and names the item.

Creating something new needs no claim. Using an existing group as a primary
or supplementary group needs no claim either. `grant_traverse` needs no
claim, because it only adds an `x` entry and records it.

### 6.2 Implementations the crate ships

| Type | Claims an item when |
|---|---|
| `Marker { tag }` | The account's comment holds `managed-by=<tag>`, the group's account or member is claimed, or the file header carries `<tag>`. `admin::user::create` writes the marker into the comment, and file writes put it in the header. It never claims files without a header or ACL entries; callers who change those need their own `Ownership`. |
| `ClaimNothing` | Never. Useful for programs that only create. Every removal fails. |

There is no "claim everything" type in the crate. A caller that wants one
must write it, which makes the choice visible in its own code.

Forma implements `Ownership` with its ledger.

### 6.3 `Journal`

```rust
// Sketch only. Not final API.
pub trait Journal {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Called before a change. If this fails, the change does not happen.
    fn intent(&mut self, change: &Change<'_>) -> Result<(), Self::Error>;

    /// Called after a change succeeds, with facts learned, such as a new user ID.
    fn applied(&mut self, change: &Change<'_>, facts: &Facts) -> Result<(), Self::Error>;
}
```

`Change` is an enum with one variant per operation. It holds what the caller
needs to undo the change, such as the ACL a change replaced. The crate ships
`NoJournal`, which does nothing.

Forma implements `Journal` with its ledger's `Pending` and `Applied`
entries (architecture plan 4.2).

### 6.4 Errors from the traits

Errors from `Ownership` and `Journal` are wrapped in the crate's error
variants `Ownership { item, source }` and `Journal { change, source }`. The
variant names the item or change. The source keeps the caller's own error
type, behind `Box<dyn Error + Send + Sync>`, so the crate's error types do
not become generic.

## 7. Refusals

The crate refuses these, with a typed error that names the account, group
or path:

| Refusal | Why |
|---|---|
| Create an account whose name or user ID exists | No adoption (corectl's `create-sys-user` adopts silently, and could give `render` to a human account with the same name). Existing **groups** are fine (4.1). |
| `PrimaryGroup::New` when a group with that name exists | The caller asked for a new group. Use `PrimaryGroup::Existing` to share an existing one. |
| Change or remove an item `Ownership` does not claim | Section 6.1. |
| Any change to user or group ID 0 | Root. |
| Any change to an ID outside the system range | Human accounts, unless `SystemConfig` allows it. |
| Delete or change a vendor entry | It lives in `/usr` and cannot be changed. |
| Delete the account of the person who started the process | Read from `/proc/self/loginuid`. |
| Delete an account with active sessions | Unless the caller asks the crate to end them (4.1, step 4). |
| Delete a group that is any account's primary group | `groupdel` refuses too; the crate says why first. |
| Delete a group named in a managed udev rule | The rule would fall back to root ownership. |
| Delete the home when the checks in 4.1 fail | Avoids corectl's `rm -rf` fallback. |
| Change the owner, mode or ACL of a file outside the allowed bases | Except `x`-only entries from `grant_traverse` (4.8). |
| A path that goes through a symlink, in any `perm` or `admin::perm` call | The link could point anywhere. |
| An unprivileged `perm` change to a file the process does not own | Fails with `NotOwner` before the kernel says `EPERM`. |

## 8. External tools

### 8.1 Which operations run a tool

| Operation | Tool | Why not an API |
|---|---|---|
| Create and delete accounts and groups | `useradd`, `userdel`, `groupadd`, `groupdel` | No stable library API. Writing the files by hand skips shadow's locks, nscd and sssd cache flushes, SELinux labels, gshadow and audit records. |
| Group membership | `gpasswd -a`, `gpasswd -d` | Same. |
| Write sub-ID ranges | `usermod --add-subuids`, `--del-subuids` (and `gids`) | Same, plus `subid:` backends. |
| Linger, end sessions, load modules | none | D-Bus (`zbus`). |
| udev rules, triggers, `modules-load.d` | none | File writes. |
| Owners, modes, ACLs | none | System calls on file descriptors (`rustix`). |

### 8.2 Guards

The runner is a private module, `admin::tool`. No public function takes
free-form arguments.

1. **One builder per tool.** Its inputs are only the checked types in 5.2.
   It produces an argument vector, which unit tests inspect.
2. **Fixed absolute path.** For example `/usr/sbin/useradd`. No `PATH`
   lookup. `System::open` checks that each binary and its directories are
   owned by root and not writable by group or others.
3. **Clean environment.** `env_clear()`, then only `LC_ALL=C`, so stderr text
   is stable.
4. **Every setting explicit.** For example, `useradd` always gets
   `--system`, `-M` or `-m -d <home>`, `-U` or `-N -g <gid>`, and
   `-s <shell>`. `login.defs` and `/etc/default/useradd` cannot change the
   result.
5. **No password option.** `-p` would show in `/proc/<pid>/cmdline`.
6. **No option injection.** Names cannot start with `-` (5.2).
7. **Stdin is null.** Each run has a timeout.
8. **Typed results.** Documented exit codes map to error variants (for
   `useradd`, 9 means the name is taken and 4 means the ID is taken). Other
   failures carry the exit code and stderr.

## 9. Locking

Every `admin` operation takes an exclusive `flock` on the lock file named
in `SystemConfig`. Callers that must not run at the same time use the same
path. This serialises callers of the crate. It does not keep other programs
out: shadow-utils takes its own locks, and the sub-ID check in 4.4 catches
races with other programs.

## 10. Testing

Tests run in three tiers. Anything that needs root or a real system runs in
the virtual machine. Everything else runs as a normal user with
`cargo test`.

### 10.1 Unit tests (no root)

Most logic lives outside `admin`, as pure functions, so unit tests cover it:

- name and value checks, with `proptest` against shadow's rules;
- parsers for `login.defs`, `/etc/subuid`, `/etc/group` and `nsswitch.conf`;
- the sub-ID allocator, with `proptest`: never overlaps, stays in bounds,
  same input gives the same result;
- udev rules and `modules-load.d` rendering, with `insta` snapshots;
- the ACL encoding, with `proptest`: decoding an encoded ACL gives the same
  ACL, and the mask matches what `setfacl` computes;
- `can_traverse`, against a table of modes, owners, groups and ACLs;
- argument vectors for every tool. For example, `useradd` always has `-M`
  or `-m`, and never `-p`;
- the order of steps and the refusals in `admin`, against an in-memory fake
  of the host (lookups, tool runs, logind, file system calls). Example:
  delete runs linger off, then terminate, then `userdel`, and stops when
  the user ID changed.

The fake is a crate-private trait with two implementations: the real host,
and the fake. It is not public API.

### 10.2 Kernel tests without root

The unprivileged `perm` functions work on files the test user owns. So
they run against the real kernel in a temporary directory, with no root and
no virtual machine. They check that:

- an ACL written by `perm::set_owned_acl` reads back the same, and matches
  `getfacl` when it is installed;
- the kernel accepts every ACL the encoder produces;
- a symlink in the path is refused;
- a file owned by someone else fails with `NotOwner`.

The temporary directory must be on a file system with ACL support. Fedora's
`/tmp` (tmpfs) has it. The tests check first and skip with a clear message
if it is missing.

### 10.3 Virtual machine tests

These cover everything in `admin`: shadow-utils, logind, udev, kernel
modules, and owners and ACLs on files the test user does not own.

**Tool: mkosi and `systemd-vmspawn`.** mkosi builds a small Fedora image.
`systemd-vmspawn` boots it under QEMU with KVM. Reasons:

- The guest runs a full systemd: logind, udevd, `systemd-modules-load`.
- `systemd-vmspawn` is already on the host (systemd 259). It shares a
  directory with the guest over virtiofs, so the test binaries built on the
  host run in the guest without copying.
- systemd tests itself this way, so the setup is well used.
- No libvirt daemon is needed. mkosi must be installed.

**Options not chosen:**

| Option | Why not |
|---|---|
| Kata Containers | The guest runs Kata's agent, not systemd. There is no logind or udevd, and the guest kernel is minimal, so `uinput` and `uhid` may not exist. It isolates containers well but does not give a whole host to test. |
| Plain QEMU | Works, but we would have to write the image build, kernel boot, directory sharing and result collection that mkosi and `systemd-vmspawn` provide. |
| virter | Materia uses it, so it would share setup. It needs libvirt. Reconsider if forma's later integration tests run with materia's. |
| A Podman container | No udevd, no logind, and it cannot load kernel modules. It would cover only shadow-utils, which the virtual machine covers too. |

**How a run works:**

1. `cargo test --no-run --features vm-tests` builds the test binaries on the
   host.
2. mkosi builds the image once and caches it. The image contains a marker
   file, `/etc/forma-user-test-vm`.
3. `systemd-vmspawn` boots it, shares the target directory, and runs the
   tests as root inside the guest.
4. The run reports the test binary's exit status and output.

Spike V1 (section 12) settles how step 3 starts the tests and how step 4
gets the results out.

**Guard.** Every VM test starts by checking for the marker file and a
`hypervisor` CPU flag. If either is missing, it fails at once. So a
`cargo test --features vm-tests` on a real host changes nothing.

**What the VM tests cover:**

- create, ensure and delete accounts and groups, including every refusal in
  section 7;
- vendor groups: a test image with a group in `/usr/lib/group` only;
- sub-ID allocation next to ranges made by `useradd` and by hand;
- linger on and off, and delete with a lingering user manager running;
- udev rules for `uinput` and `uhid`, a trigger, and the node's group and mode;
- `modules-load.d` and module loading;
- the archive and remove home policies, with a symlink planted in the home;
- `grant_traverse` and `revoke_traverse`: the account can reach the path
  afterwards and cannot list the directories above it; revoke leaves other
  entries alone.

## 11. Dependencies

| Crate | Use |
|---|---|
| `thiserror` | One error type per module. |
| `rustix` (`fs`, `process`) | `flock`, `fsync`, `renameat`, `fstat`, `fchown`, `fchmod`, `fsetxattr`, `geteuid`. |
| `cap-std` | Every file access goes through a `Dir`. |
| `nix` (`user`) | NSS lookups. |
| `zbus` 5 (blocking API) | logind and systemd over D-Bus. Proxies are written in this crate with `#[proxy]`. zbus 6.0 came out on 2026-10-16 and drops the blocking API, so we stay on 5.x for now. |
| `tracing` | Logging. |
| `udev` (optional, feature `udev-enumerate`) | Finding devices by subsystem. Needs libudev at build time (`systemd-devel`). |
| `tempfile`, `proptest`, `insta`, `rstest` | Tests only. |

**Not used:**

| Crate | Why not |
|---|---|
| `exacl` | Its API takes paths, not file descriptors, so a symlink or a renamed directory between the check and the change can redirect it. It also links the C library libacl, which needs `libacl-devel` at build time. The kernel format it would write for us is small, so the crate encodes it itself (4.8). |
| `users`, `uzers` | Read-only, and they cache results. |
| Any crate that writes the account databases directly | See section 8.1. |

## 12. Order of work

Each step ends with passing tests and
`cargo clippy --all-targets -- -W clippy::pedantic` with no warnings.

| Step | Work |
|---|---|
| 1 | Checked types (5.2), `defs` parsers, error types. |
| 2 | Lookups (5.3), `ownership` traits (section 6), `admin::System` (5.1), tool runner and guards (section 8). |
| 3 | Groups and accounts (4.1, 4.2), with the fake host. |
| 4 | Spike V1: the mkosi image and `systemd-vmspawn` runner (10.3). Then VM tests for step 3. |
| 5 | Sub-ID ranges (4.4) and linger (4.5). |
| 6 | Owners, modes and ACLs (4.8), with the kernel tests in 10.2. |
| 7 | Vendor groups (4.3). |
| 8 | udev rules and kernel modules (4.6, 4.7). |

## 13. Questions to settle

| ID | Question | Recommendation |
|---|---|---|
| U3 | How does an account join a vendor group? (a) Copy the line into `/etc/group` (4.3). (b) A drop-in for `user@<uid>.service` with `SupplementaryGroups=`: no database edit, but only processes under the account's user manager get the group, and it needs a spike. (c) Avoid the vendor group: create an own group and a udev rule that gives the device to it. Only safe for devices nobody else needs, such as `uinput`; wrong for `render`. | (a) as the default, since Fedora documents it. Offer (c) where it fits, as corectl does with `wolf-input`. Spike (b) in step 7. |
