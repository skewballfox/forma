//! Manages Linux users, groups, sub-ID ranges, udev rules and file permissions.
//!
//! Code that needs root lives in the `admin` module. The crate never gains
//! privilege itself: `admin` needs a process that already runs as root. See
//! `PLAN.md` for the design.
//!
//! Everything outside `admin` can run as a normal user: checks on names,
//! IDs and paths, file parsers, lookups, sub-ID range search, rendering of
//! udev and `modules-load.d` files, and permission changes on files the
//! process owns.
//!
//! # Features
//!
//! - `systemd` (on by default): linger, login sessions and user managers
//!   through logind and systemd, and `modules-load.d` files.
//! - `udev-enumerate`: trigger every device in a subsystem through libudev.

pub mod admin;
pub mod defs;
mod fs;
pub mod id;
pub mod lookup;
pub mod name;
pub mod ownership;
pub mod path;
pub mod perm;
pub mod spec;
pub mod subid;
#[cfg(feature = "systemd")]
pub mod systemd;
pub mod udev;
