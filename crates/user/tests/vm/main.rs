//! Tests that need root and a real system: shadow-utils, logind, udev, kernel
//! modules, and owners and ACLs on files the test user does not own.
//!
//! They change the machine they run on, so they run only in the test VM
//! (`PLAN.md` section 10.3): `just vm-test`. Every test is `#[ignore]`d, so
//! `cargo test` skips them. Run with `--ignored` anywhere else and each one
//! fails at once, before it touches anything: [`common::require_vm`] looks
//! for the marker file the VM image carries and for a `hypervisor` CPU flag.

/// Declares a test that runs in the VM only.
///
/// The body runs after [`common::require_vm`], so no test can reach the host.
macro_rules! vm_test {
    ($(#[$meta:meta])* fn $name:ident() $body:block) => {
        #[test]
        #[ignore = "needs the test VM: run `just vm-test`"]
        $(#[$meta])*
        fn $name() {
            $crate::common::require_vm();
            $body
        }
    };
}

mod accounts;
mod common;
mod groups;
mod linger;
mod modules;
mod perms;
mod subids;
mod udev;
