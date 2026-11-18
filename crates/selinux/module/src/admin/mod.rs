//! Operations that need root: changes to the SELinux policy store, and
//! reading it.
//!
//! Every public function takes a [`Token`] first (architecture 3.3). None of
//! them needs a Linux capability, so any token will do; the token shows at
//! the call site that the caller acquired one, as `forma apply` does after
//! it drops capabilities. What they do need is root's user ID, which a token
//! cannot prove, so each checks it before it runs anything and returns
//! [`Error::NotRoot`] otherwise.
//!
//! They also need an SELinux domain that may enter `semanage_exec_t`, such
//! as `unconfined_t`: an administrator's, which `run0` keeps. A confined
//! domain gets a `semodule` or `semanage` failure, not a capability error.
//!
//! Each call rebuilds the policy, which takes minutes on a small host, so
//! each runs with a limit of [`TIMEOUT`].

mod command;

use std::path::Path;
use std::time::Duration;

use forma_privilege::{Set, Token};
use forma_process::{Command, Output};
use thiserror::Error;

use crate::list::{InstalledModule, ListError, parse_full_list};

/// How long one `semodule` or `semanage` call may take.
pub const TIMEOUT: Duration = Duration::from_secs(600);

/// An SELinux change or read failed.
#[derive(Debug, Error)]
pub enum Error {
    /// The process does not run as root.
    #[error("cannot {action}: it needs root; run forma apply as root")]
    NotRoot {
        /// What forma was doing.
        action: &'static str,
    },
    /// A value was refused, or `semodule` or `semanage` could not run or
    /// failed.
    #[error(transparent)]
    Command(#[from] forma_process::Error),
    /// `semodule -lfull` printed a line that is not a module.
    #[error(transparent)]
    List(#[from] ListError),
}

/// Checks root's user ID, then runs the command with [`TIMEOUT`].
fn run(action: &'static str, command: Result<Command, forma_process::Error>) -> Result<Output, Error> {
    if !rustix::process::geteuid().is_root() {
        return Err(Error::NotRoot { action });
    }
    Ok(command?.timeout(TIMEOUT).run()?)
}

/// Installs module files at `priority`, in one transaction
/// (`semodule -X <priority> -i <file>...`).
///
/// # Capabilities
///
/// - None (VM, 2026-11-18): root owns the policy store, and loading the
///   policy is SELinux's `load_policy` permission, not `CAP_MAC_ADMIN`.
/// - Needs root's user ID, and a domain that may enter `semanage_exec_t`.
/// - Writes the policy store under `/var/lib/selinux` and the policy under
///   `/etc/selinux`, and loads the new policy.
///
/// # Errors
///
/// Returns [`Error::NotRoot`] if the process is not root, and
/// [`Error::Command`] if `files` is empty, a file is not absolute, the
/// priority is not between 1 and 999, or `semodule` fails.
pub fn install_modules(_token: &Token<impl Set>, priority: u16, files: &[&Path]) -> Result<(), Error> {
    run("install SELinux modules", command::install(priority, files)).map(drop)
}

/// Removes modules at `priority` (`semodule -X <priority> -r <name>...`). A
/// module of the same name at another priority stays, and the remove fails
/// if none is at `priority`.
///
/// # Capabilities
///
/// As [`install_modules`].
///
/// # Errors
///
/// Returns [`Error::NotRoot`] if the process is not root, and
/// [`Error::Command`] if `names` is empty, a name holds characters other
/// than letters, digits, `_`, `-` and `.`, the priority is out of range, or
/// `semodule` fails.
pub fn remove_modules(_token: &Token<impl Set>, priority: u16, names: &[&str]) -> Result<(), Error> {
    run("remove SELinux modules", command::remove(priority, names)).map(drop)
}

/// Lists every module in the policy store, at every priority
/// (`semodule -lfull`).
///
/// # Capabilities
///
/// - None.
/// - Needs root's user ID: the store is readable by root only.
/// - Reads the policy store under `/var/lib/selinux`.
///
/// # Errors
///
/// Returns [`Error::NotRoot`] if the process is not root,
/// [`Error::Command`] if `semodule` fails, and [`Error::List`] if its
/// output is not a module list.
pub fn installed_modules(_token: &Token<impl Set>) -> Result<Vec<InstalledModule>, Error> {
    let output = run("list SELinux modules", command::list())?;
    Ok(parse_full_list(&output.stdout_text())?)
}

/// Maps a login to an SELinux user (`semanage login -a -s <user> <login>`).
///
/// # Capabilities
///
/// - None, as [`install_modules`].
/// - Needs root's user ID, and a domain that may enter `semanage_exec_t`.
/// - Writes `seusers` under `/etc/selinux/<policy>` and the policy store
///   under `/var/lib/selinux`.
///
/// # Errors
///
/// Returns [`Error::NotRoot`] if the process is not root, and
/// [`Error::Command`] if a name could be read as an option or `semanage`
/// fails, for example because the login is already mapped.
pub fn map_login(_token: &Token<impl Set>, login: &str, selinux_user: &str) -> Result<(), Error> {
    run("map an SELinux login", command::map_login(login, selinux_user)).map(drop)
}

/// Removes a login mapping (`semanage login -d <login>`).
///
/// # Capabilities
///
/// As [`map_login`].
///
/// # Errors
///
/// Returns [`Error::NotRoot`] if the process is not root, and
/// [`Error::Command`] if the name could be read as an option or `semanage`
/// fails, for example because the login has no mapping.
pub fn unmap_login(_token: &Token<impl Set>, login: &str) -> Result<(), Error> {
    run("unmap an SELinux login", command::unmap_login(login)).map(drop)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use forma_privilege::{NoCapabilities, acquire};

    use super::*;

    #[test]
    fn nothing_runs_without_root() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let token = acquire::<NoCapabilities>().unwrap();
        let not_root = |result: Result<(), Error>| matches!(result, Err(Error::NotRoot { .. }));
        assert!(not_root(install_modules(&token, 350, &[Path::new("/a.cil")])));
        assert!(not_root(remove_modules(&token, 350, &["a"])));
        assert!(not_root(map_login(&token, "a", "user_u")));
        assert!(not_root(unmap_login(&token, "a")));
        assert!(matches!(installed_modules(&token), Err(Error::NotRoot { .. })));
    }
}
