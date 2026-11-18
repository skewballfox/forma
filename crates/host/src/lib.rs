//! The real host, as the planner sees it. Everything here only reads.
//!
//! The `forma` binary plans against [`LiveHost`]. It is a library of its own
//! so the VM tests can check each reading against what `forma_user::admin`
//! and `forma_selinux_module::admin` wrote.

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use forma_plan::{HostGroup, HostPath, HostUser, HostView};
use forma_privilege::{NoCapabilities, acquire};
use forma_selinux_module::admin as selinux_admin;
use forma_selinux_module::list::InstalledModule;
use forma_user::id::Uid;
use forma_user::lookup;
use forma_user::name::{GroupName, UserName};
use forma_user::path::AbsPath;
use forma_user::perm::{self, Qualifier};
use thiserror::Error;

/// Something the host holds could not be read.
#[derive(Debug, Error)]
pub enum Error {
    /// The token for the SELinux read could not be taken.
    #[error(transparent)]
    Privilege(#[from] forma_privilege::Error),
    /// `semodule` could not list the policy store, though the process runs
    /// as root.
    #[error("cannot list the SELinux modules: {0}")]
    SeLinux(#[from] selinux_admin::Error),
}

/// Reads the running system. A lookup that fails counts as "not there":
/// the planner then plans the change, and `apply` fails on it with the
/// real error.
///
/// The SELinux module store is the exception. Only root can list it, so
/// [`LiveHost::read`] lists it once, through `forma_selinux_module::admin`,
/// and a process that is not root gets a host whose module list is
/// unreadable ([`LiveHost::unread`]): it plans as if no module were
/// installed, as `forma plan` does without the root ledger, and says so. An
/// executor must refuse such a host rather than act on it: the check that
/// stops forma replacing a module it does not own (architecture 5.9) needs
/// the real list.
pub struct LiveHost {
    /// Every installed module, or `None` if the process could not list them.
    modules: Option<Vec<InstalledModule>>,
}

impl LiveHost {
    /// Reads what only root can read, once: the SELinux module store, when
    /// SELinux is on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SeLinux`] if the process runs as root and `semodule`
    /// still cannot list the store. Not being root is not an error; see
    /// [`LiveHost::unread`].
    ///
    /// # Capabilities
    ///
    /// None. Needs root's user ID for the module list, as
    /// `forma_selinux_module::admin::installed_modules`.
    pub fn read() -> Result<Self, Error> {
        if !selinux_enabled() {
            return Ok(Self { modules: Some(Vec::new()) });
        }
        match selinux_admin::installed_modules(&acquire::<NoCapabilities>()?) {
            Ok(modules) => Ok(Self { modules: Some(modules) }),
            Err(selinux_admin::Error::NotRoot { .. }) => Ok(Self { modules: None }),
            Err(error) => Err(error.into()),
        }
    }

    /// Names what [`LiveHost::read`] could not read because the process is
    /// not root. The plan treats each as empty.
    #[must_use]
    pub fn unread(&self) -> Vec<&'static str> {
        if self.modules.is_none() {
            vec!["the SELinux module store"]
        } else {
            Vec::new()
        }
    }
}

fn selinux_enabled() -> bool {
    Path::new("/sys/fs/selinux/enforce").exists()
}

impl HostView for LiveHost {
    fn user(&self, name: &str) -> Option<HostUser> {
        let user = lookup::user(&UserName::new(name).ok()?).ok()??;
        Some(HostUser {
            uid: user.uid().as_raw(),
            gid: user.gid().as_raw(),
        })
    }

    fn group(&self, name: &str) -> Option<HostGroup> {
        let group = lookup::group(&GroupName::new(name).ok()?).ok()??;
        Some(HostGroup {
            gid: group.info().gid().as_raw(),
            members: group.info().members().to_vec(),
        })
    }

    fn has_sub_ids(&self, user: &str) -> bool {
        std::fs::read_to_string("/etc/subuid")
            .is_ok_and(|text| text.lines().any(|line| line.split(':').next() == Some(user)))
    }

    fn linger(&self, user: &str) -> bool {
        // logind keeps one empty file per lingering user.
        Path::new("/var/lib/systemd/linger").join(user).exists()
    }

    fn path(&self, path: &Path) -> Option<HostPath> {
        let metadata = std::fs::symlink_metadata(path).ok()?;
        Some(HostPath {
            uid: metadata.uid(),
            gid: metadata.gid(),
        })
    }

    fn has_acl_user(&self, path: &Path, uid: u32) -> bool {
        let read = || {
            let relative = AbsPath::new(path).ok()?.relative()?;
            let root = Dir::open_ambient_dir("/", ambient_authority()).ok()?;
            let (_, acl) = perm::read(&root, &relative).ok()?;
            acl.entry(Qualifier::User(Uid::from_raw(uid)))
        };
        read().is_some()
    }

    fn selinux_enabled(&self) -> bool {
        selinux_enabled()
    }

    fn selinux_module(&self, name: &str) -> Vec<u16> {
        self.modules
            .iter()
            .flatten()
            .filter(|module| module.name == name)
            .map(|module| module.priority)
            .collect()
    }

    fn selinux_login(&self, user: &str) -> Option<String> {
        let policy_type = std::fs::read_to_string("/etc/selinux/config")
            .ok()?
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("SELINUXTYPE=")
                    .map(|kind| kind.trim().to_owned())
            })?;
        // Local mappings: one `login:selinux_user:range` line each.
        let seusers = std::fs::read_to_string(format!("/etc/selinux/{policy_type}/seusers")).ok()?;
        seusers.lines().find_map(|line| {
            let mut fields = line.split(':');
            (fields.next() == Some(user))
                .then(|| fields.next().map(str::to_owned))
                .flatten()
        })
    }
}
