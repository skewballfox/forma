//! The real host, as the planner sees it. Everything here only reads.

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use forma_plan::{HostGroup, HostPath, HostUser, HostView};
use forma_user::id::Uid;
use forma_user::lookup;
use forma_user::name::{GroupName, UserName};
use forma_user::path::AbsPath;
use forma_user::perm::{self, Qualifier};

/// Reads the running system. A lookup that fails counts as "not there":
/// the planner then plans the change, and `apply` fails on it with the
/// real error.
pub struct LiveHost;

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
        Path::new("/sys/fs/selinux/enforce").exists()
    }

    fn selinux_module(&self, name: &str) -> Vec<u16> {
        // The policy store keeps one directory per priority and module. Only
        // root can list it; for anyone else no module is visible.
        let Ok(stores) = std::fs::read_dir("/var/lib/selinux") else {
            return Vec::new();
        };
        stores
            .filter_map(Result::ok)
            .filter_map(|store| std::fs::read_dir(store.path().join("active/modules")).ok())
            .flatten()
            .filter_map(Result::ok)
            .filter(|priority| priority.path().join(name).exists())
            .filter_map(|priority| priority.file_name().to_str()?.parse().ok())
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
