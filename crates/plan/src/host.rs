//! A read-only view of the host, as the planner needs it.
//!
//! The planner never looks at the host itself. It asks a [`HostView`], so
//! tests can plan against a host that exists only in memory.

use std::path::Path;

/// An account on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUser {
    /// Its user ID.
    pub uid: u32,
    /// The ID of its primary group.
    pub gid: u32,
}

/// A group on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostGroup {
    /// Its group ID.
    pub gid: u32,
    /// The accounts listed as its members.
    pub members: Vec<String>,
}

/// A file or directory on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPath {
    /// The owner's user ID.
    pub uid: u32,
    /// The group ID.
    pub gid: u32,
}

/// What the planner can ask about the host. No method changes anything.
pub trait HostView {
    /// Returns an account, looked up by name through NSS.
    fn user(&self, name: &str) -> Option<HostUser>;
    /// Returns a group, looked up by name through NSS.
    fn group(&self, name: &str) -> Option<HostGroup>;
    /// Says whether an account has a sub-ID range.
    fn has_sub_ids(&self, user: &str) -> bool;
    /// Says whether linger is on for an account.
    fn linger(&self, user: &str) -> bool;
    /// Returns a file or directory, without following a final symlink.
    fn path(&self, path: &Path) -> Option<HostPath>;
    /// Says whether a directory's ACL has a named entry for a user.
    fn has_acl_user(&self, path: &Path, uid: u32) -> bool;
    /// Says whether SELinux is on.
    fn selinux_enabled(&self) -> bool;
    /// Returns the priorities at which an SELinux module of this name is installed.
    fn selinux_module(&self, name: &str) -> Vec<u16>;
    /// Returns the SELinux user a login is mapped to, if it has a mapping of its own.
    fn selinux_login(&self, user: &str) -> Option<String>;
}

/// A host that exists only in memory, for tests.
#[cfg(any(test, feature = "test-support"))]
pub mod fake {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    use super::{HostGroup, HostPath, HostUser, HostView};
    use crate::action::{Action, Principal};

    /// An in-memory host. Fields are public so a test can set any state.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct FakeHost {
        /// Accounts by name.
        pub users: BTreeMap<String, HostUser>,
        /// Groups by name.
        pub groups: BTreeMap<String, HostGroup>,
        /// Accounts with a sub-ID range.
        pub sub_ids: BTreeSet<String>,
        /// Accounts with linger on.
        pub linger: BTreeSet<String>,
        /// Files and directories.
        pub paths: BTreeMap<PathBuf, HostPath>,
        /// Named-user ACL entries, as directory and user ID.
        pub acl_users: BTreeSet<(PathBuf, u32)>,
        /// Whether SELinux is on.
        pub selinux: bool,
        /// Installed SELinux modules, as name and priority.
        pub modules: BTreeSet<(String, u16)>,
        /// SELinux login mappings.
        pub logins: BTreeMap<String, String>,
        /// The next ID the host hands out.
        pub next_id: u32,
    }

    impl FakeHost {
        /// A host with the groups a Fedora system has (`render`, `tss`),
        /// SELinux on, and IDs handed out from 900.
        #[must_use]
        pub fn fedora() -> Self {
            let mut host = Self {
                selinux: true,
                next_id: 900,
                ..Self::default()
            };
            for (name, gid) in [("render", 105), ("tss", 59)] {
                host.groups.insert(
                    name.to_owned(),
                    HostGroup {
                        gid,
                        members: Vec::new(),
                    },
                );
            }
            host
        }

        fn id(&mut self) -> u32 {
            self.next_id += 1;
            self.next_id - 1
        }

        fn id_of(&self, principal: &Principal, user: bool) -> u32 {
            match principal {
                Principal::Root => 0,
                Principal::Named(name) if user => self.users.get(name).map_or(u32::MAX, |user| user.uid),
                Principal::Named(name) => self.groups.get(name).map_or(u32::MAX, |group| group.gid),
            }
        }

        /// Changes the host the way the real action would, as far as the
        /// planner can see. Lets a test plan, "apply", and plan again.
        pub fn perform(&mut self, action: &Action) {
            match action {
                Action::CreateGroup { name, .. } => {
                    let gid = self.id();
                    self.groups.insert(
                        name.clone(),
                        HostGroup {
                            gid,
                            members: Vec::new(),
                        },
                    );
                }
                Action::DeleteGroup { name } => {
                    self.groups.remove(name);
                }
                Action::CreateUser { name, home, groups } => {
                    let uid = self.id();
                    self.groups.insert(
                        name.clone(),
                        HostGroup {
                            gid: uid,
                            members: Vec::new(),
                        },
                    );
                    self.users.insert(name.clone(), HostUser { uid, gid: uid });
                    for group in groups {
                        self.groups
                            .entry(group.clone())
                            .or_insert(HostGroup {
                                gid: 0,
                                members: Vec::new(),
                            })
                            .members
                            .push(name.clone());
                    }
                    if let Some(home) = home {
                        self.paths.insert(home.clone(), HostPath { uid, gid: uid });
                    }
                }
                Action::DeleteUser { name } => {
                    self.users.remove(name);
                    self.groups.remove(name);
                    for group in self.groups.values_mut() {
                        group.members.retain(|member| member != name);
                    }
                }
                Action::AddMember { user, group } => {
                    if let Some(group) = self.groups.get_mut(group) {
                        group.members.push(user.clone());
                    }
                }
                Action::RemoveMember { user, group } => {
                    if let Some(group) = self.groups.get_mut(group) {
                        group.members.retain(|member| member != user);
                    }
                }
                Action::AddSubIds { user, .. } => {
                    self.sub_ids.insert(user.clone());
                }
                Action::RemoveSubIds { user } => {
                    self.sub_ids.remove(user);
                }
                other => self.perform_on_files(other),
            }
        }

        /// The actions on files, directories, linger and SELinux.
        fn perform_on_files(&mut self, action: &Action) {
            match action {
                Action::WriteFile { path, .. } => {
                    self.paths.insert(path.clone(), HostPath { uid: 0, gid: 0 });
                }
                Action::RemovePath { path } => {
                    self.paths.remove(path);
                }
                Action::EnableLinger { user } => {
                    self.linger.insert(user.clone());
                }
                Action::DisableLinger { user } => {
                    self.linger.remove(user);
                }
                Action::CreateDir { path, owner, group, .. } => {
                    let entry = HostPath {
                        uid: self.id_of(owner, true),
                        gid: self.id_of(group, false),
                    };
                    self.paths.insert(path.clone(), entry);
                }
                Action::SetGroup { path, group } => {
                    let gid = self.groups.get(group).map_or(u32::MAX, |group| group.gid);
                    if let Some(entry) = self.paths.get_mut(path) {
                        entry.gid = gid;
                    }
                }
                Action::RestoreOwner { path, uid, gid } => {
                    if let Some(entry) = self.paths.get_mut(path) {
                        *entry = HostPath { uid: *uid, gid: *gid };
                    }
                }
                Action::GrantTraverse { path, user } => {
                    if let Some(user) = self.users.get(user) {
                        self.acl_users.insert((path.clone(), user.uid));
                    }
                }
                Action::RevokeAcl { path, id, .. } => {
                    self.acl_users.remove(&(path.clone(), *id));
                }
                Action::InstallSeLinuxModule { name, priority, .. } => {
                    self.modules.insert((name.clone(), *priority));
                }
                Action::RemoveSeLinuxModule { name, priority } => {
                    self.modules.remove(&(name.clone(), *priority));
                }
                Action::MapSeLinuxLogin { user } => {
                    self.logins.insert(user.clone(), "user_u".to_owned());
                }
                Action::UnmapSeLinuxLogin { user } => {
                    self.logins.remove(user);
                }
                Action::WaitForSocket { user } => {
                    if let Some(uid) = self.users.get(user).map(|user| user.uid) {
                        let socket = PathBuf::from(format!("/run/user/{uid}/materia/materia.sock"));
                        self.paths.insert(socket, HostPath { uid, gid: uid });
                    }
                }
                _ => {}
            }
        }
    }

    impl HostView for FakeHost {
        fn user(&self, name: &str) -> Option<HostUser> {
            self.users.get(name).cloned()
        }

        fn group(&self, name: &str) -> Option<HostGroup> {
            self.groups.get(name).cloned()
        }

        fn has_sub_ids(&self, user: &str) -> bool {
            self.sub_ids.contains(user)
        }

        fn linger(&self, user: &str) -> bool {
            self.linger.contains(user)
        }

        fn path(&self, path: &Path) -> Option<HostPath> {
            self.paths.get(path).copied()
        }

        fn has_acl_user(&self, path: &Path, uid: u32) -> bool {
            self.acl_users.contains(&(path.to_path_buf(), uid))
        }

        fn selinux_enabled(&self) -> bool {
            self.selinux
        }

        fn selinux_module(&self, name: &str) -> Vec<u16> {
            self.modules
                .iter()
                .filter(|(module, _)| module == name)
                .map(|(_, priority)| *priority)
                .collect()
        }

        fn selinux_login(&self, user: &str) -> Option<String> {
            self.logins.get(user).cloned()
        }
    }
}
