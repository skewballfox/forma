//! The actions `forma apply` can take, and the order they run in.
//!
//! This module only describes actions. Nothing here changes the host
//! (`docs/architecture.md` 5.4).

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use forma_ledger::{AclWho, HOST, Item, Key};
use forma_privilege::{Capabilities, Capability};

/// Where an action sits in a run. Stages run in this order when forma
/// makes things, and in reverse when it removes them.
///
/// An enum makes a wrong order a type error rather than a wrong number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    /// Groups: accounts join them.
    Groups,
    /// Accounts, and memberships of accounts that already exist.
    Users,
    /// Sub-ID ranges.
    SubIds,
    /// The account materia's configuration and unit, and the other units
    /// forma installs. They go before linger, so a user manager finds them
    /// when it first starts.
    ManagerFiles,
    /// Linger, which starts each account's user manager.
    Linger,
    /// Directories, and the grant on each staging directory.
    Directories,
    /// ACL entries on the directories above.
    Acls,
    /// Each account's `policy.json` and `containers.conf`.
    TrustPolicy,
    /// SELinux modules and login mappings.
    SeLinux,
    /// The wait for each account materia's socket. Last: root materia asks
    /// the account to install Quadlets right after `apply` returns.
    SocketWait,
}

/// Who owns a file or directory forma makes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Principal {
    /// Root, user or group ID 0.
    Root,
    /// An account, or the group with that name. Forma resolves the ID when
    /// it acts: the account may not exist when the plan is made.
    Named(String),
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => f.write_str("root"),
            Self::Named(name) => f.write_str(name),
        }
    }
}

/// What a file forma writes is for. The executor renders the text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FilePurpose {
    /// `/etc/forma/materia/<account>.toml`.
    AccountMateriaConfig {
        /// The account.
        account: String,
    },
    /// A unit in `/etc/systemd/user`.
    UserUnit {
        /// The unit's name.
        unit: &'static str,
    },
    /// A link in `/etc/systemd/user/<target>.wants/` that starts a unit.
    UnitWant {
        /// The unit's name.
        unit: &'static str,
        /// The target.
        target: &'static str,
    },
    /// An account's `policy.json`.
    Policy {
        /// The account.
        account: String,
    },
    /// An account's `containers.conf`.
    ContainersConf {
        /// The account.
        account: String,
    },
}

/// One change to the host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    /// Create a group.
    CreateGroup {
        /// Its name.
        name: String,
        /// Whether its ID comes from the system range.
        system: bool,
    },
    /// Delete a group forma created.
    DeleteGroup {
        /// Its name.
        name: String,
    },
    /// Create a system account, with a group of its own name.
    CreateUser {
        /// Its name.
        name: String,
        /// Its home directory, if it has one.
        home: Option<PathBuf>,
        /// Its supplementary groups.
        groups: Vec<String>,
    },
    /// Delete an account forma created. Its home is kept (decision D6).
    DeleteUser {
        /// Its name.
        name: String,
    },
    /// Add an existing account to a group.
    AddMember {
        /// The account.
        user: String,
        /// The group.
        group: String,
    },
    /// Remove an account from a group forma added it to.
    RemoveMember {
        /// The account.
        user: String,
        /// The group.
        group: String,
    },
    /// Give an account a sub-ID range.
    AddSubIds {
        /// The account.
        user: String,
        /// How many IDs.
        count: u32,
    },
    /// Remove an account's sub-ID ranges.
    RemoveSubIds {
        /// The account.
        user: String,
    },
    /// Write a file forma owns whole.
    WriteFile {
        /// The file.
        path: PathBuf,
        /// What it is for.
        purpose: FilePurpose,
    },
    /// Remove a file or an empty directory forma made.
    RemovePath {
        /// The file or directory.
        path: PathBuf,
    },
    /// Turn linger on.
    EnableLinger {
        /// The account.
        user: String,
    },
    /// Turn linger off and wait for the user manager to stop
    /// (`forma_user::admin::systemd::linger::disable_and_wait`).
    DisableLinger {
        /// The account.
        user: String,
    },
    /// Restart an account's user manager, which was running before forma
    /// installed its units. This stops the account's containers once.
    RestartUserManager {
        /// The account.
        user: String,
    },
    /// Create a directory.
    CreateDir {
        /// The directory.
        path: PathBuf,
        /// Its owner.
        owner: Principal,
        /// Its group.
        group: Principal,
        /// Its mode.
        mode: u32,
        /// Whether the directory must exist before linger starts the
        /// account's user manager. True for the directories in an account's
        /// home that forma owns: a program the manager starts could
        /// otherwise create them first, and forma never adopts.
        before_linger: bool,
    },
    /// Set the group of a directory forma did not create, so that group can
    /// read it. Used for an account's staging directory.
    SetGroup {
        /// The directory.
        path: PathBuf,
        /// The group.
        group: String,
    },
    /// Set the owner and group of a path back to what they were.
    RestoreOwner {
        /// The path.
        path: PathBuf,
        /// The user ID to restore.
        uid: u32,
        /// The group ID to restore.
        gid: u32,
    },
    /// Let an account pass through a directory, with an `x`-only ACL entry
    /// on it (and on any directory above it the account cannot pass). The
    /// entry is on `path` itself: the executor calls
    /// `forma_user::admin::perm::grant_traverse_through(path)`, not
    /// `grant_traverse(path)`, which leaves `path` alone.
    GrantTraverse {
        /// The directory.
        path: PathBuf,
        /// The account.
        user: String,
    },
    /// Remove an ACL entry forma added.
    RevokeAcl {
        /// The file.
        path: PathBuf,
        /// Whether the entry names a user or a group.
        who: AclWho,
        /// The user or group ID.
        id: u32,
    },
    /// Install an SELinux module at forma's priority.
    InstallSeLinuxModule {
        /// The module's name.
        name: String,
        /// The priority.
        priority: u16,
        /// The source file, inside the component.
        source: String,
    },
    /// Remove an SELinux module forma installed.
    RemoveSeLinuxModule {
        /// The module's name.
        name: String,
        /// The priority it is installed at.
        priority: u16,
    },
    /// Map an account to the SELinux user `user_u`.
    MapSeLinuxLogin {
        /// The account.
        user: String,
    },
    /// Remove an SELinux login mapping.
    UnmapSeLinuxLogin {
        /// The account.
        user: String,
    },
    /// Wait until an account materia's socket exists.
    WaitForSocket {
        /// The account.
        user: String,
    },
}

/// What shadow-utils needs to change the account databases: to write
/// `/etc/shadow` and `/etc/gshadow` (mode `0000`), and to leave an audit
/// record. Without `CAP_AUDIT_WRITE` the tools still succeed, but write no
/// record, so it is kept for the audit trail (VM, 2026-11-18).
const ACCOUNT_FILES: Capabilities = Capabilities::of(&[Capability::DacOverride, Capability::AuditWrite]);
/// What `useradd` needs besides, to create a home and give it to the account.
const ACCOUNTS_WITH_HOME: Capabilities =
    ACCOUNT_FILES.union(Capabilities::of(&[Capability::Chown, Capability::Fowner]));
/// What `semodule` and `semanage login` need: nothing. The policy store is
/// root's, so root writes it as its owner, and loading policy is SELinux's
/// `load_policy` permission, not `CAP_MAC_ADMIN`. They need root and a domain
/// that may enter `semanage_exec_t`, such as `unconfined_t`, which `run0`
/// keeps (VM, in `unconfined_t` with no capabilities, 2026-11-18).
const SELINUX: Capabilities = Capabilities::NONE;

impl Action {
    /// Returns where the action sits in a run.
    #[must_use]
    pub fn stage(&self) -> Stage {
        match self {
            Self::CreateGroup { .. } | Self::DeleteGroup { .. } => Stage::Groups,
            Self::CreateUser { .. } | Self::DeleteUser { .. } | Self::AddMember { .. } | Self::RemoveMember { .. } => {
                Stage::Users
            }
            Self::AddSubIds { .. } | Self::RemoveSubIds { .. } => Stage::SubIds,
            Self::WriteFile { purpose, .. } => match purpose {
                FilePurpose::Policy { .. } | FilePurpose::ContainersConf { .. } => Stage::TrustPolicy,
                _ => Stage::ManagerFiles,
            },
            Self::EnableLinger { .. } | Self::DisableLinger { .. } | Self::RestartUserManager { .. } => Stage::Linger,
            Self::CreateDir {
                before_linger: true, ..
            } => Stage::ManagerFiles,
            Self::CreateDir { .. } | Self::SetGroup { .. } | Self::RestoreOwner { .. } | Self::RemovePath { .. } => {
                Stage::Directories
            }
            Self::GrantTraverse { .. } | Self::RevokeAcl { .. } => Stage::Acls,
            Self::InstallSeLinuxModule { .. }
            | Self::RemoveSeLinuxModule { .. }
            | Self::MapSeLinuxLogin { .. }
            | Self::UnmapSeLinuxLogin { .. } => Stage::SeLinux,
            Self::WaitForSocket { .. } => Stage::SocketWait,
        }
    }

    /// Says whether the action removes something forma made.
    #[must_use]
    pub fn is_removal(&self) -> bool {
        matches!(
            self,
            Self::DeleteGroup { .. }
                | Self::DeleteUser { .. }
                | Self::RemoveMember { .. }
                | Self::RemoveSubIds { .. }
                | Self::RemovePath { .. }
                | Self::DisableLinger { .. }
                | Self::RestoreOwner { .. }
                | Self::RevokeAcl { .. }
                | Self::RemoveSeLinuxModule { .. }
                | Self::UnmapSeLinuxLogin { .. }
        )
    }

    /// Returns the Linux capabilities the action needs. These are the
    /// expected values of architecture 3.4; spike 0(d) confirms them.
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        match self {
            Self::CreateUser { .. } => ACCOUNTS_WITH_HOME,
            // A deleted account's home is kept (decision D6), so nothing
            // there needs CAP_CHOWN or CAP_FOWNER.
            Self::CreateGroup { .. }
            | Self::DeleteGroup { .. }
            | Self::DeleteUser { .. }
            | Self::AddMember { .. }
            | Self::RemoveMember { .. } => ACCOUNT_FILES,
            Self::AddSubIds { .. } | Self::RemoveSubIds { .. } | Self::RemovePath { .. } => {
                Capabilities::of(&[Capability::DacOverride])
            }
            // An account owns its home, so root needs to write past its mode.
            Self::WriteFile { purpose, .. } => match purpose {
                FilePurpose::Policy { .. } | FilePurpose::ContainersConf { .. } => {
                    Capabilities::of(&[Capability::DacOverride])
                }
                _ => Capabilities::NONE,
            },
            Self::CreateDir { .. } => {
                Capabilities::of(&[Capability::Chown, Capability::Fowner, Capability::DacOverride])
            }
            Self::SetGroup { .. } | Self::RestoreOwner { .. } => Capabilities::of(&[Capability::Chown]),
            Self::InstallSeLinuxModule { .. }
            | Self::RemoveSeLinuxModule { .. }
            | Self::MapSeLinuxLogin { .. }
            | Self::UnmapSeLinuxLogin { .. } => SELINUX,
            // Every directory the plan grants on is root's (the store root
            // and the directories above it), and an owner may set an ACL. A
            // grant on another owner's directory fails rather than widen this.
            // logind and systemd decide by user ID, not by capability.
            Self::GrantTraverse { .. }
            | Self::RevokeAcl { .. }
            | Self::EnableLinger { .. }
            | Self::DisableLinger { .. }
            | Self::RestartUserManager { .. }
            | Self::WaitForSocket { .. } => Capabilities::NONE,
        }
    }

    /// Says whether the action needs user ID 0 itself, beyond capabilities.
    /// polkit decides logind and systemd calls by user ID.
    #[must_use]
    pub fn needs_root_user(&self) -> bool {
        !matches!(self, Self::WaitForSocket { .. })
    }

    /// Returns the key of the ledger entry the action makes or removes, if
    /// it has one.
    #[must_use]
    pub fn ledger_key(&self) -> Option<Key> {
        Some(match self {
            Self::CreateGroup { name, .. } | Self::DeleteGroup { name } => Key::group(name),
            Self::CreateUser { name, .. } | Self::DeleteUser { name } => Key::user(name),
            Self::AddMember { user, group } | Self::RemoveMember { user, group } => Key::membership(user, group),
            Self::AddSubIds { user, .. } | Self::RemoveSubIds { user } => Key::sub_ids(user),
            Self::WriteFile { path, .. } | Self::CreateDir { path, .. } | Self::RemovePath { path } => Key::path(path),
            Self::EnableLinger { user } | Self::DisableLinger { user } => Key::linger(user),
            Self::SetGroup { path, .. } | Self::RestoreOwner { path, .. } => Key::owner(path),
            Self::RevokeAcl { path, who, id } => Key::acl_grant(path, *who, *id),
            Self::InstallSeLinuxModule { name, .. } | Self::RemoveSeLinuxModule { name, .. } => {
                Key::selinux_module(name)
            }
            Self::MapSeLinuxLogin { user } | Self::UnmapSeLinuxLogin { user } => Key::selinux_login(user),
            // A traverse grant is recorded per directory the account could
            // not already pass through, under the account's user ID.
            Self::GrantTraverse { .. } | Self::RestartUserManager { .. } | Self::WaitForSocket { .. } => return None,
        })
    }

    /// Returns the action that removes what a ledger entry records.
    #[must_use]
    pub fn removal_of(item: &Item) -> Self {
        match item {
            Item::Group { name, .. } => Self::DeleteGroup { name: name.clone() },
            Item::User { name, .. } => Self::DeleteUser { name: name.clone() },
            Item::Membership { user, group } => Self::RemoveMember {
                user: user.clone(),
                group: group.clone(),
            },
            Item::SubIds { user, .. } => Self::RemoveSubIds { user: user.clone() },
            Item::Linger { user } => Self::DisableLinger { user: user.clone() },
            // Forma sets a mode only on a directory it creates, so a
            // recorded mode goes with its path.
            Item::Directory { path }
            | Item::File { path, .. }
            | Item::ArchivedHome { path, .. }
            | Item::TrustKey { path, .. }
            | Item::Mode { path, .. } => Self::RemovePath { path: path.clone() },
            Item::Owner {
                path,
                previous_uid,
                previous_gid,
                ..
            } => Self::RestoreOwner {
                path: path.clone(),
                uid: *previous_uid,
                gid: *previous_gid,
            },
            Item::AclGrant { path, who, id, .. } => Self::RevokeAcl {
                path: path.clone(),
                who: *who,
                id: *id,
            },
            Item::SeLinuxModule { name, priority, .. } => Self::RemoveSeLinuxModule {
                name: name.clone(),
                priority: *priority,
            },
            Item::SeLinuxLogin { user, .. } => Self::UnmapSeLinuxLogin { user: user.clone() },
        }
    }
}

impl fmt::Display for Action {
    /// Writes the action the way materia and athanor write theirs: a verb,
    /// a kind and a name, such as `Create Group moonshine-input`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateGroup { name, .. } => write!(f, "Create Group {name}"),
            Self::DeleteGroup { name } => write!(f, "Delete Group {name}"),
            Self::CreateUser { name, home, groups } => {
                write!(f, "Create User {name}")?;
                if let Some(home) = home {
                    write!(f, " (home {})", home.display())?;
                }
                if !groups.is_empty() {
                    write!(f, " (groups {})", groups.join(", "))?;
                }
                Ok(())
            }
            Self::DeleteUser { name } => write!(f, "Delete User {name} (its home is kept)"),
            Self::AddMember { user, group } => write!(f, "Add User {user} to Group {group}"),
            Self::RemoveMember { user, group } => write!(f, "Remove User {user} from Group {group}"),
            Self::AddSubIds { user, count } => write!(f, "Add SubIds {user} ({count})"),
            Self::RemoveSubIds { user } => write!(f, "Remove SubIds {user}"),
            Self::WriteFile { path, .. } => write!(f, "Write File {}", path.display()),
            Self::RemovePath { path } => write!(f, "Remove Path {}", path.display()),
            Self::EnableLinger { user } => write!(f, "Enable Linger {user}"),
            Self::DisableLinger { user } => write!(f, "Disable Linger {user}"),
            Self::RestartUserManager { user } => {
                write!(f, "Restart User Manager {user} (stops the account's containers once)")
            }
            Self::CreateDir {
                path,
                owner,
                group,
                mode,
                ..
            } => {
                write!(f, "Create Directory {} ({owner}:{group} {mode:04o})", path.display())
            }
            Self::SetGroup { path, group } => write!(f, "Set Group {} ({group})", path.display()),
            Self::RestoreOwner { path, uid, gid } => write!(f, "Restore Owner {} ({uid}:{gid})", path.display()),
            Self::GrantTraverse { path, user } => write!(f, "Grant Traverse {} ({user})", path.display()),
            Self::RevokeAcl { path, who, id } => {
                let who = match who {
                    AclWho::User => "user",
                    AclWho::Group => "group",
                };
                write!(f, "Revoke Acl {} ({who} {id})", path.display())
            }
            Self::InstallSeLinuxModule { name, priority, .. } => {
                write!(f, "Install SELinux Module {name} (priority {priority})")
            }
            Self::RemoveSeLinuxModule { name, priority } => {
                write!(f, "Remove SELinux Module {name} (priority {priority})")
            }
            Self::MapSeLinuxLogin { user } => write!(f, "Map SELinux Login {user} (user_u)"),
            Self::UnmapSeLinuxLogin { user } => write!(f, "Unmap SELinux Login {user}"),
            Self::WaitForSocket { user } => write!(f, "Wait For Socket {user}"),
        }
    }
}

/// One action and who it is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The action.
    pub action: Action,
    /// The components the action is for, and [`HOST`] if the host itself
    /// needs it.
    pub needs: BTreeSet<String>,
}

impl Step {
    /// Returns who the step is for, as the plan prints it: component names
    /// separated by `, `, with `forma` for the host itself.
    #[must_use]
    pub fn label(&self) -> String {
        let mut names: Vec<&str> = self
            .needs
            .iter()
            .map(|need| if need == HOST { "forma" } else { need })
            .collect();
        names.sort_unstable();
        names.join(", ")
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A privileged action needs root or a Linux capability (architecture
        // glossary); most need both.
        write!(f, "({}) {}", self.label(), self.action)?;
        let capabilities = self.action.capabilities();
        match (self.action.needs_root_user(), capabilities.is_empty()) {
            (true, true) => write!(f, " [privileged: root]"),
            (true, false) => write!(f, " [privileged: root, {capabilities}]"),
            (false, false) => write!(f, " [privileged: {capabilities}]"),
            (false, true) => Ok(()),
        }
    }
}

/// Puts steps in the order they run: removals first, from the last stage
/// to the first, then everything else from the first stage to the last.
/// Steps of one stage keep the order they were planned in.
pub(crate) fn order(steps: &mut [Step]) {
    steps.sort_by_key(|step| {
        let stage = step.action.stage() as i16;
        if step.action.is_removal() {
            (0, -stage)
        } else {
            (1, stage)
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(action: Action) -> Step {
        Step {
            action,
            needs: BTreeSet::from(["moonshine".to_owned()]),
        }
    }

    #[test]
    fn a_step_prints_as_in_materia_with_its_privilege() {
        let group = step(Action::CreateGroup {
            name: "moonshine-input".into(),
            system: true,
        });
        assert_eq!(
            group.to_string(),
            "(moonshine) Create Group moonshine-input [privileged: root, CAP_AUDIT_WRITE, CAP_DAC_OVERRIDE]"
        );
        let module = step(Action::InstallSeLinuxModule {
            name: "moonshine_container".into(),
            priority: 350,
            source: "selinux/moonshine_container.cil".into(),
        });
        assert_eq!(
            module.to_string(),
            "(moonshine) Install SELinux Module moonshine_container (priority 350) [privileged: root]",
            "needs root's user ID, no capability"
        );
        let linger = step(Action::EnableLinger {
            user: "moonshine".into(),
        });
        assert_eq!(
            linger.to_string(),
            "(moonshine) Enable Linger moonshine [privileged: root]",
            "needs root's user ID, no capability"
        );
        let wait = step(Action::WaitForSocket {
            user: "moonshine".into(),
        });
        assert_eq!(wait.to_string(), "(moonshine) Wait For Socket moonshine", "needs nothing");
    }

    #[test]
    fn shared_and_host_steps_name_everyone() {
        let shared = Step {
            action: Action::EnableLinger {
                user: "moonshine".into(),
            },
            needs: BTreeSet::from(["nvidia-driver".to_owned(), "moonshine".to_owned(), HOST.to_owned()]),
        };
        assert_eq!(shared.label(), "forma, moonshine, nvidia-driver");
    }

    #[test]
    fn the_account_materia_files_come_before_linger_and_the_socket_wait_last() {
        let user = "moonshine".to_owned();
        let mut steps: Vec<Step> = [
            Action::WaitForSocket { user: user.clone() },
            Action::MapSeLinuxLogin { user: user.clone() },
            Action::WriteFile {
                path: "/var/home/moonshine/.config/containers/policy.json".into(),
                purpose: FilePurpose::Policy { account: user.clone() },
            },
            Action::GrantTraverse {
                path: "/var/lib/forma/store".into(),
                user: user.clone(),
            },
            Action::SetGroup {
                path: "/var/lib/materia/delegate/accounts/moonshine".into(),
                group: user.clone(),
            },
            Action::EnableLinger { user: user.clone() },
            Action::WriteFile {
                path: "/etc/forma/materia/moonshine.toml".into(),
                purpose: FilePurpose::AccountMateriaConfig { account: user.clone() },
            },
            Action::AddSubIds {
                user: user.clone(),
                count: 65536,
            },
            Action::CreateUser {
                name: user.clone(),
                home: None,
                groups: Vec::new(),
            },
            Action::CreateGroup {
                name: "moonshine-input".into(),
                system: true,
            },
        ]
        .into_iter()
        .map(step)
        .collect();
        order(&mut steps);
        let stages: Vec<Stage> = steps.iter().map(|step| step.action.stage()).collect();
        assert_eq!(
            stages,
            [
                Stage::Groups,
                Stage::Users,
                Stage::SubIds,
                Stage::ManagerFiles,
                Stage::Linger,
                Stage::Directories,
                Stage::Acls,
                Stage::TrustPolicy,
                Stage::SeLinux,
                Stage::SocketWait,
            ]
        );
    }

    #[test]
    fn removal_runs_first_and_in_reverse() {
        let user = "old".to_owned();
        let mut steps: Vec<Step> = [
            Action::CreateGroup {
                name: "new".into(),
                system: true,
            },
            Action::DeleteGroup {
                name: "old-input".into(),
            },
            Action::DeleteUser { name: user.clone() },
            Action::DisableLinger { user: user.clone() },
            Action::RemoveSubIds { user: user.clone() },
            Action::UnmapSeLinuxLogin { user: user.clone() },
        ]
        .into_iter()
        .map(step)
        .collect();
        order(&mut steps);
        let text: Vec<String> = steps.iter().map(|step| step.action.to_string()).collect();
        assert_eq!(
            text,
            [
                "Unmap SELinux Login old",
                "Disable Linger old",
                "Remove SubIds old",
                "Delete User old (its home is kept)",
                "Delete Group old-input",
                "Create Group new",
            ]
        );
    }

    #[test]
    fn every_ledger_item_has_a_removal_with_the_same_key() {
        let items = [
            Item::Group {
                name: "g".into(),
                gid: Some(1),
            },
            Item::User {
                name: "u".into(),
                uid: Some(1),
                gid: Some(1),
            },
            Item::Membership {
                user: "u".into(),
                group: "g".into(),
            },
            Item::SubIds {
                user: "u".into(),
                start: 1,
                count: 2,
            },
            Item::Linger { user: "u".into() },
            Item::Directory { path: "/d".into() },
            Item::File {
                path: "/f".into(),
                sha256: None,
            },
            Item::Owner {
                path: "/o".into(),
                previous_uid: 0,
                previous_gid: 0,
                uid: 0,
                gid: 5,
            },
            Item::AclGrant {
                path: "/a".into(),
                who: AclWho::User,
                id: 7,
                perms: 1,
            },
            Item::SeLinuxModule {
                name: "m".into(),
                priority: 350,
                sha256: String::new(),
            },
            Item::SeLinuxLogin {
                user: "u".into(),
                selinux_user: "user_u".into(),
            },
        ];
        for item in items {
            let removal = Action::removal_of(&item);
            assert!(removal.is_removal(), "{removal}");
            assert_eq!(removal.ledger_key(), Some(item.key()), "{removal}");
        }
    }
}
