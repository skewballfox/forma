//! Desired state minus current state (`docs/architecture.md` 5.4).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use forma_build::BaseError;
use forma_config::types::{ImageRef, SigningBackend};
use forma_config::{Config, HostConfig, MateriaConfig, ModuleKind, Skipped};
use forma_ledger::{HOST, Item, Status, Store};
use forma_privilege::Capabilities;
use forma_quadlet::units::{
    ACCOUNT_MATERIA_CONFIG_DIR, CONSUMERS_GROUP, LOAD_PATH_UNIT, LOAD_SERVICE_UNIT, MATERIA_UNIT, USER_UNIT_DIR,
};
use forma_quadlet::{Finding, UnitKind};

use crate::action::{Action, FilePurpose, Principal, Step, order};
use crate::host::HostView;

/// Where images wait for the signer.
pub const STAGING_ROOT: &str = "/var/lib/forma/staging";

/// What a run is to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope<'a> {
    /// Make the host match the repository, for one component or for all.
    /// With `prune`, also remove what nothing asks for any more.
    Apply {
        /// The one component to act for, or `None` for all.
        component: Option<&'a str>,
        /// Whether to remove what nothing asks for.
        prune: bool,
    },
    /// Undo everything that only this component needs.
    Revert {
        /// The component.
        component: &'a str,
    },
    /// Undo everything forma has done. With `data`, kept homes go too.
    Purge {
        /// Whether to delete the homes forma kept.
        data: bool,
    },
}

/// What the planner works from.
pub struct Request<'a> {
    /// The checked configuration of this host.
    pub config: &'a Config,
    /// Materia's paths.
    pub materia: &'a MateriaConfig,
    /// The host's limits.
    pub limits: &'a HostConfig,
    /// The components forma skipped. An account one of them names is never
    /// removed (delegation 9).
    pub skipped: &'a [Skipped],
    /// What the run is to do.
    pub scope: Scope<'a>,
}

/// Something that stops `forma apply` before it changes anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// A target exists and the ledger does not record it. Forma never
    /// adopts (architecture 4.3, rule 4).
    ExistsNotOwned {
        /// The target.
        what: String,
        /// Who asked for it.
        wanted_by: String,
    },
    /// The ledger records an item, and the host shows another in its place
    /// (architecture 4.3, rule 3).
    LedgerMismatch {
        /// The item, as the ledger records it.
        recorded: String,
        /// What the host shows.
        found: String,
    },
    /// The last run stopped part way. `forma apply` settles this first.
    Unsettled {
        /// The item.
        item: String,
    },
    /// A unit of a component breaks one of forma's rules.
    Unit {
        /// The component.
        component: String,
        /// The rule and where it is broken.
        finding: Finding,
    },
    /// An image's Containerfile names a base forma cannot pull, or must not
    /// (architecture 5.6, "How forma pulls base images").
    BaseImage {
        /// The component.
        component: String,
        /// The image.
        image: String,
        /// The Containerfile, in the component's staged copy.
        containerfile: PathBuf,
        /// What is wrong.
        error: BaseError,
    },
    /// A component's staged copy could not be read.
    StagedUnreadable {
        /// The component.
        component: String,
        /// Why.
        reason: String,
    },
}

impl Problem {
    /// Returns the problem's stable name. For a unit, this is the name of
    /// the rule, such as `PullNotDisabled`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::ExistsNotOwned { .. } => "ExistsNotOwned",
            Self::LedgerMismatch { .. } => "LedgerMismatch",
            Self::Unsettled { .. } => "Unsettled",
            Self::Unit { finding, .. } => finding.code.as_str(),
            Self::BaseImage { error, .. } => error.code(),
            Self::StagedUnreadable { .. } => "StagedUnreadable",
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExistsNotOwned { what, wanted_by } => write!(
                f,
                "{what} already exists and forma did not create it ({wanted_by} asks for it); forma does not take \
                 over existing items. Remove it, or choose another name"
            ),
            Self::LedgerMismatch { recorded, found } => write!(
                f,
                "the ledger records {recorded}, but the host has {found}; forma does not guess which is right"
            ),
            Self::Unsettled { item } => {
                write!(
                    f,
                    "the last run stopped while changing {item}; run forma apply to settle it"
                )
            }
            Self::Unit { component, finding } => write!(f, "component {component}: {finding}"),
            Self::BaseImage {
                component,
                image,
                containerfile,
                error,
            } => write!(
                f,
                "component {component}, image {image}: {}: {error}",
                containerfile.display()
            ),
            Self::StagedUnreadable { component, reason } => {
                write!(f, "component {component}: its staged copy cannot be read: {reason}")
            }
        }
    }
}

/// What `forma apply` would do.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// The actions, in the order they run.
    pub steps: Vec<Step>,
    /// What stops the run. With any problem, `apply` changes nothing.
    pub problems: Vec<Problem>,
    /// What an administrator should know and that does not stop the run.
    pub warnings: Vec<String>,
}

impl Plan {
    /// Returns every capability the steps need. `forma apply` drops the rest.
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        self.steps
            .iter()
            .fold(Capabilities::NONE, |all, step| all.union(step.action.capabilities()))
    }
}

impl fmt::Display for Plan {
    /// Writes the plan in materia's layout: one numbered line per action.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.steps.is_empty() {
            writeln!(f, "Plan: nothing to do")?;
        } else {
            writeln!(f, "Plan:")?;
            for (index, step) in self.steps.iter().enumerate() {
                writeln!(f, "{}. {step}", index + 1)?;
            }
        }
        if !self.warnings.is_empty() {
            writeln!(f, "\nWarnings:")?;
            for warning in &self.warnings {
                writeln!(f, "- {warning}")?;
            }
        }
        if !self.problems.is_empty() {
            writeln!(f, "\nProblems (apply will change nothing until these are fixed):")?;
            for problem in &self.problems {
                writeln!(f, "- {}: {problem}", problem.code())?;
            }
        }
        Ok(())
    }
}

/// Everything the configuration asks for, whether or not it exists yet.
#[derive(Default)]
struct Wants {
    list: Vec<Step>,
}

impl Wants {
    /// Adds an action for `needs`. The same action asked twice is one
    /// action that both need.
    fn add(&mut self, action: Action, needs: &BTreeSet<String>) {
        match self.list.iter_mut().find(|step| step.action == action) {
            Some(step) => step.needs.extend(needs.iter().cloned()),
            None => self.list.push(Step {
                action,
                needs: needs.clone(),
            }),
        }
    }
}

fn names<'a>(names: impl IntoIterator<Item = &'a forma_config::types::ComponentName>) -> BTreeSet<String> {
    names.into_iter().map(ToString::to_string).collect()
}

/// The name of the module a source file installs: its file name without
/// the extension.
fn module_name(path: &str) -> &str {
    let file = path.rsplit('/').next().unwrap_or(path);
    file.rsplit_once('.').map_or(file, |(stem, _)| stem)
}

fn home_of(limits: &HostConfig, account: &str) -> PathBuf {
    limits.home_base.value.as_path().join(account)
}

/// Everything the configuration asks for, in the order of the stages.
fn wants(request: &Request<'_>, host: &dyn HostView, warnings: &mut Vec<String>) -> Wants {
    let mut wants = Wants::default();
    host_wants(request, host, &mut wants, warnings);
    let config = request.config;
    for used in config.groups() {
        wants.add(
            Action::CreateGroup {
                name: used.group.value.name.to_string(),
                system: used.group.value.system,
            },
            &names(used.declared_by.iter().copied()),
        );
    }

    let accounts = config.accounts();
    // The units are the same for every account; they stay while any account needs them.
    let every_account: BTreeSet<String> = accounts
        .iter()
        .flat_map(|used| names(used.declared_by.iter().chain(&used.runs).copied()))
        .collect();
    if !accounts.is_empty() {
        for unit in [MATERIA_UNIT, LOAD_PATH_UNIT, LOAD_SERVICE_UNIT] {
            wants.add(
                Action::WriteFile {
                    path: Path::new(USER_UNIT_DIR).join(unit),
                    purpose: FilePurpose::UserUnit { unit },
                },
                &every_account,
            );
        }
        for unit in [MATERIA_UNIT, LOAD_PATH_UNIT] {
            wants.add(
                Action::WriteFile {
                    path: Path::new(USER_UNIT_DIR).join("default.target.wants").join(unit),
                    purpose: FilePurpose::UnitWant {
                        unit,
                        target: "default.target",
                    },
                },
                &every_account,
            );
        }
    }

    for used in &accounts {
        account_wants(request, host, used, &mut wants, warnings);
    }
    if !accounts.is_empty() && !host.selinux_enabled() {
        warnings.push(
            "SELinux is off on this host, so a service account can change its own policy.json and containers.conf; \
             forma only detects it"
                .to_owned(),
        );
    }

    component_wants(request, host, &mut wants, warnings);
    wants
}

/// What the host needs whatever is installed: the builder, the signer and the store.
fn host_wants(request: &Request<'_>, host: &dyn HostView, wants: &mut Wants, warnings: &mut Vec<String>) {
    let settings = &request.config.settings;
    let host_needs = BTreeSet::from([HOST.to_owned()]);
    let builder = settings.builder.account.as_str();
    let signer = settings.signer.as_str();
    let store_root = settings.store_root.as_abs().as_path();

    // The host's own accounts and directories.
    wants.add(
        Action::CreateGroup {
            name: CONSUMERS_GROUP.to_owned(),
            system: true,
        },
        &host_needs,
    );
    wants.add(
        Action::CreateUser {
            name: builder.to_owned(),
            home: Some(home_of(request.limits, builder)),
            groups: Vec::new(),
        },
        &host_needs,
    );
    wants.add(
        Action::AddSubIds {
            user: builder.to_owned(),
            count: settings.builder.sub_ids.get(),
        },
        &host_needs,
    );
    // Builds and their timers run under the builder's user manager.
    wants.add(
        Action::EnableLinger {
            user: builder.to_owned(),
        },
        &host_needs,
    );
    // The signer reaches the TPM through /dev/tpmrm0 as a member of tss.
    let tss = settings.signing != SigningBackend::Software && host.group("tss").is_some();
    if settings.signing == SigningBackend::Tpm && !tss {
        warnings
            .push("Signing is \"tpm\", but this host has no tss group, so the signer cannot reach a TPM".to_owned());
    }
    wants.add(
        Action::CreateUser {
            name: signer.to_owned(),
            home: Some(home_of(request.limits, signer)),
            groups: if tss { vec!["tss".to_owned()] } else { Vec::new() },
        },
        &host_needs,
    );
    for (path, mode) in [(store_root, 0o700), (Path::new(STAGING_ROOT), 0o755)] {
        wants.add(
            Action::CreateDir {
                path: path.to_path_buf(),
                owner: Principal::Root,
                group: Principal::Root,
                mode,
                before_linger: false,
            },
            &host_needs,
        );
    }
    wants.add(
        Action::GrantTraverse {
            path: store_root.to_path_buf(),
            user: signer.to_owned(),
        },
        &host_needs,
    );
}

/// What one service account needs.
fn account_wants(
    request: &Request<'_>,
    host: &dyn HostView,
    used: &forma_config::AccountUse<'_>,
    wants: &mut Wants,
    warnings: &mut Vec<String>,
) {
    let signer = request.config.settings.signer.as_str();
    let store_root = request.config.settings.store_root.as_abs().as_path();
    let account = &used.account.value;
    let name = account.name.as_str();
    let needs = names(used.declared_by.iter().chain(&used.runs).copied());
    let delegated = !used.runs.is_empty();
    let home = account.home.then(|| home_of(request.limits, name));
    let mut groups: Vec<String> = account.member_of.iter().map(|group| group.value.to_string()).collect();
    groups.push(CONSUMERS_GROUP.to_owned());

    wants.add(
        Action::CreateUser {
            name: name.to_owned(),
            home: home.clone(),
            groups: groups.clone(),
        },
        &needs,
    );
    for group in groups {
        wants.add(
            Action::AddMember {
                user: name.to_owned(),
                group,
            },
            &needs,
        );
    }
    wants.add(
        Action::AddSubIds {
            user: name.to_owned(),
            count: account.sub_ids.get(),
        },
        &needs,
    );
    if delegated {
        wants.add(
            Action::WriteFile {
                path: Path::new(ACCOUNT_MATERIA_CONFIG_DIR).join(format!("{name}.toml")),
                purpose: FilePurpose::AccountMateriaConfig {
                    account: name.to_owned(),
                },
            },
            &needs,
        );
        wants.add(
            Action::SetGroup {
                path: request.materia.staging_dir(&account.name),
                group: name.to_owned(),
            },
            &needs,
        );
    }
    if account.linger {
        wants.add(Action::EnableLinger { user: name.to_owned() }, &needs);
    } else if delegated {
        warnings.push(format!(
            "account {name} has Linger = false, so its user manager and its materia start only at a login; \
             forma does not wait for its socket"
        ));
    }
    wants.add(
        Action::CreateDir {
            path: store_root.join(name),
            owner: Principal::Named(signer.to_owned()),
            group: Principal::Named(name.to_owned()),
            mode: 0o2750,
            before_linger: false,
        },
        &needs,
    );
    wants.add(
        Action::GrantTraverse {
            path: store_root.to_path_buf(),
            user: name.to_owned(),
        },
        &needs,
    );
    home_wants(name, home.as_deref(), &needs, wants, warnings);
    if host.selinux_enabled() {
        wants.add(Action::MapSeLinuxLogin { user: name.to_owned() }, &needs);
    }
    if delegated && account.linger {
        wants.add(Action::WaitForSocket { user: name.to_owned() }, &needs);
    }
}

/// What an account needs in its home: the directories above the protected
/// items, and the items themselves (architecture 5.9).
fn home_wants(
    name: &str,
    home: Option<&Path>,
    needs: &BTreeSet<String>,
    wants: &mut Wants,
    warnings: &mut Vec<String>,
) {
    match home {
        Some(home) => {
            let containers = home.join(".config/containers");
            for directory in [home.join(".config"), containers.clone()] {
                wants.add(
                    Action::CreateDir {
                        path: directory,
                        owner: Principal::Named(name.to_owned()),
                        group: Principal::Named(name.to_owned()),
                        mode: 0o700,
                        before_linger: true,
                    },
                    needs,
                );
            }
            // The protected items are root's (architecture 5.9).
            wants.add(
                Action::WriteFile {
                    path: containers.join("policy.json"),
                    purpose: FilePurpose::Policy {
                        account: name.to_owned(),
                    },
                },
                needs,
            );
            wants.add(
                Action::WriteFile {
                    path: containers.join("containers.conf"),
                    purpose: FilePurpose::ContainersConf {
                        account: name.to_owned(),
                    },
                },
                needs,
            );
            wants.add(
                Action::CreateDir {
                    path: containers.join("containers.conf.d"),
                    owner: Principal::Root,
                    group: Principal::Root,
                    mode: 0o755,
                    before_linger: false,
                },
                needs,
            );
        }
        None => warnings.push(format!(
            "account {name} has Home = false, so it has no policy.json and cannot load or run images"
        )),
    }
}

/// What each component needs for its images and its SELinux policy.
fn component_wants(request: &Request<'_>, host: &dyn HostView, wants: &mut Wants, warnings: &mut Vec<String>) {
    let settings = &request.config.settings;
    let builder = settings.builder.account.as_str();
    let signer = settings.signer.as_str();
    for component in &request.config.components {
        let needs = BTreeSet::from([component.name.to_string()]);
        for image in &component.forma.images {
            wants.add(
                Action::CreateDir {
                    path: Path::new(STAGING_ROOT).join(image.value.tag.dir_name()),
                    owner: Principal::Named(builder.to_owned()),
                    group: Principal::Named(signer.to_owned()),
                    mode: 0o2750,
                    before_linger: false,
                },
                &needs,
            );
        }
        let Some(selinux) = &component.forma.selinux else {
            continue;
        };
        if !host.selinux_enabled() {
            warnings.push(format!(
                "component {} ships SELinux modules, and SELinux is off on this host",
                component.name
            ));
            continue;
        }
        for module in &selinux.value.modules {
            // An .fc file is compiled into the module of its .te file.
            if module.value.kind == ModuleKind::FileContexts {
                continue;
            }
            let source = module.value.path.to_string();
            wants.add(
                Action::InstallSeLinuxModule {
                    name: module_name(&source).to_owned(),
                    priority: request.limits.selinux_priority.value,
                    source,
                },
                &needs,
            );
        }
    }
}

enum Verdict {
    /// The host lacks it: do it.
    Do,
    /// The host has it and forma made it, or nothing needs doing.
    Done,
    Problem(Problem),
}

fn judge(step: &Step, ledger: &Store, host: &dyn HostView) -> Verdict {
    let owned = step
        .action
        .ledger_key()
        .and_then(|key| ledger.owned(&key).map(|entry| entry.item.clone()));
    let not_owned = |what: String| {
        Verdict::Problem(Problem::ExistsNotOwned {
            what,
            wanted_by: step.label(),
        })
    };
    let mismatch = |item: &Item, found: String| {
        Verdict::Problem(Problem::LedgerMismatch {
            recorded: item.to_string(),
            found,
        })
    };
    match &step.action {
        Action::CreateGroup { name, .. } => match (host.group(name), &owned) {
            (None, _) => Verdict::Do,
            (Some(group), Some(item @ Item::Group { gid, .. })) => {
                if *gid == Some(group.gid) {
                    Verdict::Done
                } else {
                    mismatch(item, format!("group {name} ({})", group.gid))
                }
            }
            (Some(_), _) => not_owned(format!("group {name}")),
        },
        Action::CreateUser { name, .. } => match (host.user(name), &owned) {
            (None, _) => Verdict::Do,
            (Some(user), Some(item @ Item::User { uid, .. })) => {
                if *uid == Some(user.uid) {
                    Verdict::Done
                } else {
                    mismatch(item, format!("user {name} ({})", user.uid))
                }
            }
            (Some(_), _) => not_owned(format!("user {name}")),
        },
        // A new account gets its groups from useradd. An existing one is
        // added to each group it is not in; the group need not be forma's.
        Action::AddMember { user, group } => match (host.user(user), host.group(group)) {
            (Some(_), Some(found)) if !found.members.iter().any(|member| member == user) => Verdict::Do,
            (Some(_), None) => Verdict::Do,
            _ => Verdict::Done,
        },
        Action::AddSubIds { user, .. } => {
            if host.has_sub_ids(user) {
                Verdict::Done
            } else {
                Verdict::Do
            }
        }
        Action::EnableLinger { user } => {
            if host.linger(user) {
                Verdict::Done
            } else {
                Verdict::Do
            }
        }
        Action::WriteFile { path, .. } | Action::CreateDir { path, .. } => match (host.path(path), owned) {
            (None, _) => Verdict::Do,
            (Some(_), Some(_)) => Verdict::Done,
            (Some(_), None) => not_owned(path.display().to_string()),
        },
        Action::SetGroup { path, group } => match (host.path(path), host.group(group)) {
            (Some(found), Some(group)) if found.gid == group.gid => Verdict::Done,
            // Materia stages before it runs forma. With nothing staged yet
            // there is nothing to grant; `plan` says so in a warning.
            (None, _) => Verdict::Done,
            _ => Verdict::Do,
        },
        Action::GrantTraverse { path, user } => match host.user(user) {
            Some(found) if host.has_acl_user(path, found.uid) => Verdict::Done,
            _ => Verdict::Do,
        },
        Action::InstallSeLinuxModule { name, priority, .. } => {
            let installed = host.selinux_module(name);
            match (installed.is_empty(), owned) {
                (false, Some(_)) if installed.contains(priority) => Verdict::Done,
                (false, None) => not_owned(format!("SELinux module {name}")),
                // Not installed, or forma's own module at an old priority.
                _ => Verdict::Do,
            }
        }
        Action::MapSeLinuxLogin { user } => match (host.selinux_login(user), owned) {
            (None, _) => Verdict::Do,
            (Some(_), Some(_)) => Verdict::Done,
            (Some(mapped), None) => not_owned(format!("SELinux login mapping of {user} to {mapped}")),
        },
        Action::WaitForSocket { user } => match host.user(user) {
            Some(found) if host.path(&socket(found.uid)).is_some() => Verdict::Done,
            _ => Verdict::Do,
        },
        // Removals and restarts are planned from the ledger, not judged.
        _ => Verdict::Do,
    }
}

/// The socket of an account's materia.
fn socket(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}/materia/materia.sock"))
}

/// Checks the units of every delegated component (architecture 5.10).
fn check_units(request: &Request<'_>, plan: &mut Plan) {
    let declared: BTreeSet<&ImageRef> = request
        .config
        .images()
        .iter()
        .map(|used| &used.image.value.tag)
        .collect();
    // A unit must write a forma image in full: without `localhost/`, Podman
    // would look for the name in registries.
    let is_forma_image = |reference: &str| {
        reference.starts_with("localhost/") && ImageRef::new(reference).is_ok_and(|image| image.as_str() == reference)
    };
    for component in &request.config.components {
        let Some(staged) = &component.staged else {
            if component.user.is_some() {
                plan.warnings.push(format!(
                    "component {} is delegated, but materia has staged nothing for it yet, so its units are not checked",
                    component.name
                ));
            }
            continue;
        };
        let units = match forma_quadlet::read_staged(staged) {
            Ok(units) => units,
            Err(error) => {
                plan.problems.push(Problem::StagedUnreadable {
                    component: component.name.to_string(),
                    reason: error.to_string(),
                });
                continue;
            }
        };
        let home = component
            .user
            .as_ref()
            .map(|user| home_of(request.limits, user.as_str()).display().to_string());
        let account = forma_quadlet::Account {
            is_forma_image: &is_forma_image,
            home: home.as_deref(),
        };
        for unit in &units {
            let file = unit.as_unit_file();
            // Forma's rules are for units that run as a service account.
            if component.user.is_none() && file.kind() != Some(UnitKind::Systemd) {
                continue;
            }
            for finding in forma_quadlet::check(&file, &account) {
                if finding.code.is_error() {
                    plan.problems.push(Problem::Unit {
                        component: component.name.to_string(),
                        finding,
                    });
                } else {
                    plan.warnings.push(format!("component {}: {finding}", component.name));
                }
            }
            for image in forma_quadlet::images(&file) {
                let known = ImageRef::new(&image.reference).is_ok_and(|image| declared.contains(&image));
                if is_forma_image(&image.reference) && !known {
                    plan.warnings.push(format!(
                        "component {}: {}:{}: no installed component declares {} under [[Forma.Images]], \
                         so nothing builds it",
                        component.name, image.file, image.line, image.reference
                    ));
                }
            }
        }
    }
}

/// Reads each image's Containerfile from the component's staged copy and
/// checks the bases it names. Only a delegated component has a staged copy,
/// and `forma-config` refuses images on any other (`ImageWithoutUser`).
/// A component materia has not staged yet is reported by [`check_units`].
fn check_images(request: &Request<'_>, plan: &mut Plan) {
    for used in request.config.images() {
        let Some(staged) = &used.component.staged else {
            continue;
        };
        let image = &used.image.value;
        let containerfile = image.containerfile.under(staged);
        let text = match std::fs::read_to_string(&containerfile) {
            Ok(text) => text,
            Err(error) => {
                plan.problems.push(Problem::StagedUnreadable {
                    component: used.component.name.to_string(),
                    reason: format!("{}: {error}", containerfile.display()),
                });
                continue;
            }
        };
        let checked = forma_build::bases(&text, &image.build_args)
            .and_then(|bases| forma_build::require_trust(&bases, &used.component.base_images));
        for error in checked.err().unwrap_or_default() {
            plan.problems.push(Problem::BaseImage {
                component: used.component.name.to_string(),
                image: image.tag.short().to_owned(),
                containerfile: containerfile.clone(),
                error,
            });
        }
    }
}

/// The accounts no run may remove: those a component names in its
/// `.component_version`, installed or not (delegation 9).
fn protected_accounts(request: &Request<'_>, leaving: Option<&str>) -> BTreeMap<String, String> {
    let installed = request
        .config
        .components
        .iter()
        .filter(|component| Some(component.name.as_str()) != leaving)
        .filter_map(|component| Some((component.user.as_ref()?.to_string(), component.name.to_string())));
    let skipped = request
        .skipped
        .iter()
        .filter_map(|skipped| Some((skipped.user.clone()?, skipped.name.clone())));
    installed.chain(skipped).collect()
}

/// The account a ledger item belongs to, for the items that go with one.
fn account_of(item: &Item) -> Option<&str> {
    match item {
        Item::User { name, .. } => Some(name),
        Item::SubIds { user, .. } | Item::Linger { user } | Item::SeLinuxLogin { user, .. } => Some(user),
        _ => None,
    }
}

/// Plans the removal of every applied ledger entry that `goes` selects.
fn removals(
    request: &Request<'_>,
    ledger: &Store,
    leaving: Option<&str>,
    plan: &mut Plan,
    goes: impl Fn(&forma_ledger::Entry) -> bool,
) {
    let protected = protected_accounts(request, leaving);
    for entry in ledger
        .entries()
        .iter()
        .rev()
        .filter(|entry| entry.status == Status::Applied)
    {
        if !goes(entry) {
            continue;
        }
        if let Some(component) = account_of(&entry.item).and_then(|account| protected.get(account)) {
            plan.warnings.push(format!(
                "{} is kept: component {component} still names the account in its .component_version",
                entry.item
            ));
            continue;
        }
        plan.steps.push(Step {
            action: Action::removal_of(&entry.item),
            needs: if entry.needed_by.is_empty() {
                BTreeSet::from([HOST.to_owned()])
            } else {
                entry.needed_by.clone()
            },
        });
    }
}

/// Works out what `forma apply`, `revert` or `purge` would do.
///
/// It reads the configuration, the ledger and the host, and changes none
/// of them. A plan with problems must not be applied.
#[must_use]
pub fn plan(request: &Request<'_>, ledger: &Store, host: &dyn HostView) -> Plan {
    let mut plan = Plan::default();
    plan.warnings
        .extend(request.config.warnings.iter().map(ToString::to_string));
    plan.warnings.extend(
        request
            .skipped
            .iter()
            .map(|skipped| format!("component {} is skipped: {}", skipped.name, skipped.reason)),
    );
    plan.problems
        .extend(ledger.unsettled().into_iter().map(|entry| Problem::Unsettled {
            item: entry.item.to_string(),
        }));

    match request.scope {
        Scope::Apply { component, prune } => {
            check_units(request, &mut plan);
            check_images(request, &mut plan);
            let wants = wants(request, host, &mut plan.warnings);
            for step in &wants.list {
                // One component's run acts for that component and for the host.
                if component.is_some_and(|component| !step.needs.contains(component) && !step.needs.contains(HOST)) {
                    continue;
                }
                match judge(step, ledger, host) {
                    Verdict::Do => plan.steps.push(step.clone()),
                    Verdict::Done => {}
                    Verdict::Problem(problem) => plan.problems.push(problem),
                }
            }
            restart_running_managers(&mut plan, host);
            if prune {
                let wanted: BTreeMap<_, _> = wants
                    .list
                    .iter()
                    .filter_map(|step| Some((step.action.ledger_key()?, &step.needs)))
                    .collect();
                let installed: BTreeSet<&str> = request
                    .config
                    .components
                    .iter()
                    .map(|component| component.name.as_str())
                    .chain([HOST])
                    .collect();
                removals(request, ledger, None, &mut plan, |entry| match &entry.item {
                    // A kept home goes only with `purge --data`.
                    Item::ArchivedHome { .. } => false,
                    // The configuration does not list these one by one; they
                    // stay while a component that needed them is installed.
                    Item::AclGrant { .. } | Item::Mode { .. } | Item::TrustKey { .. } => {
                        !entry.needed_by.iter().any(|need| installed.contains(need.as_str()))
                    }
                    item => !wanted.contains_key(&item.key()),
                });
            }
        }
        Scope::Revert { component } => {
            removals(request, ledger, Some(component), &mut plan, |entry| {
                !matches!(entry.item, Item::ArchivedHome { .. })
                    && entry.needed_by.len() == 1
                    && entry.needed_by.contains(component)
            });
        }
        Scope::Purge { data } => {
            removals(request, ledger, None, &mut plan, |entry| {
                data || !matches!(entry.item, Item::ArchivedHome { .. })
            });
        }
    }
    order(&mut plan.steps);
    plan
}

/// Adds a restart for each account whose user manager already runs while
/// the plan installs the account materia's unit or configuration: a
/// running manager would not start the new unit (delegation 4).
fn restart_running_managers(plan: &mut Plan, host: &dyn HostView) {
    let unit_changes = plan.steps.iter().any(|step| {
        matches!(&step.action, Action::WriteFile { purpose: FilePurpose::UserUnit { unit }, .. } if *unit == MATERIA_UNIT)
    });
    let waiting: Vec<Step> = plan
        .steps
        .iter()
        .filter(|step| matches!(step.action, Action::WaitForSocket { .. }))
        .cloned()
        .collect();
    for wait in waiting {
        let Action::WaitForSocket { user } = &wait.action else {
            continue;
        };
        let config_changes = plan.steps.iter().any(|step| {
            matches!(&step.action, Action::WriteFile { purpose: FilePurpose::AccountMateriaConfig { account }, .. } if account == user)
        });
        let running = host
            .user(user)
            .is_some_and(|found| host.path(Path::new(&format!("/run/user/{}", found.uid))).is_some());
        if running && (unit_changes || config_changes) {
            plan.steps.push(Step {
                action: Action::RestartUserManager { user: user.clone() },
                needs: wait.needs.clone(),
            });
        }
    }
}

/// Settles the entries a stopped run left in the ledger, from what the
/// host shows (architecture 4.2). `forma apply` calls this before it plans.
///
/// An entry for a kind of item this view cannot see is left as it is, and
/// its description is returned.
///
/// # Errors
///
/// Returns an error if the ledger cannot be written.
pub fn recover(ledger: &mut Store, host: &dyn HostView) -> Result<Vec<String>, forma_ledger::LedgerError> {
    let unsettled: Vec<Item> = ledger.unsettled().into_iter().map(|entry| entry.item.clone()).collect();
    let mut unknown = Vec::new();
    for item in unsettled {
        let exists = match &item {
            Item::Group { name, .. } => host.group(name).is_some(),
            Item::User { name, .. } => host.user(name).is_some(),
            Item::Membership { user, group } => host
                .group(group)
                .is_some_and(|found| found.members.iter().any(|member| member == user)),
            Item::SubIds { user, .. } => host.has_sub_ids(user),
            Item::Linger { user } => host.linger(user),
            Item::Directory { path }
            | Item::File { path, .. }
            | Item::ArchivedHome { path, .. }
            | Item::TrustKey { path, .. } => host.path(path).is_some(),
            Item::Owner { path, uid, gid, .. } => host
                .path(path)
                .is_some_and(|found| (found.uid, found.gid) == (*uid, *gid)),
            Item::AclGrant {
                path,
                who: forma_ledger::AclWho::User,
                id,
                ..
            } => host.has_acl_user(path, *id),
            Item::SeLinuxModule { name, priority, .. } => host.selinux_module(name).contains(priority),
            Item::SeLinuxLogin { user, .. } => host.selinux_login(user).is_some(),
            Item::AclGrant { .. } | Item::Mode { .. } => {
                unknown.push(item.to_string());
                continue;
            }
        };
        // Record the IDs the stopped run did not get to write down.
        ledger.resolve(&item.key(), exists, |entry| match entry {
            Item::User { name, uid, gid } => {
                if let Some(found) = host.user(name) {
                    (*uid, *gid) = (Some(found.uid), Some(found.gid));
                }
            }
            Item::Group { name, gid } => *gid = host.group(name).map(|found| found.gid),
            _ => {}
        })?;
    }
    Ok(unknown)
}
