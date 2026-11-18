//! Plans against the fixtures, with a host and a ledger that exist only in memory.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use forma_config::installed::{self, Installed, InstalledPaths};
use forma_config::testing::repository_components;
use forma_config::{Config, HostConfig, Inputs, MateriaConfig};
use forma_ledger::{Item, Key, Store};
use forma_plan::host::fake::FakeHost;
use forma_plan::{Action, HostPath, HostView, Plan, Request, Scope, plan, recover};
use forma_user::name::GroupName;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn limits() -> HostConfig {
    HostConfig::load(&fixtures().join("host/config.toml"), []).unwrap()
}

fn host_groups(name: &GroupName) -> bool {
    name.as_str() == "render"
}

/// A host on which materia installed the moonshine repository.
struct World {
    config: Config,
    installed: Installed,
    materia: MateriaConfig,
    limits: HostConfig,
    ledger: Store,
    host: FakeHost,
}

impl World {
    fn moonshine() -> Self {
        Self::moonshine_with(|_| true)
    }

    /// As `moonshine`, with only the components `keep` selects installed.
    fn moonshine_with(keep: impl Fn(&str) -> bool) -> Self {
        let base = fixtures().join("installed/moonshine");
        let paths = InstalledPaths {
            components_dir: base.join("data"),
            quadlet_dir: base.join("quadlets"),
            delegate_dir: base.join("delegate"),
        };
        let mut installed = installed::scan(&paths).unwrap();
        installed.components.retain(|component| keep(component.name.as_str()));
        let limits = limits();
        let config = forma_config::load(&Inputs {
            host: "forge",
            repository_manifest: &fixtures().join("valid/moonshine/MANIFEST.toml"),
            components: &installed.components,
            limits: &limits,
            groups: &host_groups,
        })
        .unwrap();
        let materia = MateriaConfig::parse("", Path::new("config.toml"), []).unwrap();
        let mut host = FakeHost::fedora();
        // Materia staged the account's components before it ran forma.
        let account = forma_config::types::AccountName::new("moonshine").unwrap();
        host.paths
            .insert(materia.staging_dir(&account), HostPath { uid: 0, gid: 0 });
        Self {
            config,
            installed,
            materia,
            limits,
            ledger: Store::in_memory(),
            host,
        }
    }

    fn plan(&self, scope: Scope<'_>) -> Plan {
        plan(
            &Request {
                config: &self.config,
                materia: &self.materia,
                limits: &self.limits,
                skipped: &self.installed.skipped,
                scope,
            },
            &self.ledger,
            &self.host,
        )
    }

    /// Does what `forma apply` would: changes the host and records each change.
    fn apply(&mut self, plan: &Plan) {
        assert_eq!(plan.problems, [], "a plan with problems is not applied");
        for step in &plan.steps {
            let before = self.host.clone();
            self.host.perform(&step.action);
            if step.action.is_removal() {
                if let Some(key) = step.action.ledger_key() {
                    self.ledger.forget(&key).unwrap();
                }
                continue;
            }
            for item in record(&step.action, &before, &self.host) {
                let key = item.key();
                self.ledger.begin(item, &step.needs).unwrap();
                self.ledger.complete(&key, |_| {}).unwrap();
            }
        }
        // A step that was already done still records who needs the item.
        for step in &plan.steps {
            if let Some(key) = step.action.ledger_key().filter(|key| self.ledger.get(key).is_some()) {
                for need in &step.needs {
                    self.ledger.need(&key, need).unwrap();
                }
            }
        }
    }
}

/// The ledger entries an action leaves, as `forma-user`'s journal and
/// forma's executor would record them.
fn record(action: &Action, before: &FakeHost, after: &FakeHost) -> Vec<Item> {
    match action {
        Action::CreateGroup { name, .. } => vec![Item::Group {
            name: name.clone(),
            gid: after.group(name).map(|group| group.gid),
        }],
        Action::CreateUser { name, .. } => vec![Item::User {
            name: name.clone(),
            uid: after.user(name).map(|user| user.uid),
            gid: after.user(name).map(|user| user.gid),
        }],
        Action::AddMember { user, group } => vec![Item::Membership {
            user: user.clone(),
            group: group.clone(),
        }],
        Action::AddSubIds { user, count } => vec![Item::SubIds {
            user: user.clone(),
            start: 524_288,
            count: *count,
        }],
        Action::WriteFile { path, .. } => vec![Item::File {
            path: path.clone(),
            sha256: None,
        }],
        Action::EnableLinger { user } => vec![Item::Linger { user: user.clone() }],
        Action::CreateDir { path, .. } => vec![Item::Directory { path: path.clone() }],
        Action::SetGroup { path, .. } => {
            let (old, new) = (before.path(path).unwrap(), after.path(path).unwrap());
            vec![Item::Owner {
                path: path.clone(),
                previous_uid: old.uid,
                previous_gid: old.gid,
                uid: new.uid,
                gid: new.gid,
            }]
        }
        Action::GrantTraverse { path, user } => vec![Item::AclGrant {
            path: path.clone(),
            who: forma_ledger::AclWho::User,
            id: after.user(user).unwrap().uid,
            perms: 1,
        }],
        Action::InstallSeLinuxModule { name, priority, .. } => vec![Item::SeLinuxModule {
            name: name.clone(),
            priority: *priority,
            sha256: String::new(),
        }],
        Action::MapSeLinuxLogin { user } => vec![Item::SeLinuxLogin {
            user: user.clone(),
            selinux_user: "user_u".into(),
        }],
        _ => Vec::new(),
    }
}

const ALL: Scope<'static> = Scope::Apply {
    component: None,
    prune: false,
};

/// The plan as `forma plan` prints it, without the warnings: those hold
/// paths of the machine the tests run on.
fn steps_only(plan: &Plan) -> String {
    Plan {
        steps: plan.steps.clone(),
        ..Plan::default()
    }
    .to_string()
}

fn actions(plan: &Plan) -> Vec<String> {
    plan.steps
        .iter()
        .map(|step| format!("({}) {}", step.label(), step.action))
        .collect()
}

#[test]
fn the_first_plan_for_the_moonshine_host() {
    let world = World::moonshine();
    let plan = world.plan(ALL);
    assert_eq!(plan.problems, []);
    assert_eq!(plan.warnings.len(), 2, "{:#?}", plan.warnings);
    insta::assert_snapshot!(steps_only(&plan));
    // The repository declares a backup account and group that no component
    // on this host runs as, so forma creates neither.
    assert!(
        !actions(&plan).iter().any(|line| line.contains("backup")),
        "{:#?}",
        actions(&plan)
    );
}

#[test]
fn applying_the_plan_leaves_nothing_to_do() {
    let mut world = World::moonshine();
    let first = world.plan(ALL);
    world.apply(&first);
    let second = world.plan(ALL);
    assert_eq!(actions(&second), [] as [String; 0], "apply is idempotent");
    assert_eq!(second.problems, []);
    // Pruning a host that matches the repository removes nothing.
    let prune = world.plan(Scope::Apply {
        component: None,
        prune: true,
    });
    assert_eq!(actions(&prune), [] as [String; 0]);
}

#[test]
fn one_components_run_acts_for_that_component_and_the_host() {
    let world = World::moonshine();
    let plan = world.plan(Scope::Apply {
        component: Some("nvidia-driver"),
        prune: false,
    });
    let text = actions(&plan);
    // The shared account is nvidia-driver's too, so its first SetupScript creates it.
    assert!(
        text.iter().any(|line| line.contains("Create User moonshine ")),
        "{text:#?}"
    );
    assert!(
        text.iter().any(|line| line.contains("Create User forma-build")),
        "{text:#?}"
    );
    // The SELinux modules and the other images are moonshine's alone.
    assert!(!text.iter().any(|line| line.contains("SELinux Module")), "{text:#?}");
    assert!(
        !text.iter().any(|line| line.contains("moonshine_steam_latest")),
        "{text:#?}"
    );
    assert!(
        text.iter().any(|line| line.contains("moonshine_nvidia-driver_latest")),
        "{text:#?}"
    );
    assert!(
        text.last().unwrap().contains("Wait For Socket moonshine"),
        "the socket wait is last: {text:#?}"
    );
}

#[test]
fn an_account_forma_did_not_create_stops_the_plan() {
    let mut world = World::moonshine();
    world.host.perform(&Action::CreateUser {
        name: "moonshine".into(),
        home: None,
        groups: Vec::new(),
    });
    let plan = world.plan(ALL);
    let codes: Vec<&str> = plan.problems.iter().map(forma_plan::Problem::code).collect();
    assert_eq!(codes, ["ExistsNotOwned"]);
    assert!(
        plan.problems[0]
            .to_string()
            .starts_with("user moonshine already exists"),
        "{}",
        plan.problems[0]
    );
}

#[test]
fn an_account_with_another_user_id_than_recorded_stops_the_plan() {
    let mut world = World::moonshine();
    let first = world.plan(ALL);
    world.apply(&first);
    // Someone deleted the account and created another with the same name.
    world.host.users.get_mut("moonshine").unwrap().uid = 4242;
    let plan = world.plan(ALL);
    assert!(
        plan.problems.iter().any(|problem| problem.code() == "LedgerMismatch"),
        "{:?}",
        plan.problems
    );
}

#[test]
fn reverting_one_of_two_components_keeps_what_the_other_needs() {
    let mut world = World::moonshine();
    let first = world.plan(ALL);
    world.apply(&first);

    let revert = world.plan(Scope::Revert { component: "moonshine" });
    assert_eq!(revert.problems, []);
    insta::assert_snapshot!(steps_only(&revert));
    let text = actions(&revert);
    assert!(
        !text.iter().any(|line| line.contains("Delete User")),
        "nvidia-driver still runs as the account"
    );
}

#[test]
fn reverting_the_last_component_removes_the_account_in_reverse_order() {
    // Materia has already removed moonshine; nvidia-driver's CleanupScript runs now.
    let mut world = World::moonshine_with(|name| name == "nvidia-driver");
    let first = world.plan(ALL);
    world.apply(&first);

    let revert = world.plan(Scope::Revert {
        component: "nvidia-driver",
    });
    assert_eq!(revert.problems, []);
    let text = actions(&revert);
    let position = |needle: &str| {
        text.iter()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no {needle} in {text:#?}"))
    };
    assert!(position("Disable Linger moonshine") < position("Remove SubIds moonshine"));
    assert!(position("Remove SubIds moonshine") < position("Delete User moonshine"));
    assert!(position("Delete User moonshine") < position("Delete Group moonshine-input"));
    assert!(position("Unmap SELinux Login moonshine") < position("Disable Linger moonshine"));
    assert!(position("Restore Owner") < position("Delete User moonshine"));
    // The host's own items stay: revert is for one component.
    assert!(
        !text
            .iter()
            .any(|line| line.contains("forma-build") || line.contains("forma-consumers")),
        "{text:#?}"
    );

    world.apply(&revert);
    assert!(world.host.user("moonshine").is_none());
    let staging = world
        .materia
        .staging_dir(&forma_config::types::AccountName::new("moonshine").unwrap());
    assert_eq!(
        world.host.path(&staging),
        Some(HostPath { uid: 0, gid: 0 }),
        "the staging directory is root's again"
    );
}

#[test]
fn prune_removes_what_no_installed_component_asks_for() {
    let mut world = World::moonshine();
    let first = world.plan(ALL);
    world.apply(&first);

    // Materia removed moonshine and its CleanupScript failed.
    let mut later = World::moonshine_with(|name| name == "nvidia-driver");
    later.ledger = std::mem::replace(&mut world.ledger, Store::in_memory());
    later.host = world.host;
    let prune = later.plan(Scope::Apply {
        component: None,
        prune: true,
    });
    assert_eq!(prune.problems, []);
    let text = actions(&prune);
    assert!(
        text.iter()
            .any(|line| line.contains("Remove SELinux Module moonshine_container")),
        "{text:#?}"
    );
    assert!(
        text.iter()
            .any(|line| line.contains("Remove Path /var/lib/forma/staging/moonshine_steam_latest")),
        "{text:#?}"
    );
    assert!(!text.iter().any(|line| line.contains("Delete User")), "{text:#?}");
    assert!(
        !text.iter().any(|line| line.contains("nvidia-driver_latest")),
        "{text:#?}"
    );
    // Without --prune the same run removes nothing.
    assert_eq!(actions(&later.plan(ALL)), [] as [String; 0]);
}

#[test]
fn prune_never_removes_an_account_an_incomplete_component_names() {
    let mut world = World::moonshine();
    let first = world.plan(ALL);
    world.apply(&first);

    // Both components are half installed now: no manifest, but a version file that names the account.
    let mut later = World::moonshine_with(|_| false);
    later.ledger = std::mem::replace(&mut world.ledger, Store::in_memory());
    later.host = world.host;
    later.installed.skipped.push(forma_config::Skipped {
        name: "moonshine".into(),
        user: Some("moonshine".into()),
        reason: forma_config::SkipReason::Incomplete("MANIFEST.toml"),
    });
    let prune = later.plan(Scope::Apply {
        component: None,
        prune: true,
    });
    let text = actions(&prune);
    assert!(
        !text.iter().any(|line| line.contains("Delete User moonshine")),
        "{text:#?}"
    );
    assert!(
        prune
            .warnings
            .iter()
            .any(|warning| warning.contains("user moonshine") && warning.contains("is kept"))
    );
}

#[test]
fn purge_removes_everything_but_kept_homes() {
    let mut world = World::moonshine();
    let first = world.plan(ALL);
    world.apply(&first);
    let home = Item::ArchivedHome {
        path: "/var/home/old.removed-1".into(),
        user: "old".into(),
    };
    let key = home.key();
    world.ledger.begin(home, &BTreeSet::new()).unwrap();
    world.ledger.complete(&key, |_| {}).unwrap();

    // Nothing is installed any more.
    let mut empty = World::moonshine_with(|_| false);
    empty.ledger = std::mem::replace(&mut world.ledger, Store::in_memory());
    empty.host = world.host;
    let purge = empty.plan(Scope::Purge { data: false });
    assert_eq!(purge.steps.len(), empty.ledger.entries().len() - 1);
    assert!(!actions(&purge).iter().any(|line| line.contains("old.removed")));
    let with_data = empty.plan(Scope::Purge { data: true });
    assert!(
        actions(&with_data)
            .iter()
            .any(|line| line.contains("Remove Path /var/home/old.removed-1"))
    );
    assert!(
        actions(&with_data).last().unwrap().contains("Delete Group"),
        "groups go last"
    );
}

#[test]
fn a_stopped_run_blocks_the_plan_until_it_is_settled() {
    let mut world = World::moonshine();
    let needs = BTreeSet::from(["moonshine".to_owned()]);
    // The run stopped after useradd succeeded, and before a group was created.
    world
        .ledger
        .begin(
            Item::User {
                name: "moonshine".into(),
                uid: None,
                gid: None,
            },
            &needs,
        )
        .unwrap();
    world
        .ledger
        .begin(
            Item::Group {
                name: "moonshine-input".into(),
                gid: None,
            },
            &needs,
        )
        .unwrap();
    world.host.perform(&Action::CreateUser {
        name: "moonshine".into(),
        home: None,
        groups: Vec::new(),
    });

    let blocked = world.plan(ALL);
    assert_eq!(
        blocked
            .problems
            .iter()
            .filter(|problem| problem.code() == "Unsettled")
            .count(),
        2
    );

    assert_eq!(recover(&mut world.ledger, &world.host).unwrap(), [] as [String; 0]);
    let uid = world.host.user("moonshine").unwrap().uid;
    assert_eq!(
        world.ledger.owned(&Key::user("moonshine")).unwrap().item,
        Item::User {
            name: "moonshine".into(),
            uid: Some(uid),
            gid: Some(uid)
        }
    );
    assert!(
        world.ledger.get(&Key::group("moonshine-input")).is_none(),
        "the group was never made"
    );

    let plan = world.plan(ALL);
    assert_eq!(plan.problems, []);
    let text = actions(&plan);
    assert!(
        !text.iter().any(|line| line.contains("Create User moonshine ")),
        "the account is forma's now"
    );
    assert!(text.iter().any(|line| line.contains("Create Group moonshine-input")));
    assert!(
        text.iter()
            .any(|line| line.contains("Add User moonshine to Group render")),
        "{text:#?}"
    );
}

#[test]
fn a_user_manager_that_already_runs_is_restarted_once() {
    let mut world = World::moonshine();
    let first = world.plan(ALL);
    assert!(
        !actions(&first).iter().any(|line| line.contains("Restart User Manager")),
        "linger starts it"
    );
    world.apply(&first);

    // An administrator removed the account materia's configuration.
    world.host.paths.remove(Path::new("/etc/forma/materia/moonshine.toml"));
    world
        .ledger
        .forget(&Key::path(Path::new("/etc/forma/materia/moonshine.toml")))
        .unwrap();
    let uid = world.host.user("moonshine").unwrap().uid;
    world
        .host
        .paths
        .remove(&PathBuf::from(format!("/run/user/{uid}/materia/materia.sock")));
    world
        .host
        .paths
        .insert(PathBuf::from(format!("/run/user/{uid}")), HostPath { uid, gid: uid });
    let repair = world.plan(ALL);
    assert_eq!(
        actions(&repair),
        [
            "(moonshine, nvidia-driver) Write File /etc/forma/materia/moonshine.toml",
            "(moonshine, nvidia-driver) Restart User Manager moonshine (stops the account's containers once)",
            "(moonshine, nvidia-driver) Wait For Socket moonshine",
        ]
    );
}

fn repository_plan(repository: &Path) -> Plan {
    let components = repository_components(repository);
    let limits = limits();
    let config = forma_config::load(&Inputs {
        host: "forge",
        repository_manifest: &repository.join("MANIFEST.toml"),
        components: &components,
        limits: &limits,
        groups: &host_groups,
    })
    .unwrap();
    let materia = MateriaConfig::parse("", Path::new("config.toml"), []).unwrap();
    plan(
        &Request {
            config: &config,
            materia: &materia,
            limits: &limits,
            skipped: &[],
            scope: ALL,
        },
        &Store::in_memory(),
        &FakeHost::fedora(),
    )
}

#[test]
fn the_fixtures_that_break_a_unit_or_base_image_rule_stop_the_plan() {
    for fixture in [
        "pull-allowed",
        "templated-quadlet-key",
        "unresolved-base-arg",
        "require-all-unlisted",
    ] {
        let directory = fixtures().join("invalid").join(fixture);
        let expected = std::fs::read_to_string(directory.join("EXPECTED_ERROR")).unwrap();
        let plan = repository_plan(&directory);
        let codes: Vec<&str> = plan.problems.iter().map(forma_plan::Problem::code).collect();
        assert_eq!(codes, [expected.trim()], "{fixture}");
    }
}

#[test]
fn the_valid_repositories_plan_without_problems() {
    for fixture in ["moonshine", "lowercase-keys", "shared-component-account"] {
        let plan = repository_plan(&fixtures().join("valid").join(fixture));
        assert_eq!(plan.problems, [], "{fixture}");
    }
}

#[test]
fn the_plan_lists_the_capabilities_apply_keeps() {
    let world = World::moonshine();
    let plan = world.plan(ALL);
    assert_eq!(
        plan.capabilities().to_string(),
        "CAP_AUDIT_WRITE, CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_MAC_ADMIN"
    );
}
