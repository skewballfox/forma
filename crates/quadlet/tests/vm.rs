//! The units forma installs, under a real systemd user manager.
//!
//! Forma writes `forma-materia.service`, `forma-load.timer` and
//! `forma-load.service` once, in `/etc/systemd/user/`, for every account,
//! and links the first two into `default.target.wants/`. These tests check
//! that a lingering account's user manager loads all three, that they run
//! for an account in `forma-consumers`, and that `ConditionGroup=` keeps
//! them from running for an account outside it.
//!
//! The units start `/usr/bin/true` in place of materia and forma, so a start
//! is visible and harmless. The managers are asked as their own accounts
//! (`systemctl --user`, run with the account's user and group IDs), which
//! needs no machined and no PAM.
//!
//! They write `/etc/systemd/user` and turn linger on, so they run only in a
//! VM: `just quadlet::vm-test`, or `just vm-test` for every crate. They use
//! the forma-user guest (`crates/user/vm`), whose linger tests show it can
//! run user managers. Every test is `#[ignore]`d, so `cargo test` skips them,
//! and each checks for that guest before it touches anything.

use std::collections::BTreeMap;
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use forma_quadlet::units::{
    self, ACCOUNT_MATERIA_CONFIG_DIR, CONSUMERS_GROUP, GeneratedUnit, LOAD_TIMER_UNIT, LOAD_SERVICE_UNIT, MATERIA_UNIT,
    USER_UNIT_DIR,
};

/// Exists only in the forma-user guest image.
const MARKER_FILE: &str = "/etc/forma-user-test-vm";


/// What the units start in place of materia and forma.
const STAND_IN: &str = "/usr/bin/true";

/// How long a user manager may take to start, or a unit to run.
const PATIENCE: Duration = Duration::from_secs(60);

/// How long the first load may take to come: the timer's `OnActiveSec=1min`
/// and `AccuracySec=10s`, and some slack.
const FIRST_LOAD: Duration = Duration::from_secs(150);

/// Declares a test that runs in the VM only. The body runs after
/// [`require_vm`], so no test can reach the host.
macro_rules! vm_test {
    ($(#[$meta:meta])* fn $name:ident() $body:block) => {
        #[test]
        #[ignore = "needs the test VM: run `just quadlet::vm-test`"]
        $(#[$meta])*
        fn $name() {
            require_vm();
            $body
        }
    };
}

/// Stops the test unless it runs in the test VM.
fn require_vm() {
    assert!(
        Path::new(MARKER_FILE).exists(),
        "this test changes the system and runs only in the test VM, but {MARKER_FILE} is missing; run `just quadlet::vm-test`",
    );
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let hypervisor = cpuinfo
        .lines()
        .filter(|line| line.starts_with("flags"))
        .any(|line| line.split_whitespace().any(|flag| flag == "hypervisor"));
    assert!(
        hypervisor,
        "this test changes the system and runs only in the test VM, but /proc/cpuinfo has no `hypervisor` flag",
    );
}

fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().expect("start the program");
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A system account with its own group and no home.
struct Account {
    name: String,
    uid: u32,
    gid: u32,
}

impl Account {
    fn new(name: &str, groups: &[&str]) -> Self {
        let mut args = vec!["--system", "--no-create-home"];
        let joined = groups.join(",");
        if !groups.is_empty() {
            args.extend(["--groups", &joined]);
        }
        args.push(name);
        run("/usr/sbin/useradd", &args);
        Self {
            name: name.to_owned(),
            uid: run("/usr/bin/id", &["-u", name]).parse().unwrap(),
            gid: run("/usr/bin/id", &["-g", name]).parse().unwrap(),
        }
    }

    /// Runs `systemctl --user` as the account, against its own manager.
    fn systemctl(&self, args: &[&str]) -> std::process::Output {
        Command::new("/usr/bin/systemctl")
            .arg("--user")
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .env("XDG_RUNTIME_DIR", format!("/run/user/{}", self.uid))
            .uid(self.uid)
            .gid(self.gid)
            .current_dir("/")
            .output()
            .expect("run systemctl --user")
    }

    /// The properties of a unit, as the account's manager sees it.
    fn show(&self, unit: &str) -> BTreeMap<String, String> {
        let output = self.systemctl(&[
            "show",
            unit,
            "--property=LoadState,LoadError,ActiveState,SubState,Result,ConditionResult,\
             ConditionTimestampMonotonic,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,ExecMainStatus",
        ]);
        assert!(
            output.status.success(),
            "systemctl --user show {unit} as {}: {}",
            self.name,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect()
    }

    /// Turns linger on and waits until the account's manager is up.
    fn linger(&self) {
        run("/usr/bin/loginctl", &["enable-linger", &self.name]);
        let unit = format!("user@{}.service", self.uid);
        wait_for(&format!("{unit} to start"), || {
            Command::new("/usr/bin/systemctl")
                .args(["is-active", "--quiet", &unit])
                .status()
                .expect("run systemctl")
                .success()
        });
        // The manager answers on its bus once it is active.
        wait_for(&format!("the manager of {} to answer", self.name), || {
            self.systemctl(&["show", "--property=Version"]).status.success()
        });
    }

    /// Waits until the manager has checked the unit's conditions and the
    /// unit is no longer starting, and returns its properties.
    fn settled(&self, unit: &str) -> BTreeMap<String, String> {
        let mut properties = BTreeMap::new();
        wait_for(&format!("{unit} to settle for {}", self.name), || {
            properties = self.show(unit);
            properties["ConditionTimestampMonotonic"] != "0"
                && !matches!(properties["ActiveState"].as_str(), "activating" | "deactivating" | "reloading")
        });
        properties
    }
}

/// Waits for `ready`, at most [`PATIENCE`].
fn wait_for(what: &str, ready: impl FnMut() -> bool) {
    wait_at_most(PATIENCE, what, ready);
}

/// Waits for `ready`, at most `limit`.
fn wait_at_most(limit: Duration, what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !ready() {
        assert!(Instant::now() < deadline, "gave up waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Installs the three units as forma does: the files in
/// `/etc/systemd/user`, and a link in `<target>.wants/` for each unit a
/// target starts. Also creates `forma-consumers`. Runs once per boot.
fn install_units() {
    if Path::new(USER_UNIT_DIR).join(MATERIA_UNIT).exists() {
        return;
    }
    run("/usr/sbin/groupadd", &["--system", CONSUMERS_GROUP]);
    let stand_in = Path::new(STAND_IN);
    let [timer, service] = units::load_units(stand_in);
    let generated: [GeneratedUnit; 3] = [units::account_materia(stand_in), timer, service];
    for unit in &generated {
        let file = Path::new(USER_UNIT_DIR).join(unit.name);
        std::fs::create_dir_all(USER_UNIT_DIR).unwrap();
        std::fs::write(&file, &unit.text).expect("write the unit");
        if let Some(target) = unit.wanted_by {
            let wants = Path::new(USER_UNIT_DIR).join(format!("{target}.wants"));
            std::fs::create_dir_all(&wants).unwrap();
            symlink(Path::new("..").join(unit.name), wants.join(unit.name)).expect("link the unit");
        }
    }
}

/// The account materia configuration the materia unit's condition looks for.
fn prepare_account(account: &Account) {
    std::fs::create_dir_all(ACCOUNT_MATERIA_CONFIG_DIR).unwrap();
    let config = units::account_materia_config(&account.name, "forma-user-test", Path::new("/var/lib/forma/staging"));
    std::fs::write(Path::new(ACCOUNT_MATERIA_CONFIG_DIR).join(format!("{}.toml", account.name)), config).unwrap();
}

/// Lines the account's manager logged about forma's unit files, such as an
/// unknown key: none means it took every line.
fn complaints(account: &Account) -> Vec<String> {
    run(
        "/usr/bin/journalctl",
        &["--boot", "--no-pager", "--output=cat", &format!("_UID={}", account.uid)],
    )
    .lines()
    .filter(|line| line.contains(USER_UNIT_DIR) && line.contains("forma-"))
    .map(str::to_owned)
    .collect()
}

fn assert_loaded(account: &Account, unit: &str, properties: &BTreeMap<String, String>) {
    assert_eq!(
        properties["LoadState"], "loaded",
        "{unit} for {}: {properties:#?}",
        account.name
    );
}

vm_test! {
    fn the_units_load_and_run_for_an_account_in_forma_consumers() {
        install_units();
        let account = Account::new("ftqconsumer", &[CONSUMERS_GROUP]);
        prepare_account(&account);
        account.linger();

        // default.target started materia: its conditions held and it ran.
        wait_for("materia to run", || account.show(MATERIA_UNIT)["ExecMainExitTimestampMonotonic"] != "0");
        let materia = account.settled(MATERIA_UNIT);
        assert_loaded(&account, MATERIA_UNIT, &materia);
        assert_eq!(materia["ConditionResult"], "yes", "{materia:#?}");
        assert_ne!(materia["ExecMainStartTimestampMonotonic"], "0", "{materia:#?}");
        assert_eq!(materia["ExecMainStatus"], "0", "{materia:#?}");

        // default.target started the timer, which now waits.
        let timer = account.settled(LOAD_TIMER_UNIT);
        assert_loaded(&account, LOAD_TIMER_UNIT, &timer);
        assert_eq!(timer["ConditionResult"], "yes", "{timer:#?}");
        assert_eq!((timer["ActiveState"].as_str(), timer["SubState"].as_str()), ("active", "waiting"), "{timer:#?}");

        // A minute after the manager started, the timer starts the load.
        assert_loaded(&account, LOAD_SERVICE_UNIT, &account.show(LOAD_SERVICE_UNIT));
        wait_at_most(FIRST_LOAD, "the timer to start the load", || {
            account.show(LOAD_SERVICE_UNIT)["ExecMainExitTimestampMonotonic"] != "0"
        });
        let load = account.settled(LOAD_SERVICE_UNIT);
        assert_eq!(load["ConditionResult"], "yes", "{load:#?}");
        assert_eq!(load["ExecMainStatus"], "0", "{load:#?}");
        assert_eq!(load["Result"], "success", "{load:#?}");

        // And waits again, for the next interval.
        let timer = account.settled(LOAD_TIMER_UNIT);
        assert_eq!((timer["ActiveState"].as_str(), timer["SubState"].as_str()), ("active", "waiting"), "{timer:#?}");

        assert_eq!(complaints(&account), Vec::<String>::new());
    }
}

vm_test! {
    fn condition_group_keeps_the_units_from_running_for_an_account_outside_forma_consumers() {
        install_units();
        let account = Account::new("ftqoutsider", &[]);
        prepare_account(&account);
        account.linger();

        for unit in [MATERIA_UNIT, LOAD_TIMER_UNIT] {
            let properties = account.settled(unit);
            assert_loaded(&account, unit, &properties);
            assert_eq!(properties["ConditionResult"], "no", "{unit}: {properties:#?}");
            assert_eq!(properties["ActiveState"], "inactive", "{unit}: {properties:#?}");
        }
        let materia = account.show(MATERIA_UNIT);
        assert_eq!(materia["ExecMainStartTimestampMonotonic"], "0", "{materia:#?}");

        // Started by hand, the load is skipped too: a failed condition is
        // not an error, so systemctl succeeds and nothing runs.
        let started = account.systemctl(&["start", LOAD_SERVICE_UNIT]);
        assert!(started.status.success(), "{}", String::from_utf8_lossy(&started.stderr));
        let load = account.settled(LOAD_SERVICE_UNIT);
        assert_loaded(&account, LOAD_SERVICE_UNIT, &load);
        assert_eq!(load["ConditionResult"], "no", "{load:#?}");
        assert_eq!(load["ExecMainStartTimestampMonotonic"], "0", "{load:#?}");

        assert_eq!(complaints(&account), Vec::<String>::new());
    }
}
