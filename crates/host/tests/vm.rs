//! [`LiveHost`] and the `forma` binary as root, on a host forma changed.
//!
//! The first test lets `forma_user::admin` make an account, a group,
//! sub-IDs, linger, directories and an ACL entry, and checks that each
//! `HostView` reading matches. The SELinux readings need SELinux, so they
//! are in forma-selinux-module's VM tests, in the secureblue guest.
//!
//! The second runs `forma plan` and `forma ledger show` against the
//! repository's test fixtures and a real ledger at
//! `/var/lib/forma/ledger.toml`, mode `0600`, as root and as an account.
//! `just host::vm-test` stages the binary and the fixtures in
//! `/mnt/forma-test/extra` (`vm-test-extra` in this crate's justfile).
//!
//! They change the machine they run on, so they run only in a VM:
//! `just host::vm-test`, or `just vm-test` for every crate. They use the
//! forma-user guest (`crates/user/vm`). Every test is `#[ignore]`d, so
//! `cargo test` skips them, and each checks for that guest before it touches
//! anything.

use std::convert::Infallible;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use forma_host::LiveHost;
use forma_ledger::{Recorder, Store};
use forma_plan::{HostGroup, HostPath, HostUser, HostView as _};
use forma_user::admin::{self, System, SystemConfig};
use forma_user::id::{Gid, SubIdCount, Uid};
use forma_user::lookup::{self, Group, LocalGroup, User};
use forma_user::name::{GroupName, UserName};
use forma_user::ownership::{Item, MarkerTag, NoJournal, Ownership};
use forma_user::path::AbsPath;
use forma_user::perm::FileMode;
use forma_user::spec::{GidChoice, GroupSpec, HomeSpec, PrimaryGroup, Shell, UidChoice, UserSpec};

/// Exists only in the forma-user guest image.
const MARKER_FILE: &str = "/etc/forma-user-test-vm";

/// The directory the tests may make directories in. The image makes it.
const BASE: &str = "/var/lib/forma-test-base";

/// What `vm-test-extra` staged: the `forma` binary and `tests/fixtures`.
const EXTRA: &str = "/mnt/forma-test/extra";

/// Where the CLI test copies the binary and fixtures, so an account can
/// read them: the share's owner and modes come from the host.
const WORK: &str = "/var/lib/forma-host-vm";

/// Declares a test that runs in the VM only. The body runs after
/// [`require_vm`], so no test can reach the host.
macro_rules! vm_test {
    ($(#[$meta:meta])* fn $name:ident() $body:block) => {
        #[test]
        #[ignore = "needs the test VM: run `just host::vm-test`"]
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
        "this test changes the system and runs only in the test VM, but {MARKER_FILE} is missing; run `just host::vm-test`",
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

/// Claims everything. The library's `Marker` never claims an ACL entry,
/// and the test takes its own entry back.
#[derive(Debug, Clone, Copy)]
struct ClaimAll;

impl Ownership for ClaimAll {
    type Error = Infallible;

    fn claims(&self, _item: &Item<'_>) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn abs(path: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(path.as_ref()).expect("an absolute path")
}

fn config(tag: &str, bases: &[&str]) -> SystemConfig {
    SystemConfig {
        allowed_bases: bases.iter().map(abs).collect(),
        allow_ids_outside_system_range: false,
        lock_file: abs("/run/forma-host-test.lock"),
        marker: MarkerTag::new(tag).expect("a valid tag"),
        tool_timeout: Duration::from_secs(30),
        unit_timeout: Duration::from_secs(60),
    }
}

fn user_spec(name: &str, home: HomeSpec, supplementary: Vec<LocalGroup>) -> UserSpec {
    UserSpec {
        name: UserName::new(name).unwrap(),
        uid: UidChoice::Allocate,
        primary_group: PrimaryGroup::New,
        supplementary,
        home,
        shell: Shell::NoLogin,
        comment: None,
    }
}

fn local_group(name: &str) -> LocalGroup {
    match lookup::group(&GroupName::new(name).unwrap()).expect("look up") {
        Some(Group::Local(group)) => group,
        other => panic!("{name} is not a local group: {other:?}"),
    }
}

fn run(program: &str, args: &[&str]) {
    let output = Command::new(program).args(args).output().expect("start the program");
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

vm_test! {
    fn live_host_reads_back_what_forma_user_wrote() {
        let mut system = System::open(config("forma-host-vm-test", &[BASE]), ClaimAll, NoJournal)
            .expect("open the root handle in the test VM");
        let host = LiveHost::read().expect("read the host");
        assert_eq!(host.unread(), Vec::<&str>::new(), "root reads everything");

        assert_eq!(host.user("fthostuser"), None);
        assert_eq!(host.group("fthostgroup"), None);
        let group = admin::group::create(&mut system, &GroupSpec { name: GroupName::new("fthostgroup").unwrap(), gid: GidChoice::Allocate })
            .unwrap();
        let account = admin::user::create(&mut system, &user_spec("fthostuser", HomeSpec::None, Vec::new())).unwrap();
        assert!(admin::group::add_member(&mut system, &account, &group).unwrap());

        assert_eq!(
            host.user("fthostuser"),
            Some(HostUser { uid: account.uid().as_raw(), gid: account.gid().as_raw() })
        );
        assert_eq!(
            host.group("fthostgroup"),
            Some(HostGroup { gid: group.info().gid().as_raw(), members: vec!["fthostuser".to_owned()] })
        );

        assert!(!host.has_sub_ids("fthostuser"));
        admin::subid::allocate(&mut system, &account, SubIdCount::new(SubIdCount::MIN).unwrap()).unwrap();
        assert!(host.has_sub_ids("fthostuser"));
        admin::subid::remove(&mut system, &account).unwrap();
        assert!(!host.has_sub_ids("fthostuser"));

        assert!(!host.linger("fthostuser"));
        assert!(admin::systemd::linger::set(&mut system, &account, true).unwrap());
        assert!(host.linger("fthostuser"));
        assert!(admin::systemd::linger::set(&mut system, &account, false).unwrap());
        assert!(!host.linger("fthostuser"));

        // A 0700 directory root owns, given to the account's group, and one
        // inside it the account reaches through a traverse entry.
        let outer = abs(Path::new(BASE).join("fthost-outer"));
        let inner = abs(outer.as_path().join("inner"));
        assert_eq!(host.path(outer.as_path()), None);
        admin::perm::create_dir(&mut system, &outer, Uid::ROOT, account.gid(), FileMode::new(0o700).unwrap()).unwrap();
        admin::perm::create_dir(&mut system, &inner, Uid::ROOT, Gid::ROOT, FileMode::new(0o755).unwrap()).unwrap();
        assert_eq!(host.path(outer.as_path()), Some(HostPath { uid: 0, gid: account.gid().as_raw() }));

        assert!(!host.has_acl_user(outer.as_path(), account.uid().as_raw()));
        let granted = admin::perm::grant_traverse(&mut system, &inner, &account).unwrap();
        assert!(granted.contains(&outer), "the 0700 directory needed a grant: {granted:?}");
        assert!(host.has_acl_user(outer.as_path(), account.uid().as_raw()));
        assert!(!host.has_acl_user(outer.as_path(), account.uid().as_raw() + 1), "an entry for another user");
        admin::perm::revoke_traverse(&mut system, &inner, &account).unwrap();
        assert!(!host.has_acl_user(outer.as_path(), account.uid().as_raw()));

        // A path with a symlink in it is read as the link, not followed.
        let link = Path::new(BASE).join("fthost-link");
        std::os::unix::fs::symlink(outer.as_path(), &link).unwrap();
        assert_eq!(host.path(&link), Some(HostPath { uid: 0, gid: 0 }));
    }
}

/// The fixture host of `tests/cli.rs`, copied where an account can read it.
struct Cli {
    forma: PathBuf,
    config: PathBuf,
}

impl Cli {
    fn new() -> Self {
        let work = Path::new(WORK);
        std::fs::create_dir_all(work).unwrap();
        std::fs::set_permissions(work, std::fs::Permissions::from_mode(0o755)).unwrap();
        run("/usr/bin/cp", &["-r", "--", &format!("{EXTRA}/fixtures"), WORK]);
        run("/usr/bin/chmod", &["-R", "a+rX", WORK]);
        let forma = work.join("forma");
        std::fs::copy(Path::new(EXTRA).join("forma"), &forma).expect("copy the forma binary");
        std::fs::set_permissions(&forma, std::fs::Permissions::from_mode(0o755)).unwrap();

        let fixtures = work.join("fixtures");
        let installed = fixtures.join("installed/moonshine");
        let materia_dir = work.join("materia");
        std::fs::create_dir(&materia_dir).unwrap();
        std::os::unix::fs::symlink(installed.join("data"), materia_dir.join("components")).unwrap();
        std::fs::write(
            work.join("materia.toml"),
            format!(
                "hostname = \"forge\"\nmateria_dir = \"{}\"\nquadlet_dir = \"{}\"\nsource_dir = \"{}\"\n\
                 [executor]\ndelegate_dir = \"{}\"\n",
                materia_dir.display(),
                installed.join("quadlets").display(),
                fixtures.join("valid/moonshine").display(),
                installed.join("delegate").display(),
            ),
        )
        .unwrap();
        let fixture_config = std::fs::read_to_string(fixtures.join("host/config.toml")).unwrap();
        let config = fixture_config.replace(
            "config_file = \"/etc/materia/config.toml\"",
            &format!("config_file = \"{}\"", work.join("materia.toml").display()),
        );
        assert_ne!(config, fixture_config, "the fixture names materia's configuration file");
        std::fs::write(work.join("forma.toml"), config).unwrap();
        run("/usr/bin/chmod", &["-R", "a+rX", WORK]);
        Self {
            forma,
            config: work.join("forma.toml"),
        }
    }

    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(&self.forma);
        command
            .args(arguments)
            .env_clear()
            .env("FORMA_CONFIG", &self.config)
            .current_dir("/");
        command
    }

    fn as_root(&self, arguments: &[&str]) -> Output {
        self.command(arguments).output().expect("run forma")
    }

    fn as_user(&self, user: &User, arguments: &[&str]) -> Output {
        self.command(arguments)
            .uid(user.uid().as_raw())
            .gid(user.gid().as_raw())
            .output()
            .expect("run forma as an account")
    }
}

/// The steps of a plan that name the fixture's account, for messages.
fn moonshine_steps(plan: &str) -> Vec<&str> {
    plan.lines().filter(|line| line.contains("moonshine")).collect()
}

vm_test! {
    fn forma_plan_and_ledger_show_read_a_real_ledger_and_host_as_root() {
        let cli = Cli::new();
        // The fixture's account joins render, which must exist.
        if lookup::group(&GroupName::new("render").unwrap()).expect("look up").is_none() {
            run("/usr/sbin/groupadd", &["--system", "render"]);
        }
        let bystander = {
            run("/usr/sbin/useradd", &["--system", "--no-create-home", "fthostcli"]);
            lookup::user(&UserName::new("fthostcli").unwrap()).unwrap().unwrap()
        };

        // Before forma made anything: the plan makes the account.
        let before = cli.as_root(&["plan"]);
        let printed = text(&before.stdout);
        assert!(printed.starts_with("Plan:\n"), "{printed}\n{}", text(&before.stderr));
        for step in ["Create User moonshine", "Enable Linger moonshine", "Add SubIds moonshine"] {
            assert!(printed.contains(step), "no {step:?} before forma made the account:\n{printed}");
        }

        // Forma makes the account, its sub-IDs and linger, and records them
        // in the root ledger, as the executor will.
        std::fs::create_dir_all("/var/lib/forma").unwrap();
        std::fs::create_dir_all("/var/home").unwrap();
        let recorder = Recorder::new(Store::open(forma_ledger::ROOT_LEDGER).expect("open the root ledger"));
        recorder.set_needs(["moonshine", "nvidia-driver"]);
        let mut system = System::open(config("forma", &["/var/home"]), recorder.clone(), recorder.clone())
            .expect("open the root handle in the test VM");
        let account = admin::user::create(
            &mut system,
            &user_spec("moonshine", HomeSpec::Create(abs("/var/home/moonshine")), vec![local_group("render")]),
        )
        .unwrap();
        admin::subid::allocate(&mut system, &account, SubIdCount::new(SubIdCount::MIN).unwrap()).unwrap();
        assert!(admin::systemd::linger::set(&mut system, &account, true).unwrap());
        drop(system);
        let mode = std::fs::metadata(forma_ledger::ROOT_LEDGER).expect("the ledger file").mode() & 0o777;
        assert_eq!(mode, 0o600, "mode of {}", forma_ledger::ROOT_LEDGER);

        // `forma ledger show` prints the file, as root only.
        let show = cli.as_root(&["ledger", "show"]);
        assert!(show.status.success(), "{}", text(&show.stderr));
        let expected = Store::open(forma_ledger::ROOT_LEDGER).unwrap().to_toml();
        assert_eq!(text(&show.stdout), expected);
        assert!(expected.contains("moonshine"), "{expected}");
        let refused = cli.as_user(&bystander, &["ledger", "show"]);
        assert!(!refused.status.success(), "ledger show worked for an account");
        assert!(text(&refused.stderr).contains("must run as root"), "{}", text(&refused.stderr));

        // As root, the plan reads the ledger and the host: the account,
        // its sub-IDs and linger are there, and forma made them.
        let after = cli.as_root(&["plan"]);
        let printed = text(&after.stdout);
        let stderr = text(&after.stderr);
        assert!(!stderr.contains("cannot read"), "root could not read the ledger: {stderr}");
        assert!(printed.starts_with("Plan:\n"), "{printed}\n{stderr}");
        for step in ["Create User moonshine", "Enable Linger moonshine", "Add SubIds moonshine"] {
            assert!(
                !printed.contains(step),
                "{step:?} planned again after forma made it:\n{:#?}\n{stderr}",
                moonshine_steps(&printed)
            );
        }

        // An account cannot read the 0600 ledger: the plan says so and
        // plans as if forma had made nothing.
        let unprivileged = cli.as_user(&bystander, &["plan"]);
        let stderr = text(&unprivileged.stderr);
        assert!(
            stderr.contains(&format!("warning: cannot read {}", forma_ledger::ROOT_LEDGER)),
            "{stderr}"
        );
    }
}
