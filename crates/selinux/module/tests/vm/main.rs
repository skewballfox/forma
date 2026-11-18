//! [`forma_selinux_module::admin`], run for real in the secureblue guest,
//! the capabilities forma-plan lists for it (`Action::capabilities`,
//! architecture 3.4), and what forma-host's `LiveHost` reads back of the
//! module store and `seusers`.
//!
//! They change the machine's SELinux policy, so they run only in a VM:
//! `just selinux::vm-test`, or `just vm-test` for every crate. They use the
//! secureblue guest (`vm/secureblue`), which is enforcing and has
//! secureblue's modules at priority 300.
//!
//! The capability tests drop capabilities, which `drop_all_except` refuses
//! while the process has more than one thread. libtest always runs tests
//! beside its own main thread, so this target has no libtest (`harness =
//! false` in Cargo.toml), as forma-privilege's VM tests. [`main`] runs each
//! test in a fresh copy of this binary, on that process's only thread, and
//! prints the results as libtest does. Without `--ignored`, as from `cargo
//! test`, it runs nothing.
//!
//! Each test uses its own module and account names, so a test that fails
//! part way leaves nothing another test reads.

use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, ExitCode};

use forma_host::LiveHost;
use forma_plan::{Action, HostView as _};
use forma_privilege::{Capabilities, NoCapabilities, Token, acquire, drop_all_except};
use forma_selinux_module::admin::{self, Error};
use forma_selinux_module::list::InstalledModule;

/// Exists only in the secureblue guest image.
const MARKER_FILE: &str = "/etc/forma-secureblue-test-vm";

/// Set in a child copy of the test binary to the name of the test it runs.
const CHILD: &str = "FORMA_SELINUX_MODULE_VM_CHILD";

/// Forma's module priority (architecture 5.9).
const PRIORITY: u16 = 350;

/// Where the tests write their module files: on the guest's own file
/// system, not the virtiofs share, which is `file_t`.
const WORK: &str = "/var/tmp/forma-selinux-module-vm";

/// Every test, by name. Each runs in its own process.
const TESTS: &[(&str, fn())] = &[
    (
        "a_module_installs_at_350_is_listed_and_is_removed",
        a_module_installs_at_350_is_listed_and_is_removed,
    ),
    (
        "a_remove_at_another_priority_leaves_the_module",
        a_remove_at_another_priority_leaves_the_module,
    ),
    (
        "a_login_maps_to_user_u_and_is_unmapped",
        a_login_maps_to_user_u_and_is_unmapped,
    ),
    (
        "with_the_listed_set_a_module_installs_and_is_removed",
        with_the_listed_set_a_module_installs_and_is_removed,
    ),
    (
        "with_the_listed_set_a_login_maps_and_is_unmapped",
        with_the_listed_set_a_login_maps_and_is_unmapped,
    ),
];

fn main() -> ExitCode {
    if let Ok(name) = std::env::var(CHILD) {
        let (_, test) = TESTS
            .iter()
            .find(|(test, _)| *test == name)
            .unwrap_or_else(|| panic!("no test named {name}"));
        require_vm();
        test();
        return ExitCode::SUCCESS;
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.iter().any(|arg| arg == "--ignored" || arg == "--include-ignored") {
        println!("the forma-selinux-module VM tests run only in the VM: just selinux::vm-test");
        return ExitCode::SUCCESS;
    }
    let filters: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|arg| !arg.starts_with('-'))
        .collect();
    let chosen: Vec<&str> = TESTS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| filters.is_empty() || filters.iter().any(|filter| name.contains(filter)))
        .collect();

    require_vm();
    println!("\nrunning {} tests", chosen.len());
    let mut failed = Vec::new();
    for name in &chosen {
        let output = StdCommand::new(std::env::current_exe().expect("the test binary's path"))
            .env(CHILD, name)
            .output()
            .expect("start a child copy of the test binary");
        if output.status.success() {
            println!("test {name} ... ok");
        } else {
            println!("test {name} ... FAILED");
            failed.push((name, output));
        }
    }
    if !failed.is_empty() {
        println!("\nfailures:");
        for (name, output) in &failed {
            println!(
                "\n---- {name} ({}) ----\n{}{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }
    let result = if failed.is_empty() { "ok" } else { "FAILED" };
    println!(
        "\ntest result: {result}. {} passed; {} failed; 0 ignored; 0 measured; {} filtered out",
        chosen.len() - failed.len(),
        failed.len(),
        TESTS.len() - chosen.len(),
    );
    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Stops the run unless it is in the test VM.
fn require_vm() {
    assert!(
        Path::new(MARKER_FILE).exists(),
        "this test changes the system and runs only in the test VM, but {MARKER_FILE} is missing; run `just selinux::vm-test`",
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
    assert!(rustix::process::geteuid().is_root(), "the VM runs the tests as root");
}

/// What forma-plan says every SELinux action needs.
fn listed_set() -> Capabilities {
    let actions = [
        Action::InstallSeLinuxModule {
            name: "m".into(),
            priority: PRIORITY,
            source: "m.cil".into(),
        },
        Action::RemoveSeLinuxModule {
            name: "m".into(),
            priority: PRIORITY,
        },
        Action::MapSeLinuxLogin { user: "u".into() },
        Action::UnmapSeLinuxLogin { user: "u".into() },
    ];
    let set = actions[0].capabilities();
    for action in &actions {
        assert_eq!(action.capabilities(), set, "{action}");
    }
    assert_eq!(set, Capabilities::NONE, "the table changed; update these tests");
    set
}

/// Writes a module that declares one type, and returns its path. The
/// module's name is the file's stem.
fn module_file(name: &str) -> PathBuf {
    std::fs::create_dir_all(WORK).expect("create the work directory");
    let path = Path::new(WORK).join(format!("{name}.cil"));
    std::fs::write(&path, format!("(type {name}_t)\n(roletype object_r {name}_t)\n")).expect("write the module");
    path
}

/// The host as the planner reads it now. Read afresh for each check: it
/// lists the module store once, when it is made.
fn live_host() -> LiveHost {
    LiveHost::read().expect("read the host as root")
}

/// A token for the SELinux actions, which need no capability. Taken after
/// any drop, as `forma apply` takes its own.
fn token() -> Token<NoCapabilities> {
    acquire().expect("a token for no capabilities")
}

/// The modules of one name in the store, at every priority.
fn listed(name: &str) -> Vec<InstalledModule> {
    admin::installed_modules(&token())
        .expect("semodule -lfull")
        .into_iter()
        .filter(|module| module.name == name)
        .collect()
}

fn install(name: &str) -> Result<(), Error> {
    let file = module_file(name);
    admin::install_modules(&token(), PRIORITY, &[file.as_path()])
}

fn remove(name: &str, priority: u16) -> Result<(), Error> {
    admin::remove_modules(&token(), priority, &[name])
}

fn assert_installed_at_350(name: &str) {
    assert_eq!(
        listed(name),
        [InstalledModule {
            priority: PRIORITY,
            name: name.to_owned(),
            language: "cil".to_owned(),
            enabled: true,
        }],
        "semodule -lfull after installing {name}"
    );
}

/// Creates a system account with no home, as root and before any drop.
fn useradd(name: &str) {
    let output = StdCommand::new("/usr/sbin/useradd")
        .args(["--system", "--no-create-home", name])
        .output()
        .expect("run useradd");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

/// The SELinux user `seusers` maps a login to, read from the file
/// `semanage` writes rather than from `semanage` itself.
fn seusers_entry(login: &str) -> Option<String> {
    let config = std::fs::read_to_string("/etc/selinux/config").expect("read /etc/selinux/config");
    let policy = config
        .lines()
        .find_map(|line| line.trim().strip_prefix("SELINUXTYPE="))
        .expect("SELINUXTYPE in /etc/selinux/config")
        .trim()
        .to_owned();
    let seusers = std::fs::read_to_string(format!("/etc/selinux/{policy}/seusers")).expect("read seusers");
    seusers.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next() == Some(login)).then(|| fields.next().unwrap_or_default().to_owned())
    })
}

/// The SELinux user `semanage login -l` lists for a login.
fn semanage_listed(login: &str) -> Option<String> {
    let output = StdCommand::new("/usr/sbin/semanage")
        .args(["login", "-l", "-n"])
        .output()
        .expect("run semanage login -l");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8_lossy(&output.stdout).lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next() == Some(login)).then(|| fields.next().unwrap_or_default().to_owned())
    })
}

fn a_module_installs_at_350_is_listed_and_is_removed() {
    let name = "forma_vmtest_plain";
    assert!(live_host().selinux_enabled());
    assert_eq!(live_host().selinux_module(name), Vec::<u16>::new());
    // secureblue's own modules sit at 300.
    assert_eq!(live_host().selinux_module("harden_userns"), [300]);
    install(name).expect("install the module");
    assert_installed_at_350(name);
    assert_eq!(live_host().selinux_module(name), [PRIORITY]);
    remove(name, PRIORITY).expect("remove the module");
    assert_eq!(listed(name), Vec::<InstalledModule>::new(), "the module is still listed");
    assert_eq!(live_host().selinux_module(name), Vec::<u16>::new());
}

fn a_remove_at_another_priority_leaves_the_module() {
    let name = "forma_vmtest_priority";
    install(name).expect("install the module");
    let result = remove(name, 400);
    assert!(
        matches!(result, Err(Error::Command(forma_process::Error::Failed { .. }))),
        "a remove at 400 of a module at 350: {result:?}"
    );
    assert_installed_at_350(name);
    remove(name, PRIORITY).expect("remove the module");
}

fn a_login_maps_to_user_u_and_is_unmapped() {
    let login = "ftselmap";
    useradd(login);
    assert_eq!(seusers_entry(login), None);
    admin::map_login(&token(), login, "user_u").expect("semanage login -a");
    assert_eq!(seusers_entry(login).as_deref(), Some("user_u"));
    assert_eq!(semanage_listed(login).as_deref(), Some("user_u"));
    assert_eq!(live_host().selinux_login(login).as_deref(), Some("user_u"));
    admin::unmap_login(&token(), login).expect("semanage login -d");
    assert_eq!(seusers_entry(login), None);
    assert_eq!(semanage_listed(login), None);
    assert_eq!(live_host().selinux_login(login), None);
}

fn with_the_listed_set_a_module_installs_and_is_removed() {
    drop_all_except(listed_set()).unwrap();
    let name = "forma_vmtest_capset";
    install(name).expect("install the module with the listed set");
    assert_installed_at_350(name);
    remove(name, PRIORITY).expect("remove the module with the listed set");
    assert_eq!(listed(name), Vec::<InstalledModule>::new(), "the module is still listed");
}

fn with_the_listed_set_a_login_maps_and_is_unmapped() {
    let login = "ftselcapmap";
    useradd(login);
    drop_all_except(listed_set()).unwrap();
    admin::map_login(&token(), login, "user_u").expect("semanage login -a with the listed set");
    assert_eq!(seusers_entry(login).as_deref(), Some("user_u"));
    admin::unmap_login(&token(), login).expect("semanage login -d with the listed set");
    assert_eq!(seusers_entry(login), None);
}
