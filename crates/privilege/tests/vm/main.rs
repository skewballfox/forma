//! Capability checks that need root: [`acquire`] with the capabilities
//! held, and [`drop_all_except`] read back from `/proc`.
//!
//! They run only in a VM: `just privilege::vm-test`, or `just vm-test` for
//! every crate. They use the forma-user guest (`crates/user/vm`).
//!
//! Capabilities belong to each thread, and `drop_all_except` refuses to run
//! while the process has more than one. libtest always runs tests beside its
//! own main thread, so this target has no libtest (`harness = false` in
//! Cargo.toml). [`main`] runs each test in a fresh copy of this binary, on
//! that process's only thread, and prints the results as libtest does.
//! Without `--ignored`, as from `cargo test`, it runs nothing.

use std::path::Path;
use std::process::{Command, ExitCode};

use forma_privilege::{
    Capabilities, Capability, Error, NoCapabilities, Set, acquire, capability_set, drop_all_except, effective,
};

/// Exists only in the forma-user guest image.
const MARKER_FILE: &str = "/etc/forma-user-test-vm";

/// Set in a child copy of the test binary to the name of the test it runs.
const CHILD: &str = "FORMA_PRIVILEGE_VM_CHILD";

capability_set! {
    /// Every capability forma knows.
    struct Everything: AuditWrite, Chown, DacOverride, DacReadSearch, Fowner, MacAdmin;
}

capability_set! {
    /// What creating an account needs (architecture 3.4).
    struct Accounts: AuditWrite, Chown, DacOverride, Fowner;
}

capability_set! {
    /// What installing an SELinux module needs.
    struct SeLinux: DacOverride, MacAdmin;
}

/// Every test, by name. Each runs in its own process.
const TESTS: &[(&str, fn())] = &[
    (
        "root_holds_every_capability_forma_knows",
        root_holds_every_capability_forma_knows,
    ),
    (
        "drop_all_except_leaves_only_what_was_kept_in_every_set",
        drop_all_except_leaves_only_what_was_kept_in_every_set,
    ),
    (
        "a_program_started_after_the_drop_gets_no_more_than_was_kept",
        a_program_started_after_the_drop_gets_no_more_than_was_kept,
    ),
    (
        "without_dac_override_useradd_cannot_write_the_account_files",
        without_dac_override_useradd_cannot_write_the_account_files,
    ),
    (
        "with_the_documented_set_useradd_works",
        with_the_documented_set_useradd_works,
    ),
    ("a_second_drop_cannot_widen_the_set", a_second_drop_cannot_widen_the_set),
    (
        "a_drop_with_another_thread_running_is_refused_and_changes_nothing",
        a_drop_with_another_thread_running_is_refused_and_changes_nothing,
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
        println!("the privilege VM tests run only in the VM: just privilege::vm-test");
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
        let output = Command::new(std::env::current_exe().expect("the test binary's path"))
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
        "this test changes the system and runs only in the test VM, but {MARKER_FILE} is missing; run `just privilege::vm-test`",
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

/// The kernel's number for a capability, as `/proc/<pid>/status` counts bits.
fn bit(capability: Capability) -> u64 {
    let number = match capability {
        Capability::Chown => 0,
        Capability::DacOverride => 1,
        Capability::DacReadSearch => 2,
        Capability::Fowner => 3,
        Capability::AuditWrite => 29,
        Capability::MacAdmin => 33,
    };
    1 << number
}

fn mask(set: Capabilities) -> u64 {
    set.iter().map(bit).fold(0, |all, one| all | one)
}

/// The five capability sets of a process, from its `/proc/<pid>/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sets {
    inheritable: u64,
    permitted: u64,
    effective: u64,
    bounding: u64,
    ambient: u64,
}

fn sets(status: &str) -> Sets {
    let field = |name: &str| {
        let line = status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap_or_else(|| panic!("no {name} in the status:\n{status}"));
        u64::from_str_radix(line.trim(), 16).unwrap_or_else(|_| panic!("{name} is not hex: {line}"))
    };
    Sets {
        inheritable: field("CapInh:"),
        permitted: field("CapPrm:"),
        effective: field("CapEff:"),
        bounding: field("CapBnd:"),
        ambient: field("CapAmb:"),
    }
}

/// The sets of the process: of its main thread, the only one in these tests.
fn own_sets() -> Sets {
    sets(&std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status"))
}

/// The sets a program started now gets: `cat` prints its own status.
fn child_sets() -> Sets {
    let output = Command::new("/usr/bin/cat")
        .arg("/proc/self/status")
        .output()
        .expect("run cat");
    assert!(output.status.success());
    sets(&String::from_utf8_lossy(&output.stdout))
}

fn user_exists(name: &str) -> bool {
    Command::new("/usr/bin/getent")
        .args(["passwd", name])
        .status()
        .expect("run getent")
        .success()
}

fn useradd(name: &str) -> std::process::Output {
    Command::new("/usr/sbin/useradd")
        .args(["--system", "--no-create-home", name])
        .output()
        .expect("run useradd")
}

fn root_holds_every_capability_forma_knows() {
    assert_eq!(effective().unwrap(), Everything::CAPABILITIES);
    acquire::<Everything>().unwrap();
    acquire::<NoCapabilities>().unwrap();
}

fn drop_all_except_leaves_only_what_was_kept_in_every_set() {
    drop_all_except(Accounts::CAPABILITIES).unwrap();
    let kept = mask(Accounts::CAPABILITIES);
    assert_eq!(
        own_sets(),
        Sets {
            inheritable: 0,
            permitted: kept,
            effective: kept,
            bounding: kept,
            ambient: 0
        },
        "kept {kept:#x}"
    );
    assert_eq!(effective().unwrap(), Accounts::CAPABILITIES);
    acquire::<Accounts>().unwrap();
    match acquire::<SeLinux>() {
        Err(Error::Missing { missing }) => {
            assert_eq!(missing, Capabilities::of(&[Capability::MacAdmin]));
        }
        other => panic!("acquire after the drop: {other:?}"),
    }
}

fn a_program_started_after_the_drop_gets_no_more_than_was_kept() {
    drop_all_except(Accounts::CAPABILITIES).unwrap();
    let kept = mask(Accounts::CAPABILITIES);
    let child = child_sets();
    // A program root starts gets its bounding set as permitted again,
    // and the bounding set is what was kept: nothing more.
    assert_eq!(child.bounding, kept, "{child:#x?}");
    assert_eq!(child.permitted & !kept, 0, "{child:#x?}");
    assert_eq!(child.effective & !kept, 0, "{child:#x?}");
    assert_eq!(child.ambient, 0, "{child:#x?}");
}

fn without_dac_override_useradd_cannot_write_the_account_files() {
    // root owns /etc/passwd, but /etc/shadow has mode 0000: writing it
    // needs CAP_DAC_OVERRIDE.
    drop_all_except(Capabilities::of(&[
        Capability::AuditWrite,
        Capability::Chown,
        Capability::Fowner,
    ]))
    .unwrap();
    let output = useradd("ftprivnodac");
    assert!(!output.status.success(), "useradd succeeded without CAP_DAC_OVERRIDE");
    assert!(!user_exists("ftprivnodac"), "useradd failed but left the account");
}

fn with_the_documented_set_useradd_works() {
    // The control for the test above: the same call with the set
    // architecture 3.4 lists for creating an account.
    drop_all_except(Accounts::CAPABILITIES).unwrap();
    let output = useradd("ftprivdac");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(user_exists("ftprivdac"));
}

fn a_second_drop_cannot_widen_the_set() {
    let chown = Capabilities::of(&[Capability::Chown]);
    drop_all_except(chown).unwrap();
    let wider = chown.union(Capabilities::of(&[Capability::DacOverride]));
    let result = drop_all_except(wider);
    assert!(matches!(result, Err(Error::Kernel { .. })), "{result:?}");
    assert_eq!(effective().unwrap(), chown);
    assert_eq!(own_sets().bounding, mask(chown));
}

fn a_drop_with_another_thread_running_is_refused_and_changes_nothing() {
    let before = own_sets();
    let _parked = std::thread::spawn(std::thread::park);
    match drop_all_except(Accounts::CAPABILITIES) {
        Err(Error::Threads { count: 2 }) => {}
        other => panic!("drop with two threads: {other:?}"),
    }
    assert_eq!(own_sets(), before, "the refused drop changed the sets");
    assert_eq!(effective().unwrap(), Everything::CAPABILITIES);
}
