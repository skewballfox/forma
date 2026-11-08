//! The guard, the root handle and small helpers shared by the VM tests.

use std::convert::Infallible;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use forma_user::admin::{System, SystemConfig};
use forma_user::id::{Gid, IdRange, SystemGid, SystemUid, Uid};
use forma_user::lookup::{self, User};
use forma_user::name::{GroupName, UserName};
use forma_user::ownership::{Change, Facts, Item, Journal, Marker, MarkerTag, Ownership};
use forma_user::path::AbsPath;
use forma_user::spec::{GidChoice, GroupSpec, HomeSpec, PrimaryGroup, Shell, UidChoice, UserSpec};

/// Exists only in the test image.
const MARKER_FILE: &str = "/etc/forma-user-test-vm";

/// The marker tag of every account and file the tests create.
pub const TAG: &str = "forma-vm-test";

/// The only directory the tests may create homes and files in. The image
/// makes it.
pub const BASE: &str = "/var/lib/forma-test-base";

/// Stops the test unless it runs in the test VM.
///
/// Called before anything else, so a run on a real host fails here and not
/// somewhere that has already changed something.
pub fn require_vm() {
    assert!(
        Path::new(MARKER_FILE).exists(),
        "this test changes the system and runs only in the test VM, but {MARKER_FILE} is missing; run `just vm-test`",
    );
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let hypervisor = cpuinfo
        .lines()
        .filter(|line| line.starts_with("flags"))
        .any(|line| line.split_whitespace().any(|flag| flag == "hypervisor"));
    assert!(
        hypervisor,
        "this test changes the system and runs only in the test VM, but /proc/cpuinfo has no `hypervisor` flag; run `just vm-test`",
    );
}

/// Claims every item. For tests of operations that need a claim the
/// library's [`Marker`] never gives, such as one on a file's mode.
#[derive(Debug, Clone, Copy)]
pub struct ClaimAll;

impl Ownership for ClaimAll {
    type Error = Infallible;

    fn claims(&self, _item: &Item<'_>) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Records each change as `intent: <change>` and `applied: <change>`.
#[derive(Debug, Default)]
pub struct Recorder(Vec<String>);

impl Journal for Recorder {
    type Error = Infallible;

    fn intent(&mut self, change: &Change) -> Result<(), Self::Error> {
        self.0.push(format!("intent: {change}"));
        Ok(())
    }

    fn applied(&mut self, change: &Change, _facts: &Facts) -> Result<(), Self::Error> {
        self.0.push(format!("applied: {change}"));
        Ok(())
    }
}

/// What the journal of `system` has recorded so far.
pub fn journal<O: Ownership>(system: &System<O, Recorder>) -> &[String] {
    &system.journal().0
}

pub fn marker_tag() -> MarkerTag {
    MarkerTag::new(TAG).expect("the tag is valid")
}

pub fn marker() -> Marker {
    Marker { tag: marker_tag() }
}

/// Opens the root handle with the given ownership rules.
pub fn open<O: Ownership>(ownership: O) -> System<O, Recorder> {
    require_vm();
    let config = SystemConfig {
        allowed_bases: vec![abs(BASE)],
        allow_ids_outside_system_range: false,
        lock_file: abs("/run/forma-user-test.lock"),
        marker: marker_tag(),
        tool_timeout: Duration::from_secs(30),
        unit_timeout: Duration::from_secs(30),
    };
    System::open(config, ownership, Recorder::default()).expect("open the root handle in the test VM")
}

/// A root handle that owns what carries the test marker.
pub fn marker_system() -> System<Marker, Recorder> {
    open(marker())
}

pub fn abs(path: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(path.as_ref()).expect("an absolute path")
}

/// A path inside [`BASE`].
pub fn base_path(name: &str) -> AbsPath {
    abs(Path::new(BASE).join(name))
}

pub fn user_name(name: &str) -> UserName {
    UserName::new(name).expect("a valid user name")
}

pub fn group_name(name: &str) -> GroupName {
    GroupName::new(name).expect("a valid group name")
}

/// A spec for a system account with its own group, no home and no login.
pub fn user_spec(name: &str) -> UserSpec {
    UserSpec {
        name: user_name(name),
        uid: UidChoice::Allocate,
        primary_group: PrimaryGroup::New,
        supplementary: Vec::new(),
        home: HomeSpec::None,
        shell: Shell::NoLogin,
        comment: None,
    }
}

/// A spec for a system group with an allocated ID.
pub fn group_spec(name: &str) -> GroupSpec {
    GroupSpec {
        name: group_name(name),
        gid: GidChoice::Allocate,
    }
}

/// The comment `useradd` gets for an account the tests make by hand and the
/// crate should claim.
pub fn claimed_comment() -> String {
    format!("managed-by={TAG}")
}

/// Runs a program and returns its stdout. Panics if it fails.
pub fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Runs a program as `user`, with the account's own groups. Returns whether
/// it succeeded.
pub fn succeeds_as(user: &User, program: &str, args: &[&str]) -> bool {
    Command::new("/usr/bin/setpriv")
        .arg(format!("--reuid={}", user.uid()))
        .arg(format!("--regid={}", user.gid()))
        .arg("--init-groups")
        .arg(program)
        .args(args)
        .output()
        .expect("run setpriv")
        .status
        .success()
}

/// Makes an account with `useradd`, outside the crate. `claimed` gives it the
/// marker in its comment.
pub fn raw_user(name: &str, claimed: bool, extra: &[&str]) -> User {
    let comment = if claimed { claimed_comment() } else { String::new() };
    let mut args = vec!["--system", "--no-create-home", "--comment", comment.as_str()];
    args.extend_from_slice(extra);
    args.push(name);
    run("/usr/sbin/useradd", &args);
    lookup::user(&user_name(name)).expect("look up").expect("the account exists")
}

/// Makes a group with `groupadd`, outside the crate.
pub fn raw_group(name: &str, extra: &[&str]) {
    let mut args = vec!["--system"];
    args.extend_from_slice(extra);
    args.push(name);
    run("/usr/sbin/groupadd", &args);
}

/// The highest user and group ID in the system range that nothing uses.
pub fn free_system_id(range: IdRange) -> u32 {
    free_system_id_except(range, None)
}

/// Like [`free_system_id`], but never `except`.
pub fn free_system_id_except(range: IdRange, except: Option<u32>) -> u32 {
    (range.first()..=range.last())
        .rev()
        .filter(|&id| Some(id) != except)
        .find(|&id| {
            lookup::user_by_uid(Uid::from_raw(id)).expect("look up").is_none()
                && lookup::group_by_gid(Gid::from_raw(id)).expect("look up").is_none()
        })
        .expect("a free system ID")
}

pub fn system_uid(id: u32, range: IdRange) -> SystemUid {
    SystemUid::new(Uid::from_raw(id), range).expect("in the system range")
}

pub fn system_gid(id: u32, range: IdRange) -> SystemGid {
    SystemGid::new(Gid::from_raw(id), range).expect("in the system range")
}
