//! The capability table (architecture 3.4, spike 0(d)), line by line.
//!
//! For each action `forma_user::admin` can carry out alone, one test drops
//! to exactly the set `Action::capabilities` lists and checks the action
//! works, and one test per capability in that set drops to the set less
//! that capability and checks the action fails and has not taken effect.
//! `CAP_AUDIT_WRITE` is the exception: shadow-utils works without it and
//! only loses its audit record, which this guest has no `auditd` to show,
//! so no test expects a failure without it.
//! The sets come from forma-plan, so a change to the table changes what
//! these tests run.
//!
//! Each test builds its fixture as full root, opens the root handle, and
//! only then drops: the drop is what the executor does before its first
//! action, and the fixture is not part of what is checked. Each test has
//! names of its own, so one that fails part way leaves nothing another
//! reads.
//!
//! Not here, because no public `forma_user::admin` call does them alone
//! (they wait for the executor): `WriteFile` and `RemovePath`.
//! `CreateUser` is the `useradd` pair in `main.rs`. The SELinux lines run in
//! the secureblue guest (`crates/selinux/module/tests/vm`).

use std::convert::Infallible;
use std::fmt::Debug;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use forma_plan::{Action, Principal};
use forma_privilege::{Capabilities, Capability, drop_all_except};
use forma_user::admin::{self, System, SystemConfig};
use forma_user::id::{SubIdCount, Uid};
use forma_user::lookup::{self, Group, LocalGroup, User};
use forma_user::name::{GroupName, UserName};
use forma_user::ownership::{Item, MarkerTag, NoJournal, Ownership};
use forma_user::path::AbsPath;
use forma_user::perm::FileMode;
use forma_user::spec::{DeleteOptions, GidChoice, GroupSpec, HomePolicy, SessionPolicy};

/// The directory the tests may create homes and files in. The image makes
/// it, owned by root with mode `0750`.
const BASE: &str = "/var/lib/forma-test-base";

/// One test of a line: with the listed set, or with one capability less.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Exactly the listed set.
    Listed,
    /// The listed set less this capability.
    Without(Capability),
}

impl Mode {
    /// A name of at most 14 characters for this line and mode, from a
    /// prefix of at most 6, so every account and group a test makes is its own.
    fn name(self, prefix: &str) -> String {
        let suffix = match self {
            Self::Listed => "ok",
            Self::Without(Capability::AuditWrite) => "noaudit",
            Self::Without(Capability::Chown) => "nochown",
            Self::Without(Capability::DacOverride) => "nodac",
            Self::Without(Capability::DacReadSearch) => "nodrs",
            Self::Without(Capability::Fowner) => "nofown",
            Self::Without(Capability::MacAdmin) => "nomac",
        };
        format!("ft{prefix}{suffix}")
    }

    /// Drops to the set this mode runs with.
    fn drop_for(self, action: &Action) {
        let listed = action.capabilities();
        let keep = match self {
            Self::Listed => listed,
            Self::Without(missing) => {
                assert!(listed.contains(missing), "{missing} is not listed for {action}");
                let kept: Vec<Capability> = listed.iter().filter(|capability| *capability != missing).collect();
                Capabilities::of(&kept)
            }
        };
        drop_all_except(keep).unwrap();
    }

    /// Checks the result: with the listed set the action works and took
    /// effect; without one capability it fails and did not.
    fn check<T: Debug, E: Debug>(self, action: &Action, result: &Result<T, E>, took_effect: bool) {
        match self {
            Self::Listed => {
                assert!(result.is_ok(), "{action} with its listed set: {result:?}");
                assert!(took_effect, "{action} with its listed set returned {result:?} but did not take effect");
            }
            Self::Without(missing) => {
                assert!(result.is_err(), "{action} without {missing} worked: {result:?}");
                assert!(!took_effect, "{action} without {missing} failed ({result:?}) but took effect");
            }
        }
    }
}

/// One line of the table: the action it stands for, and its test.
struct Line {
    /// The test name's stem.
    name: &'static str,
    /// The action, for its capabilities.
    action: fn() -> Action,
    /// The test, given the action and the mode.
    test: fn(Mode, &Action),
}

const LINES: &[Line] = &[
    Line {
        name: "create_group",
        action: || Action::CreateGroup {
            name: "g".into(),
            system: true,
        },
        test: create_group,
    },
    Line {
        name: "delete_group",
        action: || Action::DeleteGroup { name: "g".into() },
        test: delete_group,
    },
    Line {
        name: "delete_user",
        action: || Action::DeleteUser { name: "u".into() },
        test: delete_user,
    },
    Line {
        name: "add_member",
        action: || Action::AddMember {
            user: "u".into(),
            group: "g".into(),
        },
        test: add_member,
    },
    Line {
        name: "remove_member",
        action: || Action::RemoveMember {
            user: "u".into(),
            group: "g".into(),
        },
        test: remove_member,
    },
    Line {
        name: "add_sub_ids",
        action: || Action::AddSubIds {
            user: "u".into(),
            count: SubIdCount::MIN,
        },
        test: add_sub_ids,
    },
    Line {
        name: "remove_sub_ids",
        action: || Action::RemoveSubIds { user: "u".into() },
        test: remove_sub_ids,
    },
    Line {
        name: "create_dir",
        action: || Action::CreateDir {
            path: PathBuf::from("/d"),
            owner: Principal::Named("u".into()),
            group: Principal::Named("u".into()),
            mode: 0o700,
            before_linger: true,
        },
        test: create_dir,
    },
    Line {
        name: "set_group",
        action: || Action::SetGroup {
            path: PathBuf::from("/d"),
            group: "g".into(),
        },
        test: set_group,
    },
    Line {
        name: "restore_owner",
        action: || Action::RestoreOwner {
            path: PathBuf::from("/d"),
            uid: 0,
            gid: 0,
        },
        test: restore_owner,
    },
    Line {
        name: "grant_traverse",
        action: || Action::GrantTraverse {
            path: PathBuf::from("/d"),
            user: "u".into(),
        },
        test: grant_traverse,
    },
    Line {
        name: "revoke_acl",
        action: || Action::RevokeAcl {
            path: PathBuf::from("/d"),
            who: forma_ledger::AclWho::User,
            id: 0,
        },
        test: revoke_acl,
    },
    Line {
        name: "enable_linger",
        action: || Action::EnableLinger { user: "u".into() },
        test: enable_linger,
    },
    Line {
        name: "disable_linger",
        action: || Action::DisableLinger { user: "u".into() },
        test: disable_linger,
    },
];

/// The test of a line in one mode.
pub type Test = Box<dyn Fn()>;

/// Every test of every line: `<line>_works_with_the_listed_set`, and
/// `<line>_fails_without_<capability>` for each capability listed but
/// `CAP_AUDIT_WRITE`.
pub fn tests() -> Vec<(String, Test)> {
    let mut tests: Vec<(String, Test)> = Vec::new();
    for line in LINES {
        let (test, action) = (line.test, line.action);
        tests.push((
            format!("{}_works_with_the_listed_set", line.name),
            Box::new(move || test(Mode::Listed, &action())),
        ));
        for missing in action().capabilities().iter().filter(|&capability| capability != Capability::AuditWrite) {
            let kernel = missing.name().trim_start_matches("CAP_").to_lowercase();
            tests.push((
                format!("{}_fails_without_{kernel}", line.name),
                Box::new(move || test(Mode::Without(missing), &action())),
            ));
        }
    }
    tests
}

/// Claims everything: the fixtures are made by hand, not through the
/// library, so they carry no marker.
#[derive(Debug, Clone, Copy)]
struct ClaimAll;

impl Ownership for ClaimAll {
    type Error = Infallible;

    fn claims(&self, _item: &Item<'_>) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Opens the root handle, as full root.
fn open() -> System<ClaimAll, NoJournal> {
    let config = SystemConfig {
        allowed_bases: vec![abs(BASE)],
        allow_ids_outside_system_range: false,
        lock_file: abs("/run/forma-privilege-test.lock"),
        marker: MarkerTag::new("forma-privilege-vm-test").expect("a valid tag"),
        tool_timeout: Duration::from_secs(30),
        unit_timeout: Duration::from_secs(60),
    };
    System::open(config, ClaimAll, NoJournal).expect("open the root handle in the test VM")
}

fn abs(path: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(path.as_ref()).expect("an absolute path")
}

fn run(program: &str, args: &[&str]) {
    let output = Command::new(program).args(args).output().expect("start the program");
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Makes a system account with its own group and no home, by hand.
fn raw_user(name: &str) -> User {
    run("/usr/sbin/useradd", &["--system", "--no-create-home", name]);
    user(name).expect("the account exists")
}

/// Makes a system group, by hand.
fn raw_group(name: &str) -> LocalGroup {
    run("/usr/sbin/groupadd", &["--system", name]);
    local_group(name).expect("the group exists")
}

fn user(name: &str) -> Option<User> {
    lookup::user(&UserName::new(name).expect("a valid user name")).expect("look up")
}

fn local_group(name: &str) -> Option<LocalGroup> {
    match lookup::group(&GroupName::new(name).expect("a valid group name")).expect("look up") {
        Some(Group::Local(group)) => Some(group),
        None => None,
        Some(other) => panic!("{name} is not a local group: {other:?}"),
    }
}

fn is_member(user: &User, group: &str) -> bool {
    local_group(group).is_some_and(|group| group.info().has_member(user.name()))
}

fn sub_uid_lines(name: &str) -> usize {
    std::fs::read_to_string("/etc/subuid")
        .expect("read /etc/subuid")
        .lines()
        .filter(|line| line.split(':').next() == Some(name))
        .count()
}

/// A directory in [`BASE`] owned by `owner`, with `mode`.
fn owned_dir(name: &str, owner: &User, mode: u32) -> PathBuf {
    let path = Path::new(BASE).join(name);
    std::fs::create_dir(&path).expect("create the directory");
    chown(&path, Some(owner.uid().as_raw()), Some(owner.gid().as_raw())).expect("chown the directory");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod the directory");
    path
}

/// A directory in [`BASE`] owned by root and `gid`, with `mode`.
fn root_dir(name: &str, gid: u32, mode: u32) -> PathBuf {
    let path = Path::new(BASE).join(name);
    std::fs::create_dir(&path).expect("create the directory");
    chown(&path, Some(0), Some(gid)).expect("chown the directory");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod the directory");
    path
}

/// Whether the directory's ACL has an entry for `user` that grants `x` only.
fn has_traverse_entry(path: &Path, user: &User) -> bool {
    let output = Command::new("/usr/bin/getfacl")
        .args(["--numeric", "--omit-header", "--absolute-names"])
        .arg(path)
        .output()
        .expect("run getfacl");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let entry = format!("user:{}:--x", user.uid());
    String::from_utf8_lossy(&output.stdout).lines().any(|line| line == entry)
}

fn linger_file(user: &User) -> PathBuf {
    Path::new("/var/lib/systemd/linger").join(user.name().as_str())
}

fn create_group(mode: Mode, action: &Action) {
    let name = mode.name("cg");
    let mut system = open();
    mode.drop_for(action);
    let spec = GroupSpec {
        name: GroupName::new(&name).unwrap(),
        gid: GidChoice::Allocate,
    };
    let result = admin::group::create(&mut system, &spec);
    mode.check(action, &result, local_group(&name).is_some());
}

fn delete_group(mode: Mode, action: &Action) {
    let name = mode.name("dg");
    let group = raw_group(&name);
    let mut system = open();
    mode.drop_for(action);
    let result = admin::group::delete(&mut system, &group);
    mode.check(action, &result, local_group(&name).is_none());
}

fn delete_user(mode: Mode, action: &Action) {
    let name = mode.name("du");
    let account = raw_user(&name);
    let mut system = open();
    mode.drop_for(action);
    let options = DeleteOptions {
        home: HomePolicy::Keep,
        sessions: SessionPolicy::Refuse,
    };
    let result = admin::user::delete(&mut system, &account, options);
    mode.check(action, &result, user(&name).is_none());
}

fn add_member(mode: Mode, action: &Action) {
    let account = raw_user(&mode.name("amu"));
    let group_name = mode.name("amg");
    let group = raw_group(&group_name);
    let mut system = open();
    mode.drop_for(action);
    let result = admin::group::add_member(&mut system, &account, &group);
    mode.check(action, &result, is_member(&account, &group_name));
}

fn remove_member(mode: Mode, action: &Action) {
    let account = raw_user(&mode.name("rmu"));
    let group_name = mode.name("rmg");
    raw_group(&group_name);
    run(
        "/usr/sbin/usermod",
        &["--append", "--groups", &group_name, account.name().as_str()],
    );
    let group = local_group(&group_name).expect("the group exists");
    assert!(is_member(&account, &group_name), "the fixture's membership");
    let mut system = open();
    mode.drop_for(action);
    let result = admin::group::remove_member(&mut system, &account, &group);
    mode.check(action, &result, !is_member(&account, &group_name));
}

fn add_sub_ids(mode: Mode, action: &Action) {
    let account = raw_user(&mode.name("as"));
    let mut system = open();
    mode.drop_for(action);
    let count = SubIdCount::new(SubIdCount::MIN).unwrap();
    let result = admin::subid::allocate(&mut system, &account, count);
    mode.check(action, &result, sub_uid_lines(account.name().as_str()) == 1);
}

fn remove_sub_ids(mode: Mode, action: &Action) {
    let account = raw_user(&mode.name("rs"));
    let mut system = open();
    admin::subid::allocate(&mut system, &account, SubIdCount::new(SubIdCount::MIN).unwrap())
        .expect("the fixture's sub-IDs");
    mode.drop_for(action);
    let result = admin::subid::remove(&mut system, &account);
    mode.check(action, &result, sub_uid_lines(account.name().as_str()) == 0);
}

fn create_dir(mode: Mode, action: &Action) {
    // The plan's most demanding use: a directory forma owns inside an
    // account's home, which the account owns with mode 0700 (`.config` and
    // the directories under it, before linger). Root needs to search and
    // write the home, give the directory away, and then set the mode of a
    // directory it no longer owns. The plan asks for 0700, which is also
    // the mode `create_dir` makes the directory with; 0750 shows whether the
    // last step ran.
    let account = raw_user(&mode.name("cd"));
    let home = owned_dir(&mode.name("cd"), &account, 0o700);
    let path = home.join(".config");
    let mut system = open();
    mode.drop_for(action);
    let result = admin::perm::create_dir(
        &mut system,
        &abs(&path),
        account.uid(),
        account.gid(),
        FileMode::new(0o750).unwrap(),
    );
    // A failure after the mkdir leaves the directory as far as it got; the
    // executor's journal records the intent first, for that reason.
    let created = std::fs::symlink_metadata(&path).is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.uid() == account.uid().as_raw()
            && metadata.gid() == account.gid().as_raw()
            && metadata.mode() & 0o7777 == 0o750
    });
    mode.check(action, &result, created);
}

fn set_group(mode: Mode, action: &Action) {
    // As the plan uses it: an account's staging directory, which root
    // materia made (root's, and forma did not create it), gets the
    // account's group so the account can read it. Root is not in that group.
    let group = raw_group(&mode.name("sg"));
    let path = root_dir(&mode.name("sg"), 0, 0o750);
    let mut system = open();
    mode.drop_for(action);
    let result = admin::perm::set_owner(&mut system, &abs(&path), Uid::ROOT, group.info().gid());
    let metadata = std::fs::symlink_metadata(&path).expect("the directory");
    let changed = metadata.uid() == 0 && metadata.gid() == group.info().gid().as_raw();
    mode.check(action, &result, changed);
}

fn restore_owner(mode: Mode, action: &Action) {
    // The case that needs CAP_CHOWN: the owner before forma changed it was
    // not root's. Back to root:root needs none, because chown(2) lets an
    // owner pick any group it is in (VM, 2026-11-18); the table keeps
    // CAP_CHOWN because the ledger may record any previous owner.
    let current = raw_group(&mode.name("ro"));
    let previous = raw_user(&mode.name("rop"));
    let path = root_dir(&mode.name("ro"), current.info().gid().as_raw(), 0o750);
    let mut system = open();
    mode.drop_for(action);
    let result = admin::perm::set_owner(&mut system, &abs(&path), previous.uid(), previous.gid());
    let metadata = std::fs::symlink_metadata(&path).expect("the directory");
    let restored = (metadata.uid(), metadata.gid()) == (previous.uid().as_raw(), previous.gid().as_raw());
    mode.check(action, &result, restored);
}

fn grant_traverse(mode: Mode, action: &Action) {
    // As the plan uses it: an account passes through the store root,
    // root:root 0700, to its own directory below it, through the call the
    // action names. Root owns every directory that gets an entry, so the
    // line lists no capability.
    let account = raw_user(&mode.name("gt"));
    let store_root = root_dir(&mode.name("gt"), 0, 0o700);
    let mut system = open();
    mode.drop_for(action);
    let result = admin::perm::grant_traverse_through(&mut system, &abs(&store_root), &account);
    mode.check(action, &result, has_traverse_entry(&store_root, &account));
}

fn revoke_acl(mode: Mode, action: &Action) {
    // The grant above, taken back.
    let account = raw_user(&mode.name("ra"));
    let store_root = root_dir(&mode.name("ra"), 0, 0o700);
    let mut system = open();
    admin::perm::grant_traverse_through(&mut system, &abs(&store_root), &account).expect("the fixture's grant");
    assert!(has_traverse_entry(&store_root, &account), "the fixture's grant");
    mode.drop_for(action);
    let result = admin::perm::revoke_traverse_through(&mut system, &abs(&store_root), &account);
    mode.check(action, &result, !has_traverse_entry(&store_root, &account));
}

fn enable_linger(mode: Mode, action: &Action) {
    // logind decides by user ID (polkit), not by capability: the line
    // lists none. Turned off again so the user manager does not outlive
    // the test.
    let account = raw_user(&mode.name("el"));
    let mut system = open();
    mode.drop_for(action);
    let result = admin::systemd::linger::set(&mut system, &account, true);
    mode.check(action, &result, linger_file(&account).exists());
    admin::systemd::linger::disable_and_wait(&mut system, &account).expect("turn linger off again");
}

fn disable_linger(mode: Mode, action: &Action) {
    let account = raw_user(&mode.name("dl"));
    // By hand: the library's D-Bus connection would leave zbus's thread
    // running, and the drop refuses while there is more than one.
    run("/usr/bin/loginctl", &["enable-linger", account.name().as_str()]);
    assert!(linger_file(&account).exists(), "the fixture's linger");
    let mut system = open();
    mode.drop_for(action);
    let result = admin::systemd::linger::disable_and_wait(&mut system, &account);
    mode.check(action, &result, !linger_file(&account).exists());
}
