//! The ledger driven by a real `forma_user::admin::System`, as root.
//!
//! The unit tests in `src/journal.rs` call [`Recorder`]'s two traits by hand
//! with the changes `forma-user` is documented to report. These tests let
//! `forma-user` make real accounts, groups, sub-IDs, linger, directories and
//! ACL entries, with a [`Recorder`] as both its `Ownership` and its
//! `Journal`, and check the ledger file after each step.
//!
//! They change the machine they run on, so they run only in a VM:
//! `just ledger::vm-test`, or `just vm-test` for every crate. They use the
//! forma-user guest (`crates/user/vm`), which has everything they need.
//! Every test is `#[ignore]`d, so `cargo test` skips them, and each checks
//! for that guest before it touches anything.

use std::path::Path;
use std::time::Duration;

use forma_ledger::{Item, Key, Recorder, Status, Store};
use forma_user::admin::{self, Error, System, SystemConfig};
use forma_user::id::{Gid, SubIdCount, Uid};
use forma_user::lookup::{self, Group, LocalGroup, User};
use forma_user::name::{GroupName, UserName};
use forma_user::ownership::{Item as HostItem, MarkerTag, Ownership as _};
use forma_user::path::AbsPath;
use forma_user::perm::FileMode;
use forma_user::spec::{
    DeleteOptions, GidChoice, GroupSpec, HomePolicy, HomeSpec, PrimaryGroup, SessionPolicy, Shell, UidChoice, UserSpec,
};

/// Exists only in the forma-user guest image.
const MARKER_FILE: &str = "/etc/forma-user-test-vm";

/// The only directory the tests may create homes and files in. The image
/// makes it.
const BASE: &str = "/var/lib/forma-test-base";

/// Declares a test that runs in the VM only. The body runs after
/// [`require_vm`], so no test can reach the host.
macro_rules! vm_test {
    ($(#[$meta:meta])* fn $name:ident() $body:block) => {
        #[test]
        #[ignore = "needs the test VM: run `just ledger::vm-test`"]
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
        "this test changes the system and runs only in the test VM, but {MARKER_FILE} is missing; run `just ledger::vm-test`",
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

fn abs(path: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(path.as_ref()).expect("an absolute path")
}

fn base_path(name: &str) -> AbsPath {
    abs(Path::new(BASE).join(name))
}

/// A recorder over a ledger file in [`BASE`], and a root handle that uses it
/// as both its `Ownership` and its `Journal`, as forma's executor will.
fn open(ledger: &str, needs: &[&str]) -> (Recorder, System<Recorder, Recorder>) {
    let recorder = Recorder::new(Store::open(base_path(ledger).as_path()).expect("open the ledger"));
    recorder.set_needs(needs.iter().copied());
    let config = SystemConfig {
        allowed_bases: vec![abs(BASE)],
        allow_ids_outside_system_range: false,
        lock_file: abs("/run/forma-ledger-test.lock"),
        marker: MarkerTag::new("forma-ledger-vm-test").expect("a valid tag"),
        tool_timeout: Duration::from_secs(30),
        unit_timeout: Duration::from_secs(30),
    };
    let system = System::open(config, recorder.clone(), recorder.clone()).expect("open the root handle in the test VM");
    (recorder, system)
}

/// The ledger as the file holds it now, read afresh.
fn reread(ledger: &str) -> Store {
    Store::open(base_path(ledger).as_path()).expect("read the ledger back")
}

fn keys(store: &Store) -> Vec<String> {
    store
        .entries()
        .iter()
        .map(|entry| entry.item.key().to_string())
        .collect()
}

fn user_name(name: &str) -> UserName {
    UserName::new(name).expect("a valid user name")
}

fn group_name(name: &str) -> GroupName {
    GroupName::new(name).expect("a valid group name")
}

fn user(name: &str) -> User {
    lookup::user(&user_name(name))
        .expect("look up")
        .expect("the account exists")
}

fn local_group(name: &str) -> LocalGroup {
    match lookup::group(&group_name(name)).expect("look up") {
        Some(Group::Local(group)) => group,
        other => panic!("{name} is not a local group: {other:?}"),
    }
}

fn user_spec(name: &str, home: HomeSpec) -> UserSpec {
    UserSpec {
        name: user_name(name),
        uid: UidChoice::Allocate,
        primary_group: PrimaryGroup::New,
        supplementary: Vec::new(),
        home,
        shell: Shell::NoLogin,
        comment: None,
    }
}

fn mode(bits: u32) -> FileMode {
    FileMode::new(bits).expect("a valid mode")
}

/// Runs a program and panics if it fails.
fn run(program: &str, args: &[&str]) {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}

vm_test! {
    fn every_change_lands_in_the_ledger_file_and_goes_when_undone() {
        const LEDGER: &str = "lifecycle.toml";
        let (recorder, mut system) = open(LEDGER, &["app"]);

        // Make one of everything an account needs.
        let group = admin::group::create(&mut system, &GroupSpec { name: group_name("ftlgroup"), gid: GidChoice::Allocate })
            .unwrap();
        let account = admin::user::create(&mut system, &user_spec("ftluser", HomeSpec::Create(base_path("ftluser"))))
            .unwrap();
        assert!(admin::group::add_member(&mut system, &account, &group).unwrap());
        let range = admin::subid::allocate(&mut system, &account, SubIdCount::new(SubIdCount::MIN).unwrap()).unwrap();
        assert!(admin::systemd::linger::set(&mut system, &account, true).unwrap());
        let outer = base_path("ftl-store");
        let inner = abs(outer.as_path().join("inner"));
        admin::perm::create_dir(&mut system, &outer, Uid::ROOT, Gid::ROOT, mode(0o700)).unwrap();
        admin::perm::create_dir(&mut system, &inner, Uid::ROOT, Gid::ROOT, mode(0o755)).unwrap();
        let granted = admin::perm::grant_traverse(&mut system, &inner, &account).unwrap();
        assert!(granted.contains(&outer), "the 0700 directory needed a grant: {granted:?}");

        // The file holds every change, applied, with the IDs the host gave.
        let store = reread(LEDGER);
        let found = keys(&store);
        let mut expected = vec![
            "group:ftlgroup".to_owned(),
            "user:ftluser".to_owned(),
            "member:ftluser:ftlgroup".to_owned(),
            "subids:ftluser".to_owned(),
            "linger:ftluser".to_owned(),
            format!("path:{outer}"),
            format!("path:{inner}"),
        ];
        expected.extend(granted.iter().map(|dir| Key::acl_grant(dir.as_path(), forma_ledger::AclWho::User, account.uid().as_raw()).to_string()));
        for key in &expected {
            assert!(found.contains(key), "the ledger lacks {key}: {found:#?}");
        }
        for entry in store.entries() {
            assert_eq!(entry.status, Status::Applied, "{}", entry.item);
            assert!(entry.needed_by.contains("app"), "{}", entry.item);
        }
        let recorded_user = store.get(&Key::user("ftluser")).map(|entry| entry.item.clone());
        assert_eq!(
            recorded_user,
            Some(Item::User { name: "ftluser".into(), uid: Some(account.uid().as_raw()), gid: Some(account.gid().as_raw()) })
        );
        let recorded_group = store.get(&Key::group("ftlgroup")).map(|entry| entry.item.clone());
        assert_eq!(
            recorded_group,
            Some(Item::Group { name: "ftlgroup".into(), gid: Some(group.info().gid().as_raw()) })
        );
        assert!(
            matches!(store.get(&Key::sub_ids("ftluser")).map(|entry| &entry.item),
                Some(Item::SubIds { start, count, .. }) if *start == range.start() && *count == range.count()),
            "{:?}",
            store.get(&Key::sub_ids("ftluser"))
        );

        // The recorder claims what is on the host, so forma may change it.
        let account = user("ftluser");
        let group = local_group("ftlgroup");
        assert!(recorder.claims(&HostItem::User(&account)).unwrap());
        assert!(recorder.claims(&HostItem::Group(&group)).unwrap());
        assert!(recorder.claims(&HostItem::Membership { user: &account, group: &group }).unwrap());
        assert!(recorder.claims(&HostItem::SubIds { user: &account, range }).unwrap());
        // useradd -U made a group with the account's name; the account's entry claims it.
        assert!(recorder.claims(&HostItem::Group(&local_group("ftluser"))).unwrap());

        // Undo everything, in the order forma's revert does.
        assert_eq!(admin::perm::revoke_traverse(&mut system, &inner, &account).unwrap(), granted);
        // Waits for the user manager: until it has stopped, usermod refuses the account.
        assert!(admin::systemd::linger::disable_and_wait(&mut system, &account).unwrap());
        admin::subid::remove(&mut system, &account).unwrap();
        assert!(admin::group::remove_member(&mut system, &account, &group).unwrap());
        let options = DeleteOptions { home: HomePolicy::Remove, sessions: SessionPolicy::Terminate };
        assert_eq!(admin::user::delete(&mut system, &account, options).unwrap(), None);
        admin::group::delete(&mut system, &group).unwrap();

        // Only the two directories are left: forma-user has no call that removes a directory.
        let store = reread(LEDGER);
        assert_eq!(keys(&store), [format!("path:{outer}"), format!("path:{inner}")], "{}", store.to_toml());
        assert!(lookup::user(&user_name("ftluser")).unwrap().is_none());
        assert!(lookup::group(&group_name("ftlgroup")).unwrap().is_none());
    }
}

vm_test! {
    fn an_account_the_ledger_does_not_hold_is_never_changed() {
        let (_recorder, mut system) = open("foreign.toml", &["app"]);
        // Made by hand, with forma-user's own marker in its comment: the
        // ledger alone decides, so the marker does not help.
        run("/usr/sbin/useradd", &["--system", "--no-create-home", "--comment", "managed-by=forma-ledger-vm-test", "ftlforeign"]);
        let foreign = user("ftlforeign");

        let ensure = admin::user::ensure(&mut system, &user_spec("ftlforeign", HomeSpec::None));
        assert!(matches!(ensure, Err(Error::NotOwned(_))), "{ensure:?}");
        let options = DeleteOptions { home: HomePolicy::Keep, sessions: SessionPolicy::Refuse };
        let delete = admin::user::delete(&mut system, &foreign, options);
        assert!(matches!(delete, Err(Error::NotOwned(_))), "{delete:?}");
        let linger_off = admin::systemd::linger::set(&mut system, &foreign, false);
        assert!(matches!(linger_off, Err(Error::NotOwned(_))), "{linger_off:?}");

        assert!(lookup::user(&user_name("ftlforeign")).unwrap().is_some());
        assert_eq!(keys(&reread("foreign.toml")), [] as [String; 0]);
    }
}

vm_test! {
    fn an_account_with_the_recorded_name_and_another_user_id_is_not_forma_s() {
        const LEDGER: &str = "replaced.toml";
        let (recorder, mut system) = open(LEDGER, &["app"]);
        let made = admin::user::create(&mut system, &user_spec("ftlreplaced", HomeSpec::None)).unwrap();
        assert!(recorder.claims(&HostItem::User(&made)).unwrap());

        // Someone removes it and makes another account with the same name.
        // useradd gives a system account the highest free ID, so a filler
        // takes the freed one first.
        run("/usr/sbin/userdel", &["ftlreplaced"]);
        run("/usr/sbin/useradd", &["--system", "--no-create-home", "ftlfiller"]);
        run("/usr/sbin/useradd", &["--system", "--no-create-home", "ftlreplaced"]);
        let other = user("ftlreplaced");
        assert_ne!(other.uid(), made.uid(), "useradd reused the user ID; the test proves nothing");

        assert!(!recorder.claims(&HostItem::User(&other)).unwrap(), "architecture 4.3, rule 3");
        let options = DeleteOptions { home: HomePolicy::Keep, sessions: SessionPolicy::Refuse };
        let delete = admin::user::delete(&mut system, &other, options);
        assert!(matches!(delete, Err(Error::NotOwned(_))), "{delete:?}");
        assert!(lookup::user(&user_name("ftlreplaced")).unwrap().is_some());
        // The entry still names the account forma made.
        assert!(
            matches!(reread(LEDGER).get(&Key::user("ftlreplaced")).map(|entry| &entry.item),
                Some(Item::User { uid: Some(uid), .. }) if *uid == made.uid().as_raw()),
        );
    }
}

vm_test! {
    fn a_change_that_fails_leaves_a_pending_entry_to_settle() {
        const LEDGER: &str = "pending.toml";
        let (_recorder, mut system) = open(LEDGER, &["app"]);
        // useradd refuses a name that is taken; the ledger had already
        // recorded the intent.
        run("/usr/sbin/groupadd", &["--system", "ftlclash"]);
        let result = admin::user::create(&mut system, &user_spec("ftlclash", HomeSpec::None));
        assert!(result.is_err(), "{result:?}");

        let store = reread(LEDGER);
        let unsettled: Vec<String> = store.unsettled().iter().map(|entry| entry.item.key().to_string()).collect();
        // Either forma-user refused before it recorded anything, or the
        // entry waits as pending for `forma_plan::recover`. Never applied.
        assert!(
            unsettled.is_empty() || unsettled == ["user:ftlclash"],
            "{}",
            store.to_toml()
        );
        assert!(
            store.get(&Key::user("ftlclash")).is_none_or(|entry| entry.status == Status::Pending),
            "{}",
            store.to_toml()
        );
    }
}
