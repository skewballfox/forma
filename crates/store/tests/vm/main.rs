//! Publish and load with two real accounts, as architecture 5.7 lays the
//! store out: the signer publishes into an account directory it owns, the
//! account reads it through its group, and neither is the other.
//!
//! ```text
//! /var/lib/forma/staging/                 root:root  0755
//! └── <image-name>/                       root:<signer>  2750 (the builder's, here root's)
//! /var/lib/forma/store/                   root:root  0700, ACL u:<signer>:x, u:<account>:x
//! └── <account>/                          <signer>:<account>  2750
//! ```
//!
//! They make accounts and write under `/var/lib/forma`, so they run only in
//! a VM: `just store::vm-test`, or `just vm-test` for every crate. They use
//! the forma-user guest (`crates/user/vm`).
//!
//! Each side runs as its own user: [`main`] runs each test as root in a
//! fresh copy of this binary, and the test starts further copies as the
//! signer or the account, with their user and group IDs and no
//! supplementary groups (`std`'s `CommandExt::uid` drops them). That
//! needs no `setpriv` and no PAM. The role a copy plays is in
//! [`ROLE`]. Without `--ignored`, as from `cargo test`, it runs nothing.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use forma_signing_payload::{ManifestDigest, Payload, SignatureFile};
use forma_store::{ImageName, Publish, Published, images, lock_shared, publish};
use forma_user::lookup::{self, User};
use forma_user::name::UserName;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};

/// Exists only in the forma-user guest image.
const MARKER_FILE: &str = "/etc/forma-user-test-vm";

/// Set in a child copy of the test binary to the name of the test it runs.
const CHILD: &str = "FORMA_STORE_VM_CHILD";
/// Set in a child copy that plays a side: `publish`, `read` or `hold`.
const ROLE: &str = "FORMA_STORE_VM_ROLE";
/// The account directory a side works on.
const ACCOUNT_DIR: &str = "FORMA_STORE_VM_ACCOUNT_DIR";
/// The image a side works on.
const IMAGE: &str = "FORMA_STORE_VM_IMAGE";

const STAGING: &str = "/var/lib/forma/staging";
const STORE: &str = "/var/lib/forma/store";
/// Where the copies that run as other users are started from: the
/// virtiofs share's owner and modes come from the host.
const BINARY: &str = "/var/lib/forma-store-vm/vm-tests";
const REFERENCE: &str = "localhost/app/app:latest";

/// How long a side may take to reach the point a test waits for.
const PATIENCE: Duration = Duration::from_secs(60);

/// Every test, by name. Each runs in its own process, as root.
const TESTS: &[(&str, fn())] = &[
    (
        "a_signer_outside_the_group_publishes_and_the_account_reads_every_file",
        a_signer_outside_the_group_publishes_and_the_account_reads_every_file,
    ),
    (
        "a_load_holding_the_lock_makes_a_publish_wait_before_its_swap",
        a_load_holding_the_lock_makes_a_publish_wait_before_its_swap,
    ),
];

fn main() -> ExitCode {
    if let Ok(role) = std::env::var(ROLE) {
        // A side, already running as the signer or the account, so not root.
        require_guest();
        match role.as_str() {
            "publish" => role_publish(),
            "read" => role_read(),
            "hold" => role_hold(),
            other => panic!("no role named {other}"),
        }
        return ExitCode::SUCCESS;
    }
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
        println!("the forma-store VM tests run only in the VM: just store::vm-test");
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

/// Stops the run unless it is in the test VM, as root.
fn require_vm() {
    require_guest();
    assert!(rustix::process::geteuid().is_root(), "the VM runs the tests as root");
}

/// Stops the run unless it is in the test VM.
fn require_guest() {
    assert!(
        Path::new(MARKER_FILE).exists(),
        "this test changes the system and runs only in the test VM, but {MARKER_FILE} is missing; run `just store::vm-test`",
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

// --- The sides, each running as its own user ---

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

/// The signer: publishes the staged image, with umask 027 as 5.7 asks.
fn role_publish() {
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o027));
    let image = ImageName::new(&env(IMAGE)).unwrap();
    let account_dir = PathBuf::from(env(ACCOUNT_DIR));
    let manifest = std::fs::read(Path::new(STAGING).join(image.as_str()).join("manifest.json"))
        .expect("the signer reads the staged manifest");
    let published = publish(&Publish {
        staging: Path::new(STAGING),
        account_dir: &account_dir,
        image: &image,
        reference: REFERENCE,
        signature: &signature_for(&manifest),
    })
    .expect("publish");
    println!("{published:?}");
}

/// The account: takes the lock, lists the images and reads every file.
fn role_read() {
    let account_dir = PathBuf::from(env(ACCOUNT_DIR));
    let lock = lock_shared(&account_dir).expect("lock the account directory shared");
    let mut read = 0;
    for image in images(&account_dir).expect("list the images") {
        let dir = account_dir.join(image.as_str());
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|error| panic!("list {}: {error}", dir.display())) {
            let path = entry.expect("a directory entry").path();
            std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            read += 1;
        }
    }
    drop(lock);
    println!("{read}");
}

/// The account in the middle of a load: holds the lock shared, says so on
/// standard output, and lets go when standard input closes.
fn role_hold() {
    let account_dir = PathBuf::from(env(ACCOUNT_DIR));
    let lock = lock_shared(&account_dir).expect("lock the account directory shared");
    println!("locked");
    std::io::stdout().flush().unwrap();
    let _ = std::io::stdin().lines().count();
    drop(lock);
}

// --- Set-up, as root ---

fn signature_for(manifest: &[u8]) -> Vec<u8> {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let payload = Payload::new(REFERENCE, ManifestDigest::of(manifest)).unwrap().to_bytes();
    let signature: Signature = key.sign(&payload);
    SignatureFile::new(payload, signature.to_der().as_bytes())
        .unwrap()
        .encode()
}

fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().expect("start the program");
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Makes a system account with its own group and no home.
fn account(name: &str) -> User {
    run("/usr/sbin/useradd", &["--system", "--no-create-home", name]);
    lookup::user(&UserName::new(name).unwrap())
        .expect("look up")
        .expect("the account exists")
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).expect("stat").mode() & 0o7777
}

/// The two accounts and their store, laid out as 5.7 says.
struct Store {
    signer: User,
    account: User,
    account_dir: PathBuf,
    image: ImageName,
}

impl Store {
    fn new(signer: &str, account_name: &str, image: &str) -> Self {
        let signer = account(signer);
        let account = account(account_name);
        let image = ImageName::new(image).unwrap();

        // The binary the sides run, where both can start it.
        let binary = Path::new(BINARY);
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        if !binary.exists() {
            std::fs::copy(std::env::current_exe().unwrap(), binary).expect("copy the test binary");
            set_mode(binary, 0o755);
        }

        std::fs::create_dir_all(STAGING).unwrap();
        set_mode(Path::new("/var/lib/forma"), 0o755);
        set_mode(Path::new(STAGING), 0o755);
        std::fs::create_dir_all(STORE).unwrap();
        set_mode(Path::new(STORE), 0o700);
        for user in [&signer, &account] {
            run(
                "/usr/bin/setfacl",
                &["--modify", &format!("u:{}:x", user.uid()), STORE],
            );
        }

        let account_dir = Path::new(STORE).join(account_name);
        std::fs::create_dir(&account_dir).unwrap();
        chown(&account_dir, Some(signer.uid().as_raw()), Some(account.gid().as_raw())).unwrap();
        set_mode(&account_dir, 0o2750);

        let store = Self {
            signer,
            account,
            account_dir,
            image,
        };
        store.stage(b"{\"v\":1}", b"layer one");
        store
    }

    /// Replaces the staged image: readable by the signer's group only.
    fn stage(&self, manifest: &[u8], blob: &[u8]) {
        let dir = Path::new(STAGING).join(self.image.as_str());
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        chown(&dir, Some(0), Some(self.signer.gid().as_raw())).unwrap();
        set_mode(&dir, 0o2750);
        for (name, bytes) in [
            ("manifest.json", manifest),
            ("version", b"Directory Transport Version: 1.1\n".as_slice()),
            ("aaaa", blob),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            chown(&path, Some(0), Some(self.signer.gid().as_raw())).unwrap();
            set_mode(&path, 0o640);
        }
    }

    /// A copy of this binary playing `role` as `user`.
    fn side(&self, role: &str, user: &User) -> Command {
        let mut command = Command::new(BINARY);
        command
            .env_clear()
            .env(ROLE, role)
            .env(ACCOUNT_DIR, &self.account_dir)
            .env(IMAGE, self.image.as_str())
            .uid(user.uid().as_raw())
            .gid(user.gid().as_raw())
            .current_dir("/");
        command
    }

    /// Runs a side to the end and returns what it printed. Panics if it fails.
    fn run_side(&self, role: &str, user: &User) -> String {
        let output = self.side(role, user).output().expect("start the side");
        assert!(
            output.status.success(),
            "{role} as {}: {}\n{}",
            user.name(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn published(&self) -> PathBuf {
        self.account_dir.join(self.image.as_str())
    }

    fn new_copy(&self) -> PathBuf {
        self.account_dir.join(format!("{}.new", self.image))
    }

    /// Checks the image directory and its files: the signer's, the
    /// account's group, `2750` and `0640`.
    fn check_image_dir(&self) {
        let dir = self.published();
        let metadata = std::fs::symlink_metadata(&dir).expect("the image directory");
        assert_eq!(metadata.mode() & 0o7777, 0o2750, "mode of {}", dir.display());
        assert_eq!(metadata.uid(), self.signer.uid().as_raw(), "owner of {}", dir.display());
        assert_eq!(metadata.gid(), self.account.gid().as_raw(), "group of {}", dir.display());
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            assert_eq!(metadata.mode() & 0o7777, 0o640, "mode of {name}");
            assert_eq!(metadata.gid(), self.account.gid().as_raw(), "group of {name}");
            names.push(name);
        }
        names.sort();
        assert_eq!(names, ["aaaa", "manifest.json", "signature-1", "version"]);
    }
}

/// The supplementary and primary group IDs of an account.
fn group_ids(user: &User) -> Vec<u32> {
    lookup::group_ids(user)
        .expect("the account's groups")
        .iter()
        .map(|gid| gid.as_raw())
        .collect()
}

/// The ACL of a path as `getfacl` prints it, with numeric IDs and no header.
fn acl(path: &str) -> Vec<String> {
    run("/usr/bin/getfacl", &["--numeric", "--omit-header", path])
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Waits for `ready`, at most [`PATIENCE`].
fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !ready() {
        assert!(Instant::now() < deadline, "gave up waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Whether the kernel lists a process as waiting for a `flock` (a `->`
/// line in `/proc/locks`).
fn waits_for_flock(child: &Child) -> bool {
    let pid = child.id().to_string();
    std::fs::read_to_string("/proc/locks")
        .expect("read /proc/locks")
        .lines()
        .any(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.get(1) == Some(&"->") && fields.get(2) == Some(&"FLOCK") && fields.get(5) == Some(&pid.as_str())
        })
}

// --- The tests ---

fn a_signer_outside_the_group_publishes_and_the_account_reads_every_file() {
    let store = Store::new("ftsigner1", "ftacct1", "app_one_latest");
    assert!(
        !group_ids(&store.signer).contains(&store.account.gid().as_raw()),
        "the signer is in the account's group"
    );

    assert_eq!(store.run_side("publish", &store.signer), format!("{:?}", Published::First));

    // The store root: 0700, plus traverse-only entries. The other test's
    // accounts may have entries too, so check each line rather than the list.
    let entries = acl(STORE);
    for wanted in [
        "user::rwx".to_owned(),
        format!("user:{}:--x", store.signer.uid()),
        format!("user:{}:--x", store.account.uid()),
        "group::---".to_owned(),
        "mask::--x".to_owned(),
        "other::---".to_owned(),
    ] {
        assert!(entries.contains(&wanted), "no {wanted} in the store root's ACL: {entries:?}");
    }
    for entry in &entries {
        let named = entry.starts_with("user:") && !entry.starts_with("user::");
        assert!(!named || entry.ends_with(":--x"), "{entry} grants more than x: {entries:?}");
        assert!(!entry.starts_with("group:") || entry == "group::---", "{entry}: {entries:?}");
    }
    let root = std::fs::symlink_metadata(STORE).unwrap();
    assert_eq!((root.uid(), root.gid()), (0, 0));

    // The account directory is as root made it, and the image directory
    // got its group from it.
    let metadata = std::fs::symlink_metadata(&store.account_dir).unwrap();
    assert_eq!(mode(&store.account_dir), 0o2750);
    assert_eq!(
        (metadata.uid(), metadata.gid()),
        (store.signer.uid().as_raw(), store.account.gid().as_raw())
    );
    store.check_image_dir();

    // The account reads every file: four in the image directory.
    assert_eq!(store.run_side("read", &store.account), "4");

    // A third account, with no entry on the store root, cannot load.
    let other = account("ftother1");
    let output = store.side("read", &other).output().unwrap();
    assert!(!output.status.success(), "an account with no traverse entry read the store");
}

fn a_load_holding_the_lock_makes_a_publish_wait_before_its_swap() {
    let store = Store::new("ftsigner2", "ftacct2", "app_two_latest");
    assert_eq!(store.run_side("publish", &store.signer), format!("{:?}", Published::First));
    let old = std::fs::read(store.published().join("manifest.json")).unwrap();

    // A load in progress: the account holds the lock shared.
    let mut holder = store
        .side("hold", &store.account)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start the holding load");
    let mut line = String::new();
    BufReader::new(holder.stdout.take().unwrap())
        .read_line(&mut line)
        .expect("read from the holding load");
    assert_eq!(line.trim(), "locked");

    // A new image, published meanwhile.
    store.stage(b"{\"v\":2}", b"layer two");
    let mut publisher = store
        .side("publish", &store.signer)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the publish");

    // The copy is made without the lock; the swap waits for it.
    wait_for("the publish to wait for the lock", || {
        assert!(
            publisher.try_wait().unwrap().is_none(),
            "the publish finished while a load held the lock"
        );
        waits_for_flock(&publisher)
    });
    assert!(
        store.new_copy().join("signature-1").exists(),
        "the publish waits before its copy is complete"
    );
    assert_eq!(
        std::fs::read(store.published().join("manifest.json")).unwrap(),
        old,
        "the image changed while a load held the lock"
    );

    // The load ends; the publish swaps, stamps and removes the old copy.
    drop(holder.stdin.take());
    assert!(holder.wait().unwrap().success(), "the holding load failed");
    let output = publisher.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("{:?}", Published::Replaced)
    );
    assert_eq!(
        std::fs::read(store.published().join("manifest.json")).unwrap(),
        b"{\"v\":2}"
    );
    assert!(!store.new_copy().exists(), "the old copy was left");
    store.check_image_dir();
    assert_eq!(store.run_side("read", &store.account), "4");
}
