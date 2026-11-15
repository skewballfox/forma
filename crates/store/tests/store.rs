//! Publish and load in a temporary directory, as a normal user.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use forma_process::Rootless;
use forma_signing_payload::{ManifestDigest, Payload, SignatureFile};
use forma_store::{Error, ImageName, Publish, Published, images, lock_shared, publish, pull_command};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};

const REFERENCE: &str = "localhost/app/app:latest";

struct World {
    _temp: tempfile::TempDir,
    staging: PathBuf,
    account: PathBuf,
    image: ImageName,
}

impl World {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let staging = temp.path().join("staging");
        let account = temp.path().join("store/app");
        fs::create_dir_all(&account).unwrap();
        let world = Self {
            staging,
            account,
            image: ImageName::new("app_app_latest").unwrap(),
            _temp: temp,
        };
        world.stage(b"{\"v\":1}", &[("aaaa", b"layer one")]);
        world
    }

    fn staged(&self) -> PathBuf {
        self.staging.join(self.image.as_str())
    }

    /// Replaces the staged image with a manifest and blobs.
    fn stage(&self, manifest: &[u8], blobs: &[(&str, &[u8])]) {
        let dir = self.staged();
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("manifest.json"), manifest).unwrap();
        fs::write(dir.join("version"), b"Directory Transport Version: 1.1\n").unwrap();
        for (name, bytes) in blobs {
            fs::write(dir.join(name), bytes).unwrap();
        }
    }

    fn signature_for(manifest: &[u8], reference: &str) -> Vec<u8> {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let payload = Payload::new(reference, ManifestDigest::of(manifest))
            .unwrap()
            .to_bytes();
        let signature: Signature = key.sign(&payload);
        SignatureFile::new(payload, signature.to_der().as_bytes())
            .unwrap()
            .encode()
    }

    fn publish_signed(&self, signature: &[u8]) -> Result<Published, Error> {
        publish(&Publish {
            staging: &self.staging,
            account_dir: &self.account,
            image: &self.image,
            reference: REFERENCE,
            signature,
        })
    }

    fn publish(&self) -> Result<Published, Error> {
        let manifest = fs::read(self.staged().join("manifest.json")).unwrap();
        self.publish_signed(&Self::signature_for(&manifest, REFERENCE))
    }

    fn published(&self) -> PathBuf {
        self.account.join(self.image.as_str())
    }

    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.account)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn a_first_publish_copies_signs_and_stamps() {
    let world = World::new();
    assert_eq!(world.publish().unwrap(), Published::First);
    assert_eq!(world.entries(), [".lock", ".published", "app_app_latest"]);
    let mut files: Vec<String> = fs::read_dir(world.published())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    assert_eq!(files, ["aaaa", "manifest.json", "signature-1", "version"]);
    assert_eq!(fs::read(world.published().join("aaaa")).unwrap(), b"layer one");
    assert_eq!(mode(&world.published()), 0o750);
    assert_eq!(mode(&world.published().join("aaaa")), 0o640);
    assert_eq!(mode(&world.account.join(".lock")), 0o640);
    assert_eq!(
        fs::read_to_string(world.account.join(".published")).unwrap(),
        "app_app_latest\n"
    );
    let signature = fs::read(world.published().join("signature-1")).unwrap();
    let file = SignatureFile::decode(&signature).unwrap();
    assert_eq!(
        Payload::from_bytes(file.payload()).unwrap().digest,
        ManifestDigest::of(b"{\"v\":1}")
    );
}

#[test]
fn a_second_publish_replaces_the_image_and_removes_the_old_copy() {
    let world = World::new();
    world.publish().unwrap();
    world.stage(b"{\"v\":2}", &[("bbbb", b"layer two")]);
    assert_eq!(world.publish().unwrap(), Published::Replaced);
    assert_eq!(world.entries(), [".lock", ".published", "app_app_latest"]);
    assert!(!world.published().join("aaaa").exists());
    assert_eq!(fs::read(world.published().join("manifest.json")).unwrap(), b"{\"v\":2}");
}

#[test]
fn a_signature_for_another_manifest_or_reference_is_refused() {
    let world = World::new();
    world.publish().unwrap();
    world.stage(b"{\"v\":2}", &[]);
    // The builder changed staging after the signer signed it.
    let stale = World::signature_for(b"{\"v\":3}", REFERENCE);
    let error = world.publish_signed(&stale).unwrap_err();
    assert!(matches!(error, Error::Signature { .. }), "{error}");
    let other = World::signature_for(b"{\"v\":2}", "localhost/other/image:latest");
    let error = world.publish_signed(&other).unwrap_err();
    assert!(error.to_string().contains("localhost/other/image:latest"), "{error}");
    assert!(matches!(
        world.publish_signed(b"not a signature"),
        Err(Error::Signature { .. })
    ));
    // The published image is untouched, and no copy is left behind.
    assert_eq!(fs::read(world.published().join("manifest.json")).unwrap(), b"{\"v\":1}");
    assert_eq!(world.entries(), [".lock", ".published", "app_app_latest"]);
}

#[test]
fn staging_may_hold_only_the_files_buildah_writes() {
    type Plant = fn(&Path);
    let cases: [(&str, Plant); 5] = [
        ("link", |dir| symlink("/etc/shadow", dir.join("link")).unwrap()),
        ("sub", |dir| fs::create_dir(dir.join("sub")).unwrap()),
        ("signature-1", |dir| fs::write(dir.join("signature-1"), b"x").unwrap()),
        (".hidden", |dir| fs::write(dir.join(".hidden"), b"x").unwrap()),
        ("manifest.json", |dir| {
            fs::remove_file(dir.join("manifest.json")).unwrap();
        }),
    ];
    for (entry, plant) in cases {
        let world = World::new();
        plant(&world.staged());
        let manifest = b"{\"v\":1}";
        let error = world
            .publish_signed(&World::signature_for(manifest, REFERENCE))
            .unwrap_err();
        assert!(
            matches!(&error, Error::Staging { entry: found, .. } if found == entry),
            "{entry}: {error}"
        );
        assert_eq!(world.entries(), [".lock"], "{entry}");
    }
}

#[test]
fn a_staged_image_that_is_a_link_is_refused() {
    let world = World::new();
    let elsewhere = world.staging.join("elsewhere");
    fs::rename(world.staged(), &elsewhere).unwrap();
    symlink(&elsewhere, world.staged()).unwrap();
    let error = world.publish().unwrap_err();
    assert!(matches!(error, Error::Io { .. }), "{error}");
}

#[test]
fn a_copy_left_by_a_stopped_publish_is_removed_first() {
    let world = World::new();
    world.publish().unwrap();
    let left = world.account.join("app_app_latest.new");
    fs::create_dir(&left).unwrap();
    fs::write(left.join("manifest.json"), b"half").unwrap();
    assert_eq!(world.publish().unwrap(), Published::Replaced);
    assert_eq!(world.entries(), [".lock", ".published", "app_app_latest"]);
}

#[test]
fn a_load_in_progress_sees_no_swap() {
    let world = World::new();
    world.publish().unwrap();
    let lock = lock_shared(&world.account).unwrap();
    world.stage(b"{\"v\":2}", &[]);

    let (done, finished) = mpsc::channel();
    let (staging, account, image) = (world.staging.clone(), world.account.clone(), world.image.clone());
    let manifest = fs::read(world.staged().join("manifest.json")).unwrap();
    let publisher = std::thread::spawn(move || {
        let signature = World::signature_for(&manifest, REFERENCE);
        let result = publish(&Publish {
            staging: &staging,
            account_dir: &account,
            image: &image,
            reference: REFERENCE,
            signature: &signature,
        });
        done.send(()).unwrap();
        result
    });
    // The publish copies and signs, then waits for the load before it swaps.
    assert!(finished.recv_timeout(Duration::from_millis(500)).is_err());
    assert_eq!(fs::read(world.published().join("manifest.json")).unwrap(), b"{\"v\":1}");
    let ready = world.account.join("app_app_latest.new");
    assert_eq!(fs::read(ready.join("manifest.json")).unwrap(), b"{\"v\":2}");
    assert!(ready.join("signature-1").is_file());
    drop(lock);
    assert_eq!(publisher.join().unwrap().unwrap(), Published::Replaced);
    assert_eq!(world.entries(), [".lock", ".published", "app_app_latest"]);
}

#[test]
fn image_directories_keep_the_account_directorys_group() {
    let world = World::new();
    // 5.7: the account directory is <signer>:<account> 2750.
    fs::set_permissions(&world.account, fs::Permissions::from_mode(0o2750)).unwrap();
    world.publish().unwrap();
    assert_eq!(mode(&world.published()), 0o2750);
    let group = fs::metadata(&world.account).unwrap().gid();
    for entry in fs::read_dir(world.published()).unwrap() {
        let entry = entry.unwrap();
        assert_eq!(entry.metadata().unwrap().gid(), group, "{:?}", entry.file_name());
        assert_eq!(mode(&entry.path()), 0o640, "{:?}", entry.file_name());
    }
    // A second publish too, through the swap.
    world.stage(b"{\"v\":2}", &[]);
    world.publish().unwrap();
    assert_eq!(mode(&world.published()), 0o2750);
}

#[test]
fn images_lists_published_directories_only() {
    let world = World::new();
    assert!(matches!(lock_shared(&world.account), Err(Error::NothingPublished(_))));
    world.publish().unwrap();
    fs::create_dir(world.account.join("other.new")).unwrap();
    fs::create_dir(world.account.join("Bad Name")).unwrap();
    fs::write(world.account.join("stray"), b"").unwrap();
    symlink("/", world.account.join("link")).unwrap();
    let names: Vec<String> = images(&world.account)
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(names, ["app_app_latest"]);
}

#[test]
fn the_pull_names_the_dir_layout_and_needs_a_published_image() {
    let world = World::new();
    world.publish().unwrap();
    let rootless = Rootless {
        home: "/var/home/app".into(),
        runtime_dir: "/run/user/1001".into(),
    };
    let lock = lock_shared(&world.account).unwrap();
    let command = pull_command(&lock, &world.image, &rootless, Some(Path::new("/etc/forma/app.json"))).unwrap();
    let expected = format!("dir:{}", world.published().display());
    assert_eq!(
        command.arguments_lossy(),
        ["pull", "--signature-policy", "/etc/forma/app.json", expected.as_str()]
    );
    let missing = ImageName::new("missing").unwrap();
    assert!(matches!(
        pull_command(&lock, &missing, &rootless, None),
        Err(Error::NotPublished { .. })
    ));
    symlink(world.published(), world.account.join("linked")).unwrap();
    let linked = ImageName::new("linked").unwrap();
    assert!(matches!(
        pull_command(&lock, &linked, &rootless, None),
        Err(Error::NotPublished { .. })
    ));
}
