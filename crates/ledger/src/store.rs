//! The ledger file and the operations on it (architecture 4.2).

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::model::{Entry, Item, Key, Ledger, Status, VERSION};

/// The root ledger.
pub const ROOT_LEDGER: &str = "/var/lib/forma/ledger.toml";

/// The ledger could not be read, written or used.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// The file could not be read or written.
    #[error("cannot {action} ledger {}: {source}", path.display())]
    Io {
        /// What forma was doing.
        action: &'static str,
        /// The file.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// The file is not a ledger.
    #[error("ledger {} cannot be read: {message}", path.display())]
    Format {
        /// The file.
        path: PathBuf,
        /// What the parser said.
        message: String,
    },
    /// A newer forma wrote the file.
    #[error(
        "ledger {} has format version {found}, and this forma knows versions up to {VERSION}; \
         use the forma that wrote it, or a newer one",
        path.display()
    )]
    NewerVersion {
        /// The file.
        path: PathBuf,
        /// The version in the file.
        found: u32,
    },
    /// An operation named an item the ledger does not hold.
    #[error("the ledger has no entry {0}")]
    NoEntry(Key),
    /// A change would record an item that the ledger already holds in
    /// another form, for example a path as both a file and a directory.
    #[error("the ledger already holds {existing} under {key}, so it cannot record {new}")]
    Conflict {
        /// The shared key.
        key: Key,
        /// The item the ledger holds.
        existing: String,
        /// The item forma wanted to record.
        new: String,
    },
}

/// The one key every ledger format has.
#[derive(serde::Deserialize)]
struct Head {
    version: u32,
}

/// The ledger, and where it is kept.
///
/// Every operation that changes the ledger writes it before it returns. A
/// write replaces the file in one step: a crash leaves either the old
/// ledger or the new one.
#[derive(Debug)]
pub struct Store {
    path: Option<PathBuf>,
    ledger: Ledger,
}

impl Store {
    /// Opens the ledger at `path`. A missing file is an empty ledger.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::NewerVersion`] if a newer forma wrote the
    /// file, and [`LedgerError::Io`] or [`LedgerError::Format`] if it cannot
    /// be read.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, LedgerError> {
        let path = path.into();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: Some(path),
                    ledger: Ledger::default(),
                });
            }
            Err(source) => {
                return Err(LedgerError::Io {
                    action: "read",
                    path,
                    source,
                });
            }
        };
        // Read the version first: a newer format may not parse as this one.
        let format = |error: toml::de::Error| LedgerError::Format {
            path: path.clone(),
            message: error.message().to_owned(),
        };
        let head: Head = toml::from_str(&text).map_err(format)?;
        if head.version > VERSION {
            return Err(LedgerError::NewerVersion {
                path,
                found: head.version,
            });
        }
        let ledger: Ledger = toml::from_str(&text).map_err(format)?;
        Ok(Self {
            path: Some(path),
            ledger,
        })
    }

    /// Returns an empty ledger that is never written. For `forma plan` on a
    /// host without a ledger, and for tests.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            ledger: Ledger::default(),
        }
    }

    /// Returns every entry, oldest first.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.ledger.entries
    }

    /// Returns the entry for `key`.
    #[must_use]
    pub fn get(&self, key: &Key) -> Option<&Entry> {
        self.ledger.entries.iter().find(|entry| entry.item.key() == *key)
    }

    /// Returns the entry for `key` if forma made the item: its status is
    /// `Applied`, or `Removing` (it existed when removal began).
    #[must_use]
    pub fn owned(&self, key: &Key) -> Option<&Entry> {
        self.get(key).filter(|entry| entry.status != Status::Pending)
    }

    /// Returns the entries a stopped run left behind: `Pending` and
    /// `Removing`. Forma settles each with [`Store::resolve`] before it
    /// plans new work.
    #[must_use]
    pub fn unsettled(&self) -> Vec<&Entry> {
        self.ledger
            .entries
            .iter()
            .filter(|entry| entry.status != Status::Applied)
            .collect()
    }

    /// Returns the applied entries that nothing needs, newest first: the
    /// order to remove them in.
    #[must_use]
    pub fn unneeded(&self) -> Vec<&Entry> {
        self.ledger
            .entries
            .iter()
            .rev()
            .filter(|entry| entry.status == Status::Applied && entry.needed_by.is_empty())
            .collect()
    }

    /// Returns the text of the ledger, as it is stored.
    #[must_use]
    pub fn to_toml(&self) -> String {
        toml::to_string(&self.ledger).unwrap_or_else(|_| unreachable!("every ledger value has a TOML form"))
    }

    fn position(&self, key: &Key) -> Result<usize, LedgerError> {
        self.ledger
            .entries
            .iter()
            .position(|entry| entry.item.key() == *key)
            .ok_or_else(|| LedgerError::NoEntry(key.clone()))
    }

    /// Records that forma is about to make `item`, for `needs`.
    ///
    /// If the ledger already holds the item, its status stays as it is and
    /// `needs` are added: making an item twice is the same as making it once.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::Conflict`] if the key is taken by another
    /// kind of item, and [`LedgerError::Io`] if the ledger cannot be written.
    pub fn begin(&mut self, item: Item, needs: &BTreeSet<String>) -> Result<(), LedgerError> {
        let key = item.key();
        match self.ledger.entries.iter_mut().find(|entry| entry.item.key() == key) {
            Some(entry) => {
                if std::mem::discriminant(&entry.item) != std::mem::discriminant(&item) {
                    return Err(LedgerError::Conflict {
                        key,
                        existing: entry.item.to_string(),
                        new: item.to_string(),
                    });
                }
                entry.needed_by.extend(needs.iter().cloned());
                if entry.status == Status::Removing {
                    entry.status = Status::Pending;
                }
            }
            None => self.ledger.entries.push(Entry {
                status: Status::Pending,
                needed_by: needs.clone(),
                item,
            }),
        }
        self.write()
    }

    /// Records that the change for `key` succeeded. `learn` adds what forma
    /// found out, such as a new user ID.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::NoEntry`] if nothing was begun for `key`, and
    /// [`LedgerError::Io`] if the ledger cannot be written.
    pub fn complete(&mut self, key: &Key, learn: impl FnOnce(&mut Item)) -> Result<(), LedgerError> {
        let position = self.position(key)?;
        let entry = &mut self.ledger.entries[position];
        learn(&mut entry.item);
        entry.status = Status::Applied;
        self.write()
    }

    /// Records that forma is about to remove the item for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::NoEntry`] if the ledger does not hold the
    /// item, and [`LedgerError::Io`] if the ledger cannot be written.
    pub fn begin_removal(&mut self, key: &Key) -> Result<(), LedgerError> {
        let position = self.position(key)?;
        self.ledger.entries[position].status = Status::Removing;
        self.write()
    }

    /// Drops the entry for `key`: the item is gone. Dropping an entry the
    /// ledger does not hold is not an error.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::Io`] if the ledger cannot be written.
    pub fn forget(&mut self, key: &Key) -> Result<(), LedgerError> {
        let before = self.ledger.entries.len();
        self.ledger.entries.retain(|entry| entry.item.key() != *key);
        if self.ledger.entries.len() == before {
            Ok(())
        } else {
            self.write()
        }
    }

    /// Settles an entry a stopped run left behind, from what the host shows.
    ///
    /// | Status | Item exists | Result |
    /// |---|---|---|
    /// | `Pending` | yes | `Applied` |
    /// | `Pending` | no | dropped |
    /// | `Removing` | yes | `Applied` |
    /// | `Removing` | no | dropped |
    ///
    /// `learn` runs when the entry becomes `Applied`, to add the IDs the
    /// stopped run did not record.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::NoEntry`] if the ledger does not hold the
    /// item, and [`LedgerError::Io`] if the ledger cannot be written.
    pub fn resolve(&mut self, key: &Key, exists: bool, learn: impl FnOnce(&mut Item)) -> Result<(), LedgerError> {
        if exists {
            self.complete(key, learn)
        } else {
            self.position(key).and_then(|_| self.forget(key))
        }
    }

    /// Records that `need` needs the item for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::NoEntry`] if the ledger does not hold the
    /// item, and [`LedgerError::Io`] if the ledger cannot be written.
    pub fn need(&mut self, key: &Key, need: &str) -> Result<(), LedgerError> {
        let position = self.position(key)?;
        if self.ledger.entries[position].needed_by.insert(need.to_owned()) {
            self.write()
        } else {
            Ok(())
        }
    }

    /// Records that `need` no longer needs the item for `key`. Returns
    /// whether anything still needs it.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::NoEntry`] if the ledger does not hold the
    /// item, and [`LedgerError::Io`] if the ledger cannot be written.
    pub fn release(&mut self, key: &Key, need: &str) -> Result<bool, LedgerError> {
        let position = self.position(key)?;
        let entry = &mut self.ledger.entries[position];
        let changed = entry.needed_by.remove(need);
        let still_needed = !entry.needed_by.is_empty();
        if changed {
            self.write()?;
        }
        Ok(still_needed)
    }

    /// Records the SHA-256 of a file forma wrote.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::NoEntry`] if the ledger holds no file for
    /// `path`, and [`LedgerError::Io`] if the ledger cannot be written.
    pub fn set_file_hash(&mut self, path: &Path, hash: &str) -> Result<(), LedgerError> {
        let key = Key::path(path);
        let position = self.position(&key)?;
        match &mut self.ledger.entries[position].item {
            Item::File { sha256, .. } => *sha256 = Some(hash.to_owned()),
            _ => return Err(LedgerError::NoEntry(key)),
        }
        self.write()
    }

    /// Writes the ledger: a temporary file in the same directory, `fsync`,
    /// rename into place, `fsync` on the directory.
    fn write(&self) -> Result<(), LedgerError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let io = |action: &'static str| {
            let path = path.clone();
            move |source| LedgerError::Io { action, path, source }
        };
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        let temporary = directory.join(name);
        // A stopped run can leave the temporary file behind.
        match std::fs::remove_file(&temporary) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(io("replace")(error)),
            _ => {}
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(io("write"))?;
        file.write_all(self.to_toml().as_bytes()).map_err(io("write"))?;
        file.sync_all().map_err(io("write"))?;
        std::fs::rename(&temporary, path).map_err(io("replace"))?;
        // Without this, a crash can lose the rename.
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(io("sync the directory of"))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::model::HOST;

    fn needs(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn user(name: &str) -> Item {
        Item::User {
            name: name.to_owned(),
            uid: None,
            gid: None,
        }
    }

    #[test]
    fn a_change_is_pending_then_applied_with_what_was_learned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.toml");
        let mut store = Store::open(&path).unwrap();
        store.begin(user("moonshine"), &needs(&["moonshine"])).unwrap();

        // A second process sees the intent: it is on disk before the change.
        let seen = Store::open(&path).unwrap();
        assert_eq!(seen.get(&Key::user("moonshine")).unwrap().status, Status::Pending);
        assert!(
            seen.owned(&Key::user("moonshine")).is_none(),
            "a pending item is not owned yet"
        );

        store
            .complete(&Key::user("moonshine"), |item| {
                if let Item::User { uid, gid, .. } = item {
                    *uid = Some(975);
                    *gid = Some(974);
                }
            })
            .unwrap();
        let seen = Store::open(&path).unwrap();
        let entry = seen.owned(&Key::user("moonshine")).unwrap();
        assert_eq!(entry.status, Status::Applied);
        assert_eq!(
            entry.item,
            Item::User {
                name: "moonshine".into(),
                uid: Some(975),
                gid: Some(974)
            }
        );
    }

    #[test]
    fn the_file_is_private_and_no_temporary_file_stays() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.toml");
        let mut store = Store::open(&path).unwrap();
        store.begin(user("a"), &needs(&["x"])).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["ledger.toml"]);
    }

    #[test]
    fn a_leftover_temporary_file_does_not_stop_a_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.toml");
        std::fs::write(dir.path().join("ledger.toml.tmp"), "half a led").unwrap();
        let mut store = Store::open(&path).unwrap();
        store.begin(user("a"), &needs(&["x"])).unwrap();
        assert_eq!(Store::open(&path).unwrap().entries().len(), 1);
    }

    #[test]
    fn a_shared_item_goes_only_when_nothing_needs_it() {
        let mut store = Store::in_memory();
        let key = Key::user("moonshine");
        store.begin(user("moonshine"), &needs(&["nvidia-driver"])).unwrap();
        store.complete(&key, |_| {}).unwrap();
        // The second component declares the same account: no second entry.
        store.begin(user("moonshine"), &needs(&["moonshine"])).unwrap();
        assert_eq!(store.entries().len(), 1);
        assert_eq!(
            store.get(&key).unwrap().status,
            Status::Applied,
            "the account already exists"
        );
        assert_eq!(
            store.get(&key).unwrap().needed_by,
            needs(&["moonshine", "nvidia-driver"])
        );

        assert!(
            store.release(&key, "nvidia-driver").unwrap(),
            "moonshine still needs it"
        );
        assert_eq!(store.unneeded().len(), 0);
        assert!(!store.release(&key, "moonshine").unwrap());
        assert_eq!(store.unneeded().len(), 1);
        assert!(
            !store.release(&key, "moonshine").unwrap(),
            "releasing twice is the same as once"
        );
    }

    #[test]
    fn unneeded_items_come_newest_first() {
        let mut store = Store::in_memory();
        for name in ["a", "b", "c"] {
            store.begin(user(name), &needs(&[])).unwrap();
            store.complete(&Key::user(name), |_| {}).unwrap();
        }
        store.need(&Key::user("b"), HOST).unwrap();
        let order: Vec<String> = store
            .unneeded()
            .iter()
            .map(|entry| entry.item.key().to_string())
            .collect();
        assert_eq!(order, ["user:c", "user:a"]);
    }

    #[test]
    fn a_stopped_run_is_settled_from_what_the_host_shows() {
        let mut store = Store::in_memory();
        for name in ["made", "not-made", "removed", "not-removed"] {
            store.begin(user(name), &needs(&["x"])).unwrap();
        }
        for name in ["removed", "not-removed"] {
            store.complete(&Key::user(name), |_| {}).unwrap();
            store.begin_removal(&Key::user(name)).unwrap();
        }
        assert_eq!(store.unsettled().len(), 4);
        assert!(
            store.owned(&Key::user("removed")).is_some(),
            "an item being removed was forma's"
        );

        let learn = |item: &mut Item| {
            if let Item::User { uid, .. } = item {
                *uid = Some(901);
            }
        };
        store.resolve(&Key::user("made"), true, learn).unwrap();
        store.resolve(&Key::user("not-made"), false, |_| {}).unwrap();
        store.resolve(&Key::user("removed"), false, |_| {}).unwrap();
        store.resolve(&Key::user("not-removed"), true, |_| {}).unwrap();

        assert_eq!(store.unsettled().len(), 0);
        let left: Vec<String> = store.entries().iter().map(|entry| entry.item.to_string()).collect();
        assert_eq!(left, ["user made (901)", "user not-removed (ID not known)"]);
        assert!(matches!(
            store.resolve(&Key::user("gone"), false, |_| {}),
            Err(LedgerError::NoEntry(_))
        ));
    }

    #[test]
    fn making_an_item_again_while_it_is_being_removed_makes_it_pending() {
        let mut store = Store::in_memory();
        store.begin(user("a"), &needs(&["x"])).unwrap();
        store.complete(&Key::user("a"), |_| {}).unwrap();
        store.begin_removal(&Key::user("a")).unwrap();
        store.begin(user("a"), &needs(&["y"])).unwrap();
        assert_eq!(store.get(&Key::user("a")).unwrap().status, Status::Pending);
    }

    #[test]
    fn one_path_cannot_be_two_kinds_of_item() {
        let mut store = Store::in_memory();
        let path = PathBuf::from("/var/lib/forma/store");
        store
            .begin(Item::Directory { path: path.clone() }, &needs(&[HOST]))
            .unwrap();
        let error = store
            .begin(Item::File { path, sha256: None }, &needs(&[HOST]))
            .unwrap_err();
        assert!(matches!(error, LedgerError::Conflict { .. }), "{error}");
    }

    #[test]
    fn an_older_forma_refuses_a_newer_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.toml");
        std::fs::write(
            &path,
            format!("version = {}\n[[entry]]\nshape = \"unknown\"\n", VERSION + 1),
        )
        .unwrap();
        let error = Store::open(&path).unwrap_err();
        assert!(
            matches!(error, LedgerError::NewerVersion { found, .. } if found == VERSION + 1),
            "{error}"
        );
    }

    #[test]
    fn a_broken_ledger_is_an_error_not_an_empty_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.toml");
        for text in ["", "version = 1\n[[entry]]\nstatus = \"Applied\"\n", "not toml ["] {
            std::fs::write(&path, text).unwrap();
            assert!(
                matches!(Store::open(&path), Err(LedgerError::Format { .. })),
                "{text:?}"
            );
        }
    }

    #[test]
    fn every_kind_of_item_survives_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.toml");
        let items = vec![
            Item::Group {
                name: "g".into(),
                gid: Some(900),
            },
            user("u"),
            Item::Membership {
                user: "u".into(),
                group: "render".into(),
            },
            Item::SubIds {
                user: "u".into(),
                start: 524_288,
                count: 65_536,
            },
            Item::Linger { user: "u".into() },
            Item::Directory {
                path: "/var/lib/forma/store/u".into(),
            },
            Item::File {
                path: "/etc/forma/materia/u.toml".into(),
                sha256: Some("ab".into()),
            },
            Item::Owner {
                path: "/d".into(),
                previous_uid: 0,
                previous_gid: 0,
                uid: 0,
                gid: 900,
            },
            Item::Mode {
                path: "/d".into(),
                previous: 0o755,
                mode: 0o750,
            },
            Item::AclGrant {
                path: "/var/lib/forma/store".into(),
                who: crate::model::AclWho::User,
                id: 901,
                perms: 1,
            },
            Item::ArchivedHome {
                path: "/var/home/u.removed-1".into(),
                user: "u".into(),
            },
            Item::SeLinuxModule {
                name: "m".into(),
                priority: 350,
                sha256: "cd".into(),
            },
            Item::SeLinuxLogin {
                user: "u".into(),
                selinux_user: "user_u".into(),
            },
            Item::TrustKey {
                path: "/var/lib/forma/trust/base/k.pub".into(),
                fingerprint: "ef".into(),
            },
        ];
        let mut store = Store::open(&path).unwrap();
        for item in &items {
            store.begin(item.clone(), &needs(&["c", HOST])).unwrap();
        }
        let read: Vec<Item> = Store::open(&path)
            .unwrap()
            .entries()
            .iter()
            .map(|entry| entry.item.clone())
            .collect();
        assert_eq!(read, items);
        let keys: BTreeSet<Key> = items.iter().map(Item::key).collect();
        assert_eq!(keys.len(), items.len(), "every item has its own key");
    }

    #[test]
    fn a_file_hash_is_recorded_on_a_file_only() {
        let mut store = Store::in_memory();
        let file = PathBuf::from("/home/u/.config/containers/policy.json");
        store
            .begin(
                Item::File {
                    path: file.clone(),
                    sha256: None,
                },
                &needs(&["c"]),
            )
            .unwrap();
        store.set_file_hash(&file, "00ff").unwrap();
        assert!(matches!(&store.entries()[0].item, Item::File { sha256: Some(hash), .. } if hash == "00ff"));
        store
            .begin(Item::Directory { path: "/d".into() }, &needs(&["c"]))
            .unwrap();
        assert!(store.set_file_hash(Path::new("/d"), "00").is_err());
    }
}
