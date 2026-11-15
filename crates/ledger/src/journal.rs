//! The ledger as `forma-user`'s owner and journal.
//!
//! `forma_user::admin::System` asks an `Ownership` before it changes or
//! removes anything that exists, and tells a `Journal` before and after
//! each change. [`Recorder`] is both, backed by one [`Store`]. So the
//! ledger alone decides what forma may touch (architecture 4.1 and 4.3).

use std::cell::{Ref, RefCell, RefMut};
use std::collections::BTreeSet;
use std::path::Path;
use std::rc::Rc;

use forma_user::ownership::{Change, Facts, Item as HostItem, Journal, Ownership};
use forma_user::perm::{Acl, Qualifier};

use crate::model::{AclWho, Item, Key, Status};
use crate::store::{LedgerError, Store};

/// Records `forma-user`'s changes in the ledger and answers its ownership
/// questions from it.
///
/// Clones share one ledger. `System::open` takes one clone as the
/// `Ownership` and another as the `Journal`.
#[derive(Debug, Clone)]
pub struct Recorder {
    store: Rc<RefCell<Store>>,
    needs: Rc<RefCell<BTreeSet<String>>>,
}

impl Recorder {
    /// Wraps a ledger.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self {
            store: Rc::new(RefCell::new(store)),
            needs: Rc::new(RefCell::new(BTreeSet::new())),
        }
    }

    /// Sets who needs the items made from now on: component names, or
    /// [`crate::HOST`]. Forma sets this before each action.
    pub fn set_needs<I, S>(&self, needs: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        *self.needs.borrow_mut() = needs.into_iter().map(Into::into).collect();
    }

    /// Returns the ledger.
    ///
    /// # Panics
    ///
    /// Panics if the ledger is borrowed mutably, which only code in this
    /// crate does, and never across a call.
    #[must_use]
    pub fn store(&self) -> Ref<'_, Store> {
        self.store.borrow()
    }

    /// Returns the ledger for changes `forma-user` does not make, such as
    /// SELinux modules.
    ///
    /// # Panics
    ///
    /// Panics if the ledger is already borrowed.
    #[must_use]
    pub fn store_mut(&self) -> RefMut<'_, Store> {
        self.store.borrow_mut()
    }

    fn begin(&self, item: Item) -> Result<(), LedgerError> {
        self.store.borrow_mut().begin(item, &self.needs.borrow())
    }

    /// Starts the removal of an item, if the ledger holds it. An item the
    /// ledger does not hold was not forma's; `forma-user` asks
    /// [`Ownership::claims`] first, so this happens only for changes that
    /// need no claim.
    fn begin_removal(&self, key: &Key) -> Result<(), LedgerError> {
        let mut store = self.store.borrow_mut();
        if store.get(key).is_some() {
            store.begin_removal(key)
        } else {
            Ok(())
        }
    }
}

fn who(qualifier: Qualifier) -> (AclWho, u32) {
    match qualifier {
        Qualifier::User(uid) => (AclWho::User, uid.as_raw()),
        Qualifier::Group(gid) => (AclWho::Group, gid.as_raw()),
    }
}

/// The named entries `new` has and `previous` lacks, and the other way round.
fn acl_difference(path: &Path, previous: &Acl, new: &Acl) -> (Vec<Item>, Vec<Key>) {
    let added = new
        .entries()
        .filter(|entry| previous.entry(entry.qualifier).is_none())
        .map(|entry| {
            let (who, id) = who(entry.qualifier);
            Item::AclGrant {
                path: path.to_path_buf(),
                who,
                id,
                perms: entry.perms.bits(),
            }
        })
        .collect();
    let removed = previous
        .entries()
        .filter(|entry| new.entry(entry.qualifier).is_none())
        .map(|entry| {
            let (who, id) = who(entry.qualifier);
            Key::acl_grant(path, who, id)
        })
        .collect();
    (added, removed)
}

impl Journal for Recorder {
    type Error = LedgerError;

    fn intent(&mut self, change: &Change) -> Result<(), Self::Error> {
        match change {
            Change::CreateUser { name } => self.begin(Item::User {
                name: name.to_string(),
                uid: None,
                gid: None,
            }),
            Change::DeleteUser { user, .. } => self.begin_removal(&Key::user(user.name().as_str())),
            Change::CreateGroup { name } => self.begin(Item::Group {
                name: name.to_string(),
                gid: None,
            }),
            Change::DeleteGroup { group } => self.begin_removal(&Key::group(group.info().name().as_str())),
            Change::AddMember { user, group } => self.begin(Item::Membership {
                user: user.to_string(),
                group: group.to_string(),
            }),
            Change::RemoveMember { user, group } => self.begin_removal(&Key::membership(user.as_str(), group.as_str())),
            Change::AddSubIds { user, range } => self.begin(Item::SubIds {
                user: user.to_string(),
                start: range.start(),
                count: range.count(),
            }),
            Change::RemoveSubIds { user, .. } => self.begin_removal(&Key::sub_ids(user.as_str())),
            Change::SetLinger { user, enable: true } => self.begin(Item::Linger { user: user.to_string() }),
            Change::SetLinger { user, enable: false } => self.begin_removal(&Key::linger(user.as_str())),
            Change::WriteFile { path, .. } => self.begin(Item::File {
                path: path.as_path().to_path_buf(),
                sha256: None,
            }),
            Change::RemoveFile { path, .. } => self.begin_removal(&Key::path(path.as_path())),
            Change::CreateDir { path, .. } => self.begin(Item::Directory {
                path: path.as_path().to_path_buf(),
            }),
            Change::SetOwner { path, previous, new } => {
                // Undo goes back to what was there before forma's first change.
                let first = match self.store().get(&Key::owner(path.as_path())).map(|entry| &entry.item) {
                    Some(Item::Owner {
                        previous_uid,
                        previous_gid,
                        ..
                    }) => (*previous_uid, *previous_gid),
                    _ => (previous.0.as_raw(), previous.1.as_raw()),
                };
                if first == (new.0.as_raw(), new.1.as_raw()) {
                    return self.begin_removal(&Key::owner(path.as_path()));
                }
                self.store.borrow_mut().forget(&Key::owner(path.as_path()))?;
                self.begin(Item::Owner {
                    path: path.as_path().to_path_buf(),
                    previous_uid: first.0,
                    previous_gid: first.1,
                    uid: new.0.as_raw(),
                    gid: new.1.as_raw(),
                })
            }
            Change::SetMode { path, previous, new } => {
                let first = match self.store().get(&Key::mode(path.as_path())).map(|entry| &entry.item) {
                    Some(Item::Mode { previous, .. }) => *previous,
                    _ => *previous,
                };
                if first == new.bits() {
                    return self.begin_removal(&Key::mode(path.as_path()));
                }
                self.store.borrow_mut().forget(&Key::mode(path.as_path()))?;
                self.begin(Item::Mode {
                    path: path.as_path().to_path_buf(),
                    previous: first,
                    mode: new.bits(),
                })
            }
            Change::SetAcl { path, previous, new } => {
                let (added, removed) = acl_difference(path.as_path(), previous, new);
                added.into_iter().try_for_each(|item| self.begin(item))?;
                removed.iter().try_for_each(|key| self.begin_removal(key))
            }
        }
    }

    fn applied(&mut self, change: &Change, facts: &Facts) -> Result<(), Self::Error> {
        let mut store = self.store.borrow_mut();
        // An item whose removal was not begun was not in the ledger.
        let mut finish_removal = |key: Key| match store.get(&key).map(|entry| entry.status) {
            Some(Status::Removing) => store.forget(&key),
            _ => Ok(()),
        };
        match change {
            Change::DeleteUser { user, .. } => {
                finish_removal(Key::user(user.name().as_str()))?;
                if let Some(home) = &facts.archived_home {
                    let item = Item::ArchivedHome {
                        path: home.as_path().to_path_buf(),
                        user: user.name().to_string(),
                    };
                    let key = item.key();
                    store.begin(item, &BTreeSet::new())?;
                    store.complete(&key, |_| {})?;
                }
                Ok(())
            }
            Change::DeleteGroup { group } => finish_removal(Key::group(group.info().name().as_str())),
            Change::RemoveMember { user, group } => finish_removal(Key::membership(user.as_str(), group.as_str())),
            Change::RemoveSubIds { user, .. } => finish_removal(Key::sub_ids(user.as_str())),
            Change::SetLinger { user, enable: false } => finish_removal(Key::linger(user.as_str())),
            Change::RemoveFile { path, .. } => finish_removal(Key::path(path.as_path())),
            Change::CreateUser { name } => store.complete(&Key::user(name.as_str()), |item| {
                if let Item::User { uid, gid, .. } = item {
                    *uid = facts.uid.map(forma_user::id::Uid::as_raw);
                    *gid = facts.gid.map(forma_user::id::Gid::as_raw);
                }
            }),
            Change::CreateGroup { name } => store.complete(&Key::group(name.as_str()), |item| {
                if let Item::Group { gid, .. } = item {
                    *gid = facts.gid.map(forma_user::id::Gid::as_raw);
                }
            }),
            Change::AddMember { user, group } => {
                store.complete(&Key::membership(user.as_str(), group.as_str()), |_| {})
            }
            Change::AddSubIds { user, .. } => store.complete(&Key::sub_ids(user.as_str()), |_| {}),
            Change::SetLinger { user, enable: true } => store.complete(&Key::linger(user.as_str()), |_| {}),
            Change::WriteFile { path, .. } | Change::CreateDir { path, .. } => {
                store.complete(&Key::path(path.as_path()), |_| {})
            }
            Change::SetOwner { path, .. } => {
                let key = Key::owner(path.as_path());
                match store.get(&key).map(|entry| entry.status) {
                    Some(Status::Removing) => store.forget(&key),
                    Some(_) => store.complete(&key, |_| {}),
                    None => Ok(()),
                }
            }
            Change::SetMode { path, .. } => {
                let key = Key::mode(path.as_path());
                match store.get(&key).map(|entry| entry.status) {
                    Some(Status::Removing) => store.forget(&key),
                    Some(_) => store.complete(&key, |_| {}),
                    None => Ok(()),
                }
            }
            Change::SetAcl { path, previous, new } => {
                let (added, removed) = acl_difference(path.as_path(), previous, new);
                added.iter().try_for_each(|item| store.complete(&item.key(), |_| {}))?;
                removed
                    .into_iter()
                    .try_for_each(|key| match store.get(&key).map(|entry| entry.status) {
                        Some(Status::Removing) => store.forget(&key),
                        _ => Ok(()),
                    })
            }
        }
    }
}

impl Ownership for Recorder {
    type Error = LedgerError;

    /// Says whether forma made `item`: the ledger holds it, and the host
    /// still matches the entry. For an account, name and user ID must both
    /// match (architecture 4.3, rule 3).
    fn claims(&self, item: &HostItem<'_>) -> Result<bool, Self::Error> {
        let store = self.store();
        let owned = |key: Key| store.owned(&key).map(|entry| entry.item.clone());
        let user_matches = |user: &forma_user::lookup::User| {
            matches!(
                owned(Key::user(user.name().as_str())),
                Some(Item::User { uid: Some(uid), .. }) if uid == user.uid().as_raw()
            )
        };
        Ok(match item {
            HostItem::User(user) => user_matches(user),
            HostItem::Group(group) => {
                let name = group.info().name().as_str();
                let gid = group.info().gid().as_raw();
                // `useradd -U` makes a group with the account's name; the
                // account's entry then records the group's ID.
                matches!(owned(Key::group(name)), Some(Item::Group { gid: Some(recorded), .. }) if recorded == gid)
                    || matches!(owned(Key::user(name)), Some(Item::User { gid: Some(recorded), .. }) if recorded == gid)
            }
            HostItem::Membership { user, group } => {
                owned(Key::membership(user.name().as_str(), group.info().name().as_str())).is_some()
            }
            HostItem::SubIds { user, range } => matches!(
                owned(Key::sub_ids(user.name().as_str())),
                Some(Item::SubIds { start, count, .. }) if start == range.start() && count == range.count()
            ),
            HostItem::File { path, .. } => {
                matches!(
                    owned(Key::path(path.as_path())),
                    Some(Item::File { .. } | Item::Directory { .. })
                )
            }
            HostItem::AclEntry { path, entry } => {
                let (who, id) = who(entry.qualifier);
                matches!(
                    owned(Key::acl_grant(path.as_path(), who, id)),
                    Some(Item::AclGrant { perms, .. }) if perms == entry.perms.bits()
                )
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use forma_user::id::{Gid, SubIdCount, SubIdRange, Uid};
    use forma_user::lookup;
    use forma_user::name::{GroupName, UserName};
    use forma_user::path::AbsPath;
    use forma_user::perm::{AclEntry, FileMode, Perms};

    use super::*;
    use crate::model::HOST;

    fn recorder() -> Recorder {
        let recorder = Recorder::new(Store::in_memory());
        recorder.set_needs(["moonshine"]);
        recorder
    }

    fn apply(recorder: &mut Recorder, change: &Change, facts: &Facts) {
        recorder.intent(change).unwrap();
        recorder.applied(change, facts).unwrap();
    }

    fn abs(path: &str) -> AbsPath {
        AbsPath::new(path).unwrap()
    }

    /// The user who runs the tests: a real account to ask questions about.
    fn me() -> lookup::User {
        let uid = std::fs::metadata("/proc/self")
            .map(|meta| std::os::unix::fs::MetadataExt::uid(&meta))
            .unwrap();
        lookup::user_by_uid(Uid::from_raw(uid))
            .unwrap()
            .expect("the test user has a passwd entry")
    }

    #[test]
    fn a_new_account_is_pending_until_its_ids_are_known() {
        let mut recorder = recorder();
        let change = Change::CreateUser {
            name: UserName::new("moonshine").unwrap(),
        };
        recorder.intent(&change).unwrap();
        assert_eq!(recorder.store().entries()[0].status, Status::Pending);
        let facts = Facts {
            uid: Some(Uid::from_raw(975)),
            gid: Some(Gid::from_raw(974)),
            archived_home: None,
        };
        recorder.applied(&change, &facts).unwrap();
        let store = recorder.store();
        let entry = &store.entries()[0];
        assert_eq!(entry.status, Status::Applied);
        assert_eq!(entry.item.to_string(), "user moonshine (975)");
        assert!(entry.needed_by.contains("moonshine"));
    }

    #[test]
    fn an_account_is_claimed_only_when_name_and_user_id_both_match() {
        let me = me();
        let mut recorder = recorder();
        assert!(
            !recorder.claims(&HostItem::User(&me)).unwrap(),
            "an account forma did not create"
        );

        let change = Change::CreateUser {
            name: me.name().clone(),
        };
        recorder.intent(&change).unwrap();
        assert!(
            !recorder.claims(&HostItem::User(&me)).unwrap(),
            "a pending entry proves nothing"
        );

        // Another account had this name when forma created it.
        let other = Facts {
            uid: Some(Uid::from_raw(me.uid().as_raw() + 1)),
            ..Facts::default()
        };
        recorder.applied(&change, &other).unwrap();
        assert!(!recorder.claims(&HostItem::User(&me)).unwrap(), "the user ID differs");

        let mut recorder = self::recorder();
        let same = Facts {
            uid: Some(me.uid()),
            gid: Some(me.gid()),
            ..Facts::default()
        };
        apply(&mut recorder, &change, &same);
        assert!(recorder.claims(&HostItem::User(&me)).unwrap());

        // Its sub-IDs are claimed by range, not by account.
        let range = SubIdRange::new(524_288, SubIdCount::new(65_536).unwrap()).unwrap();
        let sub_ids = HostItem::SubIds { user: &me, range };
        assert!(!recorder.claims(&sub_ids).unwrap());
        apply(
            &mut recorder,
            &Change::AddSubIds {
                user: me.name().clone(),
                range,
            },
            &Facts::default(),
        );
        assert!(recorder.claims(&sub_ids).unwrap());
        let other_range = SubIdRange::new(1_000_000, SubIdCount::new(65_536).unwrap()).unwrap();
        assert!(
            !recorder
                .claims(&HostItem::SubIds {
                    user: &me,
                    range: other_range
                })
                .unwrap()
        );
    }

    #[test]
    fn deleting_an_account_drops_it_and_records_the_kept_home() {
        let me = me();
        let mut recorder = recorder();
        let facts = Facts {
            uid: Some(me.uid()),
            ..Facts::default()
        };
        apply(
            &mut recorder,
            &Change::CreateUser {
                name: me.name().clone(),
            },
            &facts,
        );

        let delete = Change::DeleteUser {
            user: me.clone(),
            home: forma_user::spec::HomePolicy::Archive,
        };
        recorder.intent(&delete).unwrap();
        assert_eq!(recorder.store().entries()[0].status, Status::Removing);
        assert!(
            recorder.claims(&HostItem::User(&me)).unwrap(),
            "still forma's while it is being removed"
        );

        let archived = Facts {
            archived_home: Some(abs("/var/home/me.removed-1763164800")),
            ..Facts::default()
        };
        recorder.applied(&delete, &archived).unwrap();
        let store = recorder.store();
        let left: Vec<String> = store.entries().iter().map(|entry| entry.item.to_string()).collect();
        assert_eq!(
            left,
            [format!("kept home of {} at /var/home/me.removed-1763164800", me.name())]
        );
        assert!(
            store.entries()[0].needed_by.is_empty(),
            "nothing needs a kept home: purge --data may delete it"
        );
    }

    #[test]
    fn removing_something_forma_never_recorded_leaves_the_ledger_alone() {
        let mut recorder = recorder();
        let change = Change::RemoveMember {
            user: UserName::new("app").unwrap(),
            group: GroupName::new("render").unwrap(),
        };
        apply(&mut recorder, &change, &Facts::default());
        assert_eq!(recorder.store().entries().len(), 0);
    }

    #[test]
    fn linger_and_membership_come_and_go() {
        let mut recorder = recorder();
        let user = UserName::new("app").unwrap();
        let group = GroupName::new("render").unwrap();
        let facts = Facts::default();
        apply(
            &mut recorder,
            &Change::SetLinger {
                user: user.clone(),
                enable: true,
            },
            &facts,
        );
        apply(
            &mut recorder,
            &Change::AddMember {
                user: user.clone(),
                group: group.clone(),
            },
            &facts,
        );
        let keys: Vec<String> = recorder
            .store()
            .entries()
            .iter()
            .map(|entry| entry.item.key().to_string())
            .collect();
        assert_eq!(keys, ["linger:app", "member:app:render"]);
        apply(
            &mut recorder,
            &Change::SetLinger {
                user: user.clone(),
                enable: false,
            },
            &facts,
        );
        apply(&mut recorder, &Change::RemoveMember { user, group }, &facts);
        assert_eq!(recorder.store().entries().len(), 0);
    }

    #[test]
    fn a_traverse_grant_is_one_entry_per_account_and_directory() {
        let mut recorder = recorder();
        let path = abs("/var/lib/forma/store");
        let base = Acl::from_mode(0o700);
        let entry = |uid: u32| AclEntry {
            qualifier: Qualifier::User(Uid::from_raw(uid)),
            perms: Perms::EXECUTE,
        };
        let one = base.with_entry(entry(901));
        let two = one.with_entry(entry(902));
        let facts = Facts::default();
        apply(
            &mut recorder,
            &Change::SetAcl {
                path: path.clone(),
                previous: base.clone(),
                new: one.clone(),
            },
            &facts,
        );
        recorder.set_needs(["other"]);
        apply(
            &mut recorder,
            &Change::SetAcl {
                path: path.clone(),
                previous: one.clone(),
                new: two.clone(),
            },
            &facts,
        );

        assert_eq!(recorder.store().entries().len(), 2);
        assert!(
            recorder
                .claims(&HostItem::AclEntry {
                    path: &path,
                    entry: entry(901)
                })
                .unwrap()
        );
        assert!(
            recorder
                .claims(&HostItem::AclEntry {
                    path: &path,
                    entry: entry(902)
                })
                .unwrap()
        );
        assert!(
            !recorder
                .claims(&HostItem::AclEntry {
                    path: &path,
                    entry: entry(903)
                })
                .unwrap()
        );
        // An entry an administrator widened is no longer the one forma added.
        let widened = AclEntry {
            qualifier: Qualifier::User(Uid::from_raw(901)),
            perms: Perms::from_bits(0o5).unwrap(),
        };
        assert!(
            !recorder
                .claims(&HostItem::AclEntry {
                    path: &path,
                    entry: widened
                })
                .unwrap()
        );

        // Revoking the first leaves the second.
        let only_second = two.without_entry(Qualifier::User(Uid::from_raw(901)));
        apply(
            &mut recorder,
            &Change::SetAcl {
                path: path.clone(),
                previous: two,
                new: only_second,
            },
            &facts,
        );
        let store = recorder.store();
        assert_eq!(store.entries().len(), 1);
        assert_eq!(
            store.entries()[0].item.to_string(),
            "ACL entry user:902:1 on /var/lib/forma/store"
        );
        assert!(store.entries()[0].needed_by.contains("other"));
    }

    #[test]
    fn an_owner_change_remembers_the_first_owner_and_goes_when_undone() {
        let mut recorder = recorder();
        recorder.set_needs([HOST]);
        let path = abs("/var/lib/materia/delegate/accounts/app");
        let ids = |uid: u32, gid: u32| (Uid::from_raw(uid), Gid::from_raw(gid));
        let facts = Facts::default();
        apply(
            &mut recorder,
            &Change::SetOwner {
                path: path.clone(),
                previous: ids(0, 0),
                new: ids(0, 901),
            },
            &facts,
        );
        apply(
            &mut recorder,
            &Change::SetOwner {
                path: path.clone(),
                previous: ids(0, 901),
                new: ids(0, 902),
            },
            &facts,
        );
        {
            let store = recorder.store();
            assert_eq!(store.entries().len(), 1);
            assert_eq!(
                store.entries()[0].item,
                Item::Owner {
                    path: path.as_path().to_path_buf(),
                    previous_uid: 0,
                    previous_gid: 0,
                    uid: 0,
                    gid: 902
                }
            );
        }
        // Back to root:root, as revert does.
        apply(
            &mut recorder,
            &Change::SetOwner {
                path,
                previous: ids(0, 902),
                new: ids(0, 0),
            },
            &facts,
        );
        assert_eq!(recorder.store().entries().len(), 0);
    }

    #[test]
    fn a_mode_change_is_recorded_the_same_way() {
        let mut recorder = recorder();
        let path = abs("/var/lib/forma/staging/app");
        let facts = Facts::default();
        let mode = |bits: u32| FileMode::new(bits).unwrap();
        apply(
            &mut recorder,
            &Change::SetMode {
                path: path.clone(),
                previous: 0o755,
                new: mode(0o2750),
            },
            &facts,
        );
        assert_eq!(
            recorder.store().entries()[0].item.to_string(),
            "mode 2750 of /var/lib/forma/staging/app"
        );
        apply(
            &mut recorder,
            &Change::SetMode {
                path,
                previous: 0o2750,
                new: mode(0o755),
            },
            &facts,
        );
        assert_eq!(recorder.store().entries().len(), 0);
    }

    #[test]
    fn files_and_directories_forma_made_are_claimed_by_path() {
        let mut recorder = recorder();
        let file = abs("/etc/forma/materia/app.toml");
        let directory = abs("/var/lib/forma/store/app");
        let facts = Facts::default();
        assert!(
            !recorder
                .claims(&HostItem::File {
                    path: &file,
                    header: None
                })
                .unwrap()
        );
        apply(
            &mut recorder,
            &Change::WriteFile {
                path: file.clone(),
                previous: None,
            },
            &facts,
        );
        apply(
            &mut recorder,
            &Change::CreateDir {
                path: directory.clone(),
                owner: Uid::ROOT,
                group: Gid::ROOT,
                mode: FileMode::new(0o2750).unwrap(),
            },
            &facts,
        );
        assert!(
            recorder
                .claims(&HostItem::File {
                    path: &file,
                    header: None
                })
                .unwrap()
        );
        assert!(
            recorder
                .claims(&HostItem::File {
                    path: &directory,
                    header: None
                })
                .unwrap()
        );
        // Writing a file again keeps one entry.
        apply(
            &mut recorder,
            &Change::WriteFile {
                path: file.clone(),
                previous: Some(b"old".to_vec()),
            },
            &facts,
        );
        assert_eq!(recorder.store().entries().len(), 2);
        apply(
            &mut recorder,
            &Change::RemoveFile {
                path: file.clone(),
                contents: Vec::new(),
            },
            &facts,
        );
        assert!(
            !recorder
                .claims(&HostItem::File {
                    path: &file,
                    header: None
                })
                .unwrap()
        );
    }
}
