//! Owners, modes and ACLs on files the test user does not own, and
//! `grant_traverse`, `revoke_traverse` and their `_through` forms.

use std::ffi::OsStr;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use forma_user::admin::{self, Error, Refusal};
use forma_user::id::{Gid, Uid};
use forma_user::path::{AbsPath, RelPath};
use forma_user::perm::{self, Acl, AclEntry, FileMode, Perms, Qualifier};

use crate::common::{self, BASE};

/// A new empty file in [`BASE`], owned by root, mode `0600`.
fn new_file(name: &str) -> AbsPath {
    let path = common::base_path(name);
    std::fs::write(path.as_path(), "").unwrap();
    std::fs::set_permissions(path.as_path(), std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn child(parent: &AbsPath, name: &str) -> AbsPath {
    parent.join(OsStr::new(name)).unwrap()
}

/// Reads a file's ACL from the kernel through the crate's own reader.
fn read_acl(path: &AbsPath) -> Acl {
    let base = Dir::open_ambient_dir(BASE, ambient_authority()).unwrap();
    let name = path.file_name().unwrap();
    perm::read(&base, &RelPath::new(name).unwrap()).unwrap().1
}

fn user_entry(uid: u32, perms: Perms) -> AclEntry {
    AclEntry {
        qualifier: Qualifier::User(Uid::from_raw(uid)),
        perms,
    }
}

vm_test! {
    fn set_owner_and_mode_change_a_file_the_caller_does_not_own() {
        let mut system = common::open(common::ClaimAll);
        let path = new_file("perm-file");

        admin::perm::set_owner(&mut system, &path, Uid::from_raw(4242), Gid::from_raw(4343)).unwrap();
        admin::perm::set_mode(&mut system, &path, FileMode::new(0o640).unwrap()).unwrap();

        let metadata = std::fs::metadata(path.as_path()).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (4242, 4343));
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o640);
        assert_eq!(
            common::journal(&system),
            [
                format!("intent: set owner of {path}"),
                format!("applied: set owner of {path}"),
                format!("intent: set mode of {path} to 0640"),
                format!("applied: set mode of {path} to 0640"),
            ],
        );
    }
}

vm_test! {
    fn set_acl_reads_back_the_same_and_matches_getfacl() {
        let mut system = common::open(common::ClaimAll);
        let path = new_file("perm-acl");
        let acl = Acl::from_mode(0o640).with_entry(user_entry(4242, Perms::READ.union(Perms::EXECUTE)));

        admin::perm::set_acl(&mut system, &path, &acl).unwrap();

        assert_eq!(read_acl(&path), acl);
        let getfacl = common::run("/usr/bin/getfacl", &["--numeric", "--omit-header", &path.to_string()]);
        assert!(getfacl.lines().any(|line| line == "user:4242:r-x"), "{getfacl}");
        assert!(getfacl.lines().any(|line| line == "mask::r-x"), "{getfacl}");
    }
}

vm_test! {
    fn changes_need_a_claim_and_stay_inside_the_allowed_bases() {
        let path = new_file("perm-unclaimed");
        // The marker never claims a file whose header is not known, so a
        // change to the mode of an existing file needs the caller's own rule.
        let mut marker = common::marker_system();
        let result = admin::perm::set_mode(&mut marker, &path, FileMode::new(0o644).unwrap());
        assert!(matches!(result, Err(Error::NotOwned(_))), "{result:?}");
        assert_eq!(std::fs::metadata(path.as_path()).unwrap().permissions().mode() & 0o777, 0o600);

        let mut system = common::open(common::ClaimAll);
        let hostname = common::abs("/etc/hostname");
        std::fs::write(hostname.as_path(), "ft\n").unwrap();
        let before = std::fs::metadata(hostname.as_path()).unwrap().permissions().mode();
        let result = admin::perm::set_mode(&mut system, &hostname, FileMode::new(0o600).unwrap());
        assert!(
            matches!(result, Err(Error::Refused { reason: Refusal::OutsideAllowedBases, .. })),
            "{result:?}",
        );
        assert_eq!(std::fs::metadata(hostname.as_path()).unwrap().permissions().mode(), before);
    }
}

vm_test! {
    fn create_dir_sets_owner_and_mode_and_refuses_an_existing_path_or_a_symlink() {
        let mut system = common::open(common::ClaimAll);
        let dir = common::base_path("perm-dir");

        admin::perm::create_dir(&mut system, &dir, Uid::from_raw(4242), Gid::from_raw(4343), FileMode::new(0o750).unwrap())
            .unwrap();

        let metadata = std::fs::metadata(dir.as_path()).unwrap();
        assert!(metadata.is_dir());
        assert_eq!((metadata.uid(), metadata.gid()), (4242, 4343));
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o750);

        let again = admin::perm::create_dir(&mut system, &dir, Uid::ROOT, Gid::ROOT, FileMode::new(0o700).unwrap());
        assert!(matches!(again, Err(Error::AlreadyExists(_))), "{again:?}");

        // A symlink on the way to the new directory must not redirect it.
        let link = common::base_path("perm-link");
        std::os::unix::fs::symlink("/etc", link.as_path()).unwrap();
        let through = child(&link, "ftperm-escaped");
        let result = admin::perm::create_dir(&mut system, &through, Uid::ROOT, Gid::ROOT, FileMode::new(0o700).unwrap());
        assert!(result.is_err(), "{result:?}");
        assert!(!std::path::Path::new("/etc/ftperm-escaped").exists());
    }
}

/// `BASE/<name>` (mode `0700`) holding `inner` (mode `0755`), both owned by
/// root, so only the grant lets an account reach `inner`.
fn closed_tree<O: forma_user::ownership::Ownership>(
    system: &mut forma_user::admin::System<O, common::Recorder>,
    name: &str,
) -> (AbsPath, AbsPath) {
    let outer = common::base_path(name);
    let inner = child(&outer, "inner");
    admin::perm::create_dir(system, &outer, Uid::ROOT, Gid::ROOT, FileMode::new(0o700).unwrap()).unwrap();
    admin::perm::create_dir(system, &inner, Uid::ROOT, Gid::ROOT, FileMode::new(0o755).unwrap()).unwrap();
    (outer, inner)
}

vm_test! {
    fn grant_traverse_lets_the_account_reach_the_path_but_not_list_above_it() {
        let mut system = common::open(common::ClaimAll);
        let user = common::raw_user("fttrav", true, &[]);
        let (outer, inner) = closed_tree(&mut system, "perm-trav");
        let reach = |dir: &AbsPath| common::succeeds_as(&user, "/usr/bin/test", &["-x", &dir.to_string()]);
        assert!(!reach(&inner), "the account could already reach {inner}");

        let changed = admin::perm::grant_traverse(&mut system, &inner, &user).unwrap();

        assert_eq!(changed.last(), Some(&outer), "{changed:?}");
        assert!(reach(&inner));
        assert!(!common::succeeds_as(&user, "/usr/bin/ls", &[&outer.to_string()]), "the account can list {outer}");
        assert_eq!(read_acl(&outer).entry(Qualifier::User(user.uid())), Some(Perms::EXECUTE));

        let again = admin::perm::grant_traverse(&mut system, &inner, &user).unwrap();
        assert!(again.is_empty(), "{again:?}");
    }
}

vm_test! {
    fn grant_traverse_through_lets_the_account_pass_the_directory_itself() {
        // The store root's case: the account must pass through `outer`
        // (root's, 0700) to its own directory below it.
        let mut system = common::open(common::ClaimAll);
        let user = common::raw_user("fttravthru", true, &[]);
        let (outer, inner) = closed_tree(&mut system, "perm-trav-through");
        let reach = |dir: &AbsPath| common::succeeds_as(&user, "/usr/bin/test", &["-x", &dir.to_string()]);

        // grant_traverse on the directory itself only opens what is above it.
        admin::perm::grant_traverse(&mut system, &outer, &user).unwrap();
        assert_eq!(read_acl(&outer).entry(Qualifier::User(user.uid())), None);
        assert!(!reach(&inner), "the account passed {outer} without an entry on it");

        let changed = admin::perm::grant_traverse_through(&mut system, &outer, &user).unwrap();

        assert_eq!(changed, std::slice::from_ref(&outer), "BASE had its entry already");
        assert_eq!(read_acl(&outer).entry(Qualifier::User(user.uid())), Some(Perms::EXECUTE));
        assert!(reach(&inner));
        assert!(!common::succeeds_as(&user, "/usr/bin/ls", &[&outer.to_string()]), "the account can list {outer}");
        let again = admin::perm::grant_traverse_through(&mut system, &outer, &user).unwrap();
        assert!(again.is_empty(), "{again:?}");

        let removed = admin::perm::revoke_traverse_through(&mut system, &outer, &user).unwrap();

        assert!(removed.contains(&outer), "{removed:?}");
        assert_eq!(read_acl(&outer).entry(Qualifier::User(user.uid())), None);
        assert!(!reach(&inner));
        let again = admin::perm::revoke_traverse_through(&mut system, &outer, &user).unwrap();
        assert!(again.is_empty(), "{again:?}");
    }
}

vm_test! {
    fn revoke_traverse_removes_only_the_grant() {
        let mut system = common::open(common::ClaimAll);
        let user = common::raw_user("ftrevoke", true, &[]);
        let (outer, inner) = closed_tree(&mut system, "perm-revoke");
        admin::perm::grant_traverse(&mut system, &inner, &user).unwrap();
        // Another entry on the same directory, which revoke must leave alone.
        let with_other = read_acl(&outer).with_entry(user_entry(4242, Perms::READ));
        admin::perm::set_acl(&mut system, &outer, &with_other).unwrap();
        assert!(common::succeeds_as(&user, "/usr/bin/test", &["-x", &inner.to_string()]));

        let changed = admin::perm::revoke_traverse(&mut system, &inner, &user).unwrap();

        assert_eq!(changed.last(), Some(&outer), "{changed:?}");
        assert!(!common::succeeds_as(&user, "/usr/bin/test", &["-x", &inner.to_string()]));
        let acl = read_acl(&outer);
        assert_eq!(acl.entry(Qualifier::User(user.uid())), None);
        assert_eq!(acl.entry(Qualifier::User(Uid::from_raw(4242))), Some(Perms::READ));

        let again = admin::perm::revoke_traverse(&mut system, &inner, &user).unwrap();
        assert!(again.is_empty(), "{again:?}");
    }
}

vm_test! {
    fn revoke_traverse_needs_a_claim_on_the_acl_entry() {
        let mut claim_all = common::open(common::ClaimAll);
        let user = common::raw_user("ftrevokeno", true, &[]);
        let (outer, inner) = closed_tree(&mut claim_all, "perm-revoke-no");
        admin::perm::grant_traverse(&mut claim_all, &inner, &user).unwrap();

        // The marker never claims an ACL entry.
        let mut marker = common::marker_system();
        let result = admin::perm::revoke_traverse(&mut marker, &inner, &user);

        assert!(matches!(result, Err(Error::NotOwned(_))), "{result:?}");
        assert_eq!(read_acl(&outer).entry(Qualifier::User(user.uid())), Some(Perms::EXECUTE));
    }
}
