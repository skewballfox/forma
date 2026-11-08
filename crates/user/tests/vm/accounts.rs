//! Creating, ensuring and deleting accounts, and every refusal in
//! `PLAN.md` section 7.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use forma_user::admin::{self, Ensured, Error, Refusal};
use forma_user::id::Uid;
use forma_user::lookup::{self, Group};
use forma_user::name::Comment;
use forma_user::spec::{DeleteOptions, HomePolicy, HomeSpec, NOLOGIN, PrimaryGroup, SessionPolicy, Shell, UidChoice};

use crate::common::{self, TAG};

const REMOVE_HOME: DeleteOptions = DeleteOptions {
    home: HomePolicy::Remove,
    sessions: SessionPolicy::Refuse,
};

vm_test! {
    fn create_makes_a_system_account_with_its_own_group_and_home() {
        let mut system = common::marker_system();
        let home = common::base_path("acct-create");
        let spec = forma_user::spec::UserSpec {
            home: HomeSpec::Create(home.clone()),
            comment: Some(Comment::new("created by a test").unwrap()),
            ..common::user_spec("ftcreate")
        };

        let user = admin::user::create(&mut system, &spec).unwrap();

        assert!(system.login_defs().sys_uid.contains(user.uid().as_raw()));
        assert_eq!(user.home(), home.as_path());
        assert_eq!(user.shell(), Path::new(NOLOGIN));
        assert!(user.comment().starts_with("created by a test"), "{}", user.comment());
        assert!(user.comment().contains(&format!("managed-by={TAG}")), "{}", user.comment());
        let group = lookup::group(&common::group_name("ftcreate")).unwrap().unwrap();
        assert_eq!(group.info().gid(), user.gid());
        assert!(home.as_path().is_dir());
        assert_eq!(
            common::journal(&system),
            ["intent: create user ftcreate", "applied: create user ftcreate"],
        );
    }
}

vm_test! {
    fn create_refuses_a_taken_name_or_id() {
        let mut system = common::marker_system();
        let range = system.login_defs().sys_uid;
        let id = common::free_system_id(range);
        let spec = forma_user::spec::UserSpec {
            uid: UidChoice::Fixed(common::system_uid(id, range)),
            ..common::user_spec("ftfixed")
        };
        let user = admin::user::create(&mut system, &spec).unwrap();
        assert_eq!(user.uid(), Uid::from_raw(id));

        let same_name = admin::user::create(&mut system, &spec);
        assert!(matches!(same_name, Err(Error::UserExists(_))), "{same_name:?}");

        let other = forma_user::spec::UserSpec {
            primary_group: PrimaryGroup::Existing(lookup::group(&common::group_name("ftfixed")).unwrap().unwrap()),
            ..common::user_spec("ftfixed2")
        };
        let same_id = admin::user::create(
            &mut system,
            &forma_user::spec::UserSpec {
                uid: UidChoice::Fixed(common::system_uid(id, range)),
                ..other
            },
        );
        assert!(matches!(same_id, Err(Error::UidInUse(taken)) if taken == Uid::from_raw(id)), "{same_id:?}");
        assert!(lookup::user(&common::user_name("ftfixed2")).unwrap().is_none());
    }
}

vm_test! {
    fn create_uses_existing_groups_and_refuses_a_second_new_one() {
        let mut system = common::marker_system();
        common::raw_group("ftprimary", &[]);
        common::raw_group("ftextra", &[]);
        let Some(Group::Local(extra)) = lookup::group(&common::group_name("ftextra")).unwrap() else {
            panic!("ftextra is not a local group");
        };
        let primary = lookup::group(&common::group_name("ftprimary")).unwrap().unwrap();
        let spec = forma_user::spec::UserSpec {
            primary_group: PrimaryGroup::Existing(primary.clone()),
            supplementary: vec![extra.clone()],
            ..common::user_spec("ftgroups")
        };

        let user = admin::user::create(&mut system, &spec).unwrap();

        assert_eq!(user.gid(), primary.info().gid());
        assert!(lookup::group_ids(&user).unwrap().contains(&extra.info().gid()));
        assert!(lookup::group(&common::group_name("ftgroups")).unwrap().is_none());

        common::raw_group("ftnewprimary", &[]);
        let clash = admin::user::create(&mut system, &common::user_spec("ftnewprimary"));
        assert!(matches!(clash, Err(Error::PrimaryGroupExists(_))), "{clash:?}");
    }
}

vm_test! {
    fn create_refuses_homes_outside_the_allowed_bases_or_already_there() {
        let mut system = common::marker_system();
        let outside = forma_user::spec::UserSpec {
            home: HomeSpec::Create(common::abs("/var/lib/ft-outside")),
            ..common::user_spec("ftoutside")
        };
        let result = admin::user::create(&mut system, &outside);
        assert!(
            matches!(result, Err(Error::Refused { reason: Refusal::OutsideAllowedBases, .. })),
            "{result:?}",
        );

        let home = common::base_path("acct-exists");
        std::fs::create_dir(home.as_path()).unwrap();
        let existing = forma_user::spec::UserSpec {
            home: HomeSpec::Create(home),
            ..common::user_spec("ftexists")
        };
        let result = admin::user::create(&mut system, &existing);
        assert!(matches!(result, Err(Error::AlreadyExists(_))), "{result:?}");
        assert!(lookup::user(&common::user_name("ftexists")).unwrap().is_none());
        assert!(lookup::user(&common::user_name("ftoutside")).unwrap().is_none());
    }
}

vm_test! {
    fn ensure_creates_then_matches_then_reports_a_conflict() {
        let mut system = common::marker_system();
        let spec = common::user_spec("ftensure");

        let created = admin::user::ensure(&mut system, &spec).unwrap();
        assert!(matches!(created, Ensured::Created(_)), "{created:?}");

        let matches = admin::user::ensure(&mut system, &spec).unwrap();
        assert!(matches!(matches, Ensured::Matches(_)), "{matches:?}");

        let wants_login = forma_user::spec::UserSpec {
            shell: Shell::Login(common::abs("/bin/sh")),
            ..spec
        };
        let Ensured::Conflict { existing, diff } = admin::user::ensure(&mut system, &wants_login).unwrap() else {
            panic!("expected a conflict");
        };
        assert_eq!(existing.shell(), Path::new(NOLOGIN));
        assert_eq!(diff.shell, Some(("/bin/sh".to_owned(), NOLOGIN.to_owned())));
        assert_eq!(existing.shell(), lookup::user(&common::user_name("ftensure")).unwrap().unwrap().shell());
    }
}

vm_test! {
    fn ensure_and_delete_refuse_accounts_the_caller_does_not_claim() {
        let mut system = common::marker_system();
        let foreign = common::raw_user("ftforeign", false, &[]);

        let ensure = admin::user::ensure(&mut system, &common::user_spec("ftforeign"));
        assert!(matches!(ensure, Err(Error::NotOwned(_))), "{ensure:?}");
        let delete = admin::user::delete(&mut system, &foreign, REMOVE_HOME);
        assert!(matches!(delete, Err(Error::NotOwned(_))), "{delete:?}");
        assert!(lookup::user(&common::user_name("ftforeign")).unwrap().is_some());
        assert_eq!(common::journal(&system), [] as [&str; 0]);
    }
}

vm_test! {
    fn delete_refuses_ids_outside_the_system_range() {
        let mut system = common::marker_system();
        let person = common::raw_user("ftperson", true, &["--uid", "61000", "--no-user-group", "--gid", "0"]);
        // A claimed account, but a person's ID: the system-range check comes next.
        let result = admin::user::delete(&mut system, &person, REMOVE_HOME);
        assert!(
            matches!(result, Err(Error::Refused { reason: Refusal::OutsideSystemRange, .. })),
            "{result:?}",
        );
        assert!(lookup::user(&common::user_name("ftperson")).unwrap().is_some());
    }
}

vm_test! {
    fn delete_with_archive_renames_the_home_and_gives_it_to_root() {
        let mut system = common::marker_system();
        let home = common::base_path("acct-archive");
        let spec = forma_user::spec::UserSpec {
            home: HomeSpec::Create(home.clone()),
            ..common::user_spec("ftarchive")
        };
        let user = admin::user::create(&mut system, &spec).unwrap();

        let options = DeleteOptions { home: HomePolicy::Archive, sessions: SessionPolicy::Refuse };
        let archived = admin::user::delete(&mut system, &user, options).unwrap().expect("an archived path");

        assert!(lookup::user(&common::user_name("ftarchive")).unwrap().is_none());
        assert!(lookup::group(&common::group_name("ftarchive")).unwrap().is_none());
        assert!(!home.as_path().exists());
        assert!(archived.as_path().to_string_lossy().starts_with(&format!("{home}.removed-")), "{archived}");
        let metadata = std::fs::metadata(archived.as_path()).unwrap();
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.gid(), 0);
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
    }
}

vm_test! {
    fn delete_with_remove_does_not_follow_a_symlink_in_the_home() {
        let mut system = common::marker_system();
        let home = common::base_path("acct-remove");
        let spec = forma_user::spec::UserSpec {
            home: HomeSpec::Create(home.clone()),
            ..common::user_spec("ftremove")
        };
        let user = admin::user::create(&mut system, &spec).unwrap();

        let outside = common::base_path("acct-remove-outside");
        std::fs::create_dir(outside.as_path()).unwrap();
        std::fs::write(outside.as_path().join("keep"), "keep").unwrap();
        std::os::unix::fs::symlink(outside.as_path(), home.as_path().join("link")).unwrap();

        let archived = admin::user::delete(&mut system, &user, REMOVE_HOME).unwrap();

        assert_eq!(archived, None);
        assert!(!home.as_path().exists());
        assert!(outside.as_path().join("keep").exists(), "the symlink target was emptied");
        assert!(lookup::user(&common::user_name("ftremove")).unwrap().is_none());
    }
}

vm_test! {
    fn delete_with_keep_leaves_the_home() {
        let mut system = common::marker_system();
        let home = common::base_path("acct-keep");
        let spec = forma_user::spec::UserSpec {
            home: HomeSpec::Create(home.clone()),
            ..common::user_spec("ftkeep")
        };
        let user = admin::user::create(&mut system, &spec).unwrap();

        let options = DeleteOptions { home: HomePolicy::Keep, sessions: SessionPolicy::Refuse };
        assert_eq!(admin::user::delete(&mut system, &user, options).unwrap(), None);

        assert!(home.as_path().is_dir());
        assert!(lookup::user(&common::user_name("ftkeep")).unwrap().is_none());
    }
}

vm_test! {
    fn delete_refuses_a_home_owned_by_another_user() {
        let mut system = common::marker_system();
        let home = common::base_path("acct-stolen");
        let spec = forma_user::spec::UserSpec {
            home: HomeSpec::Create(home.clone()),
            ..common::user_spec("ftstolen")
        };
        let user = admin::user::create(&mut system, &spec).unwrap();
        std::os::unix::fs::chown(home.as_path(), Some(0), Some(0)).unwrap();

        let result = admin::user::delete(&mut system, &user, REMOVE_HOME);

        assert!(
            matches!(result, Err(Error::Refused { reason: Refusal::HomeOwnedBy(owner), .. }) if owner == Uid::ROOT),
            "{result:?}",
        );
        assert!(lookup::user(&common::user_name("ftstolen")).unwrap().is_some());
        assert!(home.as_path().is_dir());
    }
}

vm_test! {
    fn delete_refuses_a_home_another_account_shares() {
        let mut system = common::marker_system();
        let home = common::base_path("acct-shared");
        let spec = forma_user::spec::UserSpec {
            home: HomeSpec::Create(home.clone()),
            ..common::user_spec("ftshared")
        };
        let user = admin::user::create(&mut system, &spec).unwrap();
        common::raw_user("ftsharer", false, &["--home-dir", &home.to_string()]);

        let result = admin::user::delete(&mut system, &user, REMOVE_HOME);

        assert!(
            matches!(result, Err(Error::Refused { reason: Refusal::HomeShared(ref other), .. }) if other == "ftsharer"),
            "{result:?}",
        );
        assert!(home.as_path().is_dir());
    }
}

vm_test! {
    fn delete_refuses_an_account_whose_id_changed() {
        let mut system = common::marker_system();
        let user = admin::user::create(&mut system, &common::user_spec("ftchanged")).unwrap();
        common::run("/usr/sbin/userdel", &["ftchanged"]);
        let range = system.login_defs().sys_uid;
        let other = common::free_system_id_except(range, Some(user.uid().as_raw())).to_string();
        common::raw_user("ftchanged", true, &["--uid", &other]);

        let result = admin::user::delete(&mut system, &user, REMOVE_HOME);

        assert!(matches!(result, Err(Error::Changed(_))), "{result:?}");
        assert!(lookup::user(&common::user_name("ftchanged")).unwrap().is_some());
    }
}
