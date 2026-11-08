//! Creating and deleting groups, membership, and vendor groups.

use forma_user::admin::{self, Ensured, Error, Refusal};
use forma_user::id::Gid;
use forma_user::lookup::{self, Group, LocalGroup};
use forma_user::ownership::ClaimNothing;
use forma_user::spec::{GidChoice, GroupSpec};
use forma_user::udev::{Assign, Match, Rule, RulesFile, RulesFileName, UdevValue};

use crate::common;

fn local(name: &str) -> LocalGroup {
    match lookup::group(&common::group_name(name)).unwrap() {
        Some(Group::Local(group)) => group,
        other => panic!("{name} is not a local group: {other:?}"),
    }
}

vm_test! {
    fn create_allocates_or_takes_the_given_id_and_refuses_a_taken_one() {
        let mut system = common::marker_system();
        let range = system.login_defs().sys_gid;

        let allocated = admin::group::create(&mut system, &common::group_spec("ftgalloc")).unwrap();
        assert!(range.contains(allocated.info().gid().as_raw()));

        let id = common::free_system_id(range);
        let fixed = GroupSpec {
            gid: GidChoice::Fixed(common::system_gid(id, range)),
            ..common::group_spec("ftgfixed")
        };
        let group = admin::group::create(&mut system, &fixed).unwrap();
        assert_eq!(group.info().gid(), Gid::from_raw(id));

        let same_name = admin::group::create(&mut system, &fixed);
        assert!(matches!(same_name, Err(Error::GroupExists(_))), "{same_name:?}");
        let same_id = admin::group::create(
            &mut system,
            &GroupSpec { gid: fixed.gid, ..common::group_spec("ftgfixed2") },
        );
        assert!(matches!(same_id, Err(Error::GidInUse(gid)) if gid == Gid::from_raw(id)), "{same_id:?}");
        assert_eq!(
            common::journal(&system).first().map(String::as_str),
            Some("intent: create group ftgalloc"),
        );
    }
}

vm_test! {
    fn ensure_reports_matches_conflict_and_unclaimed_groups() {
        // The marker claims a group only through an account of the same name
        // that uses it, so the group tests that need a claim use `ClaimAll`.
        let mut system = common::open(common::ClaimAll);
        let range = system.login_defs().sys_gid;
        let id = common::free_system_id(range);
        let spec = GroupSpec {
            gid: GidChoice::Fixed(common::system_gid(id, range)),
            ..common::group_spec("ftgensure")
        };
        assert!(matches!(admin::group::ensure(&mut system, &spec).unwrap(), Ensured::Created(_)));
        assert!(matches!(admin::group::ensure(&mut system, &spec).unwrap(), Ensured::Matches(_)));

        let other = common::free_system_id_except(range, Some(id));
        let wrong_id = GroupSpec {
            gid: GidChoice::Fixed(common::system_gid(other, range)),
            ..spec
        };
        let Ensured::Conflict { diff, .. } = admin::group::ensure(&mut system, &wrong_id).unwrap() else {
            panic!("expected a conflict");
        };
        assert_eq!(diff.gid, Some((Gid::from_raw(other), Gid::from_raw(id))));

        let mut strict = common::marker_system();
        common::raw_group("ftgforeign", &[]);
        let result = admin::group::ensure(&mut strict, &common::group_spec("ftgforeign"));
        assert!(matches!(result, Err(Error::NotOwned(_))), "{result:?}");
    }
}

vm_test! {
    fn delete_removes_a_claimed_group() {
        let mut system = common::open(common::ClaimAll);
        let group = admin::group::create(&mut system, &common::group_spec("ftgdelete")).unwrap();

        admin::group::delete(&mut system, &group).unwrap();

        assert!(lookup::group(&common::group_name("ftgdelete")).unwrap().is_none());
        assert_eq!(
            common::journal(&system),
            [
                "intent: create group ftgdelete",
                "applied: create group ftgdelete",
                "intent: delete group ftgdelete",
                "applied: delete group ftgdelete",
            ],
        );
    }
}

vm_test! {
    fn delete_refuses_an_unclaimed_group_and_a_primary_group() {
        let mut system = common::marker_system();
        common::raw_group("ftgunclaimed", &[]);
        let result = admin::group::delete(&mut system, &local("ftgunclaimed"));
        assert!(matches!(result, Err(Error::NotOwned(_))), "{result:?}");

        // An account of this crate claims its own group, so the claim passes
        // and the primary-group refusal is what stops the delete.
        admin::user::create(&mut system, &common::user_spec("ftgprimary")).unwrap();
        let result = admin::group::delete(&mut system, &local("ftgprimary"));
        assert!(
            matches!(
                result,
                Err(Error::Refused { reason: Refusal::PrimaryGroupOf(ref user), .. }) if user == "ftgprimary"
            ),
            "{result:?}",
        );
        assert!(lookup::group(&common::group_name("ftgprimary")).unwrap().is_some());
    }
}

vm_test! {
    fn delete_refuses_a_group_a_managed_udev_rule_names() {
        let mut system = common::open(common::ClaimAll);
        let group = admin::group::create(&mut system, &common::group_spec("ftgudev")).unwrap();
        let rule = Rule::new(
            vec![Match::Kernel(UdevValue::new("ftgudev-device").unwrap())],
            vec![Assign::Group(common::group_name("ftgudev"))],
        )
        .unwrap();
        let name = RulesFileName::new(70, "ftgudev").unwrap();
        let file = RulesFile::new(name.clone(), vec![rule]).unwrap();
        assert!(admin::udev::write(&mut system, &file).unwrap());

        let result = admin::group::delete(&mut system, &group);
        assert!(
            matches!(result, Err(Error::Refused { reason: Refusal::UsedByUdevRule(_), .. })),
            "{result:?}",
        );

        admin::udev::remove(&mut system, &name).unwrap();
        admin::group::delete(&mut system, &group).unwrap();
    }
}

vm_test! {
    fn membership_is_added_and_removed_once() {
        let mut system = common::open(common::ClaimAll);
        let user = common::raw_user("ftmember", true, &[]);
        let group = admin::group::create(&mut system, &common::group_spec("ftmgroup")).unwrap();

        assert!(admin::group::add_member(&mut system, &user, &group).unwrap());
        assert!(!admin::group::add_member(&mut system, &user, &group).unwrap());
        assert!(local("ftmgroup").info().has_member(user.name()));
        assert!(lookup::group_ids(&user).unwrap().contains(&group.info().gid()));

        assert!(admin::group::remove_member(&mut system, &user, &group).unwrap());
        assert!(!admin::group::remove_member(&mut system, &user, &group).unwrap());
        assert!(!local("ftmgroup").info().has_member(user.name()));
    }
}

vm_test! {
    fn removing_a_membership_the_caller_does_not_claim_is_refused() {
        let user = common::raw_user("ftmunclaimed", false, &[]);
        let group = {
            let mut system = common::open(common::ClaimAll);
            let group = admin::group::create(&mut system, &common::group_spec("ftmugroup")).unwrap();
            assert!(admin::group::add_member(&mut system, &user, &group).unwrap());
            group
        };

        let mut system = common::open(ClaimNothing);
        let result = admin::group::remove_member(&mut system, &user, &group);

        assert!(matches!(result, Err(Error::NotOwned(_))), "{result:?}");
        assert!(local("ftmugroup").info().has_member(user.name()));
    }
}

vm_test! {
    fn a_vendor_group_cannot_be_created_or_changed() {
        // The image ships `ftvendor` in /usr/lib/group only, with nss-altfiles
        // so that NSS sees it.
        let mut system = common::marker_system();
        let found = lookup::group(&common::group_name("ftvendor")).unwrap();
        assert!(matches!(found, Some(Group::Vendor(_))), "{found:?}");

        let ensure = admin::group::ensure(&mut system, &common::group_spec("ftvendor"));
        assert!(
            matches!(ensure, Err(Error::Refused { reason: Refusal::Vendor, .. })),
            "{ensure:?}",
        );
        let create = admin::group::create(&mut system, &common::group_spec("ftvendor"));
        assert!(matches!(create, Err(Error::GroupExists(_))), "{create:?}");
        assert_eq!(common::journal(&system), [] as [&str; 0]);
    }
}
