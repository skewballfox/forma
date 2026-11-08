//! Sub-ID ranges next to ranges made by `useradd` and by hand.

use std::fmt::Write as _;

use forma_user::admin::{self, Error};
use forma_user::defs::{self, SubIdEntry};
use forma_user::id::{SubIdCount, SubIdRange};

use crate::common;

const SUBUID: &str = "/etc/subuid";
const SUBGID: &str = "/etc/subgid";

fn entries(file: &'static str) -> Vec<SubIdEntry> {
    defs::parse_subids(file, &std::fs::read_to_string(file).unwrap_or_default()).unwrap()
}

fn count() -> SubIdCount {
    SubIdCount::new(SubIdCount::MIN).unwrap()
}

fn owned_by<'a>(entries: &'a [SubIdEntry], name: &str) -> Vec<&'a SubIdEntry> {
    entries.iter().filter(|entry| entry.owner == name).collect()
}

vm_test! {
    fn allocate_writes_one_range_to_both_files_and_a_second_call_is_refused() {
        let mut system = common::marker_system();
        let user = admin::user::create(&mut system, &common::user_spec("ftsub")).unwrap();

        let range = admin::subid::allocate(&mut system, &user, count()).unwrap();

        let limits = system.login_defs().sub_uid.range;
        assert_eq!(range.count(), SubIdCount::MIN);
        assert!(range.start() >= limits.first() && range.last() <= limits.last(), "{range} outside {limits}");
        for file in [SUBUID, SUBGID] {
            let all = entries(file);
            let mine = owned_by(&all, "ftsub");
            assert_eq!(mine.len(), 1, "{file}: {all:?}");
            assert_eq!(mine[0].range, range, "{file}");
        }

        let again = admin::subid::allocate(&mut system, &user, count());
        assert!(matches!(again, Err(Error::HasSubIds { .. })), "{again:?}");
    }
}

vm_test! {
    fn allocate_clears_ranges_made_by_useradd_and_by_hand() {
        let mut system = common::marker_system();
        // A person's account gets its range from useradd.
        common::run("/usr/sbin/useradd", &["--no-create-home", "ftsubperson"]);
        let all = entries(SUBUID);
        let from_useradd = owned_by(&all, "ftsubperson")[0].range;

        // A range somebody wrote into both files by hand, right after the
        // highest one in use.
        let after = entries(SUBUID).into_iter().chain(entries(SUBGID)).map(|entry| entry.range.end()).max().unwrap();
        let by_hand = SubIdRange::new(u32::try_from(after).unwrap(), count()).unwrap();
        for file in [SUBUID, SUBGID] {
            let mut text = std::fs::read_to_string(file).unwrap_or_default();
            writeln!(text, "ftsubhand:{}:{}", by_hand.start(), by_hand.count()).unwrap();
            std::fs::write(file, text).unwrap();
        }

        let user = admin::user::create(&mut system, &common::user_spec("ftsubnew")).unwrap();
        let range = admin::subid::allocate(&mut system, &user, count()).unwrap();

        assert!(!range.overlaps(from_useradd), "{range} overlaps useradd's {from_useradd}");
        assert!(!range.overlaps(by_hand), "{range} overlaps the hand-made {by_hand}");
        for file in [SUBUID, SUBGID] {
            let all = entries(file);
            for other in all.iter().filter(|entry| entry.owner != "ftsubnew") {
                assert!(!range.overlaps(other.range), "{file}: {range} overlaps {other:?}");
            }
        }
    }
}

vm_test! {
    fn add_refuses_a_range_that_overlaps_another_owner() {
        let mut system = common::marker_system();
        let first = admin::user::create(&mut system, &common::user_spec("ftsubfirst")).unwrap();
        let second = admin::user::create(&mut system, &common::user_spec("ftsubsecond")).unwrap();
        let range = admin::subid::allocate(&mut system, &first, count()).unwrap();

        let result = admin::subid::add(&mut system, &second, range);

        assert!(
            matches!(result, Err(Error::SubIdOverlap { ref owner, .. }) if owner == "ftsubfirst"),
            "{result:?}",
        );
        let all = entries(SUBUID);
        assert!(owned_by(&all, "ftsubsecond").is_empty(), "{all:?}");
    }
}

vm_test! {
    fn add_then_remove_gives_the_range_back_in_both_files() {
        let mut system = common::marker_system();
        let user = admin::user::create(&mut system, &common::user_spec("ftsubadd")).unwrap();
        let after = entries(SUBUID).into_iter().chain(entries(SUBGID)).map(|entry| entry.range.end()).max().unwrap();
        let range = SubIdRange::new(u32::try_from(after).unwrap(), count()).unwrap();

        admin::subid::add(&mut system, &user, range).unwrap();
        for file in [SUBUID, SUBGID] {
            assert_eq!(owned_by(&entries(file), "ftsubadd").iter().map(|entry| entry.range).collect::<Vec<_>>(), [range]);
        }

        let (uids, gids) = admin::subid::remove(&mut system, &user).unwrap();

        assert_eq!((uids, gids), (vec![range], vec![range]));
        for file in [SUBUID, SUBGID] {
            assert!(owned_by(&entries(file), "ftsubadd").is_empty(), "{file}");
        }
    }
}
