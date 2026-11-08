//! Linger, and deleting an account whose user manager is running.

use std::process::Command;
use std::time::{Duration, Instant};

use forma_user::admin;
use forma_user::lookup::{self, User};
use forma_user::spec::{DeleteOptions, HomePolicy, SessionPolicy, UidChoice, UserSpec};
use forma_user::systemd;

use crate::common;

fn manager_active(user: &User) -> bool {
    Command::new("/usr/bin/systemctl")
        .args(["is-active", "--quiet", &format!("user@{}.service", user.uid())])
        .status()
        .expect("run systemctl")
        .success()
}

fn wait_for_manager(user: &User) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !manager_active(user) {
        assert!(Instant::now() < deadline, "the user manager of {} did not start", user.name());
        std::thread::sleep(Duration::from_millis(200));
    }
}

vm_test! {
    fn linger_turns_on_and_off_and_a_second_call_changes_nothing() {
        let mut system = common::marker_system();
        // Not the ID `useradd` hands out next. The delete test below frees that one,
        // and a new account on the ID of a user manager that has just stopped can
        // wait on the old one's leftovers.
        let range = system.login_defs().sys_uid;
        let id = common::free_system_id_except(range, Some(common::free_system_id(range)));
        let spec = UserSpec {
            uid: UidChoice::Fixed(common::system_uid(id, range)),
            ..common::user_spec("ftlinger")
        };
        let user = admin::user::create(&mut system, &spec).unwrap();
        assert!(!systemd::linger(&user).unwrap());

        assert!(admin::systemd::linger::set(&mut system, &user, true).unwrap());
        assert!(systemd::linger(&user).unwrap());
        assert!(!admin::systemd::linger::set(&mut system, &user, true).unwrap());
        wait_for_manager(&user);

        assert!(admin::systemd::linger::set(&mut system, &user, false).unwrap());
        assert!(!systemd::linger(&user).unwrap());
        assert!(!admin::systemd::linger::set(&mut system, &user, false).unwrap());
    }
}

vm_test! {
    fn delete_stops_a_lingering_user_manager_and_clears_linger() {
        let mut system = common::marker_system();
        let user = admin::user::create(&mut system, &common::user_spec("ftlingerdel")).unwrap();
        admin::systemd::linger::set(&mut system, &user, true).unwrap();
        wait_for_manager(&user);

        let options = DeleteOptions { home: HomePolicy::Keep, sessions: SessionPolicy::Refuse };
        admin::user::delete(&mut system, &user, options).unwrap();

        assert!(lookup::user(&common::user_name("ftlingerdel")).unwrap().is_none());
        assert!(!manager_active(&user), "the user manager is still running");
        assert!(!std::path::Path::new("/var/lib/systemd/linger/ftlingerdel").exists(), "linger was left on");
    }
}
