//! Linger, and deleting an account whose user manager is running.

use std::process::Command;
use std::time::{Duration, Instant};

use forma_user::admin;
use forma_user::lookup::{self, User};
use forma_user::spec::{DeleteOptions, HomePolicy, SessionPolicy};
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
        assert!(
            Instant::now() < deadline,
            "the user manager of {} did not start\n{}",
            user.name(),
            manager_report(user),
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// What systemd and logind say about an account's user manager, for the message
/// of a test that timed out waiting for it.
fn manager_report(user: &User) -> String {
    let uid = user.uid();
    let units = [
        format!("user@{uid}.service"),
        format!("user-runtime-dir@{uid}.service"),
        format!("user-{uid}.slice"),
    ];
    let mut report = format!("uid {uid}\n");
    for unit in &units {
        report += &capture("/usr/bin/systemctl", &["status", "--no-pager", "--full", unit]);
        report += &capture("/usr/bin/journalctl", &["--no-pager", "-n", "30", "-u", unit]);
    }
    report += &capture("/usr/bin/loginctl", &["list-users", "--no-pager"]);
    report += &capture("/usr/bin/loginctl", &["show-user", &uid.to_string(), "--no-pager"]);
    report
}

/// Runs a program and returns what it printed with a heading. A failure is part
/// of the report, not a panic.
fn capture(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(output) => format!(
            "$ {program} {}\n{}{}\n",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
        Err(error) => format!("$ {program} {}\ncannot run: {error}\n", args.join(" ")),
    }
}

vm_test! {
    fn linger_turns_on_and_off_and_a_second_call_changes_nothing() {
        let mut system = common::marker_system();
        let user = admin::user::create(&mut system, &common::user_spec("ftlinger")).unwrap();
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
