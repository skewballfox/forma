//! udev rules for `uinput` and `uhid`, a trigger, and the node's group and mode.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::time::{Duration, Instant};

use forma_user::admin::udev::{SysfsDevice, RULES_DIR};
use forma_user::admin::{self, Error};
use forma_user::lookup;
use forma_user::udev::{Assign, DeviceMode, Match, Rule, RulesFile, RulesFileName, UdevValue};

use crate::common::{self, TAG};

fn rule(kernel: &str, group: &str) -> Rule {
    Rule::new(
        vec![
            Match::Kernel(UdevValue::new(kernel).unwrap()),
            Match::Subsystem(UdevValue::new("misc").unwrap()),
        ],
        vec![
            Assign::Group(common::group_name(group)),
            Assign::Mode(DeviceMode::new(0o660).unwrap()),
        ],
    )
    .unwrap()
}

vm_test! {
    fn write_is_idempotent_and_refuses_a_group_that_does_not_exist() {
        let mut system = common::marker_system();
        let name = RulesFileName::new(70, "ftwrite").unwrap();
        let missing = RulesFile::new(name.clone(), vec![rule("uinput", "ftnosuchgroup")]).unwrap();
        let result = admin::udev::write(&mut system, &missing);
        assert!(matches!(result, Err(Error::GroupMissing(_))), "{result:?}");
        assert!(!std::path::Path::new(RULES_DIR).join(name.file_name()).exists());

        admin::group::create(&mut system, &common::group_spec("ftwrite")).unwrap();
        let file = RulesFile::new(name.clone(), vec![rule("uinput", "ftwrite")]).unwrap();
        assert!(admin::udev::write(&mut system, &file).unwrap());
        assert!(!admin::udev::write(&mut system, &file).unwrap());

        let path = std::path::Path::new(RULES_DIR).join(name.file_name());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, file.render(&common::marker_tag()));
        assert!(text.starts_with(&format!("# managed-by: {TAG}\n")));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o644);

        assert!(admin::udev::remove(&mut system, &name).unwrap());
        assert!(!admin::udev::remove(&mut system, &name).unwrap());
        assert!(!path.exists());
    }
}

vm_test! {
    fn a_trigger_gives_the_device_node_the_rules_group_and_mode() {
        let mut system = common::marker_system();
        // Both modules the plan needs. The image must carry them.
        common::run("/usr/sbin/modprobe", &["uinput"]);
        common::run("/usr/sbin/modprobe", &["uhid"]);
        let group = admin::group::create(&mut system, &common::group_spec("ftinput")).unwrap();
        let name = RulesFileName::new(70, "ftinput").unwrap();
        let file = RulesFile::new(name.clone(), vec![rule("uinput", "ftinput"), rule("uhid", "ftinput")]).unwrap();
        admin::udev::write(&mut system, &file).unwrap();
        common::run("/usr/bin/udevadm", &["control", "--reload"]);

        for (node, device) in [("/dev/uinput", "devices/virtual/misc/uinput"), ("/dev/uhid", "devices/virtual/misc/uhid")] {
            admin::udev::trigger(&system, &SysfsDevice::new(device).unwrap()).unwrap();
            wait_for_group(node, group.info().gid().as_raw());
            let metadata = std::fs::metadata(node).unwrap();
            assert_eq!(metadata.gid(), group.info().gid().as_raw(), "{node}");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o660, "{node}");
        }

        admin::udev::remove(&mut system, &name).unwrap();
        assert!(lookup::group(&common::group_name("ftinput")).unwrap().is_some());
    }
}

/// Waits for udev to apply a change to a node.
fn wait_for_group(node: &str, gid: u32) {
    common::run("/usr/bin/udevadm", &["settle", "--timeout=10"]);
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::fs::metadata(node).map(|m| m.gid()).ok() != Some(gid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
}

vm_test! {
    fn trigger_refuses_a_path_that_leaves_sysfs() {
        // A path that leaves /sys never becomes a `SysfsDevice`, so `trigger`
        // cannot be handed one.
        assert!(SysfsDevice::new("../etc/hostname").is_err());
    }
}
