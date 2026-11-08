//! `modules-load.d` files and module loading.

use std::path::Path;

use forma_user::admin::systemd::modules::{self, MODULES_DIR};
use forma_user::systemd::modules::{ModuleName, ModulesLoadFile, ModulesLoadFileName};

use crate::common::{self, TAG};

fn loaded(module: &str) -> bool {
    Path::new("/sys/module").join(module).exists()
}

vm_test! {
    fn write_loads_the_module_and_rewriting_the_same_file_changes_nothing() {
        let mut system = common::marker_system();
        // Start from a state where the module is not loaded.
        let _ = std::process::Command::new("/usr/sbin/modprobe").args(["-r", "uhid"]).status();
        assert!(!loaded("uhid"), "uhid is built in or in use; the test needs a module it can unload");

        let name = ModulesLoadFileName::new("ftmodules").unwrap();
        let file = ModulesLoadFile::new(name.clone(), vec![ModuleName::new("uhid").unwrap()]).unwrap();
        assert!(modules::write(&mut system, &file).unwrap());

        let path = Path::new(MODULES_DIR).join(name.file_name());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), file.render(&common::marker_tag()));
        assert!(std::fs::read_to_string(&path).unwrap().starts_with(&format!("# managed-by: {TAG}\n")));
        assert!(loaded("uhid"), "systemd-modules-load did not load uhid");

        assert!(!modules::write(&mut system, &file).unwrap());
        assert!(modules::remove(&mut system, &name).unwrap());
        assert!(!path.exists());
    }
}
