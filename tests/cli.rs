//! Runs the `forma` binary against the installed-state fixture.
//!
//! The binary reads the real host for accounts and groups, so these tests
//! check only what does not depend on the machine they run on.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// A host configuration and a materia configuration that point at the fixture.
struct Host {
    directory: tempfile::TempDir,
}

impl Host {
    fn moonshine() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let installed = fixtures().join("installed/moonshine");
        // Materia keeps its records in <materia_dir>/components; the fixture calls that directory `data`.
        let materia_dir = directory.path().join("materia");
        std::fs::create_dir(&materia_dir).unwrap();
        std::os::unix::fs::symlink(installed.join("data"), materia_dir.join("components")).unwrap();
        std::fs::write(
            directory.path().join("materia.toml"),
            format!(
                "hostname = \"forge\"\nmateria_dir = \"{}\"\nquadlet_dir = \"{}\"\nsource_dir = \"{}\"\n\
                 [executor]\ndelegate_dir = \"{}\"\n",
                materia_dir.display(),
                installed.join("quadlets").display(),
                fixtures().join("valid/moonshine").display(),
                installed.join("delegate").display(),
            ),
        )
        .unwrap();
        let fixture_config = std::fs::read_to_string(fixtures().join("host/config.toml")).unwrap();
        let config = fixture_config.replace(
            "config_file = \"/etc/materia/config.toml\"",
            &format!("config_file = \"{}\"", directory.path().join("materia.toml").display()),
        );
        assert_ne!(config, fixture_config, "the fixture names materia's configuration file");
        std::fs::write(directory.path().join("forma.toml"), config).unwrap();
        Self { directory }
    }

    fn forma(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_forma"))
            .args(arguments)
            .env_clear()
            .env("FORMA_CONFIG", self.directory.path().join("forma.toml"))
            .output()
            .unwrap()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The fixture's account joins `render`, which must exist on the host.
fn host_has_render_group() -> bool {
    Command::new("/usr/bin/getent")
        .args(["group", "render"])
        .output()
        .is_ok_and(|output| output.status.success())
}

#[test]
fn version_prints_the_version_and_a_commit() {
    let output = Command::new(env!("CARGO_BIN_EXE_forma"))
        .arg("version")
        .output()
        .unwrap();
    let line = text(&output.stdout);
    assert!(output.status.success());
    assert!(
        line.starts_with(&format!("forma {} (", env!("CARGO_PKG_VERSION"))),
        "{line}"
    );
}

#[test]
fn config_prints_each_value_with_its_source() {
    let host = Host::moonshine();
    let output = Command::new(env!("CARGO_BIN_EXE_forma"))
        .arg("config")
        .env_clear()
        .env("FORMA_CONFIG", host.directory.path().join("forma.toml"))
        .env("FORMA_SELINUX__PRIORITY", "360")
        .output()
        .unwrap();
    let printed = text(&output.stdout);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        printed.contains("selinux.priority = 360  (environment variable FORMA_SELINUX__PRIORITY)"),
        "{printed}"
    );
    assert!(printed.contains("base_images.host_policy = respect  ("), "{printed}");
    assert!(
        printed.contains("accounts.home_base = /var/home  (default)"),
        "{printed}"
    );
}

#[test]
fn plan_lists_the_steps_for_the_fixture_host() {
    if !host_has_render_group() {
        eprintln!("skipped: this host has no render group, which the fixture's account joins");
        return;
    }
    let host = Host::moonshine();
    let output = host.forma(&["plan"]);
    let printed = text(&output.stdout);
    assert!(printed.starts_with("Plan:\n1. "), "{printed}\n{}", text(&output.stderr));
    assert!(
        printed.contains("Create User moonshine (home /var/home/moonshine)"),
        "{printed}"
    );
    assert!(
        printed.contains("Write File /etc/forma/materia/moonshine.toml"),
        "{printed}"
    );
    assert!(printed.contains("component half-installed is skipped"), "{printed}");
    // The half-installed component makes the run fail as a whole, after the plan is printed.
    assert!(!output.status.success());

    let one = host.forma(&["plan", "nvidia-driver"]);
    let printed = text(&one.stdout);
    assert!(printed.contains("Create User moonshine"), "{printed}");
    assert!(!printed.contains("moonshine_steam_latest"), "{printed}");

    let json = host.forma(&["plan", "--format", "json"]);
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert!(value["steps"].as_array().is_some_and(|steps| !steps.is_empty()));
    assert_eq!(value["problems"].as_array().map(Vec::len), Some(0), "{value:#}");
}

#[test]
fn an_unknown_component_is_an_error() {
    if !host_has_render_group() {
        return;
    }
    let host = Host::moonshine();
    let output = host.forma(&["plan", "no-such-component"]);
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("component no-such-component is not installed"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn apply_without_plan_says_it_cannot_change_the_host_yet() {
    let host = Host::moonshine();
    for arguments in [&["apply"][..], &["revert", "moonshine"], &["purge"]] {
        let output = host.forma(arguments);
        assert!(!output.status.success());
        assert!(
            text(&output.stderr).contains("is not implemented yet"),
            "{}",
            text(&output.stderr)
        );
    }
}

#[test]
fn forma_refuses_to_run_in_a_container() {
    let host = Host::moonshine();
    let output = Command::new(env!("CARGO_BIN_EXE_forma"))
        .arg("config")
        .env_clear()
        .env("FORMA_CONFIG", host.directory.path().join("forma.toml"))
        .env("container", "podman")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("forma runs on the host only"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn a_broken_manifest_is_reported_with_its_error_name() {
    let host = Host::moonshine();
    let materia = host.directory.path().join("materia.toml");
    let broken = std::fs::read_to_string(&materia).unwrap().replace(
        &fixtures().join("valid/moonshine").display().to_string(),
        &fixtures()
            .join("invalid/repo-ignores-host-policy")
            .display()
            .to_string(),
    );
    std::fs::write(&materia, broken).unwrap();
    let output = host.forma(&["plan"]);
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("- HostOnlySetting: "),
        "{}",
        text(&output.stderr)
    );
}
