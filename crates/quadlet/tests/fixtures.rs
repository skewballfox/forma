//! Runs the Quadlet checks on the fixture components.

use std::path::{Path, PathBuf};

use forma_quadlet::{Account, Code, Finding, check, images, read_staged};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn is_forma_image(reference: &str) -> bool {
    reference.starts_with("localhost/") && reference.contains(':')
}

fn findings(component: &Path) -> Vec<Finding> {
    let account = Account {
        is_forma_image: &is_forma_image,
        home: Some("/var/home/app"),
    };
    read_staged(component)
        .unwrap()
        .iter()
        .flat_map(|unit| check(&unit.as_unit_file(), &account))
        .collect()
}

#[test]
fn the_staged_moonshine_components_follow_every_rule() {
    let staged = fixtures().join("installed/moonshine/delegate/accounts/moonshine/components");
    for component in ["moonshine", "nvidia-driver"] {
        assert_eq!(findings(&staged.join(component)), [], "{component}");
    }
}

#[test]
fn forma_finds_the_images_a_component_runs_from_its_quadlets() {
    let staged = fixtures().join("installed/moonshine/delegate/accounts/moonshine/components");
    let found = |component: &str| -> Vec<String> {
        read_staged(&staged.join(component))
            .unwrap()
            .iter()
            .flat_map(|unit| images(&unit.as_unit_file()))
            .map(|image| format!("{} in {}", image.reference, image.file))
            .collect()
    };
    assert_eq!(
        found("moonshine"),
        ["localhost/moonshine/moonshine:patches in moonshine.container"]
    );
    // A forma image used as a volume counts; the plain volumes do not.
    assert_eq!(
        found("nvidia-driver"),
        ["localhost/moonshine/nvidia-driver:latest in nvidia-driver.volume"]
    );
}

#[test]
fn only_units_are_read_from_a_staged_copy() {
    let staged = fixtures().join("installed/moonshine/delegate/accounts/moonshine/components/moonshine");
    let names: Vec<String> = read_staged(&staged)
        .unwrap()
        .into_iter()
        .map(|unit| unit.name)
        .collect();
    assert_eq!(
        names,
        [
            "moonshine-bus-proxy.service",
            "moonshine-bus.volume",
            "moonshine-x11.volume",
            "moonshine.container"
        ]
    );
}

#[test]
fn the_invalid_fixtures_break_the_rule_they_name() {
    for (fixture, expected) in [
        ("pull-allowed", Code::PullNotDisabled),
        ("templated-quadlet-key", Code::TemplatedQuadletKey),
    ] {
        let directory = fixtures().join("invalid").join(fixture);
        let named = std::fs::read_to_string(directory.join("EXPECTED_ERROR")).unwrap();
        assert_eq!(named.trim(), expected.as_str());
        let codes: Vec<Code> = findings(&directory.join("components/app"))
            .into_iter()
            .map(|finding| finding.code)
            .collect();
        assert_eq!(codes, [expected], "{fixture}");
    }
}
