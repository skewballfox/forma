//! Reads the bases of every image in the fixture repositories.

use std::path::{Path, PathBuf};

use forma_build::{BaseError, Bases, bases, require_trust};
use forma_config::testing::repository_components;
use forma_config::{Config, HostConfig, ImageUse, Inputs};
use forma_user::name::GroupName;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn host_groups(name: &GroupName) -> bool {
    name.as_str() == "render"
}

fn load(repository: &Path) -> Config {
    let limits = HostConfig::load(&fixtures().join("host/config.toml"), []).unwrap();
    forma_config::load(&Inputs {
        host: "forge",
        repository_manifest: &repository.join("MANIFEST.toml"),
        components: &repository_components(repository),
        limits: &limits,
        groups: &host_groups,
    })
    .unwrap()
}

/// What `forma plan` will do for each image: read its Containerfile, find
/// the bases, and check `Require`.
fn read(image: &ImageUse<'_>) -> Result<Bases, Vec<BaseError>> {
    let root = image.component.manifest.parent().unwrap();
    let text = std::fs::read_to_string(image.image.value.containerfile.under(root)).unwrap();
    let found = bases(&text, &image.image.value.build_args)?;
    require_trust(&found, &image.component.base_images)?;
    Ok(found)
}

#[test]
fn the_moonshine_images_pull_fedora_minimal_by_digest() {
    let config = load(&fixtures().join("valid/moonshine"));
    let fedora = "registry.fedoraproject.org/fedora-minimal:44@sha256:\
                  6f263feab9835fa01d3f8a944827da527aadbf1fee5ead10ad9b892b60d14608";
    let mut seen = Vec::new();
    for image in config.images() {
        let found = read(&image).unwrap_or_else(|errors| panic!("{}: {errors:?}", image.image.value.tag.short()));
        let remote: Vec<&str> = found.remote.iter().map(|base| base.reference.as_str()).collect();
        assert_eq!(remote, [fedora], "{}", image.image.value.tag.short());
        assert!(
            found
                .remote
                .iter()
                .all(|base| base.repository == "registry.fedoraproject.org/fedora-minimal")
        );
        let own: Vec<&str> = found.own.iter().map(|base| base.image.short()).collect();
        seen.push((image.image.value.tag.short().to_owned(), own.join(",")));
    }
    // The Steam image builds on the moonshine image, which it also lists in DependsOn.
    assert_eq!(
        seen,
        [
            ("moonshine/moonshine:patches".to_owned(), String::new()),
            ("moonshine/nvidia-driver:latest".to_owned(), String::new()),
            (
                "moonshine/steam:latest".to_owned(),
                "moonshine/moonshine:patches".to_owned()
            ),
        ]
    );
}

#[test]
fn the_invalid_fixtures_fail_with_the_error_they_name() {
    for fixture in ["unresolved-base-arg", "require-all-unlisted"] {
        let directory = fixtures().join("invalid").join(fixture);
        let expected = std::fs::read_to_string(directory.join("EXPECTED_ERROR")).unwrap();
        let config = load(&directory);
        let codes: Vec<&str> = config
            .images()
            .iter()
            .flat_map(|image| read(image).err().unwrap_or_default())
            .map(|error| error.code())
            .collect();
        assert_eq!(codes, [expected.trim()], "{fixture}");
    }
}
