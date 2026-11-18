//! Runs `forma_config::load` on the fixture repositories and on the
//! installed-state fixture.

use std::path::{Path, PathBuf};

use forma_config::installed::{self, InstalledPaths};
use forma_config::testing::repository_components;
use forma_config::types::{BaseRequirement, SigningBackend, Trigger};
use forma_config::{Config, HostConfig, Inputs, ManifestError, TrustRule};
use forma_user::name::GroupName;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn limits() -> HostConfig {
    HostConfig::load(&fixtures().join("host/config.toml"), []).unwrap()
}

/// The groups on the pretend host: `render` exists, as on Fedora.
fn host_groups(name: &GroupName) -> bool {
    name.as_str() == "render"
}

fn load_repository(repository: &Path) -> Result<Config, Vec<ManifestError>> {
    let components = repository_components(repository);
    forma_config::load(&Inputs {
        host: "forge",
        repository_manifest: &repository.join("MANIFEST.toml"),
        components: &components,
        limits: &limits(),
        groups: &host_groups,
    })
}

/// The errors `forma-config` owns. Fixtures that expect another error are
/// checked by the library that owns it, and must load cleanly here.
const CONFIG_ERRORS: &[&str] = &[
    "AccountUserMismatch",
    "InvalidAccountName",
    "KeyCaseCollision",
    "AccountDeclarationConflict",
    "PathEscapesComponent",
    "HostOnlySetting",
    "MemberGroupMissing",
    "ImageWithoutUser",
    "AccountDeclaredTwice",
    "GroupDeclaredTwice",
    "ReservedAccount",
];

#[test]
fn every_invalid_fixture_fails_with_the_error_it_names() {
    let mut checked = 0;
    let mut directories: Vec<PathBuf> = std::fs::read_dir(fixtures().join("invalid"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    directories.sort();
    for directory in directories {
        let expected = std::fs::read_to_string(directory.join("EXPECTED_ERROR")).unwrap();
        let expected = expected.trim();
        let result = load_repository(&directory);
        if CONFIG_ERRORS.contains(&expected) {
            let errors = result.expect_err(&format!("{} must be refused", directory.display()));
            let codes: Vec<&str> = errors.iter().map(ManifestError::code).collect();
            assert!(
                codes.contains(&expected),
                "{}: expected {expected}, got {codes:?}",
                directory.display()
            );
            checked += 1;
        } else if let Err(errors) = result {
            let messages: Vec<String> = errors.iter().map(ToString::to_string).collect();
            panic!(
                "{}: expects {expected} from another library, but failed here: {messages:#?}",
                directory.display()
            );
        }
    }
    assert_eq!(checked, 13, "every fixture that names a forma-config error was run");
}

#[test]
fn errors_point_at_the_file_and_line() {
    let errors = load_repository(&fixtures().join("invalid/case-collision")).unwrap_err();
    let message = errors[0].to_string();
    assert!(message.contains("components/app/MANIFEST.toml:5:1"), "{message}");
    assert!(message.contains("MANIFEST.toml:4:1"), "{message}");

    let errors = load_repository(&fixtures().join("invalid/unknown-member-group")).unwrap_err();
    assert!(errors[0].to_string().contains("MANIFEST.toml:8:13"), "{}", errors[0]);
}

#[test]
fn the_moonshine_repository_loads() {
    let config = load_repository(&fixtures().join("valid/moonshine")).unwrap();
    check_moonshine(&config);
}

#[test]
fn the_installed_moonshine_host_loads_the_same() {
    let base = fixtures().join("installed/moonshine");
    let paths = InstalledPaths {
        components_dir: base.join("data"),
        quadlet_dir: base.join("quadlets"),
        delegate_dir: base.join("delegate"),
    };
    let installed = installed::scan(&paths).unwrap();
    let config = forma_config::load(&Inputs {
        host: "forge",
        // Materia's source cache holds the repository the host was installed from.
        repository_manifest: &fixtures().join("valid/moonshine/MANIFEST.toml"),
        components: &installed.components,
        limits: &limits(),
        groups: &host_groups,
    })
    .unwrap();
    check_moonshine(&config);
    for component in &config.components {
        assert!(
            component
                .staged
                .as_ref()
                .unwrap()
                .join(format!("{}.volume", component.name))
                .exists()
                || component.staged.as_ref().unwrap().join("moonshine.container").exists()
        );
    }
}

fn check_moonshine(config: &Config) {
    // [Hosts.forge.Forma] Signing = "tpm" wins over [Forma] Signing = "auto".
    assert_eq!(config.settings.signing, SigningBackend::Tpm);
    assert_eq!(config.settings.builder.account.as_str(), "forma-build");
    assert_eq!(config.settings.builder.sub_ids.get(), 65536);
    assert_eq!(config.settings.signer.as_str(), "forma-sign");
    assert_eq!(config.settings.store_root.to_string(), "/var/lib/forma/store");
    assert_eq!(config.settings.base_images.require, BaseRequirement::Listed);
    let trust = &config.settings.base_images.trust;
    assert_eq!(trust.len(), 2);
    assert_eq!(trust[0].value.scope.as_str(), "registry.fedoraproject.org");
    assert!(
        matches!(&trust[0].value.rule, TrustRule::SigstoreKey { key } if key.to_string() == "trust/fedora-registry.pub")
    );
    assert!(
        matches!(&trust[1].value.rule, TrustRule::SigstoreKeyless { issuer, .. } if issuer == "https://accounts.google.com")
    );

    let names: Vec<&str> = config
        .components
        .iter()
        .map(|component| component.name.as_str())
        .collect();
    assert_eq!(names, ["moonshine", "nvidia-driver"]);

    // One shared account, declared once by the repository and running both.
    // The repository's backup account runs nothing here, so it is left out.
    assert_eq!(config.settings.accounts.len(), 2);
    let accounts = config.accounts();
    assert_eq!(accounts.len(), 1);
    let account = &accounts[0];
    assert_eq!(account.account.value.name.as_str(), "moonshine");
    assert!(account.account.value.home && account.account.value.linger);
    let member_of: Vec<&str> = account
        .account
        .value
        .member_of
        .iter()
        .map(|group| group.value.as_str())
        .collect();
    assert_eq!(member_of, ["moonshine-input", "render"]);
    assert_eq!(account.declared_by.len(), 0, "the repository declares it");
    assert_eq!(account.runs.len(), 2);

    // backup-readers is joined only by the unused backup account.
    let groups = config.groups();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].group.value.name.as_str(), "moonshine-input");
    assert!(groups[0].group.value.system);
    assert_eq!(groups[0].declared_by.len(), 0, "the repository declares it");
    assert_eq!(groups[0].joined_by.len(), 2);

    // The override replaces nvidia-driver's whole Images list for this host.
    let driver = config.component("nvidia-driver").unwrap();
    assert_eq!(driver.forma.images.len(), 1);
    let driver_image = &driver.forma.images[0].value;
    assert_eq!(driver_image.build_args.values().collect::<Vec<_>>(), ["580.105.08"]);
    assert_eq!(
        driver_image.update,
        forma_config::Update::default(),
        "the replaced list has no Update"
    );
    assert!(driver_image.at_host_manifest(&driver.forma.images[0].at));

    // The extension adds a component-level Update. Images with their own keep them.
    let moonshine = config.component("moonshine").unwrap();
    let patches = &moonshine.forma.images[0].value;
    assert_eq!(patches.update.schedule.as_ref().unwrap().as_str(), "daily");
    assert_eq!(
        patches.update.triggers.iter().copied().collect::<Vec<_>>(),
        [Trigger::BaseDigest, Trigger::GitRef]
    );
    assert_eq!(
        patches.source.as_ref().unwrap().commit_arg.as_ref().unwrap().as_str(),
        "MOONSHINE_COMMIT"
    );
    let steam = &moonshine.forma.images[1].value;
    assert_eq!(steam.update.schedule.as_ref().unwrap().as_str(), "Sun *-*-* 04:00:00");
    assert_eq!(
        steam.update.triggers.iter().copied().collect::<Vec<_>>(),
        [Trigger::Schedule]
    );

    let selinux = &moonshine.forma.selinux.as_ref().unwrap().value;
    assert_eq!(selinux.modules.len(), 3);
    assert_eq!(selinux.templates, ["base_container", "net_container"]);
    assert_eq!(selinux.relabel[0].value.to_string(), "/etc/moonshine");

    // Build order: steam depends on moonshine's image.
    let order: Vec<&str> = config
        .images()
        .iter()
        .map(|used| used.image.value.tag.short())
        .collect();
    assert_eq!(
        order,
        [
            "moonshine/moonshine:patches",
            "moonshine/nvidia-driver:latest",
            "moonshine/steam:latest"
        ]
    );

    // The override has no [Settings]: reported, not fatal.
    let codes: Vec<&str> = config.warnings.iter().map(forma_config::Warning::code).collect();
    assert_eq!(codes, ["OverrideDropsSettings"]);
    assert_eq!(moonshine.base_images, config.settings.base_images);
}

trait FromHostManifest {
    fn at_host_manifest(&self, at: &forma_config::Origin) -> bool;
}

impl FromHostManifest for forma_config::Image {
    /// The image was declared by the repository manifest, not the component's.
    fn at_host_manifest(&self, at: &forma_config::Origin) -> bool {
        at.file
            .parent()
            .is_some_and(|parent| !parent.ends_with("nvidia-driver"))
    }
}

#[test]
fn components_can_share_an_account_they_each_declare() {
    let config = load_repository(&fixtures().join("valid/shared-component-account")).unwrap();
    assert_eq!(config.settings.accounts.len(), 0);
    let accounts = config.accounts();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].account.value.name.as_str(), "svc");
    assert_eq!(accounts[0].declared_by.len(), 2);
    assert_eq!(accounts[0].runs.len(), 2);
    let groups = config.groups();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].declared_by.len(), 2);
    assert_eq!(groups[0].joined_by.len(), 2);
}

#[test]
fn a_repository_account_needs_no_declaration_in_the_component() {
    let errors = load_repository(&fixtures().join("invalid/account-declared-twice")).unwrap_err();
    let message = errors[0].to_string();
    assert!(message.contains("components/app/MANIFEST.toml"), "{message}");
    assert!(
        message.contains("[Forma.Accounts]") || message.contains("repository manifest"),
        "{message}"
    );
}

#[test]
fn a_delegated_component_without_forma_tables_is_left_alone() {
    let config = load_repository(&fixtures().join("valid/unmanaged-account")).unwrap();
    let accounts = config.accounts();
    assert_eq!(accounts.len(), 1, "only the account forma declares");
    assert_eq!(accounts[0].account.value.name.as_str(), "app");
    assert_eq!(config.component("legacy").unwrap().user.as_ref().unwrap().as_str(), "alice");
}

#[test]
fn lower_case_keys_work_as_in_materia() {
    let config = load_repository(&fixtures().join("valid/lowercase-keys")).unwrap();
    let app = config.component("app").unwrap();
    let account = &app.forma.account.as_ref().unwrap().value;
    assert_eq!(account.name.as_str(), "app");
    assert!(account.linger, "the lower-case extension applied");
    assert_eq!(app.user.as_ref().unwrap().as_str(), "app");
    assert!(config.warnings.is_empty(), "{:?}", config.warnings);
}
