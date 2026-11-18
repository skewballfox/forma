//! Reads and checks everything forma is told: the `[Forma]` tables in
//! materia's manifests, forma's host configuration, materia's own
//! configuration, and what materia installed.
//!
//! This library changes nothing on the host. See `docs/architecture.md`,
//! sections 2 and 5.2.
//!
//! # How the parts fit
//!
//! 1. [`HostConfig::load`] reads the limits only the host may set.
//! 2. [`MateriaConfig::load`] finds materia's directories and host name.
//! 3. [`installed::scan`] lists the components materia installed.
//! 4. [`load`] reads their manifests, merges the host's overrides and
//!    extensions, and checks the result as a whole.

mod error;
mod flat;
pub mod host;
pub mod installed;
mod manifest;
pub mod materia;
mod raw;
mod schema;
#[cfg(feature = "test-support")]
pub mod testing;
pub mod types;

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use forma_user::name::GroupName;

pub use error::ManifestError;
pub use flat::{ConfigError, Setting, Source};
pub use host::{HostConfig, HostPolicyMode};
pub use installed::{ComponentInput, Installed, InstalledPaths, SkipReason, Skipped};
pub use manifest::{
    Account, BaseImages, Builder, ComponentForma, GitSource, Group, Image, Located, ModuleKind, ModuleSource, SeLinux,
    Settings, Trust, TrustRule, Update,
};
pub use materia::{LockKind, MateriaConfig};
pub use raw::{Origin, SyntaxError};
use raw::{Table, Value};
use types::{AccountName, ComponentName, ImageRef};

/// Says which groups exist on the host.
///
/// [`load`] asks it for each `MemberOf` group that no component declares.
/// The binary answers through NSS; tests answer from a list.
pub trait GroupLookup {
    /// Says whether a group with this name exists.
    fn group_exists(&self, name: &GroupName) -> bool;
}

impl<F: Fn(&GroupName) -> bool> GroupLookup for F {
    fn group_exists(&self, name: &GroupName) -> bool {
        self(name)
    }
}

/// What [`load`] reads.
pub struct Inputs<'a> {
    /// This host's name, as materia resolved it.
    pub host: &'a str,
    /// The repository manifest in materia's source cache. A missing file is
    /// read as an empty manifest, with a warning.
    pub repository_manifest: &'a Path,
    /// The installed components.
    pub components: &'a [ComponentInput],
    /// The host's limits.
    pub limits: &'a HostConfig,
    /// The groups that exist on the host.
    pub groups: &'a dyn GroupLookup,
}

/// One installed component and what it declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// The component's name.
    pub name: ComponentName,
    /// The account materia delegated the component to.
    pub user: Option<AccountName>,
    /// Its `[Forma]` tables, after the host's overrides and extensions.
    pub forma: ComponentForma,
    /// The base image requirements of its builds: the host's and its own.
    pub base_images: BaseImages,
    /// Its installed `MANIFEST.toml`.
    pub manifest: PathBuf,
    /// Its staged copy, if it is delegated and staged.
    pub staged: Option<PathBuf>,
}

/// Something `forma plan` reports and that does not stop a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// The repository manifest is not in materia's source cache, so no
    /// host override, extension or repository-wide setting was applied.
    NoRepositoryManifest(PathBuf),
    /// The repository manifest has no table for this host.
    HostNotInRepository(String),
    /// The host overrides a component without repeating its `[Settings]`.
    /// A materia without the override fix then drops `User` and the
    /// lifecycle scripts (architecture 2.3).
    OverrideDropsSettings {
        /// The component.
        component: ComponentName,
        /// The override.
        at: Origin,
    },
    /// The host changes a component that is not installed.
    PatchForUnknownComponent {
        /// The name in the manifest.
        component: String,
        /// The override or extension.
        at: Origin,
    },
}

impl Warning {
    /// Returns the warning's stable name, such as `OverrideDropsSettings`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoRepositoryManifest(_) => "NoRepositoryManifest",
            Self::HostNotInRepository(_) => "HostNotInRepository",
            Self::OverrideDropsSettings { .. } => "OverrideDropsSettings",
            Self::PatchForUnknownComponent { .. } => "PatchForUnknownComponent",
        }
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRepositoryManifest(path) => write!(
                f,
                "{} does not exist, so no host override, extension or repository-wide [Forma] setting applies",
                path.display()
            ),
            Self::HostNotInRepository(host) => {
                write!(f, "the repository manifest has no [Hosts.{host}] table")
            }
            Self::OverrideDropsSettings { component, at } => write!(
                f,
                "{at}: the override for {component} has no [Settings] table, while the component has one; \
                 a materia without the override fix drops User and the lifecycle scripts. \
                 Use Extensions, or repeat [Settings] in the override"
            ),
            Self::PatchForUnknownComponent { component, at } => {
                write!(
                    f,
                    "{at}: {component} is not installed on this host, so this table changes nothing"
                )
            }
        }
    }
}

/// An account and the components that need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUse<'a> {
    /// The declaration: the repository manifest's, or the one every
    /// declaring component shares.
    pub account: &'a Located<Account>,
    /// The components that declare it, by name. Empty for an account the
    /// repository manifest declares.
    pub declared_by: Vec<&'a ComponentName>,
    /// The components materia delegated to it, by name.
    pub runs: Vec<&'a ComponentName>,
}

/// A group forma creates and the components that need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupUse<'a> {
    /// The declaration.
    pub group: &'a Located<Group>,
    /// The components that declare it, by name. Empty for a group the
    /// repository manifest declares.
    pub declared_by: Vec<&'a ComponentName>,
    /// The components that need an account that joins it, by name.
    pub joined_by: Vec<&'a ComponentName>,
}

/// An image and the component that declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageUse<'a> {
    /// The component.
    pub component: &'a Component,
    /// The declaration.
    pub image: &'a Located<Image>,
}

/// Everything forma is told about this host, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The host's name.
    pub host: String,
    /// Settings for the whole host.
    pub settings: Settings,
    /// The installed components, by name.
    pub components: Vec<Component>,
    /// What `forma plan` should report without stopping.
    pub warnings: Vec<Warning>,
}

impl Config {
    /// Returns one component.
    #[must_use]
    pub fn component(&self, name: &str) -> Option<&Component> {
        self.components.iter().find(|component| component.name.as_str() == name)
    }

    /// Returns each service account once, by name, with the components that need it.
    ///
    /// An account in the repository manifest is listed only when an
    /// installed component runs as it.
    #[must_use]
    pub fn accounts(&self) -> Vec<AccountUse<'_>> {
        let mut accounts: BTreeMap<&AccountName, AccountUse<'_>> = BTreeMap::new();
        for account in &self.settings.accounts {
            let name = &account.value.name;
            if self
                .components
                .iter()
                .any(|component| component.user.as_ref() == Some(name))
            {
                accounts.insert(
                    name,
                    AccountUse {
                        account,
                        declared_by: Vec::new(),
                        runs: Vec::new(),
                    },
                );
            }
        }
        for component in &self.components {
            if let Some(account) = &component.forma.account {
                accounts
                    .entry(&account.value.name)
                    .or_insert_with(|| AccountUse {
                        account,
                        declared_by: Vec::new(),
                        runs: Vec::new(),
                    })
                    .declared_by
                    .push(&component.name);
            }
        }
        for component in &self.components {
            if let Some(entry) = component.user.as_ref().and_then(|user| accounts.get_mut(user)) {
                entry.runs.push(&component.name);
            }
        }
        accounts.into_values().collect()
    }

    /// Returns each group forma creates once, by name, with the components that need it.
    ///
    /// A group in the repository manifest is listed only when an account
    /// that [`Config::accounts`] lists joins it.
    #[must_use]
    pub fn groups(&self) -> Vec<GroupUse<'_>> {
        let accounts = self.accounts();
        let joined_by = |name: &GroupName| -> Vec<&ComponentName> {
            let mut needs: Vec<&ComponentName> = accounts
                .iter()
                .filter(|used| used.account.value.member_of.iter().any(|group| group.value == *name))
                .flat_map(|used| used.declared_by.iter().chain(&used.runs).copied())
                .collect();
            needs.sort();
            needs.dedup();
            needs
        };
        let mut groups: BTreeMap<&GroupName, GroupUse<'_>> = BTreeMap::new();
        for group in &self.settings.groups {
            let needs = joined_by(&group.value.name);
            if !needs.is_empty() {
                groups.insert(
                    &group.value.name,
                    GroupUse {
                        group,
                        declared_by: Vec::new(),
                        joined_by: needs,
                    },
                );
            }
        }
        for component in &self.components {
            for group in &component.forma.groups {
                groups
                    .entry(&group.value.name)
                    .or_insert_with(|| GroupUse {
                        group,
                        declared_by: Vec::new(),
                        joined_by: joined_by(&group.value.name),
                    })
                    .declared_by
                    .push(&component.name);
            }
        }
        groups.into_values().collect()
    }

    /// Returns every image in build order: an image comes after the images
    /// it depends on, and otherwise in component and declaration order.
    #[must_use]
    pub fn images(&self) -> Vec<ImageUse<'_>> {
        let all: Vec<ImageUse<'_>> = self
            .components
            .iter()
            .flat_map(|component| {
                component
                    .forma
                    .images
                    .iter()
                    .map(move |image| ImageUse { component, image })
            })
            .collect();
        let mut ordered: Vec<ImageUse<'_>> = Vec::with_capacity(all.len());
        let mut remaining = all;
        // `load` has checked that dependencies exist and form no circle, so
        // each pass places at least one image.
        while !remaining.is_empty() {
            let placed =
                |tag: &ImageRef, ordered: &[ImageUse<'_>]| ordered.iter().any(|done| done.image.value.tag == *tag);
            let (ready, waiting): (Vec<_>, Vec<_>) = remaining.into_iter().partition(|candidate| {
                candidate
                    .image
                    .value
                    .depends_on
                    .iter()
                    .all(|dependency| placed(&dependency.value, &ordered))
            });
            if ready.is_empty() {
                ordered.extend(waiting);
                break;
            }
            ordered.extend(ready);
            remaining = waiting;
        }
        ordered
    }
}

fn read(path: &Path) -> Result<(String, Arc<Path>), ManifestError> {
    let text = std::fs::read_to_string(path).map_err(|source| ManifestError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    Ok((text, Arc::from(path)))
}

fn subtable<'a>(table: &'a Table, key: &str) -> Option<(&'a Table, &'a Origin)> {
    match table.get(key) {
        Some(raw::Node {
            value: Value::Table(inner),
            at,
        }) => Some((inner, at)),
        _ => None,
    }
}

/// The repository manifest, canonical, with this host's tables picked out.
struct Repository {
    global: Table,
    global_at: Origin,
    overrides: Table,
    extensions: Table,
}

fn repository(inputs: &Inputs<'_>, warnings: &mut Vec<Warning>) -> Result<Repository, ManifestError> {
    let path = inputs.repository_manifest;
    let (text, file) = match read(path) {
        Ok(read) => read,
        Err(ManifestError::Read { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            warnings.push(Warning::NoRepositoryManifest(path.to_path_buf()));
            (String::new(), Arc::from(path))
        }
        Err(error) => return Err(error),
    };
    let table = schema::canonical(&raw::parse(&text, &file)?, schema::REPOSITORY_FIELDS, false, "")?;
    let (mut global, mut global_at) = subtable(&table, "Forma").map_or_else(
        || (Table::default(), Origin::file(&file)),
        |(forma, at)| (forma.clone(), at.clone()),
    );
    let host = subtable(&table, "Hosts").and_then(|(hosts, _)| subtable(hosts, inputs.host));
    if host.is_none() && !text.is_empty() {
        warnings.push(Warning::HostNotInRepository(inputs.host.to_owned()));
    }
    let mut overrides = Table::default();
    let mut extensions = Table::default();
    if let Some((host, _)) = host {
        if let Some((host_forma, at)) = subtable(host, "Forma") {
            if global.entries.is_empty() {
                global_at = at.clone();
            }
            schema::extend(&mut global, host_forma, schema::GLOBAL_FORMA_FIELDS);
        }
        overrides = subtable(host, "Overrides").map_or_default(|(table, _)| table.clone());
        extensions = subtable(host, "Extensions").map_or_default(|(table, _)| table.clone());
    }
    Ok(Repository {
        global,
        global_at,
        overrides,
        extensions,
    })
}

fn component(
    input: &ComponentInput,
    repository: &Repository,
    inputs: &Inputs<'_>,
    warnings: &mut Vec<Warning>,
) -> Result<Component, ManifestError> {
    let (text, file) = read(&input.manifest)?;
    let table = schema::canonical(&raw::parse(&text, &file)?, schema::COMPONENT_FIELDS, false, "")?;
    let (mut forma, mut forma_at) = subtable(&table, "Forma").map_or_else(
        || (Table::default(), Origin::file(&file)),
        |(forma, at)| (forma.clone(), at.clone()),
    );

    // Materia's order: overrides replace, then extensions add.
    if let Some(entry) = repository.overrides.entry(input.name.as_str())
        && let Value::Table(patch) = &entry.node.value
    {
        if table.get("Settings").is_some() && patch.get("Settings").is_none() {
            warnings.push(Warning::OverrideDropsSettings {
                component: input.name.clone(),
                at: entry.key_at.clone(),
            });
        }
        if let Some((over, at)) = subtable(patch, "Forma") {
            if forma.entries.is_empty() {
                forma_at = at.clone();
            }
            schema::replace(&mut forma, over);
        }
    }
    if let Some((extension, at)) =
        subtable(&repository.extensions, input.name.as_str()).and_then(|(patch, _)| subtable(patch, "Forma"))
    {
        if forma.entries.is_empty() {
            forma_at = at.clone();
        }
        schema::extend(&mut forma, extension, schema::COMPONENT_FORMA_FIELDS);
    }

    let forma = manifest::component(&forma, &forma_at, &inputs.limits.allowed_roots.value)?;
    let user = input
        .user
        .as_deref()
        .map(|user| {
            AccountName::new(user).map_err(|source| ManifestError::InvalidAccountName {
                at: Origin::file(&Arc::from(input.manifest.with_file_name(".component_version"))),
                source,
            })
        })
        .transpose()?;
    if let Some(selinux) = forma
        .selinux
        .as_ref()
        .filter(|selinux| !selinux.value.modules.is_empty())
        && !inputs.limits.selinux_allow_modules.value
    {
        return Err(ManifestError::SeLinuxModulesNotAllowed { at: selinux.at.clone() });
    }
    Ok(Component {
        name: input.name.clone(),
        user,
        base_images: BaseImages::default(),
        forma,
        manifest: input.manifest.clone(),
        staged: input.staged.clone(),
    })
}

/// Reads the manifests of every installed component and checks the host's
/// configuration as a whole.
///
/// Errors in one component do not hide errors in another: `load` returns
/// every error it finds.
///
/// # Errors
///
/// Returns each [`ManifestError`] found. Per-component errors come first,
/// in component order, then the checks across components.
pub fn load(inputs: &Inputs<'_>) -> Result<Config, Vec<ManifestError>> {
    let mut warnings = Vec::new();
    let repository = repository(inputs, &mut warnings).map_err(|error| vec![error])?;
    let settings = manifest::settings(
        &repository.global,
        &repository.global_at,
        &inputs.limits.allowed_roots.value,
    )
    .map_err(|error| vec![error])?;

    let mut errors = Vec::new();
    let mut components = Vec::new();
    for input in inputs.components {
        match component(input, &repository, inputs, &mut warnings) {
            Ok(mut component) => {
                component.base_images = settings.base_images.with(&component.forma.base_images);
                components.push(component);
            }
            Err(error) => errors.push(error),
        }
    }
    components.sort_by(|a, b| a.name.cmp(&b.name));
    for patches in [&repository.overrides, &repository.extensions] {
        for entry in &patches.entries {
            if !inputs.components.iter().any(|input| input.name.as_str() == entry.key) {
                warnings.push(Warning::PatchForUnknownComponent {
                    component: entry.key.clone(),
                    at: entry.key_at.clone(),
                });
            }
        }
    }

    let config = Config {
        host: inputs.host.to_owned(),
        settings,
        components,
        warnings,
    };
    check(&config, inputs.groups, &mut errors);
    if errors.is_empty() { Ok(config) } else { Err(errors) }
}

/// The checks that need every component at once.
fn check(config: &Config, groups: &dyn GroupLookup, errors: &mut Vec<ManifestError>) {
    check_accounts(config, errors);
    check_groups(config, groups, errors);
    check_images(config, errors);
}

fn check_accounts(config: &Config, errors: &mut Vec<ManifestError>) {
    let reserved = |account: &Located<Account>, errors: &mut Vec<ManifestError>| {
        for (role, reserved) in [
            ("builder", &config.settings.builder.account),
            ("signer", &config.settings.signer),
        ] {
            if account.value.name == *reserved {
                errors.push(ManifestError::ReservedAccount {
                    at: account.at.clone(),
                    account: account.value.name.to_string(),
                    role,
                });
            }
        }
    };
    let repository: BTreeMap<&AccountName, &Located<Account>> = config
        .settings
        .accounts
        .iter()
        .map(|account| (&account.value.name, account))
        .collect();
    for account in repository.values() {
        reserved(account, errors);
    }
    let mut first: BTreeMap<&AccountName, (&Component, &Located<Account>)> = BTreeMap::new();
    for component in &config.components {
        let Some(account) = &component.forma.account else {
            continue;
        };
        let name = &account.value.name;
        reserved(account, errors);
        if let Some(declared) = repository.get(name) {
            errors.push(ManifestError::AccountDeclaredTwice {
                account: name.to_string(),
                first: Box::new(declared.at.clone()),
                second: account.at.clone(),
                component: component.name.to_string(),
            });
        }
        match first.get(name) {
            None => {
                first.insert(name, (component, account));
            }
            Some((first_component, first_account)) if *first_account != account => {
                errors.push(ManifestError::AccountDeclarationConflict {
                    account: name.to_string(),
                    first: Box::new(first_account.at.clone()),
                    first_component: first_component.name.to_string(),
                    second: account.at.clone(),
                    second_component: component.name.to_string(),
                });
            }
            Some(_) => {}
        }
        // The component's own account must be the one materia delegated it to.
        if component.user.as_ref() != Some(name) {
            errors.push(ManifestError::AccountUserMismatch {
                component: component.name.to_string(),
                account: Some(name.to_string()),
                user: component.user.as_ref().map(ToString::to_string),
                at: Some(account.at.clone()),
            });
        }
    }
    // A delegated component that declares nothing for forma is not forma's:
    // its account may be managed by hand or by another tool.
    for component in &config.components {
        if let (Some(user), None) = (&component.user, &component.forma.account)
            && !component.forma.is_empty()
            && !first.contains_key(user)
            && !repository.contains_key(user)
        {
            errors.push(ManifestError::AccountUserMismatch {
                component: component.name.to_string(),
                account: None,
                user: Some(user.to_string()),
                at: None,
            });
        }
    }
}

fn check_groups(config: &Config, groups: &dyn GroupLookup, errors: &mut Vec<ManifestError>) {
    let repository: BTreeMap<&GroupName, &Located<Group>> = config
        .settings
        .groups
        .iter()
        .map(|group| (&group.value.name, group))
        .collect();
    let mut first: BTreeMap<&GroupName, (&Component, &Located<Group>)> = BTreeMap::new();
    for component in &config.components {
        for group in &component.forma.groups {
            if let Some(declared) = repository.get(&group.value.name) {
                errors.push(ManifestError::GroupDeclaredTwice {
                    group: group.value.name.to_string(),
                    first: Box::new(declared.at.clone()),
                    second: group.at.clone(),
                    component: component.name.to_string(),
                });
            }
            match first.get(&group.value.name) {
                None => {
                    first.insert(&group.value.name, (component, group));
                }
                Some((first_component, first_group)) if *first_group != group => {
                    errors.push(ManifestError::GroupDeclarationConflict {
                        group: group.value.name.to_string(),
                        first: Box::new(first_group.at.clone()),
                        first_component: first_component.name.to_string(),
                        second: group.at.clone(),
                        second_component: component.name.to_string(),
                    });
                }
                Some(_) => {}
            }
        }
    }
    // Report a missing group once per account, not once per component.
    for account in config.accounts() {
        for group in &account.account.value.member_of {
            if !first.contains_key(&group.value)
                && !repository.contains_key(&group.value)
                && !groups.group_exists(&group.value)
            {
                errors.push(ManifestError::MemberGroupMissing {
                    at: group.at.clone(),
                    account: account.account.value.name.to_string(),
                    group: group.value.to_string(),
                });
            }
        }
    }
}

fn check_images(config: &Config, errors: &mut Vec<ManifestError>) {
    let mut first: BTreeMap<String, (&Component, &Located<Image>)> = BTreeMap::new();
    for component in &config.components {
        for image in &component.forma.images {
            if component.user.is_none() {
                errors.push(ManifestError::ImageWithoutUser {
                    at: image.at.clone(),
                    component: component.name.to_string(),
                    image: image.value.tag.to_string(),
                });
            }
            // Two tags that give one directory name would share a store directory.
            match first.get(&image.value.tag.dir_name()) {
                None => {
                    first.insert(image.value.tag.dir_name(), (component, image));
                }
                Some((first_component, first_image)) => errors.push(ManifestError::ImageDeclarationConflict {
                    image: image.value.tag.to_string(),
                    first: first_image.at.clone(),
                    first_component: first_component.name.to_string(),
                    second: image.at.clone(),
                }),
            }
        }
    }
    let by_tag: BTreeMap<&ImageRef, &Located<Image>> =
        first.values().map(|(_, image)| (&image.value.tag, *image)).collect();
    let mut unknown = false;
    for image in by_tag.values() {
        for dependency in &image.value.depends_on {
            if !by_tag.contains_key(&dependency.value) {
                unknown = true;
                errors.push(ManifestError::UnknownImageDependency {
                    at: dependency.at.clone(),
                    image: image.value.tag.to_string(),
                    dependency: dependency.value.to_string(),
                });
            }
        }
    }
    if unknown {
        return;
    }
    // Depth-first search. An image on the current path that is reached again closes a circle.
    let mut done: Vec<&ImageRef> = Vec::new();
    for start in by_tag.keys() {
        let mut path: Vec<&ImageRef> = Vec::new();
        if let Some(cycle) = find_cycle(start, &by_tag, &mut path, &mut done) {
            errors.push(ManifestError::ImageDependencyCycle {
                at: by_tag[cycle[0]].at.clone(),
                image: cycle[0].to_string(),
                cycle: cycle.iter().map(ToString::to_string).collect(),
            });
            return;
        }
    }
}

fn find_cycle<'a>(
    image: &'a ImageRef,
    by_tag: &BTreeMap<&'a ImageRef, &'a Located<Image>>,
    path: &mut Vec<&'a ImageRef>,
    done: &mut Vec<&'a ImageRef>,
) -> Option<Vec<&'a ImageRef>> {
    if let Some(start) = path.iter().position(|on_path| *on_path == image) {
        let mut cycle = path[start..].to_vec();
        cycle.push(image);
        return Some(cycle);
    }
    if done.contains(&image) {
        return None;
    }
    path.push(image);
    for dependency in &by_tag[image].value.depends_on {
        if let Some(cycle) = find_cycle(&dependency.value, by_tag, path, done) {
            return Some(cycle);
        }
    }
    path.pop();
    done.push(image);
    None
}
