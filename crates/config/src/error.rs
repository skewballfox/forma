//! What can be wrong with a manifest.

use std::path::PathBuf;

use forma_user::id::IdError;
use forma_user::name::NameError;
use forma_user::path::PathError;
use thiserror::Error;

use crate::raw::{Origin, SyntaxError};

/// A manifest, or the set of manifests on a host, failed a check.
///
/// Each variant has a stable name, returned by [`ManifestError::code`]. The
/// fixtures in `tests/fixtures/invalid` name the variant they expect.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// A manifest could not be read.
    #[error("cannot read {}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// A manifest is not valid TOML.
    #[error(transparent)]
    Syntax(#[from] SyntaxError),
    /// One table holds two keys that differ only by case.
    #[error("{second}: key {second_key:?} differs only by case from {first_key:?} at {first}; keep one")]
    KeyCaseCollision {
        /// The first key.
        first: Origin,
        /// Its spelling.
        first_key: String,
        /// The second key.
        second: Origin,
        /// Its spelling.
        second_key: String,
    },
    /// A `[Forma]` table holds a key forma does not know.
    #[error("{at}: unknown key {key:?} in {table}")]
    UnknownKey {
        /// The key.
        at: Origin,
        /// Its spelling.
        key: String,
        /// The table that holds it.
        table: String,
    },
    /// A key is missing.
    #[error("{at}: {table} needs the key {key}")]
    MissingKey {
        /// The table.
        at: Origin,
        /// The table's name.
        table: String,
        /// The key.
        key: &'static str,
    },
    /// A value has the wrong TOML type.
    #[error("{at}: {key} must be {expected}, but it is {found}")]
    WrongType {
        /// The value.
        at: Origin,
        /// The key.
        key: String,
        /// The type forma needs.
        expected: &'static str,
        /// The type in the file.
        found: &'static str,
    },
    /// A value is not one forma accepts.
    #[error("{at}: {key} {message}")]
    InvalidValue {
        /// The value.
        at: Origin,
        /// The key.
        key: String,
        /// What is wrong, as the rest of a sentence that starts with the key.
        message: String,
    },
    /// The repository sets a value that only the host may set.
    #[error("{at}: {key} can only be set on the host, in forma's own configuration file")]
    HostOnlySetting {
        /// The key.
        at: Origin,
        /// Its name.
        key: String,
    },
    /// An account name is not a valid system user name.
    #[error("{at}: account name is not allowed: {source}")]
    InvalidAccountName {
        /// The value.
        at: Origin,
        /// The rule it breaks.
        source: NameError,
    },
    /// A group name is not a valid system group name.
    #[error("{at}: group name is not allowed: {source}")]
    InvalidGroupName {
        /// The value.
        at: Origin,
        /// The rule it breaks.
        source: NameError,
    },
    /// A component name is not one materia accepts.
    #[error("component name {name:?} is not allowed: {reason}")]
    InvalidComponentName {
        /// The name.
        name: String,
        /// The rule it breaks.
        reason: &'static str,
    },
    /// An image reference is not a local, lower-case, tagged reference.
    #[error("{at}: image reference {reference:?} is not allowed: {reason}")]
    InvalidImageRef {
        /// The value.
        at: Origin,
        /// The reference.
        reference: String,
        /// The rule it breaks.
        reason: &'static str,
    },
    /// A sub-ID count is out of range.
    #[error("{at}: {source}")]
    InvalidSubIdCount {
        /// The value.
        at: Origin,
        /// The rule it breaks.
        source: IdError,
    },
    /// A path inside a component leaves the component.
    #[error("{at}: path {path:?} leaves its component; use a relative path without '..'")]
    PathEscapesComponent {
        /// The value.
        at: Origin,
        /// The path.
        path: String,
    },
    /// A path is not written in its normal form.
    #[error("{at}: {source}")]
    InvalidPath {
        /// The value.
        at: Origin,
        /// The rule it breaks.
        source: PathError,
    },
    /// A host path is outside every root the host allows.
    #[error("{at}: path {path} is not under a root the host allows ({})", roots.join(", "))]
    PathNotAllowed {
        /// The value.
        at: Origin,
        /// The path.
        path: String,
        /// The roots the host allows.
        roots: Vec<String>,
    },
    /// A component's account and the account materia delegated it to differ.
    #[error("component {component}: {}", mismatch_text(account.as_deref(), user.as_deref()))]
    AccountUserMismatch {
        /// The component.
        component: String,
        /// The account in `[Forma.Account]`.
        account: Option<String>,
        /// The `User` materia recorded.
        user: Option<String>,
        /// The declaration, when there is one.
        at: Option<Origin>,
    },
    /// Two components declare the same account in different ways.
    #[error(
        "{second}: account {account} is declared differently by {second_component} than by \
         {first_component} at {first}; both declarations must match"
    )]
    AccountDeclarationConflict {
        /// The account.
        account: String,
        /// The first declaration.
        first: Box<Origin>,
        /// The component that holds it.
        first_component: String,
        /// The second declaration.
        second: Origin,
        /// The component that holds it.
        second_component: String,
    },
    /// Two components declare the same group in different ways.
    #[error(
        "{second}: group {group} is declared differently by {second_component} than by \
         {first_component} at {first}; both declarations must match"
    )]
    GroupDeclarationConflict {
        /// The group.
        group: String,
        /// The first declaration.
        first: Box<Origin>,
        /// The component that holds it.
        first_component: String,
        /// The second declaration.
        second: Origin,
        /// The component that holds it.
        second_component: String,
    },
    /// A component declares an account that the repository manifest
    /// declares under `[Forma.Accounts]`. Even an identical copy is refused,
    /// so the account has one place to change.
    #[error(
        "{second}: account {account} is declared in the repository manifest at {first}, so component \
         {component} must not declare it too; remove its [Forma.Account] and keep [Settings] User"
    )]
    AccountDeclaredTwice {
        /// The account.
        account: String,
        /// The declaration in the repository manifest.
        first: Box<Origin>,
        /// The component's declaration.
        second: Origin,
        /// The component.
        component: String,
    },
    /// A component declares a group that the repository manifest declares
    /// under `[Forma.Groups]`.
    #[error(
        "{second}: group {group} is declared in the repository manifest at {first}, so component \
         {component} must not declare it too; remove its [[Forma.Groups]] entry"
    )]
    GroupDeclaredTwice {
        /// The group.
        group: String,
        /// The declaration in the repository manifest.
        first: Box<Origin>,
        /// The component's declaration.
        second: Origin,
        /// The component.
        component: String,
    },
    /// Two declarations build the same image tag.
    #[error("{second}: image {image} is already declared by {first_component} at {first}")]
    ImageDeclarationConflict {
        /// The image.
        image: String,
        /// The first declaration.
        first: Origin,
        /// The component that holds it.
        first_component: String,
        /// The second declaration.
        second: Origin,
    },
    /// `MemberOf` names a group that does not exist and that forma does not create.
    #[error(
        "{at}: account {account} is to join group {group}, which does not exist on this host \
         and is declared neither under [Forma.Groups] nor under a component's [[Forma.Groups]]"
    )]
    MemberGroupMissing {
        /// The value.
        at: Origin,
        /// The account.
        account: String,
        /// The group.
        group: String,
    },
    /// `DependsOn` names an image no installed component builds.
    #[error("{at}: image {image} depends on {dependency}, which no installed component declares")]
    UnknownImageDependency {
        /// The value.
        at: Origin,
        /// The image.
        image: String,
        /// The image it names.
        dependency: String,
    },
    /// Images depend on each other in a circle.
    #[error("{at}: image {image} depends on itself, through {}", cycle.join(" -> "))]
    ImageDependencyCycle {
        /// The declaration of the first image in the circle.
        at: Origin,
        /// That image.
        image: String,
        /// The circle.
        cycle: Vec<String>,
    },
    /// A component that does not set `[Settings] User` declares an image.
    /// Forma builds images only for dedicated service accounts, and reads
    /// the Containerfile from the component's staged copy, which only a
    /// delegated component has.
    #[error(
        "{at}: component {component} declares image {image}, but sets no [Settings] User; \
         forma builds images only for components delegated to a service account"
    )]
    ImageWithoutUser {
        /// The declaration.
        at: Origin,
        /// The component.
        component: String,
        /// The image.
        image: String,
    },
    /// A component or the repository manifest declares the builder's or the
    /// signer's account as a service account.
    #[error("{at}: account {account} is forma's {role} account; it cannot be a service account")]
    ReservedAccount {
        /// The declaration.
        at: Origin,
        /// The account.
        account: String,
        /// `builder` or `signer`.
        role: &'static str,
    },
    /// A component ships SELinux modules and the host does not allow them.
    #[error("{at}: the host does not allow SELinux modules from the repository (selinux.allow_modules)")]
    SeLinuxModulesNotAllowed {
        /// The declaration.
        at: Origin,
    },
}

fn mismatch_text(account: Option<&str>, user: Option<&str>) -> String {
    match (account, user) {
        (Some(account), Some(user)) => format!(
            "[Forma.Account] names {account}, but materia delegated the component to {user}; \
             [Settings] User must name the same account"
        ),
        (Some(account), None) => format!(
            "[Forma.Account] names {account}, but materia recorded no User for the component, \
             so it installed the Quadlets as root; set [Settings] User = {account:?}"
        ),
        (None, Some(user)) => format!(
            "materia delegated the component to {user}, but neither the repository manifest's \
             [Forma.Accounts] nor an installed component's [Forma.Account] declares that account, \
             so nothing creates it"
        ),
        (None, None) => "account and User differ".to_owned(),
    }
}

impl ManifestError {
    /// Returns the variant's stable name, such as `KeyCaseCollision`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read { .. } => "Read",
            Self::Syntax(_) => "Syntax",
            Self::KeyCaseCollision { .. } => "KeyCaseCollision",
            Self::UnknownKey { .. } => "UnknownKey",
            Self::MissingKey { .. } => "MissingKey",
            Self::WrongType { .. } => "WrongType",
            Self::InvalidValue { .. } => "InvalidValue",
            Self::HostOnlySetting { .. } => "HostOnlySetting",
            Self::InvalidAccountName { .. } => "InvalidAccountName",
            Self::InvalidGroupName { .. } => "InvalidGroupName",
            Self::InvalidComponentName { .. } => "InvalidComponentName",
            Self::InvalidImageRef { .. } => "InvalidImageRef",
            Self::InvalidSubIdCount { .. } => "InvalidSubIdCount",
            Self::PathEscapesComponent { .. } => "PathEscapesComponent",
            Self::InvalidPath { .. } => "InvalidPath",
            Self::PathNotAllowed { .. } => "PathNotAllowed",
            Self::AccountUserMismatch { .. } => "AccountUserMismatch",
            Self::AccountDeclarationConflict { .. } => "AccountDeclarationConflict",
            Self::GroupDeclarationConflict { .. } => "GroupDeclarationConflict",
            Self::AccountDeclaredTwice { .. } => "AccountDeclaredTwice",
            Self::GroupDeclaredTwice { .. } => "GroupDeclaredTwice",
            Self::ImageDeclarationConflict { .. } => "ImageDeclarationConflict",
            Self::MemberGroupMissing { .. } => "MemberGroupMissing",
            Self::UnknownImageDependency { .. } => "UnknownImageDependency",
            Self::ImageDependencyCycle { .. } => "ImageDependencyCycle",
            Self::ImageWithoutUser { .. } => "ImageWithoutUser",
            Self::ReservedAccount { .. } => "ReservedAccount",
            Self::SeLinuxModulesNotAllowed { .. } => "SeLinuxModulesNotAllowed",
        }
    }
}
