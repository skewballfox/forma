//! Checked values from the repository.
//!
//! Every name and path a manifest holds passes through one of these types
//! before any other library sees it (architecture 5.2 and 7, rule 2). None
//! has a public constructor other than its checked one.

use std::fmt;
use std::path::{Component as PathPart, Path};

use forma_user::name::{GroupName, NameError, UserName};
use forma_user::path::{AbsPath, PathError, RelPath};

pub use forma_user::id::SubIdCount;

/// The name of a service account, or of the builder or signer.
///
/// It matches `[a-z_][a-z0-9_-]{0,31}` and is not `root`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountName(UserName);

impl AccountName {
    /// Checks an account name.
    ///
    /// # Errors
    ///
    /// Returns the [`NameError`] that says which rule the name breaks.
    pub fn new(name: impl Into<String>) -> Result<Self, NameError> {
        UserName::new(name).map(Self)
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Returns the name as the type `forma-user` takes.
    #[must_use]
    pub fn as_user_name(&self) -> &UserName {
        &self.0
    }

    /// Returns the name of the group `useradd -U` creates for the account.
    #[must_use]
    pub fn primary_group(&self) -> GroupName {
        GroupName::new(self.as_str()).unwrap_or_else(|_| unreachable!("user and group names share one rule"))
    }
}

impl fmt::Display for AccountName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The name of a materia component, with its instance if it has one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComponentName(String);

impl ComponentName {
    /// Checks a component name by materia's rules (`ValidateComponentName`),
    /// and by one more: the name must be a single, plain directory name.
    ///
    /// # Errors
    ///
    /// Returns the rule the name breaks.
    pub fn new(name: impl Into<String>) -> Result<Self, &'static str> {
        let name = name.into();
        let reason = if name.is_empty() {
            "it is empty"
        } else if name.contains('/') {
            "it holds '/'"
        } else if name.contains('.') {
            "it holds '.'"
        } else if name.matches('@').count() > 1 {
            "it holds more than one '@'"
        } else if name.starts_with('@') {
            "it has no name before '@'"
        } else if name.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
            "it holds a space or a control character"
        } else if name.starts_with('-') {
            "it starts with '-'"
        } else {
            return Ok(Self(name));
        };
        Err(reason)
    }

    /// Returns the whole name, with the instance.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the name without the instance.
    #[must_use]
    pub fn base(&self) -> &str {
        self.0.split_once('@').map_or(&self.0, |(base, _)| base)
    }

    /// Returns the instance: the part after `@`, when it is not empty.
    #[must_use]
    pub fn instance(&self) -> Option<&str> {
        self.0
            .split_once('@')
            .map(|(_, instance)| instance)
            .filter(|instance| !instance.is_empty())
    }
}

impl fmt::Display for ComponentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A reference to an image forma builds: `localhost/<name>:<tag>`.
///
/// A manifest may leave `localhost/` out. The reference is lower case, has a
/// tag and has no digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImageRef(String);

const LOCALHOST: &str = "localhost/";

impl ImageRef {
    /// Checks an image reference, with or without `localhost/`.
    ///
    /// # Errors
    ///
    /// Returns the rule the reference breaks.
    pub fn new(reference: &str) -> Result<Self, &'static str> {
        let rest = reference.strip_prefix(LOCALHOST).unwrap_or(reference);
        if rest.contains('@') {
            return Err("it has a digest; forma images are named by tag");
        }
        let Some((name, tag)) = rest.rsplit_once(':') else {
            return Err("it has no tag");
        };
        if name.is_empty() || name.split('/').any(|part| !valid_name_part(part)) {
            return Err(
                "its name must be lower-case parts of a-z, 0-9, '.', '_' and '-', separated by '/', \
                 each starting and ending with a letter or digit",
            );
        }
        // A first part with a dot or a port would be read as a registry.
        let first = name.split('/').next().unwrap_or_default();
        if name.contains('/') && (first.contains('.') || first == "localhost") {
            return Err("it names a registry; forma images live under localhost/ only");
        }
        let tag_ok = !tag.is_empty()
            && tag.len() <= 128
            && tag.starts_with(|ch: char| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
            && tag
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '.' | '-'));
        if !tag_ok {
            return Err("its tag must be lower-case a-z, 0-9, '_', '.' and '-', at most 128 characters");
        }
        Ok(Self(format!("{LOCALHOST}{rest}")))
    }

    /// Returns the full reference, such as `localhost/moonshine/steam:latest`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the reference without `localhost/`, such as `moonshine/steam:latest`.
    #[must_use]
    pub fn short(&self) -> &str {
        &self.0[LOCALHOST.len()..]
    }

    /// Returns a name for the image that is one safe directory name, such
    /// as `moonshine_steam_latest`. Two different references can give the
    /// same name; [`crate::Config`] refuses a host where they do.
    #[must_use]
    pub fn dir_name(&self) -> String {
        self.short().replace(['/', ':'], "_")
    }
}

fn valid_name_part(part: &str) -> bool {
    let edge = |ch: char| ch.is_ascii_lowercase() || ch.is_ascii_digit();
    part.starts_with(edge) && part.ends_with(edge) && part.chars().all(|ch| edge(ch) || matches!(ch, '.' | '_' | '-'))
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a path inside a component was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentPathError {
    /// The path is absolute or holds `..`, so it can leave the component.
    Escapes,
    /// The path is not in its normal form.
    Invalid(PathError),
}

/// A path inside a component: relative, normalised, without `..`.
///
/// `.` alone is allowed and names the component's own directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComponentPath(Option<RelPath>);

impl ComponentPath {
    /// Checks a path inside a component.
    ///
    /// # Errors
    ///
    /// Returns [`ComponentPathError::Escapes`] for an absolute path or one
    /// with `..`, and [`ComponentPathError::Invalid`] for any other path
    /// that is not normal.
    pub fn new(path: &str) -> Result<Self, ComponentPathError> {
        if path == "." {
            return Ok(Self(None));
        }
        let as_path = Path::new(path);
        if as_path.is_absolute() || as_path.components().any(|part| part == PathPart::ParentDir) {
            return Err(ComponentPathError::Escapes);
        }
        RelPath::new(path)
            .map(|rel| Self(Some(rel)))
            .map_err(ComponentPathError::Invalid)
    }

    /// Returns the path, or `None` for the component's own directory.
    #[must_use]
    pub fn as_rel(&self) -> Option<&RelPath> {
        self.0.as_ref()
    }

    /// Returns the path below `base`.
    #[must_use]
    pub fn under(&self, base: &Path) -> std::path::PathBuf {
        match &self.0 {
            Some(rel) => base.join(rel.as_path()),
            None => base.to_path_buf(),
        }
    }
}

impl fmt::Display for ComponentPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(rel) => rel.fmt(f),
            None => f.write_str("."),
        }
    }
}

/// An absolute host path under a root the host allows.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostPath(AbsPath);

impl HostPath {
    /// Checks a host path against the allowed roots.
    ///
    /// # Errors
    ///
    /// Returns `Err(Some(error))` if the path is not absolute and normal,
    /// and `Err(None)` if it is under none of `roots`.
    pub fn new(path: &str, roots: &[AbsPath]) -> Result<Self, Option<PathError>> {
        let path = AbsPath::new(path).map_err(Some)?;
        if roots.iter().any(|root| path.is_under(root)) {
            Ok(Self(path))
        } else {
            Err(None)
        }
    }

    /// Returns the path.
    #[must_use]
    pub fn as_abs(&self) -> &AbsPath {
        &self.0
    }
}

impl fmt::Display for HostPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A systemd `OnCalendar=` value that passed a basic check.
///
/// The check keeps the value on one line and out of other unit settings.
/// `forma apply` checks the syntax itself with `systemd-analyze calendar`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CalendarSpec(String);

impl CalendarSpec {
    /// Checks a calendar value.
    ///
    /// # Errors
    ///
    /// Returns the rule the value breaks.
    pub fn new(spec: &str) -> Result<Self, &'static str> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err("is empty");
        }
        if spec.len() > 256 {
            return Err("is longer than 256 bytes");
        }
        let allowed = |ch: char| {
            ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '*' | ':' | '/' | ',' | '.' | '~' | '-' | '+' | '_')
        };
        if !spec.chars().all(allowed) {
            return Err("may hold only letters, digits, spaces and the characters * : / , . ~ - + _");
        }
        Ok(Self(spec.to_owned()))
    }

    /// Returns the value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CalendarSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What can start a rebuild of an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Trigger {
    /// A base image's remote digest changed. Written `base-digest`.
    BaseDigest,
    /// The Git reference of the image's source moved. Written `git-ref`.
    GitRef,
    /// The timer fired. Written `schedule`.
    Schedule,
}

impl Trigger {
    /// Reads a trigger as a manifest writes it.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "base-digest" => Some(Self::BaseDigest),
            "git-ref" => Some(Self::GitRef),
            "schedule" => Some(Self::Schedule),
            _ => None,
        }
    }

    /// Returns the trigger as a manifest writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseDigest => "base-digest",
            Self::GitRef => "git-ref",
            Self::Schedule => "schedule",
        }
    }
}

/// Which kind of key signs images.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SigningBackend {
    /// A key held in the TPM. Written `tpm`.
    Tpm,
    /// A key in a file. Written `software`.
    Software,
    /// The TPM if the host has a usable one, otherwise a file. Written `auto`.
    #[default]
    Auto,
}

impl SigningBackend {
    /// Reads a backend as a manifest writes it.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "tpm" => Some(Self::Tpm),
            "software" => Some(Self::Software),
            "auto" => Some(Self::Auto),
            _ => None,
        }
    }

    /// Returns the backend as a manifest writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::Software => "software",
            Self::Auto => "auto",
        }
    }
}

/// How many base images need a `Trust` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum BaseRequirement {
    /// No requirement beyond the host policy. Written `none`.
    #[default]
    None,
    /// A base image that matches a `Trust` entry must satisfy it. Written `listed`.
    Listed,
    /// Every base image must match a `Trust` entry and satisfy it. Written `all`.
    All,
}

impl BaseRequirement {
    /// Reads a requirement as a manifest writes it.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "none" => Some(Self::None),
            "listed" => Some(Self::Listed),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

/// The part of the registry name space a `Trust` entry covers: a registry
/// host with an optional port, then optional path parts. No tag and no
/// digest, because a scope matches every tag.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustScope(String);

impl TrustScope {
    /// Checks a scope.
    ///
    /// # Errors
    ///
    /// Returns the rule the scope breaks.
    pub fn new(scope: &str) -> Result<Self, &'static str> {
        if scope.contains('@') {
            return Err("must not hold a digest");
        }
        let mut parts = scope.split('/');
        let host = parts.next().unwrap_or_default();
        let (name, port) = host
            .split_once(':')
            .map_or((host, None), |(name, port)| (name, Some(port)));
        let host_ok = !name.is_empty()
            && name.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .chars()
                        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
            });
        if !host_ok {
            return Err("must start with a lower-case registry host name");
        }
        if name == "localhost" {
            return Err("must name a remote registry; forma's own images need no entry");
        }
        if port.is_some_and(|port| port.is_empty() || port.len() > 5 || !port.chars().all(|ch| ch.is_ascii_digit())) {
            return Err("has a port that is not a number");
        }
        for part in parts {
            if part.contains(':') {
                return Err("must not hold a tag");
            }
            if !valid_name_part(part) {
                return Err("has a path part that is not a lower-case repository name");
            }
        }
        Ok(Self(scope.to_owned()))
    }

    /// Returns the scope.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Says whether the scope covers `repository`, a reference without tag
    /// or digest such as `quay.io/fedora/fedora`.
    #[must_use]
    pub fn covers(&self, repository: &str) -> bool {
        repository
            .strip_prefix(self.0.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    }
}

impl fmt::Display for TrustScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of a build argument: `[A-Za-z_][A-Za-z0-9_]*`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BuildArgName(String);

impl BuildArgName {
    /// Checks a build argument name.
    ///
    /// # Errors
    ///
    /// Returns the rule the name breaks.
    pub fn new(name: &str) -> Result<Self, &'static str> {
        let ok = name.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_')
            && name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if ok {
            Ok(Self(name.to_owned()))
        } else {
            Err("must be a name of letters, digits and '_'")
        }
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BuildArgName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_references_are_local_lower_case_and_tagged() {
        let image = ImageRef::new("moonshine/steam:latest").unwrap();
        assert_eq!(image.as_str(), "localhost/moonshine/steam:latest");
        assert_eq!(image.short(), "moonshine/steam:latest");
        assert_eq!(image.dir_name(), "moonshine_steam_latest");
        assert_eq!(ImageRef::new("localhost/moonshine/steam:latest").unwrap(), image);
        assert_eq!(ImageRef::new("app:1.2_x-y").unwrap().as_str(), "localhost/app:1.2_x-y");

        for bad in [
            "moonshine/steam",
            "Moonshine/steam:latest",
            "moonshine/steam:Latest",
            "docker.io/library/alpine:3",
            "localhost/localhost/x:1",
            "a//b:1",
            "/a:1",
            "a/:1",
            "a:",
            "a@sha256:00:1",
            "a b:1",
            "-a:1",
            "a:-1",
        ] {
            assert!(ImageRef::new(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn component_names_follow_materia() {
        let name = ComponentName::new("app@blue").unwrap();
        assert_eq!((name.base(), name.instance()), ("app", Some("blue")));
        assert_eq!(ComponentName::new("app").unwrap().instance(), None);
        for bad in ["", "a/b", "..", "a.b", "a@b@c", "@b", "a b", "-a"] {
            assert!(ComponentName::new(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn component_paths_cannot_leave_the_component() {
        assert_eq!(ComponentPath::new(".").unwrap().as_rel(), None);
        assert_eq!(
            ComponentPath::new("build/x.Dockerfile").unwrap().to_string(),
            "build/x.Dockerfile"
        );
        assert_eq!(
            ComponentPath::new("build").unwrap().under(Path::new("/c")),
            Path::new("/c/build")
        );
        for escape in ["../../MANIFEST.toml", "/etc/shadow", "a/../../b", ".."] {
            assert_eq!(ComponentPath::new(escape), Err(ComponentPathError::Escapes), "{escape}");
        }
        for invalid in ["", "a//b", "a/", "./a", "a/./b"] {
            assert!(
                matches!(ComponentPath::new(invalid), Err(ComponentPathError::Invalid(_))),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn host_paths_stay_under_an_allowed_root() {
        let roots = [
            AbsPath::new("/var/lib/forma").unwrap(),
            AbsPath::new("/etc/moonshine").unwrap(),
        ];
        assert!(HostPath::new("/var/lib/forma/store", &roots).is_ok());
        assert!(HostPath::new("/etc/moonshine", &roots).is_ok());
        assert_eq!(HostPath::new("/var/lib/formal", &roots), Err(None));
        assert_eq!(HostPath::new("/etc", &roots), Err(None));
        assert!(matches!(HostPath::new("/var/lib/forma/../x", &roots), Err(Some(_))));
        assert!(matches!(HostPath::new("store", &roots), Err(Some(_))));
    }

    #[test]
    fn calendar_values_stay_on_one_line() {
        assert_eq!(
            CalendarSpec::new(" Sun *-*-* 04:00:00 ").unwrap().as_str(),
            "Sun *-*-* 04:00:00"
        );
        assert!(CalendarSpec::new("daily").is_ok());
        assert!(CalendarSpec::new("Mon..Fri *-*-1/2 00:00:00 Europe/Berlin").is_ok());
        for bad in ["", "daily\nExecStart=/bin/sh", "daily; x", "a=b", "%h"] {
            assert!(CalendarSpec::new(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn trust_scopes_name_a_registry_and_no_tag() {
        let scope = TrustScope::new("quay.io/fedora").unwrap();
        assert!(scope.covers("quay.io/fedora"));
        assert!(scope.covers("quay.io/fedora/fedora-minimal"));
        assert!(!scope.covers("quay.io/fedoraproject/x"));
        assert!(!scope.covers("quay.io"));
        assert!(TrustScope::new("registry.example:5000/team").is_ok());
        for bad in [
            "",
            "quay.io/fedora:42",
            "quay.io/x@sha256:0",
            "Quay.io",
            "localhost/x",
            "quay.io//x",
            "reg:port/x",
        ] {
            assert!(TrustScope::new(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn enums_read_what_they_write() {
        for trigger in [Trigger::BaseDigest, Trigger::GitRef, Trigger::Schedule] {
            assert_eq!(Trigger::parse(trigger.as_str()), Some(trigger));
        }
        for backend in [SigningBackend::Tpm, SigningBackend::Software, SigningBackend::Auto] {
            assert_eq!(SigningBackend::parse(backend.as_str()), Some(backend));
        }
        assert!(BaseRequirement::None < BaseRequirement::Listed && BaseRequirement::Listed < BaseRequirement::All);
        assert_eq!(Trigger::parse("Base-Digest"), None);
    }
}
