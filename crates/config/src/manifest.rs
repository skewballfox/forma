//! The `[Forma]` tables, decoded into checked types.
//!
//! Input is a canonical table from [`crate::schema`]: keys have their
//! documented spelling and host changes are already merged in.

use std::collections::{BTreeMap, BTreeSet};

use forma_user::name::GroupName;
use forma_user::path::AbsPath;

use crate::error::ManifestError;
use crate::raw::{Node, Origin, Table, Value};
use crate::types::{
    AccountName, BaseRequirement, BuildArgName, CalendarSpec, ComponentPath, ComponentPathError, HostPath, ImageRef,
    SigningBackend, SubIdCount, Trigger, TrustScope,
};

/// A value and the place in a manifest that declares it.
///
/// Two located values are equal when their values are. Where they were
/// written does not count, so two components can declare the same account.
#[derive(Debug, Clone)]
pub struct Located<T> {
    /// The value.
    pub value: T,
    /// Where it was written.
    pub at: Origin,
}

impl<T: PartialEq> PartialEq for Located<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Eq> Eq for Located<T> {}

/// A service account, from `[Forma.Account]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The account's name.
    pub name: AccountName,
    /// Whether the account has a home directory. Default: yes.
    pub home: bool,
    /// Whether the account's user manager starts at boot. Default: yes.
    pub linger: bool,
    /// The size of the account's sub-ID ranges. Default: 65536.
    pub sub_ids: SubIdCount,
    /// The account's supplementary groups, sorted by name.
    pub member_of: Vec<Located<GroupName>>,
}

/// A group forma creates, from `[[Forma.Groups]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The group's name.
    pub name: GroupName,
    /// Whether the group gets an ID from the system range. Default: yes.
    pub system: bool,
}

/// Where an image's source comes from, from `[Forma.Images.Source]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitSource {
    /// The repository URL. It starts with `https://` or `ssh://`.
    pub url: String,
    /// The branch, tag or other reference to follow.
    pub reference: String,
    /// The build argument that receives the resolved commit.
    pub commit_arg: Option<BuildArgName>,
}

/// When forma checks an image for a rebuild.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Update {
    /// When the timer fires. `None` means no timer.
    pub schedule: Option<CalendarSpec>,
    /// What the timer checks. With a schedule and no trigger listed, this
    /// holds [`Trigger::Schedule`]: every firing rebuilds.
    pub triggers: BTreeSet<Trigger>,
}

/// An image forma builds, from `[[Forma.Images]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// The image's reference.
    pub tag: ImageRef,
    /// The Containerfile, inside the component.
    pub containerfile: ComponentPath,
    /// The build context, inside the component.
    pub context: ComponentPath,
    /// Build arguments.
    pub build_args: BTreeMap<BuildArgName, String>,
    /// Forma images this one is built from.
    pub depends_on: Vec<Located<ImageRef>>,
    /// The Git source the image follows.
    pub source: Option<GitSource>,
    /// When forma checks the image for a rebuild.
    pub update: Update,
}

/// The kind of file an SELinux module source is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModuleKind {
    /// A `.cil` file, installed as it is.
    Cil,
    /// A `.te` file, compiled first.
    TypeEnforcement,
    /// An `.fc` file, compiled with the `.te` file of the same name.
    FileContexts,
}

/// One SELinux module source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSource {
    /// The file, inside the component.
    pub path: ComponentPath,
    /// What kind of file it is.
    pub kind: ModuleKind,
}

/// A component's SELinux policy, from `[Forma.SELinux]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SeLinux {
    /// Module source files.
    pub modules: Vec<Located<ModuleSource>>,
    /// Names of udica templates installed in the same transaction.
    pub templates: Vec<String>,
    /// Host paths to relabel.
    pub relabel: Vec<Located<HostPath>>,
}

/// What a `Trust` entry requires of the images in its scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRule {
    /// A sigstore signature made with this key. The path is inside the repository.
    SigstoreKey {
        /// The public key file.
        key: ComponentPath,
    },
    /// A keyless sigstore signature with this identity.
    SigstoreKeyless {
        /// The OIDC issuer.
        issuer: String,
        /// The subject, an e-mail address.
        subject: String,
    },
    /// A GPG signature by a key in this keyring. The path is inside the repository.
    Gpg {
        /// The keyring file.
        keyring: ComponentPath,
    },
}

/// One `[[Forma.BaseImages.Trust]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    /// The registry, namespace or repository the entry covers.
    pub scope: TrustScope,
    /// What images in the scope must satisfy.
    pub rule: TrustRule,
}

/// Requirements for base images, from `[Forma.BaseImages]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BaseImages {
    /// How many base images need a `Trust` entry.
    pub require: BaseRequirement,
    /// The entries.
    pub trust: Vec<Located<Trust>>,
}

impl BaseImages {
    /// Adds the requirements of a narrower level (a component) to these.
    ///
    /// The stricter `Require` wins and every entry is kept, because the
    /// repository can add requirements and never remove them (architecture
    /// 5.6).
    #[must_use]
    pub fn with(&self, narrower: &Self) -> Self {
        let mut trust = self.trust.clone();
        trust.extend(
            narrower
                .trust
                .iter()
                .filter(|entry| !self.trust.contains(entry))
                .cloned(),
        );
        Self {
            require: self.require.max(narrower.require),
            trust,
        }
    }
}

/// Everything one component declares under `[Forma]`, after the host's
/// overrides and extensions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComponentForma {
    /// The account that runs the component.
    pub account: Option<Located<Account>>,
    /// Groups forma creates.
    pub groups: Vec<Located<Group>>,
    /// Images forma builds.
    pub images: Vec<Located<Image>>,
    /// SELinux policy.
    pub selinux: Option<Located<SeLinux>>,
    /// Requirements for the base images of this component's builds.
    pub base_images: BaseImages,
}

impl ComponentForma {
    /// Says whether the component declares nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.account.is_none()
            && self.groups.is_empty()
            && self.images.is_empty()
            && self.selinux.is_none()
            && self.base_images == BaseImages::default()
    }
}

/// The builder account's settings, from `[Forma.Builder]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Builder {
    /// The account that builds images. Default: `forma-build`.
    pub account: AccountName,
    /// The size of its sub-ID ranges. Default: 65536.
    pub sub_ids: SubIdCount,
}

/// Settings for the whole host: the repository's `[Forma]` table with the
/// host's `[Hosts.<host>.Forma]` merged in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Which kind of key signs images. Default: `auto`.
    pub signing: SigningBackend,
    /// The builder.
    pub builder: Builder,
    /// The account that signs images. Default: `forma-sign`.
    pub signer: AccountName,
    /// The image store. Default: `/var/lib/forma/store`.
    pub store_root: HostPath,
    /// Requirements for the base images of every build.
    pub base_images: BaseImages,
}

/// The default builder account.
pub const DEFAULT_BUILDER: &str = "forma-build";
/// The default signer account.
pub const DEFAULT_SIGNER: &str = "forma-sign";
/// The default image store.
pub const DEFAULT_STORE_ROOT: &str = "/var/lib/forma/store";

/// Reads keys of one canonical table and reports type errors by key.
struct Reader<'a> {
    table: &'a Table,
    at: &'a Origin,
    name: &'a str,
}

impl<'a> Reader<'a> {
    fn key(&self, key: &str) -> String {
        format!("{} {key}", self.name)
    }

    fn wrong_type(&self, key: &str, node: &Node, expected: &'static str) -> ManifestError {
        ManifestError::WrongType {
            at: node.at.clone(),
            key: self.key(key),
            expected,
            found: node.value.kind(),
        }
    }

    fn invalid(&self, key: &str, at: &Origin, message: impl Into<String>) -> ManifestError {
        ManifestError::InvalidValue {
            at: at.clone(),
            key: self.key(key),
            message: message.into(),
        }
    }

    fn missing(&self, key: &'static str) -> ManifestError {
        ManifestError::MissingKey {
            at: self.at.clone(),
            table: self.name.to_owned(),
            key,
        }
    }

    fn string(&self, key: &str) -> Result<Option<(&'a str, &'a Origin)>, ManifestError> {
        match self.table.get(key) {
            None => Ok(None),
            Some(Node {
                value: Value::String(text),
                at,
            }) => Ok(Some((text, at))),
            Some(node) => Err(self.wrong_type(key, node, "a string")),
        }
    }

    fn required(&self, key: &'static str) -> Result<(&'a str, &'a Origin), ManifestError> {
        self.string(key)?.ok_or_else(|| self.missing(key))
    }

    fn boolean(&self, key: &str, default: bool) -> Result<bool, ManifestError> {
        match self.table.get(key) {
            None => Ok(default),
            Some(Node {
                value: Value::Bool(flag),
                ..
            }) => Ok(*flag),
            Some(node) => Err(self.wrong_type(key, node, "true or false")),
        }
    }

    fn sub_ids(&self, key: &str) -> Result<SubIdCount, ManifestError> {
        match self.table.get(key) {
            None => Ok(default_sub_ids()),
            Some(Node {
                value: Value::Integer(count),
                at,
            }) => {
                // A count that does not fit is out of range whichever way it is clamped.
                let count = u32::try_from(*count).unwrap_or(if *count < 0 { 0 } else { u32::MAX });
                SubIdCount::new(count).map_err(|source| ManifestError::InvalidSubIdCount { at: at.clone(), source })
            }
            Some(node) => Err(self.wrong_type(key, node, "an integer")),
        }
    }

    fn strings(&self, key: &str) -> Result<Vec<(&'a str, &'a Origin)>, ManifestError> {
        match self.table.get(key) {
            None => Ok(Vec::new()),
            Some(Node {
                value: Value::Array(items),
                ..
            }) => items
                .iter()
                .map(|item| match &item.value {
                    Value::String(text) => Ok((text.as_str(), &item.at)),
                    _ => Err(self.wrong_type(key, item, "a string")),
                })
                .collect(),
            Some(node) => Err(self.wrong_type(key, node, "a list of strings")),
        }
    }

    fn table(&self, key: &str) -> Option<(&'a Table, &'a Origin)> {
        match self.table.get(key) {
            Some(Node {
                value: Value::Table(table),
                at,
            }) => Some((table, at)),
            _ => None,
        }
    }

    fn tables(&self, key: &str) -> Vec<(&'a Table, &'a Origin)> {
        match self.table.get(key) {
            Some(Node {
                value: Value::Array(items),
                ..
            }) => items
                .iter()
                .filter_map(|item| match &item.value {
                    Value::Table(table) => Some((table, &item.at)),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}

fn component_path(text: &str, at: &Origin) -> Result<ComponentPath, ManifestError> {
    ComponentPath::new(text).map_err(|error| match error {
        ComponentPathError::Escapes => ManifestError::PathEscapesComponent {
            at: at.clone(),
            path: text.to_owned(),
        },
        ComponentPathError::Invalid(source) => ManifestError::InvalidPath { at: at.clone(), source },
    })
}

fn default_sub_ids() -> SubIdCount {
    SubIdCount::new(SubIdCount::MIN).unwrap_or_else(|_| unreachable!("the minimum is in range"))
}

fn host_path(text: &str, at: &Origin, roots: &[AbsPath]) -> Result<HostPath, ManifestError> {
    HostPath::new(text, roots).map_err(|error| match error {
        Some(source) => ManifestError::InvalidPath { at: at.clone(), source },
        None => ManifestError::PathNotAllowed {
            at: at.clone(),
            path: text.to_owned(),
            roots: roots.iter().map(ToString::to_string).collect(),
        },
    })
}

fn account_name(text: &str, at: &Origin) -> Result<AccountName, ManifestError> {
    AccountName::new(text).map_err(|source| ManifestError::InvalidAccountName { at: at.clone(), source })
}

fn group_name(text: &str, at: &Origin) -> Result<GroupName, ManifestError> {
    GroupName::new(text).map_err(|source| ManifestError::InvalidGroupName { at: at.clone(), source })
}

fn image_ref(text: &str, at: &Origin) -> Result<ImageRef, ManifestError> {
    ImageRef::new(text).map_err(|reason| ManifestError::InvalidImageRef {
        at: at.clone(),
        reference: text.to_owned(),
        reason,
    })
}

fn account(table: &Table, at: &Origin) -> Result<Located<Account>, ManifestError> {
    let reader = Reader {
        table,
        at,
        name: "[Forma.Account]",
    };
    let (name, name_at) = reader.required("Name")?;
    let mut member_of = reader
        .strings("MemberOf")?
        .into_iter()
        .map(|(group, group_at)| {
            Ok(Located {
                value: group_name(group, group_at)?,
                at: group_at.clone(),
            })
        })
        .collect::<Result<Vec<_>, ManifestError>>()?;
    member_of.sort_by(|a, b| a.value.cmp(&b.value));
    member_of.dedup();
    Ok(Located {
        value: Account {
            name: account_name(name, name_at)?,
            home: reader.boolean("Home", true)?,
            linger: reader.boolean("Linger", true)?,
            sub_ids: reader.sub_ids("SubIds")?,
            member_of,
        },
        at: at.clone(),
    })
}

fn group(table: &Table, at: &Origin) -> Result<Located<Group>, ManifestError> {
    let reader = Reader {
        table,
        at,
        name: "[[Forma.Groups]]",
    };
    let (name, name_at) = reader.required("Name")?;
    Ok(Located {
        value: Group {
            name: group_name(name, name_at)?,
            system: reader.boolean("System", true)?,
        },
        at: at.clone(),
    })
}

/// Reads an `Update` table. Missing keys fall back to `inherited`.
fn update(table: Option<(&Table, &Origin)>, name: &str, inherited: &Update) -> Result<Update, ManifestError> {
    let Some((table, at)) = table else {
        return Ok(inherited.clone());
    };
    let reader = Reader { table, at, name };
    let schedule = match reader.string("Schedule")? {
        Some((text, text_at)) => {
            Some(CalendarSpec::new(text).map_err(|reason| reader.invalid("Schedule", text_at, reason))?)
        }
        None => inherited.schedule.clone(),
    };
    let listed = reader.strings("Triggers")?;
    let triggers = if table.get("Triggers").is_some() {
        listed
            .into_iter()
            .map(|(text, text_at)| {
                Trigger::parse(text).ok_or_else(|| {
                    reader.invalid(
                        "Triggers",
                        text_at,
                        format!("holds {text:?}; use \"base-digest\", \"git-ref\" or \"schedule\""),
                    )
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?
    } else {
        inherited.triggers.clone()
    };
    Ok(Update { schedule, triggers })
}

fn git_source(table: &Table, at: &Origin) -> Result<GitSource, ManifestError> {
    let reader = Reader {
        table,
        at,
        name: "[Forma.Images.Source]",
    };
    let (url, url_at) = reader.required("Git")?;
    let plain = |text: &str| !text.chars().any(|ch| ch.is_control() || ch.is_whitespace());
    if !(url.starts_with("https://") || url.starts_with("ssh://")) || !plain(url) {
        return Err(reader.invalid("Git", url_at, "must be an https:// or ssh:// URL without spaces"));
    }
    let (reference, reference_at) = reader.required("Ref")?;
    if reference.is_empty() || reference.starts_with('-') || reference.contains("..") || !plain(reference) {
        return Err(reader.invalid("Ref", reference_at, "must be a branch, tag or reference name"));
    }
    let commit_arg = reader
        .string("CommitArg")?
        .map(|(name, name_at)| BuildArgName::new(name).map_err(|reason| reader.invalid("CommitArg", name_at, reason)))
        .transpose()?;
    Ok(GitSource {
        url: url.to_owned(),
        reference: reference.to_owned(),
        commit_arg,
    })
}

fn image(table: &Table, at: &Origin, component_update: &Update) -> Result<Located<Image>, ManifestError> {
    let reader = Reader {
        table,
        at,
        name: "[[Forma.Images]]",
    };
    let (tag, tag_at) = reader.required("Tag")?;
    let (containerfile, containerfile_at) = reader.required("Containerfile")?;
    let (context, context_at) = reader.required("Context")?;
    let mut build_args = BTreeMap::new();
    if let Some((args, _)) = reader.table("BuildArgs") {
        for entry in &args.entries {
            let name = BuildArgName::new(&entry.key).map_err(|reason| {
                reader.invalid("BuildArgs", &entry.key_at, format!("key {:?} {reason}", entry.key))
            })?;
            let Value::String(value) = &entry.node.value else {
                return Err(reader.wrong_type(&format!("BuildArgs.{}", entry.key), &entry.node, "a string"));
            };
            build_args.insert(name, value.clone());
        }
    }
    let depends_on = reader
        .strings("DependsOn")?
        .into_iter()
        .map(|(dependency, dependency_at)| {
            Ok(Located {
                value: image_ref(dependency, dependency_at)?,
                at: dependency_at.clone(),
            })
        })
        .collect::<Result<Vec<_>, ManifestError>>()?;
    let source = reader
        .table("Source")
        .map(|(source, source_at)| git_source(source, source_at))
        .transpose()?;
    let mut update = update(reader.table("Update"), "[Forma.Images.Update]", component_update)?;
    match (&update.schedule, update.triggers.is_empty()) {
        (Some(_), true) => {
            update.triggers.insert(Trigger::Schedule);
        }
        (None, false) => {
            return Err(reader.invalid(
                "Update",
                at,
                "lists Triggers but has no Schedule, so nothing would ever check them",
            ));
        }
        _ => {}
    }
    if update.triggers.contains(&Trigger::GitRef) && source.is_none() {
        return Err(reader.invalid("Update", at, "lists the git-ref trigger, but the image has no [Source]"));
    }
    Ok(Located {
        value: Image {
            tag: image_ref(tag, tag_at)?,
            containerfile: component_path(containerfile, containerfile_at)?,
            context: component_path(context, context_at)?,
            build_args,
            depends_on,
            source,
            update,
        },
        at: at.clone(),
    })
}

fn selinux(table: &Table, at: &Origin, roots: &[AbsPath]) -> Result<Located<SeLinux>, ManifestError> {
    let reader = Reader {
        table,
        at,
        name: "[Forma.SELinux]",
    };
    let modules = reader
        .strings("Modules")?
        .into_iter()
        .map(|(path, path_at)| {
            let kind = match path.rsplit_once('.').map(|(_, extension)| extension) {
                Some("cil") => ModuleKind::Cil,
                Some("te") => ModuleKind::TypeEnforcement,
                Some("fc") => ModuleKind::FileContexts,
                _ => {
                    return Err(reader.invalid(
                        "Modules",
                        path_at,
                        format!("holds {path:?}; use .cil, .te or .fc files"),
                    ));
                }
            };
            Ok(Located {
                value: ModuleSource {
                    path: component_path(path, path_at)?,
                    kind,
                },
                at: path_at.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let templates = reader
        .strings("Templates")?
        .into_iter()
        .map(|(name, name_at)| {
            let ok = !name.is_empty()
                && name
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
            if ok {
                Ok(name.to_owned())
            } else {
                Err(reader.invalid(
                    "Templates",
                    name_at,
                    format!("holds {name:?}; a template name has only a-z, 0-9 and '_'"),
                ))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let relabel = reader
        .strings("Relabel")?
        .into_iter()
        .map(|(path, path_at)| {
            Ok(Located {
                value: host_path(path, path_at, roots)?,
                at: path_at.clone(),
            })
        })
        .collect::<Result<Vec<_>, ManifestError>>()?;
    Ok(Located {
        value: SeLinux {
            modules,
            templates,
            relabel,
        },
        at: at.clone(),
    })
}

fn trust(table: &Table, at: &Origin) -> Result<Located<Trust>, ManifestError> {
    let reader = Reader {
        table,
        at,
        name: "[[Forma.BaseImages.Trust]]",
    };
    let (scope, scope_at) = reader.required("Scope")?;
    let scope = TrustScope::new(scope).map_err(|reason| reader.invalid("Scope", scope_at, reason))?;
    let (kind, kind_at) = reader.required("Type")?;
    let refuse = |key: &'static str| match table.entry(key) {
        Some(entry) => Err(reader.invalid(key, &entry.key_at, format!("does not apply to Type = {kind:?}"))),
        None => Ok(()),
    };
    let plain = |key: &'static str| {
        let (text, text_at) = reader.required(key)?;
        if text.is_empty() || text.chars().any(char::is_control) {
            return Err(reader.invalid(key, text_at, "must not be empty or hold control characters"));
        }
        Ok(text.to_owned())
    };
    let rule = match kind {
        "sigstore-key" | "gpg" => {
            refuse("Issuer")?;
            refuse("Subject")?;
            let (key, key_at) = reader.required("Key")?;
            let key = component_path(key, key_at)?;
            if kind == "gpg" {
                TrustRule::Gpg { keyring: key }
            } else {
                TrustRule::SigstoreKey { key }
            }
        }
        "sigstore-keyless" => {
            refuse("Key")?;
            TrustRule::SigstoreKeyless {
                issuer: plain("Issuer")?,
                subject: plain("Subject")?,
            }
        }
        _ => {
            return Err(reader.invalid(
                "Type",
                kind_at,
                format!("is {kind:?}; use \"sigstore-key\", \"sigstore-keyless\" or \"gpg\""),
            ));
        }
    };
    Ok(Located {
        value: Trust { scope, rule },
        at: at.clone(),
    })
}

fn base_images(table: Option<(&Table, &Origin)>) -> Result<BaseImages, ManifestError> {
    let Some((table, at)) = table else {
        return Ok(BaseImages::default());
    };
    let reader = Reader {
        table,
        at,
        name: "[Forma.BaseImages]",
    };
    let require = match reader.string("Require")? {
        Some((text, text_at)) => BaseRequirement::parse(text).ok_or_else(|| {
            reader.invalid(
                "Require",
                text_at,
                format!("is {text:?}; use \"none\", \"listed\" or \"all\""),
            )
        })?,
        None => BaseRequirement::default(),
    };
    let trust = reader
        .tables("Trust")
        .into_iter()
        .map(|(entry, entry_at)| trust(entry, entry_at))
        .collect::<Result<_, _>>()?;
    Ok(BaseImages { require, trust })
}

/// Decodes a component's canonical, merged `[Forma]` table.
///
/// `at` is where the table sits, and `roots` are the host's allowed roots.
pub(crate) fn component(table: &Table, at: &Origin, roots: &[AbsPath]) -> Result<ComponentForma, ManifestError> {
    let reader = Reader {
        table,
        at,
        name: "[Forma]",
    };
    let component_update = update(reader.table("Update"), "[Forma.Update]", &Update::default())?;
    Ok(ComponentForma {
        account: reader
            .table("Account")
            .map(|(inner, inner_at)| account(inner, inner_at))
            .transpose()?,
        groups: reader
            .tables("Groups")
            .into_iter()
            .map(|(inner, inner_at)| group(inner, inner_at))
            .collect::<Result<_, _>>()?,
        images: reader
            .tables("Images")
            .into_iter()
            .map(|(inner, inner_at)| image(inner, inner_at, &component_update))
            .collect::<Result<_, _>>()?,
        selinux: reader
            .table("SELinux")
            .map(|(inner, inner_at)| selinux(inner, inner_at, roots))
            .transpose()?,
        base_images: base_images(reader.table("BaseImages"))?,
    })
}

/// Decodes the canonical `[Forma]` table of the repository manifest, with
/// the host's table merged in. An empty table gives the defaults.
pub(crate) fn settings(table: &Table, at: &Origin, roots: &[AbsPath]) -> Result<Settings, ManifestError> {
    let reader = Reader {
        table,
        at,
        name: "[Forma]",
    };
    let signing = match reader.string("Signing")? {
        Some((text, text_at)) => SigningBackend::parse(text).ok_or_else(|| {
            reader.invalid(
                "Signing",
                text_at,
                format!("is {text:?}; use \"tpm\", \"software\" or \"auto\""),
            )
        })?,
        None => SigningBackend::default(),
    };
    let named = |section: &'static str, name: &'static str, default: &'static str| {
        let table = reader.table(section);
        let inner = table.map(|(table, at)| Reader { table, at, name });
        match inner
            .as_ref()
            .map(|inner| inner.string("Account"))
            .transpose()?
            .flatten()
        {
            Some((text, text_at)) => account_name(text, text_at).map(|account| (account, inner)),
            None => account_name(default, at).map(|account| (account, inner)),
        }
    };
    let (builder_account, builder) = named("Builder", "[Forma.Builder]", DEFAULT_BUILDER)?;
    let sub_ids = match &builder {
        Some(builder) => builder.sub_ids("SubIds")?,
        None => default_sub_ids(),
    };
    let (signer, _) = named("Signer", "[Forma.Signer]", DEFAULT_SIGNER)?;
    if signer == builder_account {
        return Err(reader.invalid(
            "Signer",
            reader.table("Signer").map_or(at, |(_, signer_at)| signer_at),
            "must not be the builder's account: a builder that can sign can sign anything (decision D3)",
        ));
    }
    let store = reader
        .table("Store")
        .map(|(table, at)| {
            Reader {
                table,
                at,
                name: "[Forma.Store]",
            }
            .string("Root")
        })
        .transpose()?
        .flatten();
    let store_root = match store {
        Some((text, text_at)) => host_path(text, text_at, roots)?,
        None => host_path(DEFAULT_STORE_ROOT, at, roots)?,
    };
    Ok(Settings {
        signing,
        builder: Builder {
            account: builder_account,
            sub_ids,
        },
        signer,
        store_root,
        base_images: base_images(reader.table("BaseImages"))?,
    })
}
