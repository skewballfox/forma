//! Podman's `policy.json`, and the two policies forma generates.
//!
//! - [`account_policy`]: what a service account may load. It rejects
//!   everything except the account's own store directories, and requires
//!   forma's signature there (`docs/architecture.md` 5.5).
//! - [`build_policy`]: what a build may pull. It keeps every requirement of
//!   the host's policy, adds the repository's, and lets the build use only
//!   the images forma built itself (architecture 5.6, "Base image
//!   signatures").
//!
//! Everything here is a pure function. Writing the files is the job of
//! this library's `admin` module, which does not exist yet.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use forma_config::types::{BaseRequirement, ComponentPath, ImageRef, TrustScope};
use forma_config::{BaseImages, HostPolicyMode, TrustRule};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

/// The transports whose images come from outside the host. The build
/// policy copies the host's requirements for these unchanged.
pub const REMOTE_TRANSPORTS: [&str; 4] = ["docker", "docker-daemon", "oci-archive", "docker-archive"];

/// What forma writes into each service account's `containers.conf`: no
/// implicit pull, ever (architecture 5.5, "Service accounts never pull").
pub const CONTAINERS_CONF: &str = "# Written by forma. Do not edit: forma apply replaces this file.\n\
                                   [engine]\n\
                                   pull_policy = \"never\"\n";

/// A `policy.json`.
///
/// A requirement is kept as the JSON it is. Forma copies the host's
/// requirements into a build policy, and must not drop a key it does not
/// know: that could loosen the requirement.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Policy {
    /// The requirements for an image no scope matches.
    #[serde(default)]
    pub default: Vec<Value>,
    /// Requirements by transport, then by scope. The scope `""` is the
    /// transport's default.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub transports: BTreeMap<String, BTreeMap<String, Vec<Value>>>,
}

/// A policy could not be read or generated.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    /// The text is not a `policy.json`.
    #[error("the policy cannot be read: {0}")]
    Json(String),
    /// A keyless `Trust` entry needs Fulcio and Rekor roots, and none are set.
    #[error(
        "the Trust entry for {scope} is sigstore-keyless, and forma has no Fulcio CA and Rekor key to check it with"
    )]
    KeylessRootsMissing {
        /// The entry's scope.
        scope: String,
    },
    /// An account policy was asked for with no key.
    #[error("an account policy needs at least one public key")]
    NoKey,
}

impl Policy {
    /// Reads a `policy.json`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Json`] if the text is not one.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        serde_json::from_str(text).map_err(|error| PolicyError::Json(error.to_string()))
    }

    /// Returns the policy as the text of a `policy.json`.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_else(|_| unreachable!("a policy is plain JSON"));
        text.push('\n');
        text
    }

    fn scope_mut(&mut self, transport: &str, scope: &str) -> &mut Vec<Value> {
        self.transports
            .entry(transport.to_owned())
            .or_default()
            .entry(scope.to_owned())
            .or_default()
    }
}

fn reject() -> Value {
    json!({"type": "reject"})
}

fn accept_anything() -> Value {
    json!({"type": "insecureAcceptAnything"})
}

fn is_accept_anything(requirement: &Value) -> bool {
    requirement.get("type").and_then(Value::as_str) == Some("insecureAcceptAnything")
}

/// One image a service account may load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredImage<'a> {
    /// The image's directory in the account's store: its `dir:` layout.
    pub directory: &'a Path,
    /// The image's reference. A signature must name exactly this.
    pub reference: &'a ImageRef,
}

/// Builds the `policy.json` of one service account.
///
/// The policy rejects everything by default. For each image's store
/// directory it requires a sigstore signature by one of `keys` that names
/// the image's exact reference. `dir:` has no reference of its own, so the
/// requirement says which one to expect.
///
/// `keys` holds one key, or two during a rotation. Both go in **one**
/// requirement (`keyPaths`), which a signature by either key satisfies.
/// Two requirements would need a signature from each.
///
/// The policy has no rule for `containers-storage`: Podman checks a policy
/// when it copies an image from a transport, not when it starts a container.
///
/// # Errors
///
/// Returns [`PolicyError::NoKey`] if `keys` is empty.
pub fn account_policy(images: &[StoredImage<'_>], keys: &[&Path]) -> Result<Policy, PolicyError> {
    let mut policy = Policy {
        default: vec![reject()],
        transports: BTreeMap::new(),
    };
    let key = match keys {
        [] => return Err(PolicyError::NoKey),
        [one] => ("keyPath", json!(one)),
        several => ("keyPaths", json!(several)),
    };
    for image in images {
        let mut requirement = json!({
            "type": "sigstoreSigned",
            "signedIdentity": {"type": "exactReference", "dockerReference": image.reference.as_str()},
        });
        requirement[key.0] = key.1.clone();
        policy
            .scope_mut("dir", &image.directory.display().to_string())
            .push(requirement);
    }
    Ok(policy)
}

/// The roots a keyless sigstore signature is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeylessRoots {
    /// The Fulcio CA certificate, in PEM.
    pub fulcio_ca: PathBuf,
    /// The Rekor public key, in PEM.
    pub rekor_key: PathBuf,
}

/// What a build policy is made from.
pub struct BuildInputs<'a> {
    /// Whether the host's policy applies to base images.
    pub mode: HostPolicyMode,
    /// The host-wide `/etc/containers/policy.json`, if it could be read.
    /// Not used when `mode` is `Ignore`.
    pub host: Option<&'a Policy>,
    /// The repository's requirements for this build.
    pub base_images: &'a BaseImages,
    /// Where `forma apply` installed a trust key from the repository.
    pub key_path: &'a dyn Fn(&ComponentPath) -> PathBuf,
    /// The roots for keyless entries, if the host has them.
    pub keyless: Option<&'a KeylessRoots>,
    /// The builder's storage driver and graph root, such as `overlay` and
    /// `/var/home/forma-build/.local/share/containers/storage`.
    pub storage: (&'a str, &'a Path),
    /// The images forma built itself that this build may use as a base.
    pub own_images: &'a [&'a ImageRef],
}

/// The scopes of a `docker` reference from the most specific to the least,
/// in the order Podman tries them: the scope itself, each parent path, the
/// host, then wildcards for each parent domain.
fn docker_lookup(scope: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    // A tag or digest belongs to the last path part, never to the host's port.
    let (host, path) = scope.split_once('/').map_or((scope, ""), |(host, path)| (host, path));
    let untagged = path.split(['@', ':']).next().unwrap_or_default();
    if untagged != path {
        candidates.push(scope.to_owned());
    }
    let mut parts: Vec<&str> = untagged.split('/').filter(|part| !part.is_empty()).collect();
    while !parts.is_empty() {
        candidates.push(format!("{host}/{}", parts.join("/")));
        parts.pop();
    }
    candidates.push(host.to_owned());
    let name = host.split(':').next().unwrap_or(host);
    let mut domain = name;
    while let Some((_, parent)) = domain.split_once('.') {
        candidates.push(format!("*.{parent}"));
        domain = parent;
    }
    candidates
}

/// The requirements a policy applies to a `docker` scope: those of the
/// most specific scope that matches, then the transport's default, then
/// the policy's.
fn effective<'a>(policy: &'a Policy, scope: &str) -> &'a [Value] {
    let docker = policy.transports.get("docker");
    docker_lookup(scope)
        .iter()
        .chain([&String::new()])
        .find_map(|candidate| docker.and_then(|scopes| scopes.get(candidate)))
        .map_or(policy.default.as_slice(), Vec::as_slice)
}

fn trust_requirement(scope: &TrustScope, rule: &TrustRule, inputs: &BuildInputs<'_>) -> Result<Value, PolicyError> {
    Ok(match rule {
        TrustRule::SigstoreKey { key } => json!({"type": "sigstoreSigned", "keyPath": (inputs.key_path)(key)}),
        TrustRule::Gpg { keyring } => {
            json!({"type": "signedBy", "keyType": "GPGKeys", "keyPath": (inputs.key_path)(keyring)})
        }
        TrustRule::SigstoreKeyless { issuer, subject } => {
            let roots = inputs.keyless.ok_or_else(|| PolicyError::KeylessRootsMissing {
                scope: scope.to_string(),
            })?;
            json!({
                "type": "sigstoreSigned",
                "fulcio": {"caPath": roots.fulcio_ca, "oidcIssuer": issuer, "subjectEmail": subject},
                "rekorPublicKeyPath": roots.rekor_key,
            })
        }
    })
}

/// Builds the signature policy of one build.
///
/// 1. **Host requirements.** With `Respect`, the host's `default` and every
///    scope of a remote transport are copied unchanged.
/// 2. **Repository requirements.** Each `Trust` entry is added to its
///    `docker` scope, after whatever the host requires there. Podman needs
///    every requirement of a scope to pass, so adding never loosens. A
///    scope the host does not list starts from what the host would apply
///    to it (a parent scope, or a default), because Podman uses only the
///    most specific scope. A host scope inside a `Trust` scope gets the
///    entry too.
/// 3. **Forma's own images.** In `containers-storage`, exactly the images
///    in `own_images` are allowed, scoped to the builder's storage.
///    Everything else there is rejected.
///
/// With `Ignore`, remote images are accepted unless a `Trust` entry covers
/// them. With `Require = "all"`, or when the host has no default, the
/// default is `reject`.
///
/// # Errors
///
/// Returns [`PolicyError::KeylessRootsMissing`] for a keyless entry
/// without roots.
pub fn build_policy(inputs: &BuildInputs<'_>) -> Result<Policy, PolicyError> {
    let empty = Policy::default();
    let host = match inputs.mode {
        HostPolicyMode::Respect => inputs.host.unwrap_or(&empty),
        HostPolicyMode::Ignore => &empty,
    };
    let require_all = inputs.base_images.require == BaseRequirement::All;
    let mut policy = Policy {
        default: match (inputs.mode, host.default.is_empty(), require_all) {
            (HostPolicyMode::Respect, false, _) => host.default.clone(),
            (HostPolicyMode::Ignore, _, false) => vec![accept_anything()],
            _ => vec![reject()],
        },
        transports: BTreeMap::new(),
    };
    for transport in REMOTE_TRANSPORTS {
        if let Some(scopes) = host.transports.get(transport) {
            policy.transports.insert(transport.to_owned(), scopes.clone());
        }
    }

    // The host's view of a scope, before the repository adds to it.
    let base = Policy {
        default: policy.default.clone(),
        transports: policy.transports.clone(),
    };
    let trust: Vec<(&TrustScope, Value)> = inputs
        .base_images
        .trust
        .iter()
        .map(|entry| {
            Ok((
                &entry.value.scope,
                trust_requirement(&entry.value.scope, &entry.value.rule, inputs)?,
            ))
        })
        .collect::<Result<_, PolicyError>>()?;
    let host_scopes: Vec<String> = base
        .transports
        .get("docker")
        .map_or_default(|scopes| scopes.keys().filter(|scope| !scope.is_empty()).cloned().collect());
    let scopes = trust.iter().map(|(scope, _)| scope.to_string()).chain(host_scopes);
    for scope in scopes {
        // Every Trust entry whose scope holds this one applies to it.
        let lookup = docker_lookup(&scope);
        let added: Vec<Value> = trust
            .iter()
            .filter(|(entry, _)| lookup.iter().any(|candidate| candidate == entry.as_str()))
            .map(|(_, requirement)| requirement.clone())
            .collect();
        if added.is_empty() {
            continue;
        }
        // "Accept anything" beside a real requirement adds nothing.
        let mut requirements: Vec<Value> = effective(&base, &scope)
            .iter()
            .filter(|requirement| !is_accept_anything(requirement))
            .cloned()
            .collect();
        for requirement in added {
            if !requirements.contains(&requirement) {
                requirements.push(requirement);
            }
        }
        *policy.scope_mut("docker", &scope) = requirements;
    }

    let storage = policy.transports.entry("containers-storage".to_owned()).or_default();
    storage.insert(String::new(), vec![reject()]);
    let (driver, graph_root) = inputs.storage;
    for image in inputs.own_images {
        storage.insert(
            format!("[{driver}@{}]{image}", graph_root.display()),
            vec![accept_anything()],
        );
    }
    Ok(policy)
}

/// Says which `Trust` entry covers a base image, if any: the entry with
/// the longest scope that holds the image's repository.
///
/// `repository` is the image's reference without tag and digest, such as
/// `registry.fedoraproject.org/fedora-minimal`.
#[must_use]
pub fn covering_scope<'a>(base_images: &'a BaseImages, repository: &str) -> Option<&'a TrustScope> {
    base_images
        .trust
        .iter()
        .map(|entry| &entry.value.scope)
        .filter(|scope| scope.covers(repository))
        .max_by_key(|scope| scope.as_str().len())
}

/// Renders the `registries.d` file that makes Podman look for sigstore
/// signatures attached to images: one entry per `Trust` scope of a
/// sigstore type. The builder puts it next to the host's own entries.
#[must_use]
pub fn registries_d(base_images: &BaseImages) -> String {
    let mut text = String::from("# Written by forma for one build.\ndocker:\n");
    let mut scopes: Vec<&str> = base_images
        .trust
        .iter()
        .filter(|entry| !matches!(entry.value.rule, TrustRule::Gpg { .. }))
        .map(|entry| entry.value.scope.as_str())
        .collect();
    scopes.sort_unstable();
    scopes.dedup();
    for scope in scopes {
        // A scope holds only host and repository characters, none of which YAML treats as special in a key.
        let _ = write!(text, "  {scope}:\n    use-sigstore-attachments: true\n");
    }
    text
}

#[cfg(test)]
mod tests {
    use forma_config::{Located, Trust};

    use super::*;

    fn image(reference: &str) -> ImageRef {
        ImageRef::new(reference).unwrap()
    }

    #[test]
    fn an_account_may_load_only_its_signed_images() {
        let steam = image("moonshine/steam:latest");
        let policy = account_policy(
            &[StoredImage {
                directory: Path::new("/var/lib/forma/store/moonshine/moonshine_steam_latest"),
                reference: &steam,
            }],
            &[Path::new("/var/lib/forma/trust/forma.pub")],
        )
        .unwrap();
        insta::assert_snapshot!(policy.to_json(), @r#"
        {
          "default": [
            {
              "type": "reject"
            }
          ],
          "transports": {
            "dir": {
              "/var/lib/forma/store/moonshine/moonshine_steam_latest": [
                {
                  "keyPath": "/var/lib/forma/trust/forma.pub",
                  "signedIdentity": {
                    "dockerReference": "localhost/moonshine/steam:latest",
                    "type": "exactReference"
                  },
                  "type": "sigstoreSigned"
                }
              ]
            }
          }
        }
        "#);
        // No rule for containers-storage, and no way to pull from a registry.
        assert_eq!(policy.transports.keys().collect::<Vec<_>>(), ["dir"]);
    }

    #[test]
    fn a_rotation_lists_both_keys_in_one_requirement() {
        let steam = image("moonshine/steam:latest");
        let stored = [StoredImage {
            directory: Path::new("/s/moonshine/x"),
            reference: &steam,
        }];
        let policy = account_policy(&stored, &[Path::new("/t/old.pub"), Path::new("/t/new.pub")]).unwrap();
        let requirements = &policy.transports["dir"]["/s/moonshine/x"];
        assert_eq!(
            requirements.len(),
            1,
            "two requirements would need a signature from each key"
        );
        assert_eq!(requirements[0]["keyPaths"], json!(["/t/old.pub", "/t/new.pub"]));
        assert!(requirements[0].get("keyPath").is_none());
        assert_eq!(account_policy(&stored, &[]), Err(PolicyError::NoKey));
    }

    #[test]
    fn an_account_without_images_can_load_nothing() {
        let policy = account_policy(&[], &[Path::new("/t/forma.pub")]).unwrap();
        assert_eq!(
            policy.to_json(),
            "{\n  \"default\": [\n    {\n      \"type\": \"reject\"\n    }\n  ]\n}\n"
        );
    }

    fn base_images(require: BaseRequirement, entries: &[(&str, TrustRule)]) -> BaseImages {
        let file: std::sync::Arc<Path> = std::sync::Arc::from(Path::new("MANIFEST.toml"));
        BaseImages {
            require,
            trust: entries
                .iter()
                .map(|(scope, rule)| Located {
                    value: Trust {
                        scope: TrustScope::new(scope).unwrap(),
                        rule: rule.clone(),
                    },
                    at: forma_config::Origin::file(&file),
                })
                .collect(),
        }
    }

    fn sigstore_key(path: &str) -> TrustRule {
        TrustRule::SigstoreKey {
            key: ComponentPath::new(path).unwrap(),
        }
    }

    fn installed(key: &ComponentPath) -> PathBuf {
        Path::new("/var/lib/forma/trust/base").join(key.to_string().replace('/', "_"))
    }

    fn build(mode: HostPolicyMode, host: Option<&Policy>, base_images: &BaseImages, own: &[&ImageRef]) -> Policy {
        build_policy(&BuildInputs {
            mode,
            host,
            base_images,
            key_path: &installed,
            keyless: None,
            storage: (
                "overlay",
                Path::new("/var/home/forma-build/.local/share/containers/storage"),
            ),
            own_images: own,
        })
        .unwrap()
    }

    /// A host like secureblue: reject by default, signatures required for some registries.
    fn strict_host() -> Policy {
        Policy::parse(
            r#"{
              "default": [{"type": "reject"}],
              "transports": {
                "docker": {
                  "registry.fedoraproject.org": [{"type": "sigstoreSigned", "keyPath": "/etc/pki/containers/fedora.pub", "futureKey": 1}],
                  "quay.io/fedora/fedora-minimal": [{"type": "sigstoreSigned", "keyPath": "/etc/pki/containers/quay-fedora.pub"}],
                  "docker.io": [{"type": "insecureAcceptAnything"}],
                  "*.example.com": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/etc/pki/example.gpg"}]
                },
                "docker-daemon": {"": [{"type": "reject"}]},
                "containers-storage": {"": [{"type": "insecureAcceptAnything"}]},
                "dir": {"": [{"type": "insecureAcceptAnything"}]}
              }
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn the_host_policy_is_copied_for_remote_transports_only() {
        let host = strict_host();
        let policy = build(HostPolicyMode::Respect, Some(&host), &BaseImages::default(), &[]);
        assert_eq!(policy.default, host.default);
        assert_eq!(
            policy.transports["docker"], host.transports["docker"],
            "unchanged, unknown keys included"
        );
        assert_eq!(policy.transports["docker-daemon"], host.transports["docker-daemon"]);
        assert!(
            !policy.transports.contains_key("dir"),
            "a build has no use for the host's dir rule"
        );
        // The host accepts anything from its own storage. A build does not.
        assert_eq!(policy.transports["containers-storage"][""], [reject()]);
    }

    #[test]
    fn a_trust_entry_adds_to_what_the_host_requires() {
        let host = strict_host();
        let trust = base_images(
            BaseRequirement::Listed,
            &[
                ("registry.fedoraproject.org", sigstore_key("trust/fedora-registry.pub")),
                ("quay.io/fedora", sigstore_key("trust/quay.pub")),
            ],
        );
        let policy = build(HostPolicyMode::Respect, Some(&host), &trust, &[]);
        let docker = &policy.transports["docker"];

        // The host already has this scope: both requirements must pass.
        let fedora = &docker["registry.fedoraproject.org"];
        assert_eq!(fedora.len(), 2);
        assert_eq!(fedora[0], host.transports["docker"]["registry.fedoraproject.org"][0]);
        assert_eq!(
            fedora[1],
            json!({"type": "sigstoreSigned", "keyPath": "/var/lib/forma/trust/base/trust_fedora-registry.pub"})
        );

        // The host has no rule for quay.io/fedora, so its default applies there: reject stays.
        assert_eq!(
            docker["quay.io/fedora"][0],
            reject(),
            "a new scope must not hide the host's default"
        );
        assert_eq!(docker["quay.io/fedora"].len(), 2);

        // A host scope inside the Trust scope gets the entry too.
        let minimal = &docker["quay.io/fedora/fedora-minimal"];
        assert_eq!(minimal.len(), 2);
        assert_eq!(minimal[1]["keyPath"], "/var/lib/forma/trust/base/trust_quay.pub");

        // Scopes no Trust entry covers are as the host wrote them.
        assert_eq!(docker["docker.io"], host.transports["docker"]["docker.io"]);
        assert_eq!(docker["*.example.com"], host.transports["docker"]["*.example.com"]);
    }

    #[test]
    fn a_new_scope_inherits_from_a_parent_or_wildcard_scope_of_the_host() {
        let host = strict_host();
        let trust = base_images(
            BaseRequirement::Listed,
            &[
                ("registry.fedoraproject.org/fedora-minimal", sigstore_key("a.pub")),
                ("registry.example.com/team", sigstore_key("b.pub")),
                ("docker.io/library", sigstore_key("c.pub")),
            ],
        );
        let policy = build(HostPolicyMode::Respect, Some(&host), &trust, &[]);
        let docker = &policy.transports["docker"];
        assert_eq!(
            docker["registry.fedoraproject.org/fedora-minimal"][0]["keyPath"],
            "/etc/pki/containers/fedora.pub"
        );
        assert_eq!(
            docker["registry.example.com/team"][0]["keyPath"],
            "/etc/pki/example.gpg"
        );
        assert_eq!(docker["registry.example.com/team"].len(), 2);
        // The host accepts anything from docker.io; with an entry, the entry is the requirement.
        assert_eq!(
            docker["docker.io/library"],
            [json!({"type": "sigstoreSigned", "keyPath": "/var/lib/forma/trust/base/c.pub"})]
        );
    }

    #[test]
    fn ignore_accepts_remote_images_unless_an_entry_covers_them() {
        let host = strict_host();
        let trust = base_images(BaseRequirement::Listed, &[("quay.io/fedora", sigstore_key("q.pub"))]);
        let policy = build(HostPolicyMode::Ignore, Some(&host), &trust, &[]);
        assert_eq!(policy.default, [accept_anything()]);
        assert_eq!(
            policy.transports["docker"].keys().collect::<Vec<_>>(),
            ["quay.io/fedora"],
            "no host scope is copied"
        );
        assert_eq!(policy.transports["docker"]["quay.io/fedora"].len(), 1);
        assert_eq!(policy.transports["containers-storage"][""], [reject()]);

        let all = base_images(BaseRequirement::All, &[("quay.io/fedora", sigstore_key("q.pub"))]);
        assert_eq!(
            build(HostPolicyMode::Ignore, Some(&host), &all, &[]).default,
            [reject()]
        );
    }

    #[test]
    fn without_a_host_default_the_default_is_reject() {
        let no_default = Policy::parse(r#"{"transports": {"docker": {"quay.io": [{"type": "reject"}]}}}"#).unwrap();
        for host in [None, Some(&no_default)] {
            let policy = build(HostPolicyMode::Respect, host, &BaseImages::default(), &[]);
            assert_eq!(policy.default, [reject()]);
        }
    }

    #[test]
    fn only_formas_own_images_may_be_used_from_the_builders_storage() {
        let patches = image("moonshine/moonshine:patches");
        let policy = build(
            HostPolicyMode::Respect,
            Some(&strict_host()),
            &BaseImages::default(),
            &[&patches],
        );
        let storage = &policy.transports["containers-storage"];
        assert_eq!(storage.len(), 2);
        assert_eq!(
            storage["[overlay@/var/home/forma-build/.local/share/containers/storage]localhost/moonshine/moonshine:patches"],
            [accept_anything()]
        );
        assert_eq!(storage[""], [reject()]);
    }

    #[test]
    fn gpg_and_keyless_entries_map_to_podmans_requirements() {
        let keyless = TrustRule::SigstoreKeyless {
            issuer: "https://accounts.google.com".into(),
            subject: "release@fedoraproject.org".into(),
        };
        let gpg = TrustRule::Gpg {
            keyring: ComponentPath::new("trust/vendor.gpg").unwrap(),
        };
        let trust = base_images(
            BaseRequirement::Listed,
            &[("quay.io/fedora", keyless), ("registry.example.org", gpg)],
        );
        let inputs = |keyless| BuildInputs {
            mode: HostPolicyMode::Ignore,
            host: None,
            base_images: &trust,
            key_path: &installed,
            keyless,
            storage: ("overlay", Path::new("/s")),
            own_images: &[],
        };
        assert_eq!(
            build_policy(&inputs(None)),
            Err(PolicyError::KeylessRootsMissing {
                scope: "quay.io/fedora".into()
            })
        );
        let roots = KeylessRoots {
            fulcio_ca: "/etc/forma/fulcio.pem".into(),
            rekor_key: "/etc/forma/rekor.pub".into(),
        };
        let policy = build_policy(&inputs(Some(&roots))).unwrap();
        assert_eq!(
            policy.transports["docker"]["quay.io/fedora"],
            [json!({
                "type": "sigstoreSigned",
                "fulcio": {"caPath": "/etc/forma/fulcio.pem", "oidcIssuer": "https://accounts.google.com", "subjectEmail": "release@fedoraproject.org"},
                "rekorPublicKeyPath": "/etc/forma/rekor.pub",
            })]
        );
        assert_eq!(
            policy.transports["docker"]["registry.example.org"],
            [
                json!({"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/var/lib/forma/trust/base/trust_vendor.gpg"})
            ]
        );
    }

    #[test]
    fn lookups_go_from_the_most_specific_scope_to_wildcards() {
        assert_eq!(
            docker_lookup("registry.example.com:5000/team/app:1.0"),
            [
                "registry.example.com:5000/team/app:1.0",
                "registry.example.com:5000/team/app",
                "registry.example.com:5000/team",
                "registry.example.com:5000",
                "*.example.com",
                "*.com",
            ]
        );
        assert_eq!(docker_lookup("quay.io"), ["quay.io", "*.io"]);
    }

    #[test]
    fn the_longest_trust_scope_covers_an_image() {
        let trust = base_images(
            BaseRequirement::All,
            &[
                ("quay.io/fedora", sigstore_key("a.pub")),
                ("quay.io/fedora/fedora-minimal", sigstore_key("b.pub")),
            ],
        );
        assert_eq!(
            covering_scope(&trust, "quay.io/fedora/fedora-minimal")
                .unwrap()
                .as_str(),
            "quay.io/fedora/fedora-minimal"
        );
        assert_eq!(
            covering_scope(&trust, "quay.io/fedora/fedora").unwrap().as_str(),
            "quay.io/fedora"
        );
        assert_eq!(covering_scope(&trust, "docker.io/library/alpine"), None);
    }

    #[test]
    fn sigstore_scopes_get_attachment_lookups() {
        let trust = base_images(
            BaseRequirement::Listed,
            &[
                ("registry.fedoraproject.org", sigstore_key("a.pub")),
                (
                    "registry.example.org",
                    TrustRule::Gpg {
                        keyring: ComponentPath::new("k.gpg").unwrap(),
                    },
                ),
            ],
        );
        assert_eq!(
            registries_d(&trust),
            "# Written by forma for one build.\ndocker:\n  registry.fedoraproject.org:\n    use-sigstore-attachments: true\n"
        );
    }

    #[test]
    fn the_containers_conf_turns_implicit_pulls_off() {
        assert!(CONTAINERS_CONF.contains("[engine]\npull_policy = \"never\"\n"));
    }
}
