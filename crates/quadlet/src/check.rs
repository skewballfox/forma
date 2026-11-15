//! Forma's rules for the Quadlets and units of a delegated component
//! (architecture 5.5, 5.9 and 5.10).
//!
//! Forma reads a component's staged copy, where templates are not rendered.
//! So every key checked here must be literal text.

use std::fmt;

use crate::reader::{self, Entry};

/// What kind of unit a file is, from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnitKind {
    /// A `.container` Quadlet.
    Container,
    /// A `.volume` Quadlet.
    Volume,
    /// An `.image` Quadlet.
    Image,
    /// A `.pod` Quadlet.
    Pod,
    /// A `.kube`, `.network` or `.build` Quadlet.
    OtherQuadlet,
    /// A plain systemd unit, such as a `.service`.
    Systemd,
}

const SYSTEMD_SUFFIXES: &[&str] = &[
    "service",
    "socket",
    "timer",
    "path",
    "target",
    "mount",
    "automount",
    "slice",
    "scope",
    "swap",
    "device",
];

/// A file of a component, as it is staged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitFile<'a> {
    /// The file's name inside the component, such as `app.container.gotmpl`.
    pub name: &'a str,
    /// The file's text.
    pub text: &'a str,
}

impl UnitFile<'_> {
    /// Says whether materia renders the file as a template.
    #[must_use]
    pub fn is_template(&self) -> bool {
        self.name.ends_with(".gotmpl")
    }

    /// Returns the kind of unit, or `None` if the file is not a unit.
    #[must_use]
    pub fn kind(&self) -> Option<UnitKind> {
        kind_of(self.name)
    }
}

/// Returns the kind of unit a file name stands for, or `None` if the file
/// is not a unit. A template's `.gotmpl` suffix does not count.
#[must_use]
pub fn kind_of(name: &str) -> Option<UnitKind> {
    let name = name.strip_suffix(".gotmpl").unwrap_or(name);
    let (_, suffix) = name.rsplit_once('.')?;
    match suffix {
        "container" => Some(UnitKind::Container),
        "volume" => Some(UnitKind::Volume),
        "image" => Some(UnitKind::Image),
        "pod" => Some(UnitKind::Pod),
        "kube" | "network" | "build" => Some(UnitKind::OtherQuadlet),
        suffix if SYSTEMD_SUFFIXES.contains(&suffix) => Some(UnitKind::Systemd),
        _ => None,
    }
}

/// The name of a rule a unit breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// A `.container` does not set `Pull=never`.
    PullNotDisabled,
    /// A key forma checks holds a template action, or sits in a template block.
    TemplatedQuadletKey,
    /// An `.image` unit, which exists to pull.
    ImageUnit,
    /// An `Image=` that is not one of forma's images.
    ForeignImage,
    /// A mount that covers the runtime directory or a unit directory.
    UnsafeMount,
    /// A `SELinuxContext=` that names an SELinux user other than `user_u`.
    ForeignSeLinuxUser,
    /// A key in the reserved `[X-Forma]` section.
    UnknownXFormaKey,
    /// Warning: a container that runs a forma image without `AutoUpdate=local`.
    NoAutoUpdate,
    /// Warning: a mount forma cannot check, because it holds a template
    /// action or a specifier forma does not know.
    UncheckedMount,
}

impl Code {
    /// Returns the rule's stable name, such as `PullNotDisabled`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PullNotDisabled => "PullNotDisabled",
            Self::TemplatedQuadletKey => "TemplatedQuadletKey",
            Self::ImageUnit => "ImageUnit",
            Self::ForeignImage => "ForeignImage",
            Self::UnsafeMount => "UnsafeMount",
            Self::ForeignSeLinuxUser => "ForeignSeLinuxUser",
            Self::UnknownXFormaKey => "UnknownXFormaKey",
            Self::NoAutoUpdate => "NoAutoUpdate",
            Self::UncheckedMount => "UncheckedMount",
        }
    }

    /// Says whether the rule stops `forma apply`. The others are warnings.
    #[must_use]
    pub fn is_error(self) -> bool {
        !matches!(self, Self::NoAutoUpdate | Self::UncheckedMount)
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One rule a unit breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The rule.
    pub code: Code,
    /// The file's name inside the component.
    pub file: String,
    /// The line, counted from 1. Line 1 when the whole file is at fault.
    pub line: usize,
    /// What is wrong and what to do.
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.message)
    }
}

/// How a unit uses an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageRole {
    /// `Image=` of a `.container`.
    Container,
    /// `Image=` of a `.volume` with `Driver=image`.
    Volume,
}

/// An image a unit runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageUse {
    /// The reference, exactly as the unit writes it.
    pub reference: String,
    /// The file's name inside the component.
    pub file: String,
    /// The line of the `Image=` key.
    pub line: usize,
    /// How the unit uses the image.
    pub role: ImageRole,
}

/// What the checks need to know about the account.
pub struct Account<'a> {
    /// Says whether a reference, as a unit writes it, is one of forma's images.
    pub is_forma_image: &'a dyn Fn(&str) -> bool,
    /// The account's home directory, when it is known. Literal mount
    /// sources below it are then checked like `%h`.
    pub home: Option<&'a str>,
}

/// Finds the images a unit runs: `Image=` of a `.container`, and `Image=`
/// of a `.volume` with `Driver=image`. Values that hold a template action
/// are left out; [`check`] reports them.
#[must_use]
pub fn images(file: &UnitFile<'_>) -> Vec<ImageUse> {
    let (section, role) = match file.kind() {
        Some(UnitKind::Container) => ("Container", ImageRole::Container),
        Some(UnitKind::Volume) => ("Volume", ImageRole::Volume),
        _ => return Vec::new(),
    };
    let entries: Vec<Entry<'_>> = reader::entries(file.text)
        .filter(|entry| entry.section == section)
        .collect();
    let image_volume = entries
        .iter()
        .rfind(|entry| entry.key == "Driver")
        .is_some_and(|entry| entry.value == "image");
    if role == ImageRole::Volume && !image_volume {
        return Vec::new();
    }
    entries
        .iter()
        .rfind(|entry| entry.key == "Image")
        .filter(|entry| !entry.value.is_empty())
        .filter(|entry| !file.is_template() || !entry.value.contains("{{"))
        .map(|entry| ImageUse {
            reference: entry.value.to_string(),
            file: file.name.to_owned(),
            line: entry.line,
            role,
        })
        .into_iter()
        .collect()
}

/// The keys whose values forma reads, by section.
const LITERAL_KEYS: &[(&str, &str)] = &[
    ("Container", "Image"),
    ("Container", "Pull"),
    ("Container", "AutoUpdate"),
    ("Volume", "Image"),
    ("Volume", "Driver"),
    ("Service", "SELinuxContext"),
];

/// Finds the lines of a template that sit inside a block (`if`, `range`,
/// `with`, `define`, `block`). Returns one flag per line.
fn lines_in_blocks(text: &str) -> Vec<bool> {
    let mut depth = 0_usize;
    text.lines()
        .map(|line| {
            let inside = depth > 0;
            let mut rest = line;
            while let Some((_, after)) = rest.split_once("{{") {
                let action = after.split_once("}}").map_or(after, |(action, _)| action);
                let word = action
                    .trim_start_matches('-')
                    .split_whitespace()
                    .next()
                    .unwrap_or_default();
                match word.trim_end_matches('-') {
                    "if" | "range" | "with" | "define" | "block" => depth += 1,
                    "end" => depth = depth.saturating_sub(1),
                    _ => {}
                }
                rest = after;
            }
            // A line that opens or closes a block is itself conditional text.
            inside || depth > 0
        })
        .collect()
}

/// Checks one unit against forma's rules. Returns nothing for a file that
/// is not a unit.
#[must_use]
pub fn check(file: &UnitFile<'_>, account: &Account<'_>) -> Vec<Finding> {
    let Some(kind) = file.kind() else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    let mut report = |code: Code, line: usize, message: String| {
        findings.push(Finding {
            code,
            file: file.name.to_owned(),
            line,
            message,
        });
    };
    let entries: Vec<Entry<'_>> = reader::entries(file.text).collect();
    let in_block = if file.is_template() {
        lines_in_blocks(file.text)
    } else {
        Vec::new()
    };
    let mut templated: Vec<(&str, &str)> = Vec::new();

    for entry in &entries {
        if LITERAL_KEYS.contains(&(entry.section, entry.key)) {
            let in_action = file.is_template() && entry.value.contains("{{");
            let conditional = in_block.get(entry.line - 1).copied().unwrap_or(false);
            if in_action || conditional {
                templated.push((entry.section, entry.key));
                report(
                    Code::TemplatedQuadletKey,
                    entry.line,
                    format!(
                        "{}= {}; forma reads this file before materia renders it, so write the value as literal text",
                        entry.key,
                        if in_action {
                            "holds a template action"
                        } else {
                            "sits inside a template block"
                        }
                    ),
                );
            }
        }
        if entry.section == "X-Forma" {
            report(
                Code::UnknownXFormaKey,
                entry.line,
                format!("[X-Forma] is reserved for forma and has no key {}", entry.key),
            );
        }
        if entry.key == "SELinuxContext"
            && entry.section == "Service"
            && !templated.contains(&("Service", "SELinuxContext"))
        {
            // systemd allows a leading '-' that makes a failure non-fatal.
            let context = entry.value.trim_start_matches('-');
            let user = context.split(':').next().unwrap_or_default();
            if user != "user_u" {
                report(
                    Code::ForeignSeLinuxUser,
                    entry.line,
                    format!(
                        "SELinuxContext= names the SELinux user {user:?}; a forma account runs as user_u and cannot \
                         switch user or role, so the unit would fail to start. Remove the setting and use a type \
                         transition from user_t"
                    ),
                );
            }
        }
        if matches!(kind, UnitKind::Container | UnitKind::Pod)
            && matches!(entry.section, "Container" | "Pod")
            && matches!(entry.key, "Volume" | "Mount")
            && let Some((code, message)) = check_mount(entry, file.is_template(), account)
        {
            report(code, entry.line, message);
        }
    }

    check_whole(kind, file, &entries, &templated, account, &mut report);
    findings.sort_by_key(|finding| finding.line);
    findings
}

/// The rules that look at a unit as a whole, not at one setting.
fn check_whole(
    kind: UnitKind,
    file: &UnitFile<'_>,
    entries: &[Entry<'_>],
    templated: &[(&str, &str)],
    account: &Account<'_>,
    report: &mut impl FnMut(Code, usize, String),
) {
    match kind {
        UnitKind::Image => report(
            Code::ImageUnit,
            1,
            "an .image unit pulls an image, and a forma account never pulls; declare the image under \
             [[Forma.Images]] instead"
                .to_owned(),
        ),
        UnitKind::Container => {
            let last = |key: &str| {
                entries
                    .iter()
                    .rfind(|entry| entry.section == "Container" && entry.key == key)
            };
            if !templated.contains(&("Container", "Pull")) && last("Pull").is_none_or(|pull| pull.value != "never") {
                report(
                    Code::PullNotDisabled,
                    last("Pull").map_or(1, |pull| pull.line),
                    "a forma account never pulls; set Pull=never in [Container], so a missing image fails at once"
                        .to_owned(),
                );
            }
            let runs_forma_image = images(file)
                .iter()
                .any(|image| (account.is_forma_image)(&image.reference));
            if runs_forma_image
                && !templated.contains(&("Container", "AutoUpdate"))
                && last("AutoUpdate").is_none_or(|update| update.value != "local")
            {
                report(
                    Code::NoAutoUpdate,
                    last("AutoUpdate").map_or(1, |update| update.line),
                    "without AutoUpdate=local the container keeps its old image when forma loads a new one".to_owned(),
                );
            }
        }
        _ => {}
    }
    for image in images(file) {
        if !(account.is_forma_image)(&image.reference) {
            report(
                Code::ForeignImage,
                image.line,
                format!(
                    "Image={} is not an image forma builds on this host; a forma account can run only images \
                     from forma's store, written as localhost/<name>:<tag>",
                    image.reference
                ),
            );
        }
    }
}

/// Where a mount source points, as far as forma can tell without the host.
#[derive(Debug, PartialEq, Eq)]
enum Place {
    /// Below the account's runtime directory. Holds the path below it.
    Runtime(String),
    /// Below the account's home. Holds the path below it.
    Home(String),
    /// Another absolute path.
    Absolute(String),
    /// A named volume or another unit, not a host path.
    Named,
    /// Forma cannot tell.
    Unknown,
}

/// Brings a path to the form `a/b/c`: no empty parts, no `.`, and `..`
/// applied. Returns `None` if `..` leaves the start.
fn clean(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    Some(parts.join("/"))
}

fn place(source: &str, home: Option<&str>) -> Place {
    // systemd specifiers for a user unit: %t runtime directory, %h home,
    // %E configuration home, %D data home.
    let specifier = |prefix: &str, below_home: &str| {
        source
            .strip_prefix(prefix)
            .filter(|rest| rest.is_empty() || rest.starts_with('/'))
            .map(|rest| {
                if rest.contains('%') {
                    return Place::Unknown;
                }
                match (clean(&format!("{below_home}/{rest}")), prefix) {
                    (None, _) => Place::Unknown,
                    (Some(path), "%t") => Place::Runtime(path),
                    (Some(path), _) => Place::Home(path),
                }
            })
    };
    if let Some(found) = specifier("%t", "")
        .or_else(|| specifier("%h", ""))
        .or_else(|| specifier("%E", ".config"))
        .or_else(|| specifier("%D", ".local/share"))
    {
        return found;
    }
    if source.contains('%') {
        return Place::Unknown;
    }
    if !source.starts_with('/') {
        // Podman reads a source without a leading '/' or '.' as a volume name.
        return if source.starts_with('.') {
            Place::Unknown
        } else {
            Place::Named
        };
    }
    let Some(path) = clean(source) else {
        return Place::Unknown;
    };
    if let Some(home) = home.and_then(clean) {
        if path == home {
            return Place::Home(String::new());
        }
        if let Some(below) = path.strip_prefix(&home).and_then(|rest| rest.strip_prefix('/')) {
            return Place::Home(below.to_owned());
        }
    }
    // /run/user/<uid> is every account's runtime directory.
    let mut parts = path.splitn(4, '/');
    if (parts.next(), parts.next()) == (Some("run"), Some("user")) && parts.next().is_some() {
        return Place::Runtime(parts.next().unwrap_or_default().to_owned());
    }
    Place::Absolute(path)
}

/// The unit directories, below the home.
const UNIT_DIRECTORIES: &[&str] = &[
    ".config/containers/systemd",
    ".config/systemd",
    ".local/share/systemd/user",
];

fn covers(outer: &str, inner: &str) -> bool {
    outer.is_empty() || inner == outer || inner.strip_prefix(outer).is_some_and(|rest| rest.starts_with('/'))
}

/// Returns the mount source of a `Volume=` or `Mount=` value, or `None`
/// when the value mounts no host path.
fn mount_source<'a>(key: &str, value: &'a str) -> Option<&'a str> {
    if key == "Volume" {
        // SOURCE:DEST[:OPTIONS]. A value without ':' is an anonymous volume.
        return value.split_once(':').map(|(source, _)| source);
    }
    let field = |name: &str| {
        value.split(',').find_map(|part| {
            part.split_once('=')
                .filter(|(key, _)| *key == name)
                .map(|(_, value)| value)
        })
    };
    match field("type") {
        Some("bind" | "glob") | None => field("source").or_else(|| field("src")),
        _ => None,
    }
}

fn check_mount(entry: &Entry<'_>, is_template: bool, account: &Account<'_>) -> Option<(Code, String)> {
    if is_template && entry.value.contains("{{") {
        return Some((
            Code::UncheckedMount,
            format!(
                "{}= holds a template action, so forma cannot check what it mounts",
                entry.key
            ),
        ));
    }
    let source = mount_source(entry.key, &entry.value)?;
    let unsafe_mount = |what: &str| {
        Some((
            Code::UnsafeMount,
            format!(
                "{}={} mounts {what} into the container, which lets the container leave its sandbox",
                entry.key, entry.value
            ),
        ))
    };
    match place(source, account.home) {
        Place::Named => None,
        Place::Unknown => Some((
            Code::UncheckedMount,
            format!(
                "forma cannot tell where the source of {}={} points",
                entry.key, entry.value
            ),
        )),
        Place::Runtime(_) => unsafe_mount("the account's runtime directory, or a part of it"),
        Place::Home(below) => UNIT_DIRECTORIES
            .iter()
            .any(|directory| covers(&below, directory) || covers(directory, &below))
            .then(|| unsafe_mount("a directory that holds the account's units"))
            .flatten(),
        // "run/user" and its parents hold every runtime directory. A parent
        // of the home holds the unit directories; with an unknown home,
        // forma can only know the root.
        Place::Absolute(path) => (covers(&path, "run/user")
            || account.home.and_then(clean).is_some_and(|home| covers(&path, &home)))
        .then(|| unsafe_mount("a directory that holds the account's runtime or unit directories"))
        .flatten(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(home: Option<&'static str>) -> Account<'static> {
        Account {
            is_forma_image: &|reference| reference.starts_with("localhost/") && reference.contains(':'),
            home,
        }
    }

    fn codes(name: &str, text: &str) -> Vec<Code> {
        check(&UnitFile { name, text }, &account(Some("/var/home/app")))
            .into_iter()
            .map(|finding| finding.code)
            .collect()
    }

    const GOOD: &str = "[Container]\nImage=localhost/app/app:latest\nAutoUpdate=local\nPull=never\n";

    #[test]
    fn a_container_that_follows_the_rules_has_no_findings() {
        assert_eq!(codes("app.container", GOOD), []);
    }

    #[test]
    fn a_container_must_disable_pulls() {
        assert_eq!(
            codes("app.container", "[Container]\nImage=localhost/a:b\nAutoUpdate=local\n"),
            [Code::PullNotDisabled]
        );
        let text = "[Container]\nImage=localhost/a:b\nAutoUpdate=local\nPull=missing\n";
        let findings = check(
            &UnitFile {
                name: "app.container",
                text,
            },
            &account(None),
        );
        assert_eq!((findings[0].code, findings[0].line), (Code::PullNotDisabled, 4));
        // The last value wins, as in systemd.
        assert_eq!(
            codes("app.container", &format!("{GOOD}Pull=always\n")),
            [Code::PullNotDisabled]
        );
    }

    #[test]
    fn a_missing_auto_update_is_a_warning() {
        let found = codes("app.container", "[Container]\nImage=localhost/a:b\nPull=never\n");
        assert_eq!(found, [Code::NoAutoUpdate]);
        assert!(!found[0].is_error());
    }

    #[test]
    fn images_that_are_not_formas_are_refused() {
        for image in ["docker.io/library/alpine:3", "alpine", "other.image", "app.build"] {
            let text = format!("[Container]\nImage={image}\nPull=never\n");
            assert_eq!(codes("app.container", &text), [Code::ForeignImage], "{image}");
        }
        assert_eq!(
            codes("data.volume", "[Volume]\nDriver=image\nImage=quay.io/x/y:1\n"),
            [Code::ForeignImage]
        );
    }

    #[test]
    fn image_units_are_refused() {
        assert_eq!(codes("base.image", "[Image]\nImage=quay.io/x/y:1\n"), [Code::ImageUnit]);
    }

    #[test]
    fn images_come_from_containers_and_image_volumes_only() {
        let found = images(&UnitFile {
            name: "app.container",
            text: GOOD,
        });
        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].reference.as_str(), found[0].line, found[0].role),
            ("localhost/app/app:latest", 2, ImageRole::Container)
        );
        let volume = images(&UnitFile {
            name: "d.volume",
            text: "[Volume]\nDriver=image\nImage=localhost/d:1\n",
        });
        assert_eq!(volume[0].role, ImageRole::Volume);
        assert_eq!(
            images(&UnitFile {
                name: "p.volume",
                text: "[Volume]\nImage=localhost/d:1\n"
            }),
            []
        );
        assert_eq!(
            images(&UnitFile {
                name: "p.volume",
                text: "[Volume]\nVolumeName=x\n"
            }),
            []
        );
        assert_eq!(
            images(&UnitFile {
                name: "a.service",
                text: "[Service]\nImage=localhost/d:1\n"
            }),
            []
        );
        assert_eq!(
            images(&UnitFile {
                name: "a.container.gotmpl",
                text: "[Container]\nImage={{ .image }}\n"
            }),
            []
        );
    }

    #[test]
    fn checked_keys_must_be_literal_in_templates() {
        let action = "[Container]\nImage={{ .image }}\nAutoUpdate=local\nPull=never\n";
        assert_eq!(codes("app.container.gotmpl", action), [Code::TemplatedQuadletKey]);

        let block = "[Container]\nImage=localhost/a:b\nAutoUpdate=local\n{{ if .x }}\nPull=never\n{{- end }}\n";
        assert_eq!(codes("app.container.gotmpl", block), [Code::TemplatedQuadletKey]);

        // Other lines may use templates freely.
        let free = "[Container]\nImage=localhost/a:b\nAutoUpdate=local\nPull=never\n\
                    {{ range .ports }}\nPublishPort={{ . }}\n{{ end }}\nEnvironment=X={{ .x }}\n";
        assert_eq!(codes("app.container.gotmpl", free), []);

        // Without the .gotmpl suffix materia does not render, so braces are plain text.
        assert_eq!(
            codes(
                "app.container",
                "[Container]\nImage=localhost/a:b\nPull=never\nAutoUpdate=local\nExec={{x}}\n"
            ),
            []
        );
    }

    #[test]
    fn a_selinux_context_must_name_user_u() {
        let unit = |context: &str| format!("[Service]\nSELinuxContext={context}\nExecStart=/bin/true\n");
        assert_eq!(
            codes("p.service", &unit("unconfined_u:unconfined_r:moonshine_bus_t:s0")),
            [Code::ForeignSeLinuxUser]
        );
        assert_eq!(
            codes("p.service", &unit("-system_u:system_r:x_t:s0")),
            [Code::ForeignSeLinuxUser]
        );
        assert_eq!(codes("p.service", &unit("user_u:user_r:x_t:s0")), []);
        let quadlet = format!("{GOOD}[Service]\nSELinuxContext=unconfined_u:unconfined_r:x_t:s0\n");
        assert_eq!(codes("app.container", &quadlet), [Code::ForeignSeLinuxUser]);
        let templated = "[Service]\nSELinuxContext={{ .context }}\n";
        assert_eq!(codes("p.service.gotmpl", templated), [Code::TemplatedQuadletKey]);
    }

    #[test]
    fn the_reserved_section_takes_no_keys() {
        assert_eq!(codes("app.container", &format!("{GOOD}[X-Forma]\n")), []);
        assert_eq!(
            codes("app.container", &format!("{GOOD}[X-Forma]\nAnything=1\n")),
            [Code::UnknownXFormaKey]
        );
    }

    fn mount(line: &str) -> Vec<Code> {
        codes("app.container", &format!("{GOOD}{line}\n"))
    }

    #[test]
    fn named_volumes_and_ordinary_paths_are_fine() {
        for line in [
            "Volume=nvidia-driver.volume:/usr/nvidia:ro",
            "Volume=data:/data",
            "Volume=/data",
            "Volume=/etc/moonshine:/etc/moonshine:ro,Z",
            "Volume=%h/games:/games",
            "Volume=/var/home/app/.config/moonshine:/config",
            "Volume=%E/moonshine:/config",
            "Volume=%h/.local/share/containers/storage/volumes/x/_data:/x",
            "Volume=/run/udev:/run/udev:ro",
            "Mount=type=volume,source=data,destination=/data",
            "Mount=type=tmpfs,destination=/tmp",
            "Mount=type=image,source=localhost/a:b,destination=/x",
        ] {
            assert_eq!(mount(line), [], "{line}");
        }
    }

    #[test]
    fn the_runtime_directory_and_everything_in_it_are_refused() {
        for line in [
            "Volume=%t:/run/host",
            "Volume=%t/podman/podman.sock:/var/run/docker.sock",
            "Volume=%t/bus:/run/bus:ro",
            "Volume=/run/user/975/materia:/m",
            "Volume=/run/user/975:/r",
            "Volume=/run/user:/r",
            "Volume=/run:/r",
            "Volume=/:/host",
            "Volume=/run/../run/user/1/bus:/bus",
            "Mount=type=bind,source=%t/systemd/private,destination=/p",
            "Mount=type=bind,src=/run/user/975/bus,dst=/bus",
            "Mount=source=%t/bus,destination=/bus",
        ] {
            assert_eq!(mount(line), [Code::UnsafeMount], "{line}");
        }
    }

    #[test]
    fn unit_directories_and_their_parents_are_refused() {
        for line in [
            "Volume=%h:/home",
            "Volume=%h/.config:/config",
            "Volume=%E:/config:ro",
            "Volume=%E/containers/systemd:/units",
            "Volume=%E/systemd/user/x.service:/x",
            "Volume=%h/.local:/local",
            "Volume=%D/systemd/user:/units",
            "Volume=/var/home/app/.config/containers:/c",
            "Volume=/var/home/app:/home",
            "Volume=/var/home:/homes",
            "Volume=/var:/var",
            "Volume=%h/games/../.config:/c",
        ] {
            assert_eq!(mount(line), [Code::UnsafeMount], "{line}");
        }
    }

    #[test]
    fn mounts_forma_cannot_read_are_warnings() {
        for line in [
            "Volume=%S/x:/x",
            "Volume=%h/%u:/x",
            "Volume=./relative:/x",
            "Volume=%h/../..:/x",
        ] {
            assert_eq!(mount(line), [Code::UncheckedMount], "{line}");
        }
        let templated = format!("{GOOD}Volume={{{{ .dir }}}}:/x\n");
        assert_eq!(codes("app.container.gotmpl", &templated), [Code::UncheckedMount]);
    }

    #[test]
    fn without_a_known_home_literal_home_paths_cannot_be_matched() {
        let file = UnitFile {
            name: "app.container",
            text: &format!("{GOOD}Volume=/var/home/app/.config:/c\n"),
        };
        assert_eq!(check(&file, &account(None)), []);
        let file = UnitFile {
            name: "app.container",
            text: &format!("{GOOD}Volume=%h/.config:/c\n"),
        };
        assert_eq!(check(&file, &account(None))[0].code, Code::UnsafeMount);
    }

    #[test]
    fn files_that_are_not_units_are_ignored() {
        assert_eq!(codes("build/app.Dockerfile", "FROM scratch\n"), []);
        assert_eq!(codes("MANIFEST.toml", "[Container]\nImage=x\n"), []);
        assert_eq!(kind_of("a.container.gotmpl"), Some(UnitKind::Container));
        assert_eq!(kind_of("a.service"), Some(UnitKind::Systemd));
        assert_eq!(kind_of("a.kube"), Some(UnitKind::OtherQuadlet));
        assert_eq!(kind_of("README"), None);
    }

    #[test]
    fn template_blocks_are_tracked_across_lines() {
        let text = "a\n{{ if .x }}\nb\n{{ else }}\nc\n{{ end }}\nd\n{{- range .y -}} e {{- end -}}\nf\n";
        assert_eq!(
            lines_in_blocks(text),
            [false, true, true, true, true, true, false, false, false]
        );
    }
}
