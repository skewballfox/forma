//! Finds the base images a Containerfile names (architecture 5.6, "How
//! forma pulls base images", step 1).
//!
//! A base is named by `FROM`, `COPY --from=` or `RUN --mount=…,from=`.
//! `ARG` values come from the image's `BuildArgs`, then from the `ARG`
//! defaults, with the scoping buildah uses: `FROM` sees only the `ARG`s
//! declared before the first `FROM`; the other instructions see the `ARG`s
//! declared in their stage. Earlier stages, `scratch` and forma's own
//! images (`localhost/…`) are not pulled.
//!
//! Forma does not guess. An `ARG` with no value, a short name that only
//! `registries.conf` could resolve, and an expansion form this reader does
//! not know are errors, not skipped.
//!
//! This reader does not need to see every base: forma builds with
//! `--pull=never`, so a base it missed fails the build ("image not known")
//! instead of being pulled unchecked.

use std::collections::BTreeMap;
use std::fmt;

use forma_config::BaseImages;
use forma_config::types::{BaseRequirement, BuildArgName, ImageRef};
use forma_signing_trust::covering_scope;

/// A base image from a registry, which forma pulls and checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBase {
    /// The reference after `ARG` expansion, as buildah will pull it.
    pub reference: String,
    /// The reference without tag and digest, which `Trust` scopes match.
    pub repository: String,
    /// The line of the Containerfile that first names it, from 1.
    pub line: usize,
}

/// One of forma's own images, used as a base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnBase {
    /// The image.
    pub image: ImageRef,
    /// The line of the Containerfile that first names it, from 1.
    pub line: usize,
}

/// The images a build needs before it starts, each listed once, in the
/// order the Containerfile first names them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bases {
    /// Images forma pulls and checks.
    pub remote: Vec<RemoteBase>,
    /// Forma's own images, which must be built first.
    pub own: Vec<OwnBase>,
}

/// Why forma cannot tell what a build would pull, or must not pull it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BaseError {
    /// A base reference uses an `ARG` that has no value.
    #[error(
        "line {line}: the base image {text:?} needs ARG {arg}, which has no value; give it a default or a BuildArgs entry"
    )]
    Unresolved {
        /// The line.
        line: usize,
        /// The reference as written.
        text: String,
        /// The `ARG` without a value.
        arg: String,
    },
    /// A base reference names no registry.
    #[error(
        "line {line}: the base image {reference:?} names no registry; write it in full, such as docker.io/library/{reference}"
    )]
    ShortName {
        /// The line.
        line: usize,
        /// The reference.
        reference: String,
    },
    /// A base reference is not an image reference.
    #[error("line {line}: the base image {reference:?} is not a valid reference: {reason}")]
    InvalidReference {
        /// The line.
        line: usize,
        /// The reference.
        reference: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The Containerfile cannot be read.
    #[error("line {line}: {reason}")]
    Syntax {
        /// The line.
        line: usize,
        /// What is wrong.
        reason: String,
    },
    /// `Require = "all"`, and no `Trust` entry covers this base.
    #[error("line {line}: the base image {reference:?} matches no Trust entry, and Require is \"all\"")]
    NotTrusted {
        /// The line.
        line: usize,
        /// The reference.
        reference: String,
    },
}

impl BaseError {
    /// The error's name, as the fixtures' `EXPECTED_ERROR` files write it.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unresolved { .. } => "UnresolvedBaseImage",
            Self::ShortName { .. } => "ShortBaseImageName",
            Self::InvalidReference { .. } => "InvalidBaseImage",
            Self::Syntax { .. } => "ContainerfileSyntax",
            Self::NotTrusted { .. } => "BaseImageNotTrusted",
        }
    }

    /// The line of the Containerfile the error is about.
    #[must_use]
    pub fn line(&self) -> usize {
        match self {
            Self::Unresolved { line, .. }
            | Self::ShortName { line, .. }
            | Self::InvalidReference { line, .. }
            | Self::Syntax { line, .. }
            | Self::NotTrusted { line, .. } => *line,
        }
    }
}

/// Reads the bases of a Containerfile, given the image's `BuildArgs`.
///
/// # Errors
///
/// Returns every base that cannot be resolved or is not a full reference,
/// or the first syntax error.
pub fn bases(containerfile: &str, build_args: &BTreeMap<BuildArgName, String>) -> Result<Bases, Vec<BaseError>> {
    let instructions = instructions(containerfile).map_err(|error| vec![error])?;
    let build_args: BTreeMap<&str, &str> = build_args
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut reader = Reader {
        build_args: &build_args,
        global: Scope::default(),
        stage: Scope::default(),
        stages: Vec::new(),
        bases: Bases::default(),
        errors: Vec::new(),
    };
    for instruction in &instructions {
        reader.read(instruction);
    }
    if reader.errors.is_empty() {
        Ok(reader.bases)
    } else {
        Err(reader.errors)
    }
}

/// Checks `Require = "all"`: every remote base needs a `Trust` entry. With
/// `none` or `listed` there is nothing to check before the pull, which
/// enforces whatever entries match.
///
/// # Errors
///
/// Returns one error for each remote base no entry covers.
pub fn require_trust(bases: &Bases, rules: &BaseImages) -> Result<(), Vec<BaseError>> {
    if rules.require != BaseRequirement::All {
        return Ok(());
    }
    let errors: Vec<BaseError> = bases
        .remote
        .iter()
        .filter(|base| covering_scope(rules, &base.repository).is_none())
        .map(|base| BaseError::NotTrusted {
            line: base.line,
            reference: base.reference.clone(),
        })
        .collect();
    if errors.is_empty() { Ok(()) } else { Err(errors) }
}

/// One instruction, with continuation lines joined and heredoc bodies
/// left out.
#[derive(Debug, PartialEq, Eq)]
struct Instruction {
    line: usize,
    /// The keyword, upper case.
    keyword: String,
    /// What follows the keyword.
    rest: String,
    /// The escape character, `\` unless a parser directive changes it.
    escape: char,
}

/// Splits a Containerfile into instructions.
fn instructions(text: &str) -> Result<Vec<Instruction>, BaseError> {
    let lines: Vec<&str> = text.lines().collect();
    let mut escape = '\\';
    let mut index = 0;
    // Parser directives: `# key=value` lines before anything else.
    while let Some(line) = lines.get(index) {
        let Some((key, value)) = line.trim().strip_prefix('#').and_then(|rest| rest.split_once('=')) else {
            break;
        };
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() || !key.chars().all(|ch| ch.is_ascii_alphabetic()) {
            break;
        }
        if key == "escape" {
            escape = match value.trim() {
                "\\" => '\\',
                "`" => '`',
                other => {
                    return Err(BaseError::Syntax {
                        line: index + 1,
                        reason: format!("the escape directive takes \\ or `, not {other:?}"),
                    });
                }
            };
        }
        index += 1;
    }

    let mut result = Vec::new();
    while index < lines.len() {
        let first = index;
        let trimmed = lines[index].trim();
        index += 1;
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut logical = String::new();
        let mut current = trimmed;
        while let Some(head) = current.strip_suffix(escape) {
            logical.push_str(head);
            logical.push(' ');
            // Comment and empty lines inside a continuation are dropped.
            while lines
                .get(index)
                .is_some_and(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
            {
                index += 1;
            }
            current = lines.get(index).map_or("", |next| next.trim());
            index += 1;
        }
        logical.push_str(current);
        let (keyword, rest) = logical
            .split_once(char::is_whitespace)
            .map_or((logical.as_str(), ""), |(keyword, rest)| (keyword, rest.trim()));
        let keyword = keyword.to_ascii_uppercase();
        if matches!(keyword.as_str(), "RUN" | "COPY" | "ADD") {
            for (delimiter, strip_tabs) in heredoc_delimiters(rest) {
                loop {
                    let Some(body) = lines.get(index) else {
                        return Err(BaseError::Syntax {
                            line: first + 1,
                            reason: format!("the heredoc {delimiter} is not closed"),
                        });
                    };
                    index += 1;
                    let body = if strip_tabs {
                        body.trim_start_matches('\t')
                    } else {
                        body
                    };
                    if body == delimiter {
                        break;
                    }
                }
            }
        }
        result.push(Instruction {
            line: first + 1,
            rest: rest.to_owned(),
            keyword,
            escape,
        });
    }
    Ok(result)
}

/// The heredocs a line opens, in order: each delimiter, and whether `<<-`
/// strips leading tabs from the body.
fn heredoc_delimiters(line: &str) -> Vec<(&str, bool)> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find("<<") {
        let after = &rest[at + 2..];
        rest = after;
        // `<<<` is a here-string, not a heredoc.
        if after.starts_with('<') {
            rest = after.trim_start_matches('<');
            continue;
        }
        let (strip_tabs, after) = after.strip_prefix('-').map_or((false, after), |after| (true, after));
        let (quote, after) = match after.chars().next() {
            Some(quote @ ('"' | '\'')) => (Some(quote), &after[1..]),
            _ => (None, after),
        };
        let end = after
            .find(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
            .unwrap_or(after.len());
        let delimiter = &after[..end];
        if delimiter.is_empty() || quote.is_some_and(|quote| !after[end..].starts_with(quote)) {
            continue;
        }
        found.push((delimiter, strip_tabs));
        rest = &after[end..];
    }
    found
}

/// What an `ARG` holds.
#[derive(Debug, Clone)]
enum Arg {
    Set(String),
    /// No value: the name of the `ARG` that has none, which may be another
    /// one the default refers to.
    Missing(String),
}

#[derive(Debug, Default)]
struct Scope(BTreeMap<String, Arg>);

impl Scope {
    fn get(&self, name: &str) -> Arg {
        self.0
            .get(name)
            .cloned()
            .unwrap_or_else(|| Arg::Missing(name.to_owned()))
    }
}

struct Reader<'a> {
    build_args: &'a BTreeMap<&'a str, &'a str>,
    /// `ARG`s declared before the first `FROM`.
    global: Scope,
    /// `ARG`s declared in the current stage.
    stage: Scope,
    /// The stage names so far, lower case; `None` for an unnamed stage.
    stages: Vec<Option<String>>,
    bases: Bases,
    errors: Vec<BaseError>,
}

impl Reader<'_> {
    fn read(&mut self, instruction: &Instruction) {
        match instruction.keyword.as_str() {
            "ARG" => self.arg(instruction),
            "FROM" => self.from(instruction),
            "COPY" => {
                for flag in flags(&instruction.rest) {
                    if let Some(source) = flag.strip_prefix("--from=") {
                        self.base_or_stage(instruction, source);
                    }
                }
            }
            "RUN" => {
                for flag in flags(&instruction.rest) {
                    let Some(mount) = flag.strip_prefix("--mount=") else {
                        continue;
                    };
                    for option in unquote(mount).split(',') {
                        if let Some(source) = option.strip_prefix("from=") {
                            self.base_or_stage(instruction, source);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn arg(&mut self, instruction: &Instruction) {
        let in_stage = !self.stages.is_empty();
        for declaration in instruction.rest.split_whitespace() {
            let (name, default) = declaration
                .split_once('=')
                .map_or((declaration, None), |(name, default)| (name, Some(default)));
            let value = if let Some(value) = self.build_args.get(name) {
                Arg::Set((*value).to_owned())
            } else if let Some(default) = default {
                let scope = if in_stage { &self.stage } else { &self.global };
                match expand(unquote(default), instruction.escape, scope) {
                    Ok(value) => Arg::Set(value),
                    Err(Expansion::Missing(missing)) => Arg::Missing(missing),
                    Err(Expansion::Unsupported(form)) => {
                        self.errors.push(unsupported(instruction.line, &form));
                        Arg::Missing(name.to_owned())
                    }
                }
            } else if in_stage {
                // `ARG NAME` in a stage takes the value declared before the first `FROM`.
                self.global.get(name)
            } else {
                Arg::Missing(name.to_owned())
            };
            let scope = if in_stage { &mut self.stage } else { &mut self.global };
            scope.0.insert(name.to_owned(), value);
        }
    }

    fn from(&mut self, instruction: &Instruction) {
        let words: Vec<&str> = instruction
            .rest
            .split_whitespace()
            .filter(|word| !word.starts_with("--"))
            .collect();
        let (image, name) = match words.as_slice() {
            [image] => (*image, None),
            [image, keyword, name] if keyword.eq_ignore_ascii_case("as") => (*image, Some(name.to_ascii_lowercase())),
            _ => {
                self.errors.push(BaseError::Syntax {
                    line: instruction.line,
                    reason: format!(
                        "FROM takes an image and an optional AS name, not {:?}",
                        instruction.rest
                    ),
                });
                return;
            }
        };
        if let Some(reference) = self.resolve(instruction, image, Which::Global)
            && !reference.eq_ignore_ascii_case("scratch")
            && !self.is_stage(&reference)
        {
            self.add(instruction.line, &reference);
        }
        self.stages.push(name);
        self.stage = Scope::default();
    }

    fn base_or_stage(&mut self, instruction: &Instruction, source: &str) {
        let Some(reference) = self.resolve(instruction, unquote(source), Which::Stage) else {
            return;
        };
        let stage_index = reference.parse::<usize>().is_ok_and(|index| index < self.stages.len());
        if !stage_index && !self.is_stage(&reference) {
            self.add(instruction.line, &reference);
        }
    }

    fn is_stage(&self, reference: &str) -> bool {
        let lower = reference.to_ascii_lowercase();
        self.stages.iter().flatten().any(|stage| *stage == lower)
    }

    fn resolve(&mut self, instruction: &Instruction, text: &str, which: Which) -> Option<String> {
        let scope = match which {
            Which::Global => &self.global,
            Which::Stage => &self.stage,
        };
        match expand(text, instruction.escape, scope) {
            Ok(reference) => Some(reference),
            Err(Expansion::Missing(arg)) => {
                self.errors.push(BaseError::Unresolved {
                    line: instruction.line,
                    text: text.to_owned(),
                    arg,
                });
                None
            }
            Err(Expansion::Unsupported(form)) => {
                self.errors.push(unsupported(instruction.line, &form));
                None
            }
        }
    }

    fn add(&mut self, line: usize, reference: &str) {
        match classify(reference) {
            Ok(Classified::Own(image)) => {
                if !self.bases.own.iter().any(|base| base.image == image) {
                    self.bases.own.push(OwnBase { image, line });
                }
            }
            Ok(Classified::Remote(repository)) => {
                if !self.bases.remote.iter().any(|base| base.reference == reference) {
                    self.bases.remote.push(RemoteBase {
                        reference: reference.to_owned(),
                        repository,
                        line,
                    });
                }
            }
            Err(Classify::Short) => self.errors.push(BaseError::ShortName {
                line,
                reference: reference.to_owned(),
            }),
            Err(Classify::Invalid(reason)) => self.errors.push(BaseError::InvalidReference {
                line,
                reference: reference.to_owned(),
                reason,
            }),
        }
    }
}

#[derive(Clone, Copy)]
enum Which {
    Global,
    Stage,
}

/// The `--flag` words at the start of an instruction.
fn flags(rest: &str) -> impl Iterator<Item = &str> {
    rest.split_whitespace().take_while(|word| word.starts_with("--"))
}

fn unquote(text: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = text.strip_prefix(quote).and_then(|text| text.strip_suffix(quote)) {
            return inner;
        }
    }
    text
}

fn unsupported(line: usize, form: &str) -> BaseError {
    BaseError::Syntax {
        line,
        reason: format!("forma cannot expand {form:?}; use $NAME, ${{NAME}}, ${{NAME:-word}} or ${{NAME:+word}}"),
    }
}

enum Expansion {
    /// The `ARG` that has no value.
    Missing(String),
    /// A form of `${…}` this reader does not handle.
    Unsupported(String),
}

/// Expands `$NAME`, `${NAME}`, `${NAME:-word}` and `${NAME:+word}`. An
/// escaped `$` stays a `$`.
fn expand(text: &str, escape: char, scope: &Scope) -> Result<String, Expansion> {
    let set = |name: &str| match scope.get(name) {
        Arg::Set(value) if !value.is_empty() => Some(value),
        _ => None,
    };
    let mut out = String::with_capacity(text.len());
    let mut chars = text.char_indices().peekable();
    while let Some((at, ch)) = chars.next() {
        if ch == escape && chars.peek().is_some_and(|&(_, next)| next == '$') {
            out.push('$');
            chars.next();
            continue;
        }
        if ch != '$' {
            out.push(ch);
            continue;
        }
        match chars.peek().copied() {
            Some((open, '{')) => {
                let Some(close) = text[open..].find('}').map(|close| open + close) else {
                    return Err(Expansion::Unsupported(text[at..].to_owned()));
                };
                let inner = &text[open + 1..close];
                while chars.next_if(|&(index, _)| index <= close).is_some() {}
                if let Some((name, word)) = inner.split_once(":-") {
                    match set(name) {
                        Some(value) => out.push_str(&value),
                        None => out.push_str(&expand(word, escape, scope)?),
                    }
                } else if let Some((name, word)) = inner.split_once(":+") {
                    if set(name).is_some() {
                        out.push_str(&expand(word, escape, scope)?);
                    }
                } else if is_name(inner) {
                    out.push_str(&value(scope, inner)?);
                } else {
                    return Err(Expansion::Unsupported(text[at..=close].to_owned()));
                }
            }
            Some((start, first)) if first.is_ascii_alphabetic() || first == '_' => {
                let end = text[start..]
                    .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                    .map_or(text.len(), |end| start + end);
                while chars.next_if(|&(index, _)| index < end).is_some() {}
                out.push_str(&value(scope, &text[start..end])?);
            }
            _ => out.push('$'),
        }
    }
    Ok(out)
}

fn value(scope: &Scope, name: &str) -> Result<String, Expansion> {
    match scope.get(name) {
        Arg::Set(value) => Ok(value),
        Arg::Missing(missing) => Err(Expansion::Missing(missing)),
    }
}

fn is_name(text: &str) -> bool {
    text.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_')
        && text.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

enum Classified {
    Own(ImageRef),
    /// The repository, without tag and digest.
    Remote(String),
}

enum Classify {
    Short,
    Invalid(&'static str),
}

/// Sorts a reference into forma's own images and remote ones.
fn classify(reference: &str) -> Result<Classified, Classify> {
    if reference.starts_with("localhost/") {
        return ImageRef::new(reference).map(Classified::Own).map_err(Classify::Invalid);
    }
    let without_digest = match reference.split_once('@') {
        Some((name, digest)) => {
            let valid = digest.split_once(':').is_some_and(|(algorithm, hex)| {
                !algorithm.is_empty()
                    && !hex.is_empty()
                    && hex.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
            });
            if !valid {
                return Err(Classify::Invalid("its digest is not <algorithm>:<lower-case hex>"));
            }
            name
        }
        None => reference,
    };
    let last_slash = without_digest.rfind('/');
    let repository = match without_digest.rfind(':') {
        Some(colon) if last_slash.is_none_or(|slash| colon > slash) => {
            let tag = &without_digest[colon + 1..];
            let tag_ok = !tag.is_empty()
                && tag.len() <= 128
                && tag
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'));
            if !tag_ok {
                return Err(Classify::Invalid("its tag is not letters, digits, '_', '.' and '-'"));
            }
            &without_digest[..colon]
        }
        _ => without_digest,
    };
    let Some((host, path)) = repository.split_once('/') else {
        return Err(Classify::Short);
    };
    // As in containers/image: the first part is a registry if it has a dot or a port.
    if !(host.contains('.') || host.contains(':')) {
        return Err(Classify::Short);
    }
    let path_ok = path.split('/').all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-'))
    });
    let host_ok = host
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-' | ':'));
    if !(path_ok && host_ok) {
        return Err(Classify::Invalid(
            "its repository is not lower-case registry and path parts",
        ));
    }
    Ok(Classified::Remote(repository.to_owned()))
}

impl fmt::Display for RemoteBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reference)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use forma_config::types::TrustScope;
    use forma_config::{Located, Origin, Trust, TrustRule};

    use super::*;

    fn args(pairs: &[(&str, &str)]) -> BTreeMap<BuildArgName, String> {
        pairs
            .iter()
            .map(|(name, value)| (BuildArgName::new(name).unwrap(), (*value).to_owned()))
            .collect()
    }

    fn remote(text: &str) -> Vec<String> {
        bases(text, &BTreeMap::new())
            .unwrap()
            .remote
            .into_iter()
            .map(|base| base.reference)
            .collect()
    }

    fn codes(text: &str, build_args: &[(&str, &str)]) -> Vec<&'static str> {
        bases(text, &args(build_args))
            .unwrap_err()
            .iter()
            .map(BaseError::code)
            .collect()
    }

    #[test]
    fn from_copy_and_mount_name_bases() {
        let text = "FROM quay.io/a/b:1 AS build\n\
                    RUN --mount=type=bind,from=ghcr.io/c/d:2,target=/x make\n\
                    COPY --from=registry.example.com:5000/e@sha256:abc0 /f /f\n\
                    FROM quay.io/a/b:1\n";
        let found = bases(text, &BTreeMap::new()).unwrap();
        let pairs: Vec<(&str, &str, usize)> = found
            .remote
            .iter()
            .map(|base| (base.reference.as_str(), base.repository.as_str(), base.line))
            .collect();
        assert_eq!(
            pairs,
            [
                ("quay.io/a/b:1", "quay.io/a/b", 1),
                ("ghcr.io/c/d:2", "ghcr.io/c/d", 2),
                (
                    "registry.example.com:5000/e@sha256:abc0",
                    "registry.example.com:5000/e",
                    3
                ),
            ]
        );
        assert_eq!(found.own, []);
    }

    #[test]
    fn stages_scratch_and_stage_numbers_are_not_pulled() {
        let text = "FROM quay.io/a/b:1 AS Build\nFROM scratch\nCOPY --from=build /x /x\nCOPY --from=0 /y /y\n\
                    FROM BUILD\nRUN --mount=from=build,target=/z true\n";
        assert_eq!(remote(text), ["quay.io/a/b:1"]);
    }

    #[test]
    fn forma_images_are_listed_apart() {
        let found = bases(
            "FROM localhost/moonshine/moonshine:patches AS m\nFROM quay.io/a/b:1\n",
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(found.own.len(), 1);
        assert_eq!(found.own[0].image.short(), "moonshine/moonshine:patches");
        assert_eq!(remote("FROM localhost/a/b:1\n"), Vec::<String>::new());
    }

    #[test]
    fn from_sees_the_args_before_the_first_from() {
        let text = "ARG V=44\nARG BASE=quay.io/f/m:${V}\nFROM $BASE\nARG V=45\nFROM quay.io/x/y:$V\n";
        assert_eq!(remote(text), ["quay.io/f/m:44", "quay.io/x/y:44"]);
    }

    #[test]
    fn build_args_win_over_defaults() {
        let text = "ARG V=44\nFROM quay.io/f/m:${V}\n";
        assert_eq!(
            bases(text, &args(&[("V", "45")])).unwrap().remote[0].reference,
            "quay.io/f/m:45"
        );
    }

    #[test]
    fn a_stage_sees_only_the_args_it_declares() {
        // Declared again in the stage, the ARG takes the value from before the first FROM.
        let text = "ARG S=quay.io/a/b:1\nFROM scratch\nARG S\nCOPY --from=$S /x /x\n";
        assert_eq!(remote(text), ["quay.io/a/b:1"]);
        let text = "ARG S=quay.io/a/b:1\nFROM scratch\nCOPY --from=$S /x /x\n";
        assert_eq!(codes(text, &[]), ["UnresolvedBaseImage"]);
    }

    #[test]
    fn default_and_alternative_forms_expand() {
        let text = "ARG E\nARG T=2\nFROM quay.io/a/b:${E:-1}\nFROM quay.io/c/d${T:+:$T}\nFROM quay.io/e/f${E:+:x}\n";
        assert_eq!(remote(text), ["quay.io/a/b:1", "quay.io/c/d:2", "quay.io/e/f"]);
    }

    #[test]
    fn an_arg_without_a_value_is_an_error_naming_it() {
        let errors = bases("ARG BASE\nFROM ${BASE}\n", &BTreeMap::new()).unwrap_err();
        assert_eq!(
            errors,
            [BaseError::Unresolved {
                line: 2,
                text: "${BASE}".to_owned(),
                arg: "BASE".to_owned()
            }]
        );
        // The missing ARG is the one a default refers to.
        let errors = bases("ARG V\nARG BASE=quay.io/a/b:$V\nFROM $BASE\n", &BTreeMap::new()).unwrap_err();
        assert!(matches!(&errors[0], BaseError::Unresolved { arg, .. } if arg == "V"));
        // Never declared at all.
        assert_eq!(codes("FROM $NOPE\n", &[]), ["UnresolvedBaseImage"]);
    }

    #[test]
    fn an_arg_no_base_uses_may_stay_empty() {
        assert_eq!(
            remote("FROM quay.io/a/b:1\nARG COMMIT\nRUN echo $COMMIT\n"),
            ["quay.io/a/b:1"]
        );
    }

    #[test]
    fn short_names_and_bad_references_are_errors() {
        assert_eq!(codes("FROM alpine:3\n", &[]), ["ShortBaseImageName"]);
        assert_eq!(codes("FROM library/alpine\n", &[]), ["ShortBaseImageName"]);
        assert_eq!(codes("FROM quay.io/A/b\n", &[]), ["InvalidBaseImage"]);
        assert_eq!(codes("FROM quay.io/a/b@sha256\n", &[]), ["InvalidBaseImage"]);
        assert_eq!(codes("FROM localhost/a\n", &[]), ["InvalidBaseImage"]);
        assert_eq!(codes("FROM quay.io/a/b:${V#x}\n", &[]), ["ContainerfileSyntax"]);
        // Every bad base is reported, not just the first.
        assert_eq!(
            codes("FROM a\nFROM b\n", &[]),
            ["ShortBaseImageName", "ShortBaseImageName"]
        );
    }

    #[test]
    fn continuations_comments_and_heredocs_are_not_instructions() {
        let text = "# syntax=docker/dockerfile:1\n\
                    FROM \\\n  # a comment inside\n  quay.io/a/b:1 \\\n  AS one\n\
                    RUN <<EOF cat > /x && <<-'TWO' sh\n\
                    FROM quay.io/not/a:base\n\
                    EOF\n\
                    \tCOPY --from=quay.io/not/either:base\n\
                    \tTWO\n\
                    COPY --from=one /x /x\n";
        let found = bases(text, &BTreeMap::new()).unwrap();
        assert_eq!(found.remote.len(), 1);
        assert_eq!(found.remote[0].reference, "quay.io/a/b:1");
        assert_eq!(found.remote[0].line, 2);
    }

    #[test]
    fn an_unclosed_heredoc_is_an_error() {
        assert_eq!(
            codes("FROM quay.io/a/b:1\nRUN <<EOF\necho\n", &[]),
            ["ContainerfileSyntax"]
        );
    }

    #[test]
    fn the_escape_directive_changes_continuations_and_escapes() {
        let text = "# escape=`\nARG A=quay.io/a/b:1\nFROM `\n $A\nRUN echo `$A\n";
        assert_eq!(remote(text), ["quay.io/a/b:1"]);
        // An escaped $ is not expanded.
        assert_eq!(codes("FROM quay.io/a/b:\\$V\n", &[]), ["InvalidBaseImage"]);
    }

    #[test]
    fn keywords_and_as_ignore_case() {
        assert_eq!(
            remote("from quay.io/a/b:1 as x\ncopy --from=X /a /a\n"),
            ["quay.io/a/b:1"]
        );
    }

    fn rules(require: BaseRequirement, scopes: &[&str]) -> BaseImages {
        let file: Arc<Path> = Arc::from(Path::new("MANIFEST.toml"));
        BaseImages {
            require,
            trust: scopes
                .iter()
                .map(|scope| Located {
                    value: Trust {
                        scope: TrustScope::new(scope).unwrap(),
                        rule: TrustRule::SigstoreKeyless {
                            issuer: "https://issuer".to_owned(),
                            subject: "a@b".to_owned(),
                        },
                    },
                    at: Origin::file(&file),
                })
                .collect(),
        }
    }

    #[test]
    fn require_all_needs_an_entry_for_every_remote_base() {
        let found = bases(
            "FROM registry.fedoraproject.org/fedora-minimal:44\nFROM docker.io/library/alpine:3\nFROM localhost/a/b:1\n",
            &BTreeMap::new(),
        )
        .unwrap();
        let scopes = ["registry.fedoraproject.org"];
        assert_eq!(require_trust(&found, &rules(BaseRequirement::None, &scopes)), Ok(()));
        assert_eq!(require_trust(&found, &rules(BaseRequirement::Listed, &scopes)), Ok(()));
        assert_eq!(
            require_trust(&found, &rules(BaseRequirement::All, &scopes)),
            Err(vec![BaseError::NotTrusted {
                line: 2,
                reference: "docker.io/library/alpine:3".to_owned()
            }])
        );
        let scopes = ["registry.fedoraproject.org", "docker.io/library"];
        assert_eq!(require_trust(&found, &rules(BaseRequirement::All, &scopes)), Ok(()));
    }
}
