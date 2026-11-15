//! The keys forma knows, and the two operations that depend on them:
//! renaming keys to their documented spelling, and merging host changes.
//!
//! Materia matches manifest keys exactly first, then without case
//! (architecture 2.1). [`canonical`] does the same in one pass and renames
//! each key to the spelling in [`Shape`]. The decoder then matches exactly.

use crate::error::ManifestError;
use crate::raw::{Entry, Node, Table, Value};

/// What forma expects under one key.
#[derive(Debug)]
pub(crate) enum Shape {
    /// A value forma reads as it is: a scalar or a list of scalars.
    Leaf,
    /// A key that only the host configuration may set.
    HostOnly,
    /// A table whose keys are data, such as build arguments.
    Free,
    /// A table whose keys are names, such as host names. Each value has the
    /// inner shape.
    Map(&'static Shape),
    /// A table with known keys. A strict table rejects any other key.
    Table { fields: &'static [Field], strict: bool },
    /// A list of tables. `key` names the field that identifies an item when
    /// an extension merges into the list.
    List { item: &'static Shape, key: &'static str },
}

pub(crate) type Field = (&'static str, Shape);

const fn strict(fields: &'static [Field]) -> Shape {
    Shape::Table { fields, strict: true }
}

const fn open(fields: &'static [Field]) -> Shape {
    Shape::Table { fields, strict: false }
}

static TRUST: Shape = strict(&[
    ("Scope", Shape::Leaf),
    ("Type", Shape::Leaf),
    ("Key", Shape::Leaf),
    ("Issuer", Shape::Leaf),
    ("Subject", Shape::Leaf),
]);

static BASE_IMAGES_FIELDS: &[Field] = &[
    ("Require", Shape::Leaf),
    (
        "Trust",
        Shape::List {
            item: &TRUST,
            key: "Scope",
        },
    ),
    ("HostPolicy", Shape::HostOnly),
];

static GROUP: Shape = strict(&[("Name", Shape::Leaf), ("System", Shape::Leaf)]);

static IMAGE: Shape = strict(&[
    ("Tag", Shape::Leaf),
    ("Containerfile", Shape::Leaf),
    ("Context", Shape::Leaf),
    ("BuildArgs", Shape::Free),
    ("DependsOn", Shape::Leaf),
    (
        "Source",
        strict(&[("Git", Shape::Leaf), ("Ref", Shape::Leaf), ("CommitArg", Shape::Leaf)]),
    ),
    (
        "Update",
        strict(&[("Schedule", Shape::Leaf), ("Triggers", Shape::Leaf)]),
    ),
]);

/// The `[Forma]` table of a component.
pub(crate) static COMPONENT_FORMA_FIELDS: &[Field] = &[
    (
        "Account",
        strict(&[
            ("Name", Shape::Leaf),
            ("Home", Shape::Leaf),
            ("Linger", Shape::Leaf),
            ("SubIds", Shape::Leaf),
            ("MemberOf", Shape::Leaf),
        ]),
    ),
    (
        "Groups",
        Shape::List {
            item: &GROUP,
            key: "Name",
        },
    ),
    (
        "Images",
        Shape::List {
            item: &IMAGE,
            key: "Tag",
        },
    ),
    (
        "Update",
        strict(&[("Schedule", Shape::Leaf), ("Triggers", Shape::Leaf)]),
    ),
    (
        "SELinux",
        strict(&[
            ("Modules", Shape::Leaf),
            ("Templates", Shape::Leaf),
            ("Relabel", Shape::Leaf),
        ]),
    ),
    ("BaseImages", strict(BASE_IMAGES_FIELDS)),
];

/// The `[Forma]` table of the repository manifest, and of one host in it.
pub(crate) static GLOBAL_FORMA_FIELDS: &[Field] = &[
    ("Signing", Shape::Leaf),
    ("Builder", strict(&[("Account", Shape::Leaf), ("SubIds", Shape::Leaf)])),
    ("Signer", strict(&[("Account", Shape::Leaf)])),
    ("Store", strict(&[("Root", Shape::Leaf)])),
    ("BaseImages", strict(BASE_IMAGES_FIELDS)),
];

/// What a host changes about one component.
static COMPONENT_PATCH: Shape = open(&[("Forma", strict(COMPONENT_FORMA_FIELDS)), ("Settings", Shape::Leaf)]);

static HOST: Shape = open(&[
    ("Forma", strict(GLOBAL_FORMA_FIELDS)),
    ("Overrides", Shape::Map(&COMPONENT_PATCH)),
    ("Extensions", Shape::Map(&COMPONENT_PATCH)),
]);

/// The repository manifest. Materia owns every key but `Forma`.
pub(crate) static REPOSITORY_FIELDS: &[Field] = &[("Forma", strict(GLOBAL_FORMA_FIELDS)), ("Hosts", Shape::Map(&HOST))];

/// A component manifest. Materia owns every key but `Forma`.
pub(crate) static COMPONENT_FIELDS: &[Field] = &[("Forma", strict(COMPONENT_FORMA_FIELDS)), ("Settings", Shape::Leaf)];

/// The installed `.component_version` file.
pub(crate) static COMPONENT_VERSION_FIELDS: &[Field] = &[("Version", Shape::Leaf), ("User", Shape::Leaf)];

/// Renames every known key of `table` to its documented spelling.
///
/// `name` describes the table in error messages, for example `[Forma]`.
///
/// # Errors
///
/// - [`ManifestError::KeyCaseCollision`] if two keys name the same field.
/// - [`ManifestError::UnknownKey`] if a strict table holds a key not in `fields`.
/// - [`ManifestError::WrongType`] if a table or a list of tables is something else.
/// - [`ManifestError::HostOnlySetting`] for a key the repository may not set.
pub(crate) fn canonical(
    table: &Table,
    fields: &'static [Field],
    strict: bool,
    name: &str,
) -> Result<Table, ManifestError> {
    let mut result = Table::default();
    let mut seen: Vec<(&'static str, &Entry)> = Vec::new();
    for entry in &table.entries {
        let field = fields
            .iter()
            .find(|(field, _)| *field == entry.key)
            .or_else(|| fields.iter().find(|(field, _)| field.eq_ignore_ascii_case(&entry.key)));
        let Some((field, shape)) = field else {
            if strict {
                return Err(ManifestError::UnknownKey {
                    at: entry.key_at.clone(),
                    key: entry.key.clone(),
                    table: name.to_owned(),
                });
            }
            result.entries.push(entry.clone());
            continue;
        };
        if let Some((_, first)) = seen.iter().find(|(seen_field, _)| seen_field == field) {
            return Err(ManifestError::KeyCaseCollision {
                first: first.key_at.clone(),
                first_key: first.key.clone(),
                second: entry.key_at.clone(),
                second_key: entry.key.clone(),
            });
        }
        seen.push((field, entry));
        let child_name = child_name(name, field);
        result.entries.push(Entry {
            key: (*field).to_owned(),
            key_at: entry.key_at.clone(),
            node: canonical_node(&entry.node, shape, &child_name, entry)?,
        });
    }
    Ok(result)
}

/// Names a table inside `parent` as a manifest writes it: `[Forma.Account]`.
fn child_name(parent: &str, key: &str) -> String {
    match parent.strip_prefix('[').and_then(|inner| inner.strip_suffix(']')) {
        Some(inner) => format!("[{inner}.{key}]"),
        None => format!("[{key}]"),
    }
}

fn canonical_node(node: &Node, shape: &'static Shape, name: &str, entry: &Entry) -> Result<Node, ManifestError> {
    let wrong_type = |expected: &'static str, found: &Node| ManifestError::WrongType {
        at: found.at.clone(),
        key: name.to_owned(),
        expected,
        found: found.value.kind(),
    };
    let value = match (shape, &node.value) {
        (Shape::Leaf, _) | (Shape::Free, Value::Table(_)) => node.value.clone(),
        (Shape::HostOnly, _) => {
            return Err(ManifestError::HostOnlySetting {
                at: entry.key_at.clone(),
                key: name.to_owned(),
            });
        }
        (Shape::Table { fields, strict }, Value::Table(table)) => {
            Value::Table(canonical(table, fields, *strict, name)?)
        }
        (Shape::Map(inner), Value::Table(table)) => Value::Table(Table {
            entries: table
                .entries
                .iter()
                .map(|item| {
                    let item_name = child_name(name, &item.key);
                    Ok(Entry {
                        key: item.key.clone(),
                        key_at: item.key_at.clone(),
                        node: canonical_node(&item.node, inner, &item_name, item)?,
                    })
                })
                .collect::<Result<_, ManifestError>>()?,
        }),
        (Shape::List { item, .. }, Value::Array(items)) => Value::Array(
            items
                .iter()
                .map(|element| match &element.value {
                    Value::Table(_) => canonical_node(element, item, name, entry),
                    _ => Err(wrong_type("a table", element)),
                })
                .collect::<Result<_, _>>()?,
        ),
        (Shape::Free | Shape::Table { .. } | Shape::Map(_), _) => return Err(wrong_type("a table", node)),
        (Shape::List { .. }, _) => return Err(wrong_type("a list of tables", node)),
    };
    Ok(Node {
        value,
        at: node.at.clone(),
    })
}

/// Applies a host override: each key of `over` replaces the same key of
/// `base` whole, as materia's `Overrides` do. Both tables are canonical.
pub(crate) fn replace(base: &mut Table, over: &Table) {
    for entry in &over.entries {
        base.set(entry.clone());
    }
}

/// Applies a host extension: `extension` merges into `base`. Both tables are
/// canonical.
///
/// | Kind of value | Rule |
/// |---|---|
/// | Table with known keys | Merged key by key. |
/// | List of tables (`Images`, `Groups`, `Trust`) | An item whose identifying key matches one in `base` merges into it. Any other item is added at the end. |
/// | Table of free keys (`BuildArgs`) | Each key is set. |
/// | List of scalars (`MemberOf`) | Items not yet in the list are added at the end. |
/// | Scalar | Replaced. |
pub(crate) fn extend(base: &mut Table, extension: &Table, fields: &'static [Field]) {
    for entry in &extension.entries {
        let shape = fields
            .iter()
            .find(|(field, _)| *field == entry.key)
            .map(|(_, shape)| shape);
        match base.get_mut(&entry.key) {
            None => base.entries.push(entry.clone()),
            Some(existing) => extend_node(existing, &entry.node, shape),
        }
    }
}

fn extend_node(base: &mut Node, extension: &Node, shape: Option<&'static Shape>) {
    match (shape, &mut base.value, &extension.value) {
        (Some(Shape::Table { fields, .. }), Value::Table(base_table), Value::Table(ext)) => {
            extend(base_table, ext, fields);
        }
        (Some(Shape::Map(inner)), Value::Table(base_table), Value::Table(ext)) => {
            for entry in &ext.entries {
                match base_table.get_mut(&entry.key) {
                    None => base_table.entries.push(entry.clone()),
                    Some(existing) => extend_node(existing, &entry.node, Some(inner)),
                }
            }
        }
        (Some(Shape::Free), Value::Table(base_table), Value::Table(ext)) => {
            for entry in &ext.entries {
                base_table.set(entry.clone());
            }
        }
        (Some(Shape::List { item, key }), Value::Array(base_items), Value::Array(ext_items)) => {
            for ext_item in ext_items {
                let id = identity(ext_item, key);
                let found = base_items
                    .iter_mut()
                    .find(|base_item| id.is_some() && identity(base_item, key) == id);
                match found {
                    Some(base_item) => extend_node(base_item, ext_item, Some(item)),
                    None => base_items.push(ext_item.clone()),
                }
            }
        }
        (Some(Shape::Leaf) | None, Value::Array(base_items), Value::Array(ext_items)) => {
            for ext_item in ext_items {
                if !base_items.iter().any(|base_item| base_item.same_value(ext_item)) {
                    base_items.push(ext_item.clone());
                }
            }
        }
        _ => *base = extension.clone(),
    }
}

/// The value of an item's identifying key, if it is a string.
fn identity<'a>(item: &'a Node, key: &str) -> Option<&'a str> {
    match &item.value {
        Value::Table(table) => match &table.get(key)?.value {
            Value::String(text) => Some(text),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use super::*;
    use crate::raw;

    fn forma(text: &str) -> Result<Table, ManifestError> {
        let file: Arc<Path> = Arc::from(Path::new("MANIFEST.toml"));
        let parsed = raw::parse(text, &file)?;
        let table = canonical(&parsed, COMPONENT_FIELDS, false, "")?;
        match table.get("Forma") {
            Some(Node {
                value: Value::Table(forma),
                ..
            }) => Ok(forma.clone()),
            _ => Ok(Table::default()),
        }
    }

    fn strings(node: &Node) -> Vec<&str> {
        match &node.value {
            Value::Array(items) => items
                .iter()
                .map(|item| match &item.value {
                    Value::String(text) => text.as_str(),
                    _ => panic!("not a string"),
                })
                .collect(),
            _ => panic!("not an array"),
        }
    }

    fn table<'a>(table: &'a Table, key: &str) -> &'a Table {
        match &table.get(key).unwrap_or_else(|| panic!("no {key}")).value {
            Value::Table(inner) => inner,
            _ => panic!("{key} is not a table"),
        }
    }

    fn list<'a>(table: &'a Table, key: &str) -> Vec<&'a Table> {
        match &table.get(key).unwrap().value {
            Value::Array(items) => items
                .iter()
                .map(|item| match &item.value {
                    Value::Table(inner) => inner,
                    _ => panic!("not a table"),
                })
                .collect(),
            _ => panic!("{key} is not an array"),
        }
    }

    #[test]
    fn keys_in_any_case_get_the_documented_spelling() {
        let forma = forma("[forma.ACCOUNT]\nname = \"app\"\nmemberof = [\"render\"]\n").unwrap();
        let account = table(&forma, "Account");
        assert_eq!(account.get("Name").unwrap().value, Value::String("app".into()));
        assert!(account.get("MemberOf").is_some());
    }

    #[test]
    fn two_spellings_of_one_key_collide() {
        let error = forma("[Forma.Account]\nName = \"app\"\nname = \"other\"\n").unwrap_err();
        assert_eq!(error.code(), "KeyCaseCollision");
        let error = forma("[Forma]\n[forma]\n").map(|_| ());
        // TOML itself allows both tables; forma does not.
        assert_eq!(error.unwrap_err().code(), "KeyCaseCollision");
    }

    #[test]
    fn free_tables_keep_keys_that_differ_by_case() {
        let forma =
            forma("[[Forma.Images]]\nTag = \"a/b:c\"\nBuildArgs = { version = \"1\", VERSION = \"2\" }\n").unwrap();
        let args = table(list(&forma, "Images")[0], "BuildArgs");
        assert_eq!(args.entries.len(), 2);
    }

    #[test]
    fn an_unknown_forma_key_is_an_error_and_names_its_table() {
        let error = forma("[Forma.Account]\nName = \"app\"\nLingr = true\n").unwrap_err();
        assert_eq!(error.code(), "UnknownKey");
        assert!(error.to_string().contains("[Forma.Account]"), "{error}");
        assert!(error.to_string().contains("MANIFEST.toml:3:1"), "{error}");
    }

    #[test]
    fn keys_outside_forma_are_left_alone() {
        forma("[Defaults]\nimage = 1\nImage = 2\n[Whatever]\nx = 1\n").unwrap();
    }

    #[test]
    fn host_only_keys_are_refused() {
        let error = forma("[Forma.BaseImages]\nhostpolicy = \"ignore\"\n").unwrap_err();
        assert_eq!(error.code(), "HostOnlySetting");
    }

    #[test]
    fn a_scalar_where_a_table_belongs_is_a_type_error() {
        assert_eq!(forma("[Forma]\nAccount = \"app\"\n").unwrap_err().code(), "WrongType");
        assert_eq!(forma("[Forma]\nImages = [\"a\"]\n").unwrap_err().code(), "WrongType");
        assert_eq!(forma("[Forma.Images]\nTag = \"a\"\n").unwrap_err().code(), "WrongType");
    }

    #[test]
    fn an_override_replaces_whole_keys() {
        let mut base = forma(
            "[Forma.Account]\nName = \"app\"\nLinger = true\n\
             [[Forma.Images]]\nTag = \"a/a:1\"\n[[Forma.Images]]\nTag = \"a/b:1\"\n",
        )
        .unwrap();
        let over = forma("[[Forma.Images]]\nTag = \"a/c:1\"\n").unwrap();
        replace(&mut base, &over);
        assert_eq!(list(&base, "Images").len(), 1);
        assert!(table(&base, "Account").get("Linger").is_some());
    }

    #[test]
    fn an_extension_merges_tables_and_keyed_lists() {
        let mut base = forma(
            "[Forma.Account]\nName = \"app\"\nMemberOf = [\"render\"]\n\
             [[Forma.Images]]\nTag = \"a/a:1\"\nContext = \"build\"\nBuildArgs = { A = \"1\", B = \"2\" }\n",
        )
        .unwrap();
        let extension = forma(
            "[forma.account]\nlinger = true\nmemberof = [\"video\", \"render\"]\n\
             [[forma.images]]\ntag = \"a/a:1\"\nbuildargs = { B = \"3\" }\n\
             [[forma.images]]\ntag = \"a/new:1\"\n",
        )
        .unwrap();
        extend(&mut base, &extension, COMPONENT_FORMA_FIELDS);

        let account = table(&base, "Account");
        assert_eq!(account.get("Name").unwrap().value, Value::String("app".into()));
        assert_eq!(account.get("Linger").unwrap().value, Value::Bool(true));
        assert_eq!(strings(account.get("MemberOf").unwrap()), ["render", "video"]);

        let images = list(&base, "Images");
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].get("Context").unwrap().value, Value::String("build".into()));
        let args = table(images[0], "BuildArgs");
        assert_eq!(args.get("A").unwrap().value, Value::String("1".into()));
        assert_eq!(args.get("B").unwrap().value, Value::String("3".into()));
    }
}
