//! Input for [`crate::load`] built from a repository tree, as the fixtures
//! in `tests/fixtures/valid` and `tests/fixtures/invalid` are laid out.
//!
//! On a host, forma reads what materia installed. A fixture repository has
//! no installed state, so this module stands in for materia: every
//! component under `components/` counts as installed, its `[Settings] User`
//! is what materia would record, and its own directory is its staged copy.

use std::path::Path;
use std::sync::Arc;

use crate::installed::ComponentInput;
use crate::raw::{self, Value};
use crate::types::ComponentName;

/// Lists the components of the repository at `repository`, by name.
///
/// # Panics
///
/// Panics if the tree cannot be read. This is test support.
#[must_use]
pub fn repository_components(repository: &Path) -> Vec<ComponentInput> {
    let mut components: Vec<ComponentInput> = std::fs::read_dir(repository.join("components"))
        .expect("the repository has a components directory")
        .map(|entry| entry.expect("the components directory can be listed").path())
        .filter(|path| path.join("MANIFEST.toml").is_file())
        .map(|path| {
            let manifest = path.join("MANIFEST.toml");
            let name = path
                .file_name()
                .expect("a component directory has a name")
                .to_string_lossy()
                .into_owned();
            ComponentInput {
                name: ComponentName::new(name).expect("fixture components have valid names"),
                user: settings_user(&manifest),
                manifest,
                staged: Some(path),
            }
        })
        .collect();
    components.sort_by(|a, b| a.name.cmp(&b.name));
    components
}

/// Reads `[Settings] User` the way materia's decoder matches keys.
fn settings_user(manifest: &Path) -> Option<String> {
    let text = std::fs::read_to_string(manifest).expect("the manifest can be read");
    let file: Arc<Path> = Arc::from(manifest);
    // A manifest with a syntax error has no User; `load` reports the error.
    let table = raw::parse(&text, &file).ok()?;
    let Value::Table(settings) = &table.get_ignore_case("Settings")?.value else {
        return None;
    };
    match &settings.get_ignore_case("User")?.value {
        Value::String(user) if !user.is_empty() => Some(user.clone()),
        _ => None,
    }
}
