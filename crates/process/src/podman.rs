//! Commands for `podman`, as a service account runs them (architecture 5.5 and 5.7).

use std::path::Path;

use crate::{Command, Error, Rootless, absolute};

/// Where `podman` is installed.
pub const PROGRAM: &str = "/usr/bin/podman";

const TOOL: &str = "podman";

/// Loads an image from a `dir:` layout in the store into the account's
/// storage, checked against `policy`.
///
/// `--signature-policy` is a hidden flag of `podman pull`. If Podman drops
/// it, pass `None`: Podman then reads the account's own `policy.json`,
/// which forma writes and owns.
///
/// # Errors
///
/// Returns an [`Error`](enum@Error) if a path is not absolute.
pub fn pull_from_dir(rootless: &Rootless, policy: Option<&Path>, directory: &Path) -> Result<Command, Error> {
    let mut command = rootless.apply(Command::new(PROGRAM)?).arg("pull");
    if let Some(policy) = policy {
        command = command
            .arg("--signature-policy")
            .arg(absolute(TOOL, "signature policy", policy)?);
    }
    let mut source = std::ffi::OsString::from("dir:");
    source.push(absolute(TOOL, "store directory", directory)?);
    Ok(command.arg(source))
}

/// Restarts the containers whose image changed, and rolls back those that
/// fail. Quadlets that run forma images set `AutoUpdate=local`.
///
/// # Errors
///
/// Returns an [`Error`](enum@Error) only if the program path is not usable.
pub fn auto_update(rootless: &Rootless) -> Result<Command, Error> {
    Ok(rootless.apply(Command::new(PROGRAM)?).arg("auto-update"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rootless() -> Rootless {
        Rootless {
            home: "/var/home/moonshine".into(),
            runtime_dir: "/run/user/975".into(),
        }
    }

    #[test]
    fn a_load_pulls_from_the_store_with_the_accounts_policy() {
        let store = Path::new("/var/lib/forma/store/moonshine/moonshine_steam_latest");
        let policy = Path::new("/var/home/moonshine/.config/containers/policy.json");
        let command = pull_from_dir(&rootless(), Some(policy), store).unwrap();
        assert_eq!(
            command.arguments_lossy(),
            [
                "pull",
                "--signature-policy",
                "/var/home/moonshine/.config/containers/policy.json",
                "dir:/var/lib/forma/store/moonshine/moonshine_steam_latest",
            ]
        );
        let without_flag = pull_from_dir(&rootless(), None, store).unwrap();
        assert_eq!(
            without_flag.arguments_lossy(),
            ["pull", "dir:/var/lib/forma/store/moonshine/moonshine_steam_latest"]
        );
    }

    #[test]
    fn relative_paths_are_refused() {
        assert!(pull_from_dir(&rootless(), None, Path::new("store/x")).is_err());
        assert!(pull_from_dir(&rootless(), Some(Path::new("policy.json")), Path::new("/s/x")).is_err());
    }

    #[test]
    fn auto_update_takes_no_arguments() {
        assert_eq!(auto_update(&rootless()).unwrap().arguments_lossy(), ["auto-update"]);
    }
}
