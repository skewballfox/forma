//! Records the Git commit forma is built from, for `forma version`.

use std::process::Command;

fn main() {
    // A build outside a Git checkout, or without git, has no commit to show.
    let commit = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or_else(|| "unknown".to_owned(), |commit| commit.trim().to_owned());
    println!("cargo::rustc-env=FORMA_GIT_COMMIT={commit}");
    println!("cargo::rerun-if-changed=.git/HEAD");
    println!("cargo::rerun-if-changed=.git/refs");
}
