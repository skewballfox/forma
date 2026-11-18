//! Commands for `buildah` (architecture 5.5 and 5.6).

use std::path::Path;

use crate::{Command, Error, Rootless, absolute, operand};

/// Where `buildah` is installed.
pub const PROGRAM: &str = "/usr/bin/buildah";

const TOOL: &str = "buildah";

fn base(rootless: &Rootless) -> Result<Command, Error> {
    Ok(rootless.apply(Command::new(PROGRAM)?))
}

/// Pulls a base image and checks it against `policy` before it is stored.
///
/// # Errors
///
/// Returns an [`Error`](enum@Error) if `reference` could be read as an option, or
/// `policy` is not an absolute path.
pub fn pull(rootless: &Rootless, policy: &Path, reference: &str) -> Result<Command, Error> {
    Ok(base(rootless)?
        .arg("pull")
        .arg("--signature-policy")
        .arg(absolute(TOOL, "signature policy", policy)?)
        .arg(operand(TOOL, "image reference", reference)?))
}

/// One image build.
#[derive(Debug, Clone, Copy)]
pub struct Build<'a> {
    /// The reference the image gets, such as `localhost/app/app:latest`.
    pub tag: &'a str,
    /// The Containerfile.
    pub containerfile: &'a Path,
    /// The build context.
    pub context: &'a Path,
    /// The generated build policy.
    pub policy: &'a Path,
    /// Build arguments, as name and value.
    pub build_args: &'a [(&'a str, &'a str)],
}

/// Builds an image without pulling: `--pull=never`, `--layers`,
/// `--isolation chroot`. Forma pulls and checks every base image first, so
/// a base the build names and forma did not pull fails with "image not
/// known" instead of being pulled unchecked.
///
/// # Errors
///
/// Returns an [`Error`](enum@Error) if a path is not absolute, or the tag or a build
/// argument name could be read as an option or holds `=`.
pub fn build(rootless: &Rootless, build: &Build<'_>) -> Result<Command, Error> {
    let mut command = base(rootless)?
        .args(["build", "--layers", "--isolation", "chroot", "--pull=never"])
        .arg("--signature-policy")
        .arg(absolute(TOOL, "signature policy", build.policy)?);
    for (name, value) in build.build_args {
        let name = operand(TOOL, "build argument name", name)?;
        if name.contains('=') {
            return Err(Error::BadValue {
                tool: TOOL,
                what: "build argument name",
                value: name.to_owned(),
                reason: "it holds '='",
            });
        }
        command = command.arg("--build-arg").arg(format!("{name}={value}"));
    }
    Ok(command
        .arg("--file")
        .arg(absolute(TOOL, "Containerfile", build.containerfile)?)
        .arg("--tag")
        .arg(operand(TOOL, "image tag", build.tag)?)
        .arg(absolute(TOOL, "build context", build.context)?))
}

/// Exports a built image to a `dir:` layout, with `--format oci` so
/// buildah does not pick a format: the signature covers the manifest bytes.
///
/// # Errors
///
/// Returns an [`Error`](enum@Error) if `tag` could be read as an option, or
/// `directory` is not an absolute path.
pub fn push_to_dir(rootless: &Rootless, tag: &str, directory: &Path) -> Result<Command, Error> {
    let directory = absolute(TOOL, "staging directory", directory)?;
    let mut destination = std::ffi::OsString::from("dir:");
    destination.push(directory);
    Ok(base(rootless)?
        .args(["push", "--format", "oci"])
        .arg(operand(TOOL, "image tag", tag)?)
        .arg(destination))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rootless() -> Rootless {
        Rootless {
            home: "/var/home/forma-build".into(),
            runtime_dir: "/run/user/970".into(),
        }
    }

    #[test]
    fn a_build_never_pulls_and_always_names_its_policy() {
        let command = build(
            &rootless(),
            &Build {
                tag: "localhost/moonshine/nvidia-driver:latest",
                containerfile: Path::new("/var/lib/forma/contexts/nvidia-driver/x/build/nvidia-driver.Dockerfile"),
                context: Path::new("/var/lib/forma/contexts/nvidia-driver/x/build"),
                policy: Path::new("/run/user/970/forma/policy.json"),
                build_args: &[("NV_VERSION", "580.105.08")],
            },
        )
        .unwrap();
        assert_eq!(command.program(), Path::new("/usr/bin/buildah"));
        assert_eq!(
            command.arguments_lossy(),
            [
                "build",
                "--layers",
                "--isolation",
                "chroot",
                "--pull=never",
                "--signature-policy",
                "/run/user/970/forma/policy.json",
                "--build-arg",
                "NV_VERSION=580.105.08",
                "--file",
                "/var/lib/forma/contexts/nvidia-driver/x/build/nvidia-driver.Dockerfile",
                "--tag",
                "localhost/moonshine/nvidia-driver:latest",
                "/var/lib/forma/contexts/nvidia-driver/x/build",
            ]
        );
        let environment: Vec<String> = command
            .environment()
            .iter()
            .map(|(name, value)| format!("{}={}", name.display(), value.display()))
            .collect();
        assert_eq!(
            environment,
            [
                "LC_ALL=C",
                "HOME=/var/home/forma-build",
                "XDG_RUNTIME_DIR=/run/user/970"
            ]
        );
    }

    #[test]
    fn a_pull_checks_the_policy_before_the_image_is_stored() {
        let command = pull(
            &rootless(),
            Path::new("/p/policy.json"),
            "registry.fedoraproject.org/fedora-minimal:44",
        )
        .unwrap();
        assert_eq!(
            command.arguments_lossy(),
            [
                "pull",
                "--signature-policy",
                "/p/policy.json",
                "registry.fedoraproject.org/fedora-minimal:44"
            ]
        );
    }

    #[test]
    fn an_export_fixes_the_format() {
        let command = push_to_dir(
            &rootless(),
            "localhost/a/b:c",
            Path::new("/var/lib/forma/staging/a_b_c"),
        )
        .unwrap();
        assert_eq!(
            command.arguments_lossy(),
            [
                "push",
                "--format",
                "oci",
                "localhost/a/b:c",
                "dir:/var/lib/forma/staging/a_b_c"
            ]
        );
    }

    #[test]
    fn values_from_the_repository_cannot_become_options() {
        let policy = Path::new("/p/policy.json");
        assert!(pull(&rootless(), policy, "--tls-verify=false").is_err());
        assert!(pull(&rootless(), Path::new("policy.json"), "quay.io/a/b:c").is_err());
        assert!(push_to_dir(&rootless(), "-a", Path::new("/d")).is_err());
        assert!(push_to_dir(&rootless(), "localhost/a:b", Path::new("relative")).is_err());
        let bad_arg = Build {
            tag: "localhost/a:b",
            containerfile: Path::new("/c/Containerfile"),
            context: Path::new("/c"),
            policy,
            build_args: &[("A=B", "x")],
        };
        assert!(build(&rootless(), &bad_arg).is_err());
        let bad_arg = Build {
            build_args: &[("--network", "host")],
            ..bad_arg
        };
        assert!(build(&rootless(), &bad_arg).is_err());
    }
}
