//! Commands for `semodule` and `semanage` (architecture 5.9).

use std::path::Path;

use crate::{Command, Error, absolute, operand};

/// Where `semodule` is installed.
pub const SEMODULE: &str = "/usr/sbin/semodule";
/// Where `semanage` is installed.
pub const SEMANAGE: &str = "/usr/sbin/semanage";

fn priority(priority: u16) -> Result<String, Error> {
    if (1..=999).contains(&priority) {
        Ok(priority.to_string())
    } else {
        Err(Error::BadValue {
            tool: "semodule",
            what: "priority",
            value: priority.to_string(),
            reason: "it is not between 1 and 999",
        })
    }
}

fn module_name(name: &str) -> Result<&str, Error> {
    let name = operand("semodule", "module name", name)?;
    if name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        Ok(name)
    } else {
        Err(Error::BadValue {
            tool: "semodule",
            what: "module name",
            value: name.to_owned(),
            reason: "it holds characters other than letters, digits, '_', '-' and '.'",
        })
    }
}

/// Installs module files in one transaction, at forma's own priority.
///
/// # Errors
///
/// Returns an [`Error`] if `files` is empty, a file is not an absolute
/// path, or the priority is out of range.
pub fn install(module_priority: u16, files: &[&Path]) -> Result<Command, Error> {
    if files.is_empty() {
        return Err(Error::BadValue {
            tool: "semodule",
            what: "module list",
            value: String::new(),
            reason: "it is empty",
        });
    }
    let mut command = Command::new(SEMODULE)?.arg("-X").arg(priority(module_priority)?);
    for file in files {
        command = command.arg("-i").arg(absolute("semodule", "module file", file)?);
    }
    Ok(command)
}

/// Removes modules at forma's own priority. A remove at one priority
/// cannot touch a module at another, even one with the same name.
///
/// # Errors
///
/// Returns an [`Error`] if `names` is empty, a name is not a module name,
/// or the priority is out of range.
pub fn remove(module_priority: u16, names: &[&str]) -> Result<Command, Error> {
    if names.is_empty() {
        return Err(Error::BadValue {
            tool: "semodule",
            what: "module list",
            value: String::new(),
            reason: "it is empty",
        });
    }
    let mut command = Command::new(SEMODULE)?.arg("-X").arg(priority(module_priority)?);
    for name in names {
        command = command.arg("-r").arg(module_name(name)?);
    }
    Ok(command)
}

/// Lists installed modules with their priorities (`semodule -lfull`).
///
/// # Errors
///
/// Returns an [`Error`] only if the program path is not usable.
pub fn list() -> Result<Command, Error> {
    Ok(Command::new(SEMODULE)?.arg("-lfull"))
}

/// Maps a login to an SELinux user (`semanage login -a -s <selinux user> <login>`).
///
/// # Errors
///
/// Returns an [`Error`] if either name could be read as an option.
pub fn map_login(login: &str, selinux_user: &str) -> Result<Command, Error> {
    Ok(Command::new(SEMANAGE)?
        .args(["login", "-a", "-s"])
        .arg(operand("semanage", "SELinux user", selinux_user)?)
        .arg(operand("semanage", "login", login)?))
}

/// Removes a login mapping (`semanage login -d <login>`).
///
/// # Errors
///
/// Returns an [`Error`] if the name could be read as an option.
pub fn unmap_login(login: &str) -> Result<Command, Error> {
    Ok(Command::new(SEMANAGE)?
        .args(["login", "-d"])
        .arg(operand("semanage", "login", login)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modules_install_in_one_transaction_at_formas_priority() {
        let files = [
            Path::new("/var/lib/forma/selinux/a.cil"),
            Path::new("/usr/share/udica/templates/base_container.cil"),
        ];
        assert_eq!(
            install(350, &files).unwrap().arguments_lossy(),
            [
                "-X",
                "350",
                "-i",
                "/var/lib/forma/selinux/a.cil",
                "-i",
                "/usr/share/udica/templates/base_container.cil"
            ]
        );
    }

    #[test]
    fn modules_are_removed_at_the_same_priority() {
        assert_eq!(
            remove(350, &["moonshine_container"]).unwrap().arguments_lossy(),
            ["-X", "350", "-r", "moonshine_container"]
        );
    }

    #[test]
    fn bad_values_are_refused() {
        assert!(install(350, &[]).is_err());
        assert!(install(0, &[Path::new("/a.cil")]).is_err());
        assert!(install(1000, &[Path::new("/a.cil")]).is_err());
        assert!(install(350, &[Path::new("a.cil")]).is_err());
        assert!(remove(350, &[]).is_err());
        assert!(remove(350, &["-a"]).is_err());
        assert!(remove(350, &["a b"]).is_err());
        assert!(remove(350, &["a;b"]).is_err());
    }

    #[test]
    fn logins_map_to_a_confined_user() {
        assert_eq!(
            map_login("moonshine", "user_u").unwrap().arguments_lossy(),
            ["login", "-a", "-s", "user_u", "moonshine"]
        );
        assert_eq!(
            unmap_login("moonshine").unwrap().arguments_lossy(),
            ["login", "-d", "moonshine"]
        );
        assert!(map_login("-x", "user_u").is_err());
        assert_eq!(list().unwrap().arguments_lossy(), ["-lfull"]);
    }
}
