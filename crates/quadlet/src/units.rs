//! The units forma installs. Each is the same for every account: systemd
//! fills in the account through `%u`, and `ConditionGroup=` keeps the unit
//! from starting for anyone else.

use std::fmt::Write as _;
use std::path::Path;

/// The group every service account joins. Forma creates it.
pub const CONSUMERS_GROUP: &str = "forma-consumers";

/// The directory forma installs user units in.
pub const USER_UNIT_DIR: &str = "/etc/systemd/user";

/// The directory that holds one account materia configuration per account.
pub const ACCOUNT_MATERIA_CONFIG_DIR: &str = "/etc/forma/materia";

/// The unit that runs each account's materia.
pub const MATERIA_UNIT: &str = "forma-materia.service";
/// The timer that starts an account's load.
pub const LOAD_TIMER_UNIT: &str = "forma-load.timer";
/// The unit that loads new images for an account.
pub const LOAD_SERVICE_UNIT: &str = "forma-load.service";
/// How long after one load ends the timer starts the next.
pub const LOAD_INTERVAL: &str = "2min";

const HEADER: &str = "# Written by forma. Do not edit: forma apply replaces this file.\n";

/// A unit file forma installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedUnit {
    /// The file's name in [`USER_UNIT_DIR`].
    pub name: &'static str,
    /// The file's text.
    pub text: String,
    /// The target that starts the unit: forma links the unit into
    /// `<target>.wants/`. `None` for a unit another unit starts.
    pub wanted_by: Option<&'static str>,
}

/// Renders the unit that runs each account's materia (delegation 4).
///
/// `materia` is the materia program. The path must be absolute and hold
/// no space.
#[must_use]
pub fn account_materia(materia: &Path) -> GeneratedUnit {
    let mut text = String::from(HEADER);
    let _ = write!(
        text,
        "[Unit]\n\
         Description=Materia for this service account (managed by forma)\n\
         ConditionGroup={CONSUMERS_GROUP}\n\
         ConditionPathExists={ACCOUNT_MATERIA_CONFIG_DIR}/%u.toml\n\
         Wants=podman.socket\n\
         After=podman.socket\n\
         \n\
         [Service]\n\
         Environment=MATERIA_CONFIG={ACCOUNT_MATERIA_CONFIG_DIR}/%u.toml\n\
         ExecStart={} server\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        materia.display()
    );
    GeneratedUnit {
        name: MATERIA_UNIT,
        text,
        wanted_by: Some("default.target"),
    }
}

/// Renders the pair of units that load new images (architecture 5.7): a
/// timer, and the service it starts, `forma load`.
///
/// A timer and not a path unit: an account may only pass through the store
/// root (`0700`, a traverse-only ACL entry), and systemd watches every
/// directory on a `PathChanged=` path from `/` down, stopping without a
/// word at the first it cannot read. A path unit on
/// `<store>/%u/.published` waits for ever. Polling needs no more access
/// than the load itself; `forma load` does nothing when `.published` has
/// not changed since its last load.
///
/// `forma` is the forma program. The path must be absolute and hold no
/// space.
#[must_use]
pub fn load_units(forma: &Path) -> [GeneratedUnit; 2] {
    let mut timer = String::from(HEADER);
    let _ = write!(
        timer,
        "[Unit]\n\
         Description=Check for new forma images for this service account\n\
         ConditionGroup={CONSUMERS_GROUP}\n\
         \n\
         [Timer]\n\
         OnActiveSec=1min\n\
         OnUnitInactiveSec={LOAD_INTERVAL}\n\
         AccuracySec=10s\n\
         Unit={LOAD_SERVICE_UNIT}\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    );
    let mut service = String::from(HEADER);
    let _ = write!(
        service,
        "[Unit]\n\
         Description=Load new forma images for this service account\n\
         ConditionGroup={CONSUMERS_GROUP}\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart={} load\n",
        forma.display()
    );
    [
        GeneratedUnit {
            name: LOAD_TIMER_UNIT,
            text: timer,
            wanted_by: Some("default.target"),
        },
        GeneratedUnit {
            name: LOAD_SERVICE_UNIT,
            text: service,
            wanted_by: None,
        },
    ]
}

/// Renders the configuration of one account's materia (delegation 4).
///
/// `hostname` is the name root materia resolved, and `staging` the
/// account's staging directory. The file holds no secret.
#[must_use]
pub fn account_materia_config(account: &str, hostname: &str, staging: &Path) -> String {
    // TOML basic strings escape '\' and '"'. Host names and paths hold
    // neither in practice; escaping keeps the file valid if one does.
    let quote = |text: &str| text.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "# {ACCOUNT_MATERIA_CONFIG_DIR}/{account}.toml: written by forma. Do not edit.\n\
         hostname = \"{}\"\n\
         attributes = \"file\"\n\
         \n\
         [source]\n\
         kind = \"local\"\n\
         url = \"file://{}\"\n\
         \n\
         [file]\n\
         base_dir = \"attributes\"\n\
         load_all_vaults = true\n",
        quote(hostname),
        quote(&staging.display().to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_account_materia_unit_matches_the_delegation_note() {
        let unit = account_materia(Path::new("/usr/bin/materia"));
        insta::assert_snapshot!(unit.text, @r"
        # Written by forma. Do not edit: forma apply replaces this file.
        [Unit]
        Description=Materia for this service account (managed by forma)
        ConditionGroup=forma-consumers
        ConditionPathExists=/etc/forma/materia/%u.toml
        Wants=podman.socket
        After=podman.socket

        [Service]
        Environment=MATERIA_CONFIG=/etc/forma/materia/%u.toml
        ExecStart=/usr/bin/materia server
        Restart=on-failure
        RestartSec=5

        [Install]
        WantedBy=default.target
        ");
        assert_eq!(unit.name, "forma-materia.service");
        // No update interval: root materia decides when the account updates.
        assert!(!unit.text.contains("update_interval"));
    }

    #[test]
    fn the_load_units_poll_with_a_timer() {
        let [timer, service] = load_units(Path::new("/usr/bin/forma"));
        insta::assert_snapshot!(timer.text, @r"
        # Written by forma. Do not edit: forma apply replaces this file.
        [Unit]
        Description=Check for new forma images for this service account
        ConditionGroup=forma-consumers

        [Timer]
        OnActiveSec=1min
        OnUnitInactiveSec=2min
        AccuracySec=10s
        Unit=forma-load.service

        [Install]
        WantedBy=default.target
        ");
        assert_eq!(timer.name, "forma-load.timer");
        assert_eq!(timer.wanted_by, Some("default.target"));
        assert_eq!(service.wanted_by, None);
        assert!(service.text.contains("ExecStart=/usr/bin/forma load\n"));
        // Nothing watches a path: see load_units.
        assert!(!timer.text.contains("Path"));
        for unit in [&timer, &service] {
            assert!(unit.text.contains("ConditionGroup=forma-consumers\n"), "{}", unit.name);
        }
    }

    #[test]
    fn the_account_materia_configuration_matches_the_delegation_note() {
        let text = account_materia_config(
            "moonshine",
            "forge",
            Path::new("/var/lib/materia/delegate/accounts/moonshine"),
        );
        insta::assert_snapshot!(text, @r#"
        # /etc/forma/materia/moonshine.toml: written by forma. Do not edit.
        hostname = "forge"
        attributes = "file"

        [source]
        kind = "local"
        url = "file:///var/lib/materia/delegate/accounts/moonshine"

        [file]
        base_dir = "attributes"
        load_all_vaults = true
        "#);
    }
}
