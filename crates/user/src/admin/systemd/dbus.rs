//! The few logind and systemd D-Bus calls the crate makes. Private to
//! [`crate::admin::systemd`].

use std::time::{Duration, Instant};

use zbus::blocking::Connection;
use zbus::proxy::CacheProperties;
use zbus::zvariant::OwnedObjectPath;

use super::SystemdError as Error;

/// One row of `ListSessions`: ID, user ID, user name, seat, object path.
type SessionRow = (String, u32, String, String, OwnedObjectPath);

/// How often a unit or job is checked while waiting.
const POLL: Duration = Duration::from_millis(100);

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1",
    gen_async = false,
    blocking_name = "LoginManagerProxy"
)]
trait LoginManager {
    fn set_user_linger(&self, uid: u32, enable: bool, interactive: bool) -> zbus::Result<()>;
    fn terminate_user(&self, uid: u32) -> zbus::Result<()>;
    fn list_sessions(&self) -> zbus::Result<Vec<SessionRow>>;
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.Session",
    default_service = "org.freedesktop.login1",
    gen_async = false,
    blocking_name = "LoginSessionProxy"
)]
trait LoginSession {
    #[zbus(property)]
    fn class(&self) -> zbus::Result<String>;
}

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1",
    gen_async = false,
    blocking_name = "SystemdManagerProxy"
)]
trait SystemdManager {
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn restart_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1",
    gen_async = false,
    blocking_name = "SystemdUnitProxy"
)]
trait SystemdUnit {
    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
}

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Job",
    default_service = "org.freedesktop.systemd1",
    gen_async = false,
    blocking_name = "SystemdJobProxy"
)]
trait SystemdJob {
    #[zbus(property)]
    fn state(&self) -> zbus::Result<String>;
}

/// Says whether a D-Bus error has the given name.
fn is_error(error: &zbus::Error, name: &str) -> bool {
    match error {
        zbus::Error::MethodError(error_name, _, _) => error_name.as_str() == name,
        zbus::Error::FDO(fdo) => match name {
            "org.freedesktop.DBus.Error.UnknownObject" => matches!(**fdo, zbus::fdo::Error::UnknownObject(_)),
            "org.freedesktop.DBus.Error.UnknownMethod" => matches!(**fdo, zbus::fdo::Error::UnknownMethod(_)),
            _ => false,
        },
        _ => false,
    }
}

fn login(bus: &Connection) -> Result<LoginManagerProxy<'static>, Error> {
    LoginManagerProxy::new(bus).map_err(|source| Error::bus("reach logind", source))
}

fn systemd(bus: &Connection) -> Result<SystemdManagerProxy<'static>, Error> {
    SystemdManagerProxy::new(bus).map_err(|source| Error::bus("reach systemd", source))
}

/// Turns linger on or off.
pub(crate) fn set_linger(bus: &Connection, uid: u32, enable: bool) -> Result<(), Error> {
    login(bus)?
        .set_user_linger(uid, enable, false)
        .map_err(|source| Error::bus(format!("set linger for user ID {uid}"), source))
}

/// Ends every session and the user manager of an account. Succeeds if the
/// account has none.
pub(crate) fn terminate_user(bus: &Connection, uid: u32) -> Result<(), Error> {
    match login(bus)?.terminate_user(uid) {
        Ok(()) => Ok(()),
        Err(error) if is_error(&error, "org.freedesktop.login1.NoSuchUser") => Ok(()),
        Err(source) => Err(Error::bus(format!("end the sessions of user ID {uid}"), source)),
    }
}

/// Returns the IDs of an account's login sessions. The sessions logind
/// makes for a user manager (class `manager` and `manager-early`) are left
/// out, so a lingering account with no logins has none.
pub(crate) fn login_sessions(bus: &Connection, uid: u32) -> Result<Vec<String>, Error> {
    let sessions = login(bus)?
        .list_sessions()
        .map_err(|source| Error::bus("list logind sessions", source))?;
    let mut ids = Vec::new();
    for (id, session_uid, _, _, path) in sessions {
        if session_uid != uid {
            continue;
        }
        let class = LoginSessionProxy::builder(bus)
            .path(path)
            .and_then(|builder| builder.cache_properties(CacheProperties::No).build())
            .and_then(|session| session.class());
        match class {
            Ok(class) if class.starts_with("manager") => {}
            Ok(_) => ids.push(id),
            // The session ended while it was being read.
            Err(error) if is_error(&error, "org.freedesktop.DBus.Error.UnknownObject") => {}
            Err(source) => return Err(Error::bus(format!("read logind session {id}"), source)),
        }
    }
    Ok(ids)
}

/// Returns a unit's active state, or `None` if systemd has not loaded it.
pub(crate) fn unit_state(bus: &Connection, unit: &str) -> Result<Option<String>, Error> {
    let path = match systemd(bus)?.get_unit(unit) {
        Ok(path) => path,
        Err(error) if is_error(&error, "org.freedesktop.systemd1.NoSuchUnit") => return Ok(None),
        Err(source) => return Err(Error::bus(format!("find unit {unit}"), source)),
    };
    let state = SystemdUnitProxy::builder(bus)
        .path(path)
        .and_then(|builder| builder.cache_properties(CacheProperties::No).build())
        .and_then(|proxy| proxy.active_state());
    match state {
        Ok(state) => Ok(Some(state)),
        Err(error) if is_error(&error, "org.freedesktop.DBus.Error.UnknownObject") => Ok(None),
        Err(source) => Err(Error::bus(format!("read the state of {unit}"), source)),
    }
}

/// Waits until a unit is unloaded, inactive or failed.
pub(crate) fn wait_stopped(bus: &Connection, unit: &str, timeout: Duration) -> Result<(), Error> {
    let started = Instant::now();
    loop {
        match unit_state(bus, unit)?.as_deref() {
            None | Some("inactive" | "failed") => return Ok(()),
            Some(_) if started.elapsed() < timeout => std::thread::sleep(POLL),
            Some(_) => return Err(Error::Timeout(format!("{unit} to stop"))),
        }
    }
}

/// Restarts a unit, waits for the job to finish, and returns the unit's state.
pub(crate) fn restart_and_wait(bus: &Connection, unit: &str, timeout: Duration) -> Result<String, Error> {
    let job = systemd(bus)?
        .restart_unit(unit, "replace")
        .map_err(|source| Error::bus(format!("restart {unit}"), source))?;
    let started = Instant::now();
    loop {
        // The job object disappears when the job finishes.
        let state = SystemdJobProxy::builder(bus)
            .path(job.clone())
            .and_then(|builder| builder.cache_properties(CacheProperties::No).build())
            .and_then(|proxy| proxy.state());
        match state {
            Ok(_) if started.elapsed() < timeout => std::thread::sleep(POLL),
            Ok(_) => return Err(Error::Timeout(format!("the restart of {unit}"))),
            Err(error)
                if is_error(&error, "org.freedesktop.DBus.Error.UnknownObject")
                    || is_error(&error, "org.freedesktop.DBus.Error.UnknownMethod") =>
            {
                break;
            }
            Err(source) => return Err(Error::bus(format!("follow the restart of {unit}"), source)),
        }
    }
    Ok(unit_state(bus, unit)?.unwrap_or_else(|| "unloaded".to_owned()))
}
