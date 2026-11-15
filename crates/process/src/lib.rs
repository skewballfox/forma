//! Runs external tools for forma.
//!
//! Every tool forma runs goes through [`Command`]:
//!
//! - the program is an absolute path, never looked up in `PATH`;
//! - arguments are an argument vector, never a shell line;
//! - the environment is cleared, then only what the caller sets is passed;
//! - standard input is closed, and each run has a time limit;
//! - a non-zero exit is a typed error with the tool's standard error.
//!
//! A [`Secret`] cannot be an argument: arguments are `&OsStr`, and `Secret`
//! does not convert to one (`docs/architecture.md` 7, rule 9).
//!
//! ```compile_fail
//! use forma_process::{Command, Secret};
//! let pin = Secret::new(b"1234".to_vec());
//! // A secret on a command line is readable by every user: this does not compile.
//! Command::new("/usr/bin/tool").unwrap().arg(&pin);
//! ```
//!
//! [`buildah`], [`podman`] and [`selinux`] build the commands forma needs
//! from typed values, so no caller assembles flags by hand.

pub mod buildah;
pub mod podman;
pub mod selinux;

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use thiserror::Error;
use zeroize::Zeroizing;

/// How long a tool may run when the caller sets no limit.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// A PIN, an auth value or a key password.
///
/// It has no `Display`, its `Debug` prints `Secret(..)`, and its memory is
/// cleared when it is dropped. It does not convert to `&OsStr`, so it can
/// never be a command-line argument.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Takes ownership of the secret's bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Returns the bytes, for code that hands them to a library in memory.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// A tool could not be run, or failed.
#[derive(Debug, Error)]
pub enum Error {
    /// The program is not an absolute path.
    #[error("program {} is not an absolute path; forma never searches PATH", .0.display())]
    NotAbsolute(PathBuf),
    /// A value would be read by the tool as an option.
    #[error("{what} {value:?} starts with '-', so {tool} would read it as an option")]
    OptionLike {
        /// The tool.
        tool: &'static str,
        /// What the value is, such as `image reference`.
        what: &'static str,
        /// The value.
        value: String,
    },
    /// A value cannot be passed to the tool.
    #[error("{what} {value:?} cannot be passed to {tool}: {reason}")]
    BadValue {
        /// The tool.
        tool: &'static str,
        /// What the value is.
        what: &'static str,
        /// The value.
        value: String,
        /// Why not.
        reason: &'static str,
    },
    /// The program could not be started.
    #[error("cannot start {}: {source}", program.display())]
    Spawn {
        /// The program.
        program: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// Waiting for the program, or reading its output, failed.
    #[error("cannot wait for {}: {source}", program.display())]
    Wait {
        /// The program.
        program: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// The program ran longer than its time limit and was killed.
    #[error("{} did not finish within {} seconds and was stopped", program.display(), limit.as_secs())]
    TimedOut {
        /// The program.
        program: PathBuf,
        /// The limit.
        limit: Duration,
    },
    /// The program exited with a failure.
    #[error(
        "{} failed{}: {}",
        program.display(),
        code.map_or_else(|| " (stopped by a signal)".to_owned(), |code| format!(" with exit code {code}")),
        if stderr.is_empty() { "it wrote nothing to standard error" } else { stderr.as_str() }
    )]
    Failed {
        /// The program.
        program: PathBuf,
        /// The exit code, or `None` if a signal stopped the program.
        code: Option<i32>,
        /// What the program wrote to standard error, trimmed.
        stderr: String,
    },
}

/// What a tool wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error, trimmed. Tools write warnings here even when they succeed.
    pub stderr: String,
}

impl Output {
    /// Returns standard output as text, trimmed. Bytes that are not UTF-8
    /// are replaced.
    #[must_use]
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim().to_owned()
    }
}

/// One run of an external tool.
#[derive(Debug)]
pub struct Command {
    program: PathBuf,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    secrets: Vec<(OsString, Secret)>,
    directory: Option<PathBuf>,
    timeout: Duration,
}

impl Command {
    /// Starts a command for the program at an absolute path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAbsolute`] if `program` is not absolute.
    pub fn new(program: impl Into<PathBuf>) -> Result<Self, Error> {
        let program = program.into();
        if !program.is_absolute() {
            return Err(Error::NotAbsolute(program));
        }
        Ok(Self {
            program,
            arguments: Vec::new(),
            // A fixed locale keeps the text of error messages stable.
            environment: vec![("LC_ALL".into(), "C".into())],
            secrets: Vec::new(),
            directory: None,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Adds one argument.
    #[must_use]
    pub fn arg(mut self, argument: impl AsRef<OsStr>) -> Self {
        self.arguments.push(argument.as_ref().to_os_string());
        self
    }

    /// Adds arguments.
    #[must_use]
    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.arguments
            .extend(arguments.into_iter().map(|argument| argument.as_ref().to_os_string()));
        self
    }

    /// Sets one environment variable. The tool gets no variable the caller
    /// did not set, apart from `LC_ALL=C`.
    #[must_use]
    pub fn env(mut self, name: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        let name = name.as_ref();
        self.environment.retain(|(existing, _)| existing != name);
        self.environment
            .push((name.to_os_string(), value.as_ref().to_os_string()));
        self
    }

    /// Passes a secret in the tool's environment.
    ///
    /// This is the last resort of architecture 7, rule 9: use it only for a
    /// tool that takes a secret no other way. Only root and the account
    /// that runs the tool can read the environment of a direct child. Never
    /// use it for a command started through `run0` or `systemd-run`, which
    /// write their command, and with `--setenv` its environment, to the
    /// journal.
    ///
    /// The secret must be UTF-8 without a NUL byte; [`Command::run`] fails
    /// otherwise.
    #[must_use]
    pub fn secret_env(mut self, name: impl AsRef<OsStr>, secret: Secret) -> Self {
        self.secrets.push((name.as_ref().to_os_string(), secret));
        self
    }

    /// Sets the directory the tool starts in.
    #[must_use]
    pub fn current_dir(mut self, directory: impl Into<PathBuf>) -> Self {
        self.directory = Some(directory.into());
        self
    }

    /// Sets how long the tool may run.
    #[must_use]
    pub fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = limit;
        self
    }

    /// Returns the program.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Returns the arguments, without the program.
    #[must_use]
    pub fn arguments(&self) -> Vec<&OsStr> {
        self.arguments.iter().map(OsString::as_os_str).collect()
    }

    /// Returns the arguments as text, for tests and for `forma plan`.
    /// Arguments that are not UTF-8 have the odd bytes replaced.
    #[must_use]
    pub fn arguments_lossy(&self) -> Vec<String> {
        self.arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    /// Returns the environment the tool gets, without secrets.
    #[must_use]
    pub fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }

    /// Runs the tool and waits for it.
    ///
    /// # Errors
    ///
    /// - [`Error::Spawn`] if the program cannot be started.
    /// - [`Error::TimedOut`] if it runs past its limit. It is killed first.
    /// - [`Error::Failed`] if it exits with a failure.
    /// - [`Error::BadValue`] if a secret cannot be an environment value.
    pub fn run(&self) -> Result<Output, Error> {
        let mut command = std::process::Command::new(&self.program);
        command
            .args(&self.arguments)
            .env_clear()
            .envs(self.environment.iter().map(|(name, value)| (name, value)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, secret) in &self.secrets {
            let value = std::str::from_utf8(secret.expose())
                .ok()
                .filter(|text| !text.contains('\0'))
                .ok_or(Error::BadValue {
                    tool: "the tool",
                    what: "secret for",
                    value: name.to_string_lossy().into_owned(),
                    reason: "it is not UTF-8 text without NUL bytes",
                })?;
            command.env(name, value);
        }
        if let Some(directory) = &self.directory {
            command.current_dir(directory);
        }
        let mut child = command.spawn().map_err(|source| Error::Spawn {
            program: self.program.clone(),
            source,
        })?;
        let wait_error = |source| Error::Wait {
            program: self.program.clone(),
            source,
        };
        // Read both pipes on their own threads: a tool that fills one pipe
        // while forma reads the other would block for ever.
        let drain = |pipe: Option<Box<dyn std::io::Read + Send>>| {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                if let Some(mut pipe) = pipe {
                    pipe.read_to_end(&mut bytes)?;
                }
                Ok::<_, std::io::Error>(bytes)
            })
        };
        let stdout = drain(child.stdout.take().map(|pipe| Box::new(pipe) as _));
        let stderr = drain(child.stderr.take().map(|pipe| Box::new(pipe) as _));

        let deadline = Instant::now() + self.timeout;
        let mut pause = Duration::from_millis(1);
        let status = loop {
            if let Some(status) = child.try_wait().map_err(wait_error)? {
                break status;
            }
            if Instant::now() >= deadline {
                // The child may have exited between the two checks; both calls then fail harmlessly.
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::TimedOut {
                    program: self.program.clone(),
                    limit: self.timeout,
                });
            }
            std::thread::sleep(pause);
            pause = (pause * 2).min(Duration::from_millis(50));
        };
        let join = |reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>>| {
            reader.join().unwrap_or_else(|_| Ok(Vec::new())).map_err(wait_error)
        };
        let stdout = join(stdout)?;
        let stderr = String::from_utf8_lossy(&join(stderr)?).trim().to_owned();
        if status.success() {
            Ok(Output { stdout, stderr })
        } else {
            Err(Error::Failed {
                program: self.program.clone(),
                code: status.code(),
                stderr,
            })
        }
    }
}

/// Refuses a value a tool would read as an option, or that is empty.
pub(crate) fn operand<'a>(tool: &'static str, what: &'static str, value: &'a str) -> Result<&'a str, Error> {
    if value.starts_with('-') {
        return Err(Error::OptionLike {
            tool,
            what,
            value: value.to_owned(),
        });
    }
    if value.is_empty() || value.contains('\0') {
        return Err(Error::BadValue {
            tool,
            what,
            value: value.to_owned(),
            reason: "it is empty or holds a NUL byte",
        });
    }
    Ok(value)
}

/// Refuses a path that is not absolute. An absolute path starts with `/`,
/// so a tool cannot read it as an option.
pub(crate) fn absolute<'a>(tool: &'static str, what: &'static str, path: &'a Path) -> Result<&'a Path, Error> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(Error::BadValue {
            tool,
            what,
            value: path.display().to_string(),
            reason: "it is not an absolute path",
        })
    }
}

/// What a rootless container tool needs from the environment: where the
/// account's storage and runtime files are. Forma passes both explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rootless {
    /// The account's home directory (`HOME`).
    pub home: PathBuf,
    /// The account's runtime directory (`XDG_RUNTIME_DIR`), `/run/user/<uid>`.
    pub runtime_dir: PathBuf,
}

impl Rootless {
    pub(crate) fn apply(&self, command: Command) -> Command {
        command
            .env("HOME", &self.home)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        // The tests use a shell as a stand-in tool. Forma itself never does.
        Command::new("/bin/sh").unwrap().arg("-c").arg(script)
    }

    #[test]
    fn output_and_warnings_come_back() {
        let output = sh("echo out; echo warn >&2").run().unwrap();
        assert_eq!(output.stdout_text(), "out");
        assert_eq!(output.stderr, "warn");
    }

    #[test]
    fn a_failure_carries_the_exit_code_and_standard_error() {
        let error = sh("echo 'no such image' >&2; exit 125").run().unwrap_err();
        assert!(
            matches!(&error, Error::Failed { code: Some(125), stderr, .. } if stderr == "no such image"),
            "{error}"
        );
        assert_eq!(error.to_string(), "/bin/sh failed with exit code 125: no such image");
    }

    #[test]
    fn the_environment_is_cleared() {
        // The parent runs with a full environment (cargo sets dozens of variables); the child gets two.
        let output = sh("env").env("FORMA_TEST", "1").run().unwrap();
        let mut names: Vec<String> = output
            .stdout_text()
            .lines()
            .filter_map(|line| line.split_once('=').map(|(name, _)| name.to_owned()))
            // The shell sets these itself.
            .filter(|name| !matches!(name.as_str(), "PWD" | "SHLVL" | "_" | "OLDPWD"))
            .collect();
        names.sort();
        assert_eq!(names, ["FORMA_TEST", "LC_ALL"]);
    }

    #[test]
    fn standard_input_is_closed() {
        assert_eq!(sh("cat; echo done").run().unwrap().stdout_text(), "done");
    }

    #[test]
    fn a_tool_that_runs_too_long_is_stopped() {
        let started = Instant::now();
        let error = sh("sleep 30").timeout(Duration::from_millis(100)).run().unwrap_err();
        assert!(matches!(error, Error::TimedOut { .. }), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_lot_of_output_on_both_pipes_does_not_block() {
        let output = sh("head -c 300000 /dev/zero; head -c 300000 /dev/zero >&2")
            .run()
            .unwrap();
        assert_eq!(output.stdout.len(), 300_000);
    }

    #[test]
    fn a_program_must_be_an_absolute_path() {
        assert!(matches!(Command::new("sh"), Err(Error::NotAbsolute(_))));
        let error = Command::new("/nonexistent/tool").unwrap().run().unwrap_err();
        assert!(matches!(error, Error::Spawn { .. }), "{error}");
    }

    #[test]
    fn a_secret_reaches_the_tool_only_through_its_environment_and_never_prints() {
        let secret = Secret::new(b"hunter2".to_vec());
        assert_eq!(format!("{secret:?}"), "Secret(..)");
        let command = sh("printf %s \"$PIN\"").secret_env("PIN", secret);
        assert!(!format!("{command:?}").contains("hunter2"));
        assert!(command.environment().iter().all(|(name, _)| name != "PIN"));
        assert_eq!(command.run().unwrap().stdout_text(), "hunter2");
    }

    #[test]
    fn operands_cannot_look_like_options() {
        assert!(matches!(
            operand("podman", "image", "--privileged"),
            Err(Error::OptionLike { .. })
        ));
        assert!(matches!(operand("podman", "image", ""), Err(Error::BadValue { .. })));
        assert_eq!(operand("podman", "image", "localhost/a:b").unwrap(), "localhost/a:b");
        assert!(absolute("podman", "policy", Path::new("policy.json")).is_err());
    }
}
