//! The shadow-utils runner. Private to [`crate::admin`].
//!
//! Guards, in the order of `PLAN.md` section 8.2:
//!
//! 1. Arguments come only from [`Invocation`], which only this crate builds,
//!    from checked types.
//! 2. Each tool runs from a fixed absolute path, found once when the root
//!    handle opens. Every part of that path must be owned by root and not
//!    writable by group or others.
//! 3. The environment is cleared, then only `LC_ALL=C` is set.
//! 4. Stdin is closed and each run has a timeout.
//! 5. A failure carries the exit code and stderr.

use std::ffi::OsString;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

/// How often a running tool is checked for exit.
const POLL: Duration = Duration::from_millis(20);

/// The shadow-utils tools the crate runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tool {
    Useradd,
    Userdel,
    Usermod,
    Groupadd,
    Groupdel,
    Gpasswd,
}

impl Tool {
    const ALL: [Self; 6] = [
        Self::Useradd,
        Self::Userdel,
        Self::Usermod,
        Self::Groupadd,
        Self::Groupdel,
        Self::Gpasswd,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Useradd => "useradd",
            Self::Userdel => "userdel",
            Self::Usermod => "usermod",
            Self::Groupadd => "groupadd",
            Self::Groupdel => "groupdel",
            Self::Gpasswd => "gpasswd",
        }
    }

    const fn candidates(self) -> [&'static str; 2] {
        match self {
            Self::Useradd => ["/usr/sbin/useradd", "/usr/bin/useradd"],
            Self::Userdel => ["/usr/sbin/userdel", "/usr/bin/userdel"],
            Self::Usermod => ["/usr/sbin/usermod", "/usr/bin/usermod"],
            Self::Groupadd => ["/usr/sbin/groupadd", "/usr/bin/groupadd"],
            Self::Groupdel => ["/usr/sbin/groupdel", "/usr/bin/groupdel"],
            Self::Gpasswd => ["/usr/bin/gpasswd", "/usr/sbin/gpasswd"],
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|&tool| tool == self).unwrap_or_default()
    }
}

/// One command line. Only this crate builds these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invocation {
    tool: Tool,
    args: Vec<OsString>,
}

impl Invocation {
    pub(crate) fn new(tool: Tool) -> Self {
        Self { tool, args: Vec::new() }
    }

    /// Adds a flag without a value, such as `--system`.
    pub(crate) fn flag(mut self, flag: &'static str) -> Self {
        self.args.push(flag.into());
        self
    }

    /// Adds a flag and its value as two arguments, such as `--uid 975`.
    pub(crate) fn value(mut self, flag: &'static str, value: impl Into<OsString>) -> Self {
        self.args.push(flag.into());
        self.args.push(value.into());
        self
    }

    /// Adds a positional argument. Callers pass only checked names, which
    /// cannot start with `-`.
    pub(crate) fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

}

/// The checked path of each tool.
#[derive(Debug, Clone)]
pub(crate) struct Tools([PathBuf; 6]);

impl Tools {
    /// Finds each tool and checks that root alone can change it.
    pub(crate) fn resolve() -> Result<Self, ToolError> {
        let mut paths: [PathBuf; 6] = Default::default();
        for tool in Tool::ALL {
            paths[tool.index()] = resolve(tool)?;
        }
        Ok(Self(paths))
    }

    /// Runs one command and waits for it, up to `timeout`.
    pub(crate) fn run(&self, invocation: &Invocation, timeout: Duration) -> Result<(), ToolError> {
        let tool = invocation.tool;
        let mut child = Command::new(&self.0[tool.index()])
            .args(&invocation.args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| ToolError::Spawn {
                tool: tool.name(),
                source,
            })?;

        // Read stderr on another thread, so a full pipe cannot block the tool.
        let mut stderr = child.stderr.take();
        let reader = std::thread::spawn(move || {
            let mut text = String::new();
            if let Some(stderr) = stderr.as_mut() {
                // A read error only loses the message, not the result.
                let _ = stderr.read_to_string(&mut text);
            }
            text
        });

        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < timeout => std::thread::sleep(POLL),
                Ok(None) => {
                    // Best effort: the tool may exit between the check and the kill.
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ToolError::Timeout {
                        tool: tool.name(),
                        after: timeout,
                    });
                }
                Err(source) => {
                    return Err(ToolError::Spawn {
                        tool: tool.name(),
                        source,
                    });
                }
            }
        };
        let stderr = reader.join().unwrap_or_default();
        if status.success() {
            return Ok(());
        }
        Err(ToolError::Failed {
            tool: tool.name(),
            code: status.code(),
            stderr: stderr.trim().to_owned(),
        })
    }
}

fn resolve(tool: Tool) -> Result<PathBuf, ToolError> {
    let found = tool
        .candidates()
        .into_iter()
        .find_map(|candidate| std::fs::canonicalize(candidate).ok())
        .ok_or(ToolError::NotFound(tool.name()))?;
    check_trusted(&found)?;
    Ok(found)
}

/// Checks that `path` and every directory above it are owned by root and not
/// writable by group or others.
fn check_trusted(path: &Path) -> Result<(), ToolError> {
    for part in path.ancestors() {
        let meta = std::fs::symlink_metadata(part).map_err(|source| ToolError::Unsafe {
            path: part.to_path_buf(),
            reason: format!("cannot read its status: {source}"),
        })?;
        if meta.uid() != 0 {
            return Err(ToolError::Unsafe {
                path: part.to_path_buf(),
                reason: format!("it is owned by user ID {}", meta.uid()),
            });
        }
        if meta.mode() & 0o022 != 0 {
            return Err(ToolError::Unsafe {
                path: part.to_path_buf(),
                reason: format!("its mode {:04o} lets group or others write", meta.mode() & 0o7777),
            });
        }
    }
    Ok(())
}

/// A shadow-utils command could not run, or failed.
#[derive(Debug, Error)]
pub enum ToolError {
    /// The tool is not installed.
    #[error("{0} is not installed in /usr/sbin or /usr/bin")]
    NotFound(&'static str),
    /// Someone other than root could change the tool.
    #[error("refusing to run {}: {reason}", path.display())]
    Unsafe {
        /// The file or directory.
        path: PathBuf,
        /// What is wrong.
        reason: String,
    },
    /// The tool could not be started or waited for.
    #[error("cannot run {tool}")]
    Spawn {
        /// The tool.
        tool: &'static str,
        /// The error.
        source: std::io::Error,
    },
    /// The tool ran too long and was killed.
    #[error("{tool} did not finish within {after:?}")]
    Timeout {
        /// The tool.
        tool: &'static str,
        /// The time allowed.
        after: Duration,
    },
    /// The tool exited with an error.
    #[error("{tool} failed{}: {stderr}", code.map(|code| format!(" with exit code {code}")).unwrap_or_default())]
    Failed {
        /// The tool.
        tool: &'static str,
        /// Its exit code, or `None` if a signal ended it.
        code: Option<i32>,
        /// What it wrote to stderr.
        stderr: String,
    },
}

impl ToolError {
    /// Returns the exit code if the tool ran and failed.
    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        match self {
            Self::Failed { code, .. } => *code,
            _ => None,
        }
    }
}
