//! Works out what `forma apply` would do.
//!
//! The planner takes the checked configuration, the ledger and a read-only
//! view of the host, and returns an ordered list of actions. It has no
//! `admin` module: it describes changes and makes none
//! (`docs/architecture.md` 5.4).
//!
//! `forma plan` prints the result, so an administrator can review it
//! before approving privileged work.

mod action;
pub mod host;
mod planner;

pub use action::{Action, FilePurpose, Principal, Stage, Step};
pub use host::{HostGroup, HostPath, HostUser, HostView};
pub use planner::{Plan, Problem, Request, STAGING_ROOT, Scope, plan, recover};
