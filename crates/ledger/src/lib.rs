//! Forma's record of every change it has made to the host.
//!
//! The repository says what should exist. It cannot prove what forma
//! created. So forma keeps a ledger, and the ledger alone decides what
//! forma owns (`docs/architecture.md`, section 4).
//!
//! - [`Store`] reads and writes the ledger file, one atomic write per change.
//! - [`Recorder`] plugs a [`Store`] into `forma-user`, as its `Ownership`
//!   and its `Journal`.

mod journal;
mod model;
mod store;

pub use journal::Recorder;
pub use model::{AclWho, Entry, HOST, Item, Key, Ledger, Status, VERSION};
pub use store::{LedgerError, ROOT_LEDGER, Store};
