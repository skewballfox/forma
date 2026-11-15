//! The parts of `forma-build` (architecture 5.6) that need no buildah:
//!
//! - [`containerfile`] finds the base images a build would pull, so forma
//!   can pull and check each one before it builds with `--pull=never`.
//! - [`heredoc`] rewrites shebang heredocs so they build with
//!   `--isolation chroot`.
//!
//! Running buildah as the builder is not here yet: it needs the builder
//! account, which needs root.

pub mod containerfile;
pub mod heredoc;

pub use containerfile::{BaseError, Bases, OwnBase, RemoteBase, bases, require_trust};
