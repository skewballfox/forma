//! Installs and removes forma's SELinux modules, and maps service accounts
//! to an SELinux user (architecture 5.9).
//!
//! Every change goes through `semodule` or `semanage`, run with
//! `forma-process`: no maintained Rust binding to `libsemanage` exists.
//! Forma's modules sit at their own priority, so a remove at that priority
//! cannot touch a module the distribution or an administrator installed.
//!
//! Code that needs root lives in the [`admin`] module (architecture 3.1).
//! Everything outside it runs as any user: reading `semodule -lfull` output
//! is [`list`].

pub mod admin;
pub mod list;
