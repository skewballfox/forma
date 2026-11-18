//! Capability tokens for forma's privileged code.
//!
//! A privileged function takes a [`Token`] as its first argument. The token
//! is a zero-sized value that proves the process holds a set of Linux
//! capabilities. The only way to get one is [`acquire`], which checks the
//! effective set once. Code that calls a privileged function without a
//! matching token does not compile (`docs/architecture.md` 3.3).
//!
//! ```
//! use forma_privilege::{Chown, Fowner, Has, Token, capability_set};
//!
//! capability_set! {
//!     /// What creating a store directory needs.
//!     pub struct StoreDirs: Chown, Fowner;
//! }
//!
//! fn create_store_dir(_token: &Token<impl Has<Chown> + Has<Fowner>>) {}
//!
//! // An unprivileged process holds neither capability, so it gets no token.
//! if let Ok(token) = forma_privilege::acquire::<StoreDirs>() {
//!     create_store_dir(&token);
//! }
//! ```
//!
//! [`drop_all_except`] removes every other capability from the process
//! before `forma apply` acts, so child processes cannot gain more either. It
//! must run while the process has a single thread (capabilities belong to
//! each thread), and refuses otherwise.

use std::fmt;
use std::marker::PhantomData;

use thiserror::Error;

/// A Linux capability forma's actions can need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// `CAP_AUDIT_WRITE`: shadow-utils writes audit records.
    AuditWrite,
    /// `CAP_CHOWN`: change file owners.
    Chown,
    /// `CAP_DAC_OVERRIDE`: write files whatever their mode, such as `/etc/shadow`.
    DacOverride,
    /// `CAP_DAC_READ_SEARCH`: read files whatever their mode.
    DacReadSearch,
    /// `CAP_FOWNER`: change modes and ACLs of files the process does not own.
    Fowner,
    /// `CAP_MAC_ADMIN`: change SELinux policy and labels.
    MacAdmin,
}

impl Capability {
    /// Every capability forma knows.
    pub const ALL: [Self; 6] = [
        Self::AuditWrite,
        Self::Chown,
        Self::DacOverride,
        Self::DacReadSearch,
        Self::Fowner,
        Self::MacAdmin,
    ];

    /// Returns the kernel's name, such as `CAP_CHOWN`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::AuditWrite => "CAP_AUDIT_WRITE",
            Self::Chown => "CAP_CHOWN",
            Self::DacOverride => "CAP_DAC_OVERRIDE",
            Self::DacReadSearch => "CAP_DAC_READ_SEARCH",
            Self::Fowner => "CAP_FOWNER",
            Self::MacAdmin => "CAP_MAC_ADMIN",
        }
    }

    fn kernel(self) -> caps::Capability {
        match self {
            Self::AuditWrite => caps::Capability::CAP_AUDIT_WRITE,
            Self::Chown => caps::Capability::CAP_CHOWN,
            Self::DacOverride => caps::Capability::CAP_DAC_OVERRIDE,
            Self::DacReadSearch => caps::Capability::CAP_DAC_READ_SEARCH,
            Self::Fowner => caps::Capability::CAP_FOWNER,
            Self::MacAdmin => caps::Capability::CAP_MAC_ADMIN,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of capabilities, as a value. Actions declare one as a constant,
/// and `forma apply` adds them up to know what to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Capabilities(u8);

impl Capabilities {
    /// No capability.
    pub const NONE: Self = Self(0);

    /// Builds a set from a list.
    #[must_use]
    pub const fn of(list: &[Capability]) -> Self {
        let mut bits = 0;
        let mut index = 0;
        while index < list.len() {
            bits |= 1 << list[index] as u8;
            index += 1;
        }
        Self(bits)
    }

    /// Returns the capabilities in either set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Says whether the set holds `capability`.
    #[must_use]
    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & (1 << capability as u8) != 0
    }

    /// Says whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the capabilities in the set, in a fixed order.
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .into_iter()
            .filter(move |capability| self.contains(*capability))
    }
}

impl FromIterator<Capability> for Capabilities {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        iter.into_iter()
            .fold(Self::NONE, |set, capability| set.union(Self::of(&[capability])))
    }
}

impl fmt::Display for Capabilities {
    /// Writes the names separated by `, `, or `none`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("none");
        }
        for (index, capability) in self.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            f.write_str(capability.name())?;
        }
        Ok(())
    }
}

/// A capability as a type, so a function can name it in its signature.
pub trait Marker {
    /// The capability the type stands for.
    const CAPABILITY: Capability;
}

macro_rules! markers {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {$(
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name;

        impl Marker for $name {
            const CAPABILITY: Capability = Capability::$name;
        }
    )*};
}

markers! {
    /// `CAP_AUDIT_WRITE`, as a type.
    AuditWrite,
    /// `CAP_CHOWN`, as a type.
    Chown,
    /// `CAP_DAC_OVERRIDE`, as a type.
    DacOverride,
    /// `CAP_DAC_READ_SEARCH`, as a type.
    DacReadSearch,
    /// `CAP_FOWNER`, as a type.
    Fowner,
    /// `CAP_MAC_ADMIN`, as a type.
    MacAdmin,
}

/// A set of capabilities as a type. Define one with [`capability_set!`].
pub trait Set {
    /// The capabilities in the set.
    const CAPABILITIES: Capabilities;
}

/// Says that the set `Self` holds the capability `C`.
///
/// [`capability_set!`] implements it. Do not implement it by hand: a wrong
/// implementation lets a token claim a capability [`acquire`] never checked.
pub trait Has<C: Marker>: Set {}

/// Defines a set of capabilities as a type.
///
/// ```
/// forma_privilege::capability_set! {
///     /// What `useradd` needs.
///     pub struct Accounts: Chown, DacOverride, Fowner, AuditWrite;
/// }
/// ```
#[macro_export]
macro_rules! capability_set {
    ($(#[$doc:meta])* $visibility:vis struct $name:ident: $($capability:ident),+ $(,)?;) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy)]
        $visibility struct $name;

        impl $crate::Set for $name {
            const CAPABILITIES: $crate::Capabilities = $crate::Capabilities::of(&[
                $(<$crate::$capability as $crate::Marker>::CAPABILITY),+
            ]);
        }

        $(impl $crate::Has<$crate::$capability> for $name {})+
    };
}

/// The set with no capability. A token for it proves nothing; it exists
/// for actions that need root's user ID and no capability.
#[derive(Debug, Clone, Copy)]
pub struct NoCapabilities;

impl Set for NoCapabilities {
    const CAPABILITIES: Capabilities = Capabilities::NONE;
}

/// Proof that the process held the capabilities of `S` when [`acquire`] ran.
///
/// It has no size and cannot be built any other way.
#[derive(Debug)]
pub struct Token<S: Set>(PhantomData<S>);

/// A capability check or change failed.
#[derive(Debug, Error)]
pub enum Error {
    /// The process lacks capabilities it needs.
    #[error("the process lacks {missing}; run forma apply as root")]
    Missing {
        /// The capabilities it lacks.
        missing: Capabilities,
    },
    /// The process has more than one thread. Capabilities belong to each
    /// thread, and no thread can change another's, so a drop would leave
    /// the others holding everything.
    #[error("the process has {count} threads; drop capabilities before any other thread starts")]
    Threads {
        /// How many threads it has.
        count: usize,
    },
    /// The kernel refused to read or change a capability set.
    #[error("cannot {action}: {message}")]
    Kernel {
        /// What forma was doing.
        action: &'static str,
        /// What the kernel said.
        message: String,
    },
}

fn kernel(action: &'static str) -> impl Fn(caps::errors::CapsError) -> Error {
    move |error| Error::Kernel {
        action,
        message: error.to_string(),
    }
}

/// Returns the capabilities forma knows that are in the process's
/// effective set.
///
/// # Errors
///
/// Returns [`Error::Kernel`] if the set cannot be read.
pub fn effective() -> Result<Capabilities, Error> {
    let held = caps::read(None, caps::CapSet::Effective).map_err(kernel("read the effective capability set"))?;
    Ok(Capability::ALL
        .into_iter()
        .filter(|capability| held.contains(&capability.kernel()))
        .collect())
}

/// Checks that the process holds every capability of `S`, and returns the
/// token that proves it.
///
/// # Errors
///
/// Returns [`Error::Missing`] with the capabilities the process lacks, or
/// [`Error::Kernel`] if the effective set cannot be read.
pub fn acquire<S: Set>() -> Result<Token<S>, Error> {
    let held = effective()?;
    let missing: Capabilities = S::CAPABILITIES
        .iter()
        .filter(|capability| !held.contains(*capability))
        .collect();
    if missing.is_empty() {
        Ok(Token(PhantomData))
    } else {
        Err(Error::Missing { missing })
    }
}

/// Removes every capability but those in `keep` from the process, for good.
///
/// It clears the ambient and inheritable sets, drops every other capability
/// from the bounding set, and cuts the permitted and effective sets down to
/// `keep`. Child processes inherit the smaller bounding set, so `useradd` or
/// `semodule` cannot gain a capability forma gave up (architecture 3.3).
///
/// The bounding set is changed first, because that needs `CAP_SETPCAP`,
/// which this call then gives up with the rest.
///
/// Capability sets belong to each thread, and the kernel lets a thread
/// change only its own. So this must run while the process has one thread,
/// before any runtime or pool starts: every thread started after it gets
/// the reduced sets. It checks, and changes nothing if there are others.
///
/// # Errors
///
/// Returns [`Error::Threads`], having changed nothing, if the process has
/// more than one thread. Returns [`Error::Kernel`] if the threads cannot be
/// counted or a set cannot be changed. A process without `CAP_SETPCAP`
/// cannot change its bounding set; some sets may already have been reduced
/// when that error returns.
pub fn drop_all_except(keep: Capabilities) -> Result<(), Error> {
    // With one thread, nothing can start another before the drop below.
    let count = std::fs::read_dir("/proc/self/task")
        .map_err(|error| Error::Kernel {
            action: "count the process's threads",
            message: error.to_string(),
        })?
        .count();
    if count != 1 {
        return Err(Error::Threads { count });
    }
    let keep: caps::CapsHashSet = keep.iter().map(Capability::kernel).collect();
    caps::clear(None, caps::CapSet::Ambient).map_err(kernel("clear the ambient capability set"))?;
    for capability in caps::all() {
        if keep.contains(&capability) {
            continue;
        }
        // A capability the running kernel does not know cannot be in the set.
        if caps::has_cap(None, caps::CapSet::Bounding, capability).unwrap_or(false) {
            caps::drop(None, caps::CapSet::Bounding, capability)
                .map_err(kernel("drop a capability from the bounding set"))?;
        }
    }
    caps::clear(None, caps::CapSet::Inheritable).map_err(kernel("clear the inheritable capability set"))?;
    caps::set(None, caps::CapSet::Effective, &keep).map_err(kernel("reduce the effective capability set"))?;
    caps::set(None, caps::CapSet::Permitted, &keep).map_err(kernel("reduce the permitted capability set"))
}

#[cfg(test)]
mod tests {
    use super::*;

    capability_set! {
        /// A set for the tests.
        struct Accounts: Chown, DacOverride, Fowner, AuditWrite;
    }

    fn needs_chown(_token: &Token<impl Has<Chown>>) {}

    #[test]
    fn a_set_type_lists_its_capabilities() {
        assert_eq!(
            Accounts::CAPABILITIES.to_string(),
            "CAP_AUDIT_WRITE, CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER"
        );
        assert!(Accounts::CAPABILITIES.contains(Capability::Chown));
        assert!(!Accounts::CAPABILITIES.contains(Capability::MacAdmin));
        assert_eq!(Capabilities::NONE.to_string(), "none");
        assert_eq!(std::mem::size_of::<Token<Accounts>>(), 0);
    }

    #[test]
    fn sets_add_up() {
        let users = Capabilities::of(&[Capability::Chown, Capability::DacOverride]);
        let selinux = Capabilities::of(&[Capability::DacOverride, Capability::MacAdmin]);
        let both = users.union(selinux);
        assert_eq!(both.iter().count(), 3);
        assert_eq!(
            both,
            [Capability::MacAdmin, Capability::Chown, Capability::DacOverride]
                .into_iter()
                .collect()
        );
        assert_eq!(Capabilities::NONE.union(Capabilities::NONE), Capabilities::NONE);
    }

    #[test]
    fn a_token_needs_every_capability_of_its_set() {
        let held = effective().unwrap();
        match acquire::<Accounts>() {
            Ok(token) => {
                // Only a privileged test run gets here.
                assert!(
                    Accounts::CAPABILITIES
                        .iter()
                        .all(|capability| held.contains(capability))
                );
                needs_chown(&token);
            }
            Err(Error::Missing { missing }) => {
                assert!(!missing.is_empty());
                assert!(missing.iter().all(|capability| !held.contains(capability)));
            }
            Err(other) => panic!("{other}"),
        }
    }

    #[test]
    fn the_empty_set_needs_nothing() {
        assert!(acquire::<NoCapabilities>().is_ok());
    }

    #[test]
    fn the_error_names_what_is_missing() {
        let error = Error::Missing {
            missing: Capabilities::of(&[Capability::Chown, Capability::MacAdmin]),
        };
        assert_eq!(
            error.to_string(),
            "the process lacks CAP_CHOWN, CAP_MAC_ADMIN; run forma apply as root"
        );
    }
}
