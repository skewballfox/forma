//! Sub-ID range logic, as pure functions. Nothing here reads or writes a file.
//!
//! [`crate::admin::subid`] reads the files, calls these functions, and
//! writes the result.

use thiserror::Error;

use crate::defs::{SubIdEntry, SubIdLimits};
use crate::id::{IdRange, SubIdCount, SubIdRange};
use crate::lookup::User;

/// Finds the lowest free range of `count` sub-IDs inside `limits`.
///
/// A range is free if it overlaps nothing in `taken` and nothing in
/// `avoid`. Pass the user and group ID ranges for people in `avoid`, so a
/// sub-ID never equals a real account's ID.
///
/// This is the same search shadow-utils runs (`find_free_range`), so a range
/// picked here is one `useradd` could have picked.
///
/// # Errors
///
/// Returns [`SubIdError::NoFreeRange`] if no gap is large enough.
pub fn find_free_range(
    taken: &[SubIdRange],
    avoid: &[IdRange],
    limits: SubIdLimits,
    count: SubIdCount,
) -> Result<SubIdRange, SubIdError> {
    let mut busy: Vec<(u64, u64)> = taken
        .iter()
        .map(|range| (u64::from(range.start()), range.end()))
        .chain(
            avoid
                .iter()
                .map(|ids| (u64::from(ids.first()), u64::from(ids.last()) + 1)),
        )
        .collect();
    busy.sort_unstable();

    let size = u64::from(count.get());
    let limit_end = u64::from(limits.range.last()) + 1;
    let mut candidate = u64::from(limits.range.first());
    for (start, end) in busy {
        if start >= candidate + size {
            break;
        }
        candidate = candidate.max(end);
    }

    let no_room = || SubIdError::NoFreeRange { count, limits: limits.range };
    if candidate + size > limit_end {
        return Err(no_room());
    }
    let start = u32::try_from(candidate).map_err(|_| no_room())?;
    SubIdRange::new(start, count).map_err(|_| no_room())
}

/// Returns the ranges in `entries` that belong to `user`.
///
/// An entry belongs to the account if its owner is the account's name or
/// its user ID.
#[must_use]
pub fn ranges_of(entries: &[SubIdEntry], user: &User) -> Vec<SubIdRange> {
    entries
        .iter()
        .filter(|entry| owned_by(entry, user))
        .map(|entry| entry.range)
        .collect()
}

/// Returns the entries of other owners that overlap `range`.
#[must_use]
pub fn conflicts<'a>(entries: &'a [SubIdEntry], range: SubIdRange, user: &User) -> Vec<&'a SubIdEntry> {
    entries
        .iter()
        .filter(|entry| !owned_by(entry, user) && entry.range.overlaps(range))
        .collect()
}

fn owned_by(entry: &SubIdEntry, user: &User) -> bool {
    entry.owner == user.name().as_str() || entry.owner == user.uid().to_string()
}

/// A sub-ID range could not be found.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SubIdError {
    /// No free range of the size asked for exists.
    #[error("no free range of {} sub-IDs in {limits}", count.get())]
    NoFreeRange {
        /// The size asked for.
        count: SubIdCount,
        /// Where the range had to fall.
        limits: IdRange,
    },
}
