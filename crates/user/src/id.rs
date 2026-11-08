//! User, group and sub-ID numbers, and the ranges they must fall in.

use std::fmt;

use thiserror::Error;

/// A user ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uid(u32);

impl Uid {
    /// The root user ID.
    pub const ROOT: Self = Self(0);

    /// Wraps a raw user ID.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw user ID.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A group ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gid(u32);

impl Gid {
    /// The root group ID.
    pub const ROOT: Self = Self(0);

    /// Wraps a raw group ID.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw group ID.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Gid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// An inclusive range of IDs, such as `SYS_UID_MIN..=SYS_UID_MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdRange {
    first: u32,
    last: u32,
}

impl IdRange {
    /// Builds a range from its first and last ID.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::EmptyRange`] if `first` is greater than `last`.
    pub const fn new(first: u32, last: u32) -> Result<Self, IdError> {
        if first > last {
            return Err(IdError::EmptyRange { first, last });
        }
        Ok(Self { first, last })
    }

    /// Returns the first ID in the range.
    #[must_use]
    pub const fn first(self) -> u32 {
        self.first
    }

    /// Returns the last ID in the range.
    #[must_use]
    pub const fn last(self) -> u32 {
        self.last
    }

    /// Says whether the range holds `id`.
    #[must_use]
    pub const fn contains(self, id: u32) -> bool {
        self.first <= id && id <= self.last
    }
}

impl fmt::Display for IdRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.first, self.last)
    }
}

/// A user ID inside the system range from `login.defs`. Never root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SystemUid(Uid);

impl SystemUid {
    /// Checks that `uid` is not root and lies in `range`.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::Root`] for user ID 0, and [`IdError::OutsideRange`]
    /// if `uid` is outside `range`.
    pub fn new(uid: Uid, range: IdRange) -> Result<Self, IdError> {
        check_system_id(uid.as_raw(), range).map(|()| Self(uid))
    }

    /// Returns the user ID.
    #[must_use]
    pub const fn uid(self) -> Uid {
        self.0
    }
}

/// A group ID inside the system range from `login.defs`. Never root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SystemGid(Gid);

impl SystemGid {
    /// Checks that `gid` is not root and lies in `range`.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::Root`] for group ID 0, and [`IdError::OutsideRange`]
    /// if `gid` is outside `range`.
    pub fn new(gid: Gid, range: IdRange) -> Result<Self, IdError> {
        check_system_id(gid.as_raw(), range).map(|()| Self(gid))
    }

    /// Returns the group ID.
    #[must_use]
    pub const fn gid(self) -> Gid {
        self.0
    }
}

fn check_system_id(id: u32, range: IdRange) -> Result<(), IdError> {
    match id {
        0 => Err(IdError::Root),
        id if range.contains(id) => Ok(()),
        id => Err(IdError::OutsideRange { id, range }),
    }
}

/// The size of a sub-ID range: 65536 to 2^31.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubIdCount(u32);

impl SubIdCount {
    /// The smallest count allowed. Rootless Podman needs at least this many.
    pub const MIN: u32 = 65_536;
    /// The largest count allowed.
    pub const MAX: u32 = 1 << 31;

    /// Checks that `count` lies in `MIN..=MAX`.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::SubIdCount`] otherwise.
    pub const fn new(count: u32) -> Result<Self, IdError> {
        if count < Self::MIN || count > Self::MAX {
            return Err(IdError::SubIdCount(count));
        }
        Ok(Self(count))
    }

    /// Returns the count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A range of sub-IDs: a start and a count.
///
/// The range never includes `u32::MAX`, which the kernel treats as "no ID".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubIdRange {
    start: u32,
    count: u32,
}

impl SubIdRange {
    /// Builds a range for a new assignment.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::SubIdRangeOverflow`] if the range would reach
    /// `u32::MAX`.
    pub fn new(start: u32, count: SubIdCount) -> Result<Self, IdError> {
        Self::from_parts(start, count.get()).ok_or(IdError::SubIdRangeOverflow {
            start,
            count: count.get(),
        })
    }

    /// Builds a range of any non-zero size, as found in an existing file.
    pub(crate) fn from_parts(start: u32, count: u32) -> Option<Self> {
        let end = u64::from(start) + u64::from(count);
        (count > 0 && u32::try_from(end).is_ok()).then_some(Self { start, count })
    }

    /// Returns the first sub-ID.
    #[must_use]
    pub const fn start(self) -> u32 {
        self.start
    }

    /// Returns the number of sub-IDs.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.count
    }

    /// Returns the last sub-ID in the range.
    #[must_use]
    pub const fn last(self) -> u32 {
        // Cannot overflow: `from_parts` keeps `start + count <= u32::MAX`.
        self.start + (self.count - 1)
    }

    /// Returns one past the last sub-ID, as a `u64` so it cannot overflow.
    #[must_use]
    pub fn end(self) -> u64 {
        u64::from(self.start) + u64::from(self.count)
    }

    /// Says whether two ranges share any sub-ID.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        u64::from(self.start) < other.end() && u64::from(other.start) < self.end()
    }

    /// Says whether this range shares any ID with an [`IdRange`].
    #[must_use]
    pub fn overlaps_ids(self, ids: IdRange) -> bool {
        u64::from(self.start) <= u64::from(ids.last()) && u64::from(ids.first()) < self.end()
    }
}

/// Formats the range as `FIRST-LAST`, the form `usermod --add-subuids` takes.
impl fmt::Display for SubIdRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.last())
    }
}

/// An ID or range failed a check.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdError {
    /// The first ID of a range is after its last.
    #[error("ID range {first}-{last} is empty")]
    EmptyRange {
        /// First ID given.
        first: u32,
        /// Last ID given.
        last: u32,
    },
    /// The ID is 0, which is root.
    #[error("ID 0 is root")]
    Root,
    /// The ID is outside the system range.
    #[error("ID {id} is outside the system range {range}")]
    OutsideRange {
        /// The ID given.
        id: u32,
        /// The range it must fall in.
        range: IdRange,
    },
    /// The sub-ID count is outside the allowed sizes.
    #[error("sub-ID count {0} is outside {min}..={max}", min = SubIdCount::MIN, max = SubIdCount::MAX)]
    SubIdCount(u32),
    /// The sub-ID range would reach `u32::MAX`.
    #[error("sub-ID range starting at {start} with {count} IDs runs past the largest ID")]
    SubIdRangeOverflow {
        /// First sub-ID.
        start: u32,
        /// Number of sub-IDs.
        count: u32,
    },
}
