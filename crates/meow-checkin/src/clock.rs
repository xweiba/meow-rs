//! Wall-clock time, injectable. The schedule only ever asks "what local
//! day and minute is it now"; it keeps no deadline of its own, so a clock
//! that jumps (NTP, suspend, a new time zone) cannot strand it.

use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

pub trait Clock: Send + Sync {
    fn now_utc(&self) -> OffsetDateTime;
    /// The machine's offset from UTC at `at`.
    fn local_offset(&self, at: OffsetDateTime) -> UtcOffset;
}

/// The machine's clock and time zone.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    #[cfg(unix)]
    fn local_offset(&self, at: OffsetDateTime) -> UtcOffset {
        let t: libc::time_t = at.unix_timestamp() as libc::time_t;
        // SAFETY: `localtime_r` writes into the zeroed `tm` we own and
        // reads the `time_t` we pass; a null return leaves `tm` untouched.
        let seconds = unsafe {
            let mut tm: libc::tm = std::mem::zeroed();
            if libc::localtime_r(&t, &mut tm).is_null() {
                0
            } else {
                tm.tm_gmtoff as i32
            }
        };
        UtcOffset::from_whole_seconds(seconds).unwrap_or(UtcOffset::UTC)
    }

    #[cfg(not(unix))]
    fn local_offset(&self, at: OffsetDateTime) -> UtcOffset {
        UtcOffset::local_offset_at(at).unwrap_or(UtcOffset::UTC)
    }
}

/// Now, as the schedule and the run records need it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalNow {
    pub utc: OffsetDateTime,
    /// `yyyy-MM-dd`, local.
    pub day: String,
    /// Minutes after local midnight.
    pub minute: u16,
}

pub fn local_now(clock: &dyn Clock) -> LocalNow {
    let utc = clock.now_utc();
    let local = utc.to_offset(clock.local_offset(utc));
    LocalNow {
        utc,
        day: format!(
            "{:04}-{:02}-{:02}",
            local.year(),
            u8::from(local.month()),
            local.day()
        ),
        minute: u16::from(local.hour()) * 60 + u16::from(local.minute()),
    }
}

/// RFC 3339, UTC, whole seconds: `2026-10-12T00:30:00Z`.
pub fn rfc3339(at: OffsetDateTime) -> String {
    at.to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    struct Fixed(OffsetDateTime, UtcOffset);
    impl Clock for Fixed {
        fn now_utc(&self) -> OffsetDateTime {
            self.0
        }
        fn local_offset(&self, _at: OffsetDateTime) -> UtcOffset {
            self.1
        }
    }

    #[test]
    fn the_day_and_minute_are_local() {
        let east = UtcOffset::from_hms(8, 0, 0).unwrap();
        let now = local_now(&Fixed(datetime!(2026-10-11 16:30:59 UTC), east));
        assert_eq!(now.day, "2026-10-12");
        assert_eq!(now.minute, 30);
        let west = UtcOffset::from_hms(-5, 0, 0).unwrap();
        let now = local_now(&Fixed(datetime!(2026-10-12 03:15:00 UTC), west));
        assert_eq!(now.day, "2026-10-11");
        assert_eq!(now.minute, 22 * 60 + 15);
    }

    #[test]
    fn times_are_written_in_utc_to_the_second() {
        assert_eq!(
            rfc3339(datetime!(2026-10-12 08:30:00.123 +8)),
            "2026-10-12T00:30:00Z"
        );
    }

    #[test]
    fn the_system_clock_answers() {
        let c = SystemClock;
        let now = c.now_utc();
        let off = c.local_offset(now);
        assert!(off.whole_hours().abs() <= 14);
    }
}
