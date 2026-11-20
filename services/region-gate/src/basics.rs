// SPDX-License-Identifier: CC0-1.0

//! The small pieces the Regional availability checks share: the mode a check runs in, what the
//! data can say about one item, and how old data is.
//!
//! They live in this crate, below the request router, so the router's service check and the
//! CloudFormation check read one setting and one set of words. `service_common` re-exports them
//! from `region_availability`, where they were first written.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The environment variable that selects the [`Mode`].
pub const MODE_ENV: &str = "EMULATOR_REGION_AVAILABILITY";

/// How many days old the data may be before a message or the log says so.
pub const STALE_AFTER_DAYS: i64 = 30;

/// Whole days from a dataset's `last_updated` time (RFC 3339) to `now`. `None` when the date
/// cannot be read. Negative when the data is dated after the clock.
pub fn age_days(last_updated: &str, now: SystemTime) -> Option<i64> {
    let today = i64::try_from(now.duration_since(UNIX_EPOCH).ok()?.as_secs() / 86_400).ok()?;
    Some(today - days_from_date(last_updated.get(..10)?)?)
}

/// A clause saying how old the data is, once it is older than [`STALE_AFTER_DAYS`].
pub fn staleness_note(last_updated: &str, now: SystemTime) -> Option<String> {
    let age = age_days(last_updated, now)?;
    (age > STALE_AFTER_DAYS).then(|| format!("that data is {age} days old, so check it is current"))
}

/// Days since 1970-01-01 of a `YYYY-MM-DD` date (proleptic Gregorian calendar).
pub fn days_from_date(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

/// What the emulator does with a request the data says the Region cannot serve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Do not consult the data.
    Off,
    /// Let the request through and log a warning that names what AWS would refuse.
    Warn,
    /// Refuse the request the way AWS does.
    Enforce,
}

impl Mode {
    /// The mode used when [`MODE_ENV`] is not set.
    pub const DEFAULT: Mode = Mode::Enforce;

    /// `off`, `warn` or `enforce`, in any letter case.
    pub fn parse(raw: &str) -> Option<Mode> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Mode::Off),
            "warn" => Some(Mode::Warn),
            "enforce" => Some(Mode::Enforce),
            _ => None,
        }
    }

    /// The mode the router's service check uses when [`MODE_ENV`] is not set: `warn`. The
    /// service table has rows that are wrong for services the emulator ships (IoT Data Plane is
    /// listed in us-east-1 only), and the refresh does not update that table, so the router
    /// refuses only when a user asks for `enforce`. The CloudFormation check keeps [`Self::DEFAULT`].
    pub const ROUTER_DEFAULT: Mode = Mode::Warn;

    /// The mode [`MODE_ENV`] selects, or [`Self::DEFAULT`]. See [`Self::from_env_or`].
    pub fn from_env() -> Mode {
        Mode::from_env_or(Mode::DEFAULT)
    }

    /// The mode [`MODE_ENV`] selects, or `default` when it is not set. A value that is not a
    /// mode is logged and ignored, so a typo cannot silently turn the check off. The log line is
    /// written once per value, not once per request, because the router asks on every request.
    pub fn from_env_or(default: Mode) -> Mode {
        let raw = std::env::var(MODE_ENV).ok();
        let mode = Mode::from_setting(raw.as_deref(), default);
        if let Some(raw) = raw.filter(|raw| Mode::parse(raw).is_none()) {
            if first_time_seen(&raw) {
                tracing::warn!("{}", typo_text(&raw));
            }
        }
        mode
    }

    /// The mode for a setting: the setting when it is a mode, else `default` (unset or a typo).
    pub fn from_setting(raw: Option<&str>, default: Mode) -> Mode {
        raw.and_then(Mode::parse).unwrap_or(default)
    }
}

/// What the data says about one type in one Region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Available,
    Unavailable,
    /// The data does not list the type or the Region; the caller must not refuse.
    Unknown,
}

/// The note for a setting that is not a mode. It is written once per value, by whichever check
/// reads it first, so it names both defaults: each check keeps its own.
pub(crate) fn typo_text(raw: &str) -> String {
    format!(
        "{MODE_ENV}={raw:?} is not off, warn or enforce, so each check keeps its default: \
         CloudFormation templates {}, API requests {}",
        Mode::DEFAULT.name(),
        Mode::ROUTER_DEFAULT.name()
    )
}

impl Mode {
    /// `off`, `warn` or `enforce`.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Warn => "warn",
            Mode::Enforce => "enforce",
        }
    }
}

/// `true` the first time `raw` is passed in a row, so a bad setting is logged once and not on
/// every request. The same value again is `false`; a different one (the setting changed) is
/// `true` again.
pub(crate) fn first_time_seen(raw: &str) -> bool {
    static LAST: Mutex<Option<String>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if last.as_deref() == Some(raw) {
        return false;
    }
    *last = Some(raw.to_string());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A moment `days` whole days after 1970-01-01, plus a few hours.
    fn day(days: u64) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(days * 86_400 + 5 * 3_600)
    }

    #[test]
    fn a_date_counts_days_from_1970() {
        let cases = [
            ("1970-01-01", Some(0)),
            ("2000-03-01", Some(11_017)),
            ("2026-11-17", Some(20_774)),
            ("2026-11-17T00:03:09+00:00", None),
            ("2026-13-01", None),
            ("2026-11-00", None),
            ("2026-11", None),
            ("2026-11-17-1", None),
            ("november", None),
        ];
        for (date, expected) in cases {
            assert_eq!(days_from_date(date), expected, "{date}");
        }
    }

    #[test]
    fn data_is_stale_only_past_the_limit() {
        // The dataset's own time stamp, dated 2026-11-17 (day 20_774).
        let stamp = "2026-11-17T00:03:09.441208+00:00";
        assert_eq!(age_days(stamp, day(20_774)), Some(0));
        assert_eq!(age_days(stamp, day(20_774 + 30)), Some(30));
        assert_eq!(staleness_note(stamp, day(20_774)), None);
        assert_eq!(
            staleness_note(stamp, day(20_774 + 30)),
            None,
            "30 days is the limit"
        );
        assert_eq!(
            staleness_note(stamp, day(20_774 + 31)).as_deref(),
            Some("that data is 31 days old, so check it is current")
        );
        // Data dated after the clock is not stale, and an unreadable date says nothing.
        assert_eq!(age_days(stamp, day(20_700)), Some(-74));
        assert_eq!(staleness_note(stamp, day(20_700)), None);
        assert_eq!(staleness_note("unknown", day(30_000)), None);
        assert_eq!(staleness_note("", day(30_000)), None);
    }

    #[test]
    fn a_mode_is_off_warn_or_enforce_in_any_letter_case() {
        assert_eq!(Mode::parse("off"), Some(Mode::Off));
        assert_eq!(Mode::parse(" Warn "), Some(Mode::Warn));
        assert_eq!(Mode::parse("ENFORCE"), Some(Mode::Enforce));
        assert_eq!(Mode::parse("on"), None);
        assert_eq!(Mode::parse(""), None);
    }

    /// The router defaults to `warn`, the CloudFormation check to `enforce`. A typo keeps the
    /// default of the check that reads it, so it never turns a check off.
    #[test]
    fn each_check_keeps_its_own_default_and_a_typo_never_turns_one_off() {
        assert_eq!(Mode::ROUTER_DEFAULT, Mode::Warn);
        assert_eq!(Mode::DEFAULT, Mode::Enforce);
        for default in [Mode::Warn, Mode::Enforce] {
            assert_eq!(Mode::from_setting(None, default), default);
            for typo in ["of", "disabled", "", "0", "on", "true"] {
                assert_eq!(Mode::from_setting(Some(typo), default), default, "{typo:?}");
            }
            assert_eq!(Mode::from_setting(Some("off"), default), Mode::Off);
            assert_eq!(Mode::from_setting(Some(" Warn "), default), Mode::Warn);
            assert_eq!(Mode::from_setting(Some("ENFORCE"), default), Mode::Enforce);
        }
    }

    #[test]
    fn the_typo_note_names_both_defaults() {
        assert_eq!(
            typo_text("enfroce"),
            "EMULATOR_REGION_AVAILABILITY=\"enfroce\" is not off, warn or enforce, so each check \
             keeps its default: CloudFormation templates enforce, API requests warn"
        );
        assert_eq!(
            [Mode::Off.name(), Mode::Warn.name(), Mode::Enforce.name()],
            ["off", "warn", "enforce"]
        );
    }

    #[test]
    fn a_bad_mode_is_logged_once_per_value() {
        assert!(first_time_seen("onn"));
        assert!(!first_time_seen("onn"), "the same typo again is not news");
        assert!(first_time_seen("offf"), "a different one is");
        assert!(
            first_time_seen("onn"),
            "and the first one again after a change"
        );
    }
}
