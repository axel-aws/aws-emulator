// SPDX-License-Identifier: CC0-1.0

//! Which AWS resources exist in which Region, from AWS's published Regional availability
//! data.
//!
//! AWS publishes, per Region, which services, API operations and CloudFormation resource
//! types it offers (the "AWS Capabilities by Region" data, also served as JSON from a public
//! S3 access point and refreshed daily). A request for something a Region does not offer
//! fails on AWS, so an emulator that accepts it hides a failure that only shows at deploy
//! time. This module answers one question, "does Region R offer CloudFormation resource type
//! T", from a snapshot bundled in the crate.
//!
//! ## The snapshot
//!
//! `data/cfn_resource_availability.txt`, generated from the dataset's `cfn_resources.json`
//! and `regions.json`. Its header names the source file, the source's SHA-256 and the
//! dataset's own `last_updated` time, which every refusal quotes. Each data line is a type
//! and a hex mask over the header's `# regions` list (bit 0 is the first Region listed):
//! a set bit means the dataset says `Available`.
//!
//! ## What is never refused
//!
//! The answer is [`Verdict::Unknown`], and the caller lets the request through, when the
//! dataset has nothing to say: a type it does not list (a custom resource, a third-party
//! extension, `AWS::CDK::Metadata`, a type newer than the snapshot) or a Region it does not
//! list (a Region newer than the snapshot, or a partition the dataset omits). Only a listed
//! type in a listed Region that is not marked `Available` is [`Verdict::Unavailable`].
//!
//! shortcut: the snapshot only covers CloudFormation resource types, and it is replaced by
//! regenerating the file, not at run time. Extend to API operations and to a user-supplied
//! refresh file in the follow-up changes.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// The environment variable that selects the [`Mode`].
pub const MODE_ENV: &str = "EMULATOR_REGION_AVAILABILITY";

/// How many days old the data may be before a message or the log says so.
pub const STALE_AFTER_DAYS: i64 = 30;

/// The bundled snapshot of CloudFormation resource type availability.
const BUNDLED_CFN: &str = include_str!("../data/cfn_resource_availability.txt");

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
fn days_from_date(date: &str) -> Option<i64> {
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

    /// The mode [`MODE_ENV`] selects. A value that is not a mode is logged and ignored, so a
    /// typo cannot silently turn the check off.
    pub fn from_env() -> Mode {
        match std::env::var(MODE_ENV) {
            Ok(raw) => Mode::parse(&raw).unwrap_or_else(|| {
                tracing::warn!(
                    "{MODE_ENV}={raw:?} is not off, warn or enforce; using {:?}",
                    Mode::DEFAULT
                );
                Mode::DEFAULT
            }),
            Err(_) => Mode::DEFAULT,
        }
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

/// A parsed availability snapshot.
#[derive(Debug)]
pub struct Snapshot {
    last_updated: String,
    regions: Vec<String>,
    masks: HashMap<String, u64>,
}

impl Snapshot {
    /// Parse the snapshot text. `Err` names the first line that does not follow the format.
    pub fn parse(text: &str) -> Result<Snapshot, String> {
        let mut last_updated = None;
        let mut regions: Option<Vec<String>> = None;
        let mut masks = HashMap::new();
        for (number, line) in text.lines().enumerate() {
            let number = number + 1;
            if let Some(header) = line.strip_prefix("# ") {
                if let Some(value) = header.strip_prefix("last_updated ") {
                    last_updated = Some(value.trim().to_string());
                } else if let Some(value) = header.strip_prefix("regions ") {
                    let list: Vec<String> = value.split_whitespace().map(str::to_string).collect();
                    if list.is_empty() || list.len() > 64 {
                        return Err(format!("line {number}: expected 1 to 64 Regions"));
                    }
                    regions = Some(list);
                }
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            let (name, mask) = line
                .split_once(' ')
                .ok_or_else(|| format!("line {number}: expected `<type> <hex mask>`"))?;
            let mask = u64::from_str_radix(mask.trim(), 16)
                .map_err(|_| format!("line {number}: {mask:?} is not a hex mask"))?;
            masks.insert(name.to_string(), mask);
        }
        Ok(Snapshot {
            last_updated: last_updated.ok_or("missing `# last_updated` header")?,
            regions: regions.ok_or("missing `# regions` header")?,
            masks,
        })
    }

    /// The snapshot bundled in this crate, parsed once.
    pub fn bundled() -> &'static Snapshot {
        static BUNDLED: OnceLock<Snapshot> = OnceLock::new();
        BUNDLED.get_or_init(|| {
            let snapshot = Snapshot::parse(BUNDLED_CFN)
                .expect("the bundled availability snapshot is well formed");
            if let Some(note) = snapshot.staleness_note(SystemTime::now()) {
                tracing::warn!(
                    "the bundled AWS Regional availability data of {}: {note}",
                    snapshot.data_date()
                );
            }
            snapshot
        })
    }

    /// The dataset's `last_updated` time, as published (RFC 3339).
    pub fn last_updated(&self) -> &str {
        &self.last_updated
    }

    /// The date part of [`Self::last_updated`], for messages.
    pub fn data_date(&self) -> &str {
        self.last_updated.get(..10).unwrap_or(&self.last_updated)
    }

    /// [`staleness_note`] for this snapshot.
    pub fn staleness_note(&self, now: SystemTime) -> Option<String> {
        staleness_note(&self.last_updated, now)
    }

    /// How many types the snapshot lists.
    pub fn type_count(&self) -> usize {
        self.masks.len()
    }

    /// The Regions the snapshot lists.
    pub fn regions(&self) -> &[String] {
        &self.regions
    }

    /// Whether CloudFormation offers `resource_type` (for example `AWS::MemoryDB::Cluster`)
    /// in `region`. The type is matched exactly; the Region ignores letter case, as a Region
    /// read off a credential scope does.
    pub fn cfn_resource_type(&self, region: &str, resource_type: &str) -> Verdict {
        let Some(bit) = self
            .regions
            .iter()
            .position(|listed| listed.eq_ignore_ascii_case(region))
        else {
            return Verdict::Unknown;
        };
        match self.masks.get(resource_type) {
            None => Verdict::Unknown,
            Some(mask) if mask >> bit & 1 == 1 => Verdict::Available,
            Some(_) => Verdict::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# last_updated 2026-11-17T00:03:09.441208+00:00\n\
                          # regions us-east-1 ap-southeast-7 ap-southeast-6\n\
                          AWS::MemoryDB::Cluster 1\n\
                          AWS::AppSync::GraphQLApi 3\n\
                          AWS::SQS::Queue 7\n";

    #[test]
    fn a_listed_type_is_available_only_where_its_bit_is_set() {
        let snapshot = Snapshot::parse(SAMPLE).unwrap();
        let cases = [
            ("us-east-1", "AWS::MemoryDB::Cluster", Verdict::Available),
            (
                "ap-southeast-7",
                "AWS::MemoryDB::Cluster",
                Verdict::Unavailable,
            ),
            (
                "ap-southeast-6",
                "AWS::MemoryDB::Cluster",
                Verdict::Unavailable,
            ),
            (
                "ap-southeast-7",
                "AWS::AppSync::GraphQLApi",
                Verdict::Available,
            ),
            (
                "ap-southeast-6",
                "AWS::AppSync::GraphQLApi",
                Verdict::Unavailable,
            ),
            ("ap-southeast-6", "AWS::SQS::Queue", Verdict::Available),
            ("AP-SOUTHEAST-7", "AWS::SQS::Queue", Verdict::Available),
        ];
        for (region, resource_type, expected) in cases {
            assert_eq!(
                snapshot.cfn_resource_type(region, resource_type),
                expected,
                "{resource_type} in {region}"
            );
        }
    }

    #[test]
    fn what_the_data_does_not_list_is_unknown_and_so_never_refused() {
        let snapshot = Snapshot::parse(SAMPLE).unwrap();
        let cases = [
            ("xx-test-1", "AWS::MemoryDB::Cluster"),
            ("us-east-1", "Custom::Thing"),
            ("us-east-1", "AWS::Made::Up"),
            ("us-east-1", "aws::memorydb::cluster"),
            ("", "AWS::SQS::Queue"),
        ];
        for (region, resource_type) in cases {
            assert_eq!(
                snapshot.cfn_resource_type(region, resource_type),
                Verdict::Unknown,
                "{resource_type} in {region:?}"
            );
        }
    }

    #[test]
    fn the_data_date_is_the_date_part_of_last_updated() {
        let snapshot = Snapshot::parse(SAMPLE).unwrap();
        assert_eq!(snapshot.data_date(), "2026-11-17");
        assert_eq!(snapshot.last_updated(), "2026-11-17T00:03:09.441208+00:00");
    }

    #[test]
    fn a_malformed_snapshot_names_the_line_or_header_at_fault() {
        let cases = [
            ("# regions a\nAWS::X::Y 1\n", "last_updated"),
            ("# last_updated 2026-11-17\nAWS::X::Y 1\n", "regions"),
            ("# last_updated d\n# regions a\nAWS::X::Y zz\n", "line 3"),
            ("# last_updated d\n# regions a\nAWS::X::Y\n", "line 3"),
        ];
        for (text, expected) in cases {
            let error = Snapshot::parse(text).unwrap_err();
            assert!(error.contains(expected), "{text:?}: got {error:?}");
        }
    }

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
    fn a_snapshot_reports_its_own_staleness() {
        let snapshot = Snapshot::parse(SAMPLE).unwrap();
        let note = snapshot.staleness_note(day(20_774 + 31)).unwrap();
        assert!(note.contains("31 days old"), "{note}");
        assert_eq!(snapshot.staleness_note(day(20_774 + 5)), None);
    }

    #[test]
    fn a_mode_is_off_warn_or_enforce_in_any_letter_case() {
        assert_eq!(Mode::parse("off"), Some(Mode::Off));
        assert_eq!(Mode::parse(" Warn "), Some(Mode::Warn));
        assert_eq!(Mode::parse("ENFORCE"), Some(Mode::Enforce));
        assert_eq!(Mode::parse("on"), None);
        assert_eq!(Mode::parse(""), None);
    }

    /// The shipped file parses, is dated, and carries the Regions and cases the gate exists
    /// for: Bangkok and Auckland lack MemoryDB, Grafana and EventBridge Pipes, Auckland
    /// lacks AppSync and Bangkok has it, and the oldest Region has all of them.
    #[test]
    fn the_bundled_snapshot_answers_for_bangkok_and_auckland() {
        let snapshot = Snapshot::bundled();
        assert!(
            snapshot.type_count() > 2000,
            "{} types",
            snapshot.type_count()
        );
        assert!(snapshot.regions().len() >= 37);
        assert_eq!(
            snapshot.data_date().len(),
            10,
            "{}",
            snapshot.last_updated()
        );
        let cases = [
            ("AWS::MemoryDB::Cluster", "us-east-1", Verdict::Available),
            (
                "AWS::MemoryDB::Cluster",
                "ap-southeast-7",
                Verdict::Unavailable,
            ),
            (
                "AWS::MemoryDB::Cluster",
                "ap-southeast-6",
                Verdict::Unavailable,
            ),
            (
                "AWS::Grafana::Workspace",
                "ap-southeast-7",
                Verdict::Unavailable,
            ),
            ("AWS::Pipes::Pipe", "ap-southeast-6", Verdict::Unavailable),
            (
                "AWS::AppSync::GraphQLApi",
                "ap-southeast-7",
                Verdict::Available,
            ),
            (
                "AWS::AppSync::GraphQLApi",
                "ap-southeast-6",
                Verdict::Unavailable,
            ),
            ("AWS::SQS::Queue", "ap-southeast-7", Verdict::Available),
            ("AWS::SQS::Queue", "ap-southeast-6", Verdict::Available),
            ("AWS::CDK::Metadata", "ap-southeast-7", Verdict::Unknown),
        ];
        for (resource_type, region, expected) in cases {
            assert_eq!(
                snapshot.cfn_resource_type(region, resource_type),
                expected,
                "{resource_type} in {region}"
            );
        }
    }
}
