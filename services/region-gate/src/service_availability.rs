// SPDX-License-Identifier: CC0-1.0

//! Whether AWS offers an API service in a Region, from AWS's published Regional availability
//! data.
//!
//! The sibling of `service_common::region_availability`, which answers the same question for
//! CloudFormation resource types. A request to a service that a Region does not offer fails on
//! AWS (the endpoint does not exist); the emulator would otherwise answer it. This module
//! answers one question, "does Region R offer the API service with Smithy shape id S", from a
//! snapshot bundled in the crate, and turns the answer into a [`Decision`] for the caller.
//!
//! ## The snapshot
//!
//! `data/service_availability.txt`, generated from the dataset's `apis.json` and `regions.json`.
//! The dataset names a service by its SDK id, which is the `sdkId` of the service's own Smithy
//! model, so the generator keys each service by the model's service shape id, the name the
//! router knows it by. A service is offered in a Region when at least one of its operations
//! is. Each data line is `<shape id> <hex mask> <sdkId>`, the mask over the header's
//! `# regions` list (bit 0 is the first Region listed).
//!
//! ## What is never refused
//!
//! A service the data does not list (an emulator service with no dataset entry) and a Region it
//! does not list answer [`Verdict::Unknown`], and [`decide`] lets the request through. Only a
//! listed service in a listed Region whose bit is clear is [`Verdict::Unavailable`].
//!
//! shortcut: service level only. A listed service that is offered in a Region but lacks one of
//! its operations there is not caught; add an operation level to the snapshot when that is
//! wanted. The request router calls [`decide`] through [`crate::gate`], right after it has named
//! the service and before the operation runs. The table is bundled; the refresh command does
//! not update it (the dataset's `apis.json` needs a converter of its own).

use crate::basics::{staleness_note, Mode, Verdict, MODE_ENV};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::SystemTime;

/// The bundled snapshot of API service availability.
const BUNDLED_SERVICES: &str = include_str!("../data/service_availability.txt");

/// What to do with one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Serve it.
    Allow,
    /// Serve it, and log this message.
    Warn(String),
    /// Refuse it with this message.
    Refuse(String),
}

#[derive(Debug)]
struct Entry {
    mask: u64,
    sdk_id: String,
}

/// A parsed service availability snapshot.
#[derive(Debug)]
pub struct ServiceSnapshot {
    last_updated: String,
    regions: Vec<String>,
    services: HashMap<String, Entry>,
}

impl ServiceSnapshot {
    /// Parse the snapshot text. `Err` names the first line that does not follow the format.
    pub fn parse(text: &str) -> Result<ServiceSnapshot, String> {
        let mut last_updated = None;
        let mut regions: Option<Vec<String>> = None;
        let mut services = HashMap::new();
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
            let mut fields = line.splitn(3, ' ');
            let (Some(shape_id), Some(mask), Some(sdk_id)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(format!(
                    "line {number}: expected `<shape id> <hex mask> <sdkId>`"
                ));
            };
            let mask = u64::from_str_radix(mask, 16)
                .map_err(|_| format!("line {number}: {mask:?} is not a hex mask"))?;
            services.insert(
                shape_id.to_string(),
                Entry {
                    mask,
                    sdk_id: sdk_id.trim().to_string(),
                },
            );
        }
        Ok(ServiceSnapshot {
            last_updated: last_updated.ok_or("missing `# last_updated` header")?,
            regions: regions.ok_or("missing `# regions` header")?,
            services,
        })
    }

    /// The snapshot bundled in this crate, parsed once.
    pub fn bundled() -> &'static ServiceSnapshot {
        static BUNDLED: OnceLock<ServiceSnapshot> = OnceLock::new();
        BUNDLED.get_or_init(|| {
            let snapshot = ServiceSnapshot::parse(BUNDLED_SERVICES)
                .expect("the bundled service availability snapshot is well formed");
            if let Some(note) = staleness_note(&snapshot.last_updated, SystemTime::now()) {
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

    /// How many services the snapshot lists.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// The Regions the snapshot lists.
    pub fn regions(&self) -> &[String] {
        &self.regions
    }

    /// The Smithy shape ids of the services the snapshot lists.
    pub fn shape_ids(&self) -> impl Iterator<Item = &str> {
        self.services.keys().map(String::as_str)
    }

    /// Whether the service with Smithy shape id `shape_id` (for example
    /// `com.amazonaws.memorydb#AmazonMemoryDB`) is offered in `region`. The shape id is matched
    /// exactly; the Region ignores letter case, as a Region read off a credential scope does.
    pub fn service(&self, region: &str, shape_id: &str) -> Verdict {
        let Some(bit) = self
            .regions
            .iter()
            .position(|listed| listed.eq_ignore_ascii_case(region))
        else {
            return Verdict::Unknown;
        };
        match self.services.get(shape_id) {
            None => Verdict::Unknown,
            Some(entry) if entry.mask >> bit & 1 == 1 => Verdict::Available,
            Some(_) => Verdict::Unavailable,
        }
    }

    /// The sentence that refuses a request to `shape_id` in `region`, as of `now`; `None` for a
    /// service the snapshot does not list.
    pub fn refusal_message(&self, shape_id: &str, region: &str, now: SystemTime) -> Option<String> {
        let entry = self.services.get(shape_id)?;
        let age = staleness_note(&self.last_updated, now)
            .map(|note| format!("{note}; "))
            .unwrap_or_default();
        Some(format!(
            "{} is not offered in {region}: AWS Regional availability data of {} lists none of \
             its operations there; {age}set {MODE_ENV}=off to skip this check",
            entry.sdk_id,
            self.data_date(),
        ))
    }
}

/// What to do with a request to the service `shape_id` in `region` under `mode`, as of `now`.
pub fn decide(
    mode: Mode,
    snapshot: &ServiceSnapshot,
    shape_id: &str,
    region: &str,
    now: SystemTime,
) -> Decision {
    if mode == Mode::Off || snapshot.service(region, shape_id) != Verdict::Unavailable {
        return Decision::Allow;
    }
    let message = snapshot
        .refusal_message(shape_id, region, now)
        .expect("an unavailable service is a listed one");
    match mode {
        Mode::Warn => Decision::Warn(message),
        _ => Decision::Refuse(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# last_updated 2026-11-18T00:05:07.391849+00:00\n\
                          # regions us-east-1 ap-southeast-7 ap-southeast-6\n\
                          com.amazonaws.memorydb#AmazonMemoryDB 1 MemoryDB\n\
                          com.amazonaws.appsync#AWSDeepdishControlPlaneService 3 AppSync\n\
                          com.amazonaws.sqs#AmazonSQS 7 SQS\n";

    const MEMORYDB: &str = "com.amazonaws.memorydb#AmazonMemoryDB";
    const GRAFANA: &str = "com.amazonaws.grafana#AWSGrafanaControlPlane";
    const PIPES: &str = "com.amazonaws.pipes#Pipes";
    const APPSYNC: &str = "com.amazonaws.appsync#AWSDeepdishControlPlaneService";

    /// 2026-11-19, the day after the sample data, so it is not old.
    fn soon() -> SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(20_776 * 86_400)
    }

    #[test]
    fn a_listed_service_is_offered_only_where_its_bit_is_set() {
        let snapshot = ServiceSnapshot::parse(SAMPLE).unwrap();
        let cases = [
            ("us-east-1", MEMORYDB, Verdict::Available),
            ("ap-southeast-7", MEMORYDB, Verdict::Unavailable),
            ("ap-southeast-7", APPSYNC, Verdict::Available),
            ("ap-southeast-6", APPSYNC, Verdict::Unavailable),
            (
                "AP-SOUTHEAST-6",
                "com.amazonaws.sqs#AmazonSQS",
                Verdict::Available,
            ),
            // Not listed: an emulator service the data omits, and a Region the data omits.
            (
                "us-east-1",
                "com.amazonaws.lex#LexRuntimeService",
                Verdict::Unknown,
            ),
            ("cn-north-1", MEMORYDB, Verdict::Unknown),
            ("", MEMORYDB, Verdict::Unknown),
        ];
        for (region, shape_id, expected) in cases {
            assert_eq!(
                snapshot.service(region, shape_id),
                expected,
                "{shape_id} in {region:?}"
            );
        }
    }

    #[test]
    fn a_decision_follows_the_mode_and_only_a_missing_service_is_held() {
        let snapshot = ServiceSnapshot::parse(SAMPLE).unwrap();
        let decide = |mode, shape_id, region| decide(mode, &snapshot, shape_id, region, soon());
        let message = "MemoryDB is not offered in ap-southeast-7: AWS Regional availability data \
                       of 2026-11-18 lists none of its operations there; set \
                       EMULATOR_REGION_AVAILABILITY=off to skip this check";
        assert_eq!(
            decide(Mode::Enforce, MEMORYDB, "ap-southeast-7"),
            Decision::Refuse(message.into())
        );
        assert_eq!(
            decide(Mode::Warn, MEMORYDB, "ap-southeast-7"),
            Decision::Warn(message.into())
        );
        assert_eq!(
            decide(Mode::Off, MEMORYDB, "ap-southeast-7"),
            Decision::Allow
        );
        assert_eq!(
            decide(Mode::Enforce, MEMORYDB, "us-east-1"),
            Decision::Allow
        );
        assert_eq!(
            decide(Mode::Enforce, "com.example#Other", "ap-southeast-7"),
            Decision::Allow
        );
        assert_eq!(
            decide(Mode::Enforce, MEMORYDB, "cn-north-1"),
            Decision::Allow
        );
    }

    #[test]
    fn a_refusal_says_when_its_data_is_old() {
        let snapshot = ServiceSnapshot::parse(SAMPLE).unwrap();
        let late = std::time::UNIX_EPOCH + std::time::Duration::from_secs((20_775 + 45) * 86_400);
        let message = snapshot
            .refusal_message(MEMORYDB, "ap-southeast-7", late)
            .unwrap();
        assert!(
            message.contains("there; that data is 45 days old, so check it is current; set "),
            "{message}"
        );
        assert_eq!(
            snapshot.refusal_message("com.example#Other", "ap-southeast-7", late),
            None
        );
    }

    #[test]
    fn a_malformed_snapshot_names_the_line_or_header_at_fault() {
        let cases = [
            ("# regions a\nx#Y 1 Y\n", "last_updated"),
            ("# last_updated 2026-11-18\nx#Y 1 Y\n", "regions"),
            ("# last_updated d\n# regions a\nx#Y zz Y\n", "line 3"),
            ("# last_updated d\n# regions a\nx#Y 1\n", "line 3"),
        ];
        for (text, expected) in cases {
            let error = ServiceSnapshot::parse(text).unwrap_err();
            assert!(error.contains(expected), "{text:?}: got {error:?}");
        }
    }

    /// The four services and the Regions of the Bangkok and Auckland proof, answered from the
    /// shipped file: Bangkok and Auckland lack MemoryDB, Managed Grafana and EventBridge Pipes,
    /// Auckland lacks AppSync and Bangkok has it, and us-east-1 has all four. The first seven
    /// rows are the proof's seven missing cases.
    #[test]
    fn the_bundled_snapshot_refuses_the_bangkok_and_auckland_cases() {
        let snapshot = ServiceSnapshot::bundled();
        let missing = [
            (MEMORYDB, "ap-southeast-7"),
            (MEMORYDB, "ap-southeast-6"),
            (GRAFANA, "ap-southeast-7"),
            (GRAFANA, "ap-southeast-6"),
            (PIPES, "ap-southeast-7"),
            (PIPES, "ap-southeast-6"),
            (APPSYNC, "ap-southeast-6"),
        ];
        for (shape_id, region) in missing {
            let decision = decide(Mode::Enforce, snapshot, shape_id, region, soon());
            let Decision::Refuse(message) = decision else {
                panic!("{shape_id} in {region}: expected a refusal, got {decision:?}");
            };
            assert!(
                message.contains(&format!("not offered in {region}:")),
                "{message}"
            );
            assert!(message.contains("data of 20"), "{message}");
        }
        let present = [
            (APPSYNC, "ap-southeast-7"),
            (MEMORYDB, "us-east-1"),
            (GRAFANA, "us-east-1"),
            (PIPES, "us-east-1"),
            (APPSYNC, "us-east-1"),
        ];
        for (shape_id, region) in present {
            assert_eq!(
                decide(Mode::Enforce, snapshot, shape_id, region, soon()),
                Decision::Allow,
                "{shape_id} in {region}"
            );
        }
    }

    /// Every listed service in every listed Region, against a second decode of the shipped
    /// text that shares no code with the loader: a service whose bit is clear is refused and
    /// every other pair is allowed. The numbers print with `--nocapture`.
    #[test]
    fn every_pair_the_data_marks_unavailable_is_refused_and_every_other_is_allowed() {
        let snapshot = ServiceSnapshot::bundled();
        let regions: Vec<&str> = BUNDLED_SERVICES
            .lines()
            .find_map(|line| line.strip_prefix("# regions "))
            .expect("a regions header")
            .split_whitespace()
            .collect();
        let (mut refused, mut allowed, mut services) = (0usize, 0usize, 0usize);
        for line in BUNDLED_SERVICES
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let mut fields = line.splitn(3, ' ');
            let shape_id = fields.next().unwrap();
            let mask = u64::from_str_radix(fields.next().unwrap(), 16).unwrap();
            services += 1;
            for (bit, region) in regions.iter().enumerate() {
                let decision = decide(Mode::Enforce, snapshot, shape_id, region, soon());
                if mask >> bit & 1 == 0 {
                    assert!(
                        matches!(decision, Decision::Refuse(_)),
                        "{shape_id} in {region}"
                    );
                    refused += 1;
                } else {
                    assert_eq!(decision, Decision::Allow, "{shape_id} in {region}");
                    allowed += 1;
                }
            }
        }
        println!(
            "service sweep: {services} services x {} Regions = {} pairs; refused {refused}, \
             allowed {allowed}",
            regions.len(),
            refused + allowed
        );
        assert_eq!(services, snapshot.service_count());
        assert_eq!(refused + allowed, services * regions.len());
        assert!(refused > 0 && allowed > 0);
        for region in ["xx-test-1", "cn-north-1", "cn-northwest-1", ""] {
            for shape_id in snapshot.shape_ids() {
                assert_eq!(
                    decide(Mode::Enforce, snapshot, shape_id, region, soon()),
                    Decision::Allow,
                    "{shape_id} in {region:?}"
                );
            }
        }
    }

    /// The join is sound: every service the snapshot lists is a service this repository
    /// scaffolds (the list `.emulator/scaffolded-specs.json` holds), spelled the same way.
    #[test]
    fn every_listed_service_is_a_service_of_this_emulator() {
        const SPECS: &str = include_str!("../../../.emulator/scaffolded-specs.json");
        let snapshot = ServiceSnapshot::bundled();
        let emulator_services = SPECS.matches("\"shape_id\"").count();
        let mut covered = 0usize;
        for shape_id in snapshot.shape_ids() {
            assert!(
                SPECS.contains(&format!("\"shape_id\": \"{shape_id}\"")),
                "{shape_id} is not a service of this emulator"
            );
            covered += 1;
        }
        println!("join: {covered} of the emulator's {emulator_services} services are in the data");
        assert!(covered >= 400 && covered <= emulator_services);
    }
}
