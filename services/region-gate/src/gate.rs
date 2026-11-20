// SPDX-License-Identifier: CC0-1.0

//! The question the request router asks right after it has chosen the service for a request:
//! does AWS offer that service in the Region the request is signed for?
//!
//! The answer is the text of a refusal, or nothing. Nothing means serve the request: the mode is
//! `off`, the mode is `warn` (the warning is logged here), the service or the Region is not in
//! the data, or the data says the Region offers the service. The router turns a refusal into the
//! error of the protocol the request was made in.
//!
//! What AWS itself does for a service with no endpoint in a Region is not an HTTP answer: the
//! host name does not resolve, so the client fails before it sends anything. Clients report it as
//! `EndpointConnectionError: Could not connect to the endpoint URL` (Python) or an
//! `UnknownEndpoint` error, "This service may not be available in the `<region>' region" (the
//! JavaScript SDK, version 2). The emulator answers over HTTP, so it has to send something; it
//! sends [`REFUSAL_CODE`], named after the second, with the message of
//! [`ServiceSnapshot::refusal_message`], which names the service, the Region and the date of the
//! data.

use crate::basics::Mode;
use crate::service_availability::{decide, Decision, ServiceSnapshot};
use std::time::SystemTime;

/// The error code of a refusal. Not a code AWS sends: see the module notes.
pub const REFUSAL_CODE: &str = "UnknownEndpoint";

/// The refusal for a request to the service with Smithy shape id `shape_id`, signed for `region`,
/// under the mode `EMULATOR_REGION_AVAILABILITY` selects and the bundled data; `None` to serve it.
/// With the setting unset the mode is `warn` ([`Mode::ROUTER_DEFAULT`]): the request is served and
/// the refusal it would get is logged. A user asks for refusals with `enforce`.
pub fn refusal(shape_id: &str, region: &str) -> Option<String> {
    refusal_with(
        Mode::from_env_or(Mode::ROUTER_DEFAULT),
        ServiceSnapshot::bundled(),
        shape_id,
        region,
        SystemTime::now(),
    )
}

/// [`refusal`] under a given mode, data and clock.
pub fn refusal_with(
    mode: Mode,
    snapshot: &ServiceSnapshot,
    shape_id: &str,
    region: &str,
    now: SystemTime,
) -> Option<String> {
    match decide(mode, snapshot, shape_id, region, now) {
        Decision::Allow => None,
        Decision::Warn(message) => {
            tracing::warn!("{}", warn_text(&message));
            None
        }
        Decision::Refuse(message) => Some(message),
    }
}

/// The log line for a request served in `warn` mode: it says the request was served, and that
/// `enforce` would refuse it, then gives the refusal itself.
pub fn warn_text(refusal: &str) -> String {
    format!(
        "served in warn mode; EMULATOR_REGION_AVAILABILITY=enforce would refuse this request: {refusal}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# last_updated 2026-11-18T00:05:07.391849+00:00\n\
                          # regions us-east-1 ap-southeast-7 ap-southeast-6\n\
                          com.amazonaws.memorydb#AmazonMemoryDB 1 MemoryDB\n\
                          com.amazonaws.appsync#AWSDeepdishControlPlaneService 3 AppSync\n";
    const MEMORYDB: &str = "com.amazonaws.memorydb#AmazonMemoryDB";
    const APPSYNC: &str = "com.amazonaws.appsync#AWSDeepdishControlPlaneService";

    fn now() -> SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(20_776 * 86_400)
    }

    fn run(mode: Mode, shape_id: &str, region: &str) -> Option<String> {
        let snapshot = ServiceSnapshot::parse(SAMPLE).unwrap();
        refusal_with(mode, &snapshot, shape_id, region, now())
    }

    #[test]
    fn only_enforce_refuses_and_only_what_the_data_says_is_missing() {
        let message = run(Mode::Enforce, MEMORYDB, "ap-southeast-7").expect("refused");
        assert!(
            message.starts_with("MemoryDB is not offered in ap-southeast-7:"),
            "{message}"
        );
        assert!(message.contains("of 2026-11-18"), "{message}");
        assert_eq!(run(Mode::Warn, MEMORYDB, "ap-southeast-7"), None);
        assert_eq!(run(Mode::Off, MEMORYDB, "ap-southeast-7"), None);
        assert_eq!(run(Mode::Enforce, MEMORYDB, "us-east-1"), None);
        // AppSync is offered in Bangkok and not in Auckland.
        assert_eq!(run(Mode::Enforce, APPSYNC, "ap-southeast-7"), None);
        assert!(run(Mode::Enforce, APPSYNC, "ap-southeast-6").is_some());
        // Not in the data: a service, a Region.
        assert_eq!(
            run(Mode::Enforce, "com.amazonaws.made#Up", "ap-southeast-7"),
            None
        );
        assert_eq!(run(Mode::Enforce, MEMORYDB, "xx-test-1"), None);
        assert_eq!(run(Mode::Enforce, MEMORYDB, ""), None);
    }

    #[test]
    fn the_bundled_data_refuses_the_seven_cases_and_admits_the_control() {
        let bundled = ServiceSnapshot::bundled();
        let ask = |shape: &str, region: &str| {
            refusal_with(
                Mode::Enforce,
                bundled,
                shape,
                region,
                std::time::SystemTime::now(),
            )
        };
        let grafana = "com.amazonaws.grafana#AWSGrafanaControlPlane";
        let pipes = "com.amazonaws.pipes#Pipes";
        for region in ["ap-southeast-7", "ap-southeast-6"] {
            for shape in [MEMORYDB, grafana, pipes] {
                assert!(ask(shape, region).is_some(), "{shape} in {region}");
            }
            assert_eq!(ask(MEMORYDB, "us-east-1"), None);
        }
        assert!(ask(APPSYNC, "ap-southeast-6").is_some());
        assert_eq!(ask(APPSYNC, "ap-southeast-7"), None, "the control");
    }

    /// Known real offers that the bundled table has listed wrongly: AWS documents IoT device
    /// data endpoints in many Regions, and the table has listed IoT Data Plane in us-east-1 only.
    /// Under the router's default they are served, whatever the table says, so this test holds
    /// before and after the table is fixed. What `enforce` does is tested on rows that are right.
    #[test]
    fn known_real_offers_the_table_gets_wrong_are_served_by_default() {
        let bundled = ServiceSnapshot::bundled();
        let iot_data = "com.amazonaws.iotdataplane#IotMoonrakerService";
        let now = std::time::SystemTime::now();
        for region in ["eu-west-1", "us-west-2", "us-east-1"] {
            assert_eq!(
                refusal_with(Mode::ROUTER_DEFAULT, bundled, iot_data, region, now),
                None,
                "IoT Data Plane in {region} under the default"
            );
        }
    }

    /// In `warn` mode the request is served and one warning is logged. It says the request was
    /// served, that `enforce` would refuse it, and the refusal itself. `off` logs nothing.
    #[test]
    fn warn_mode_logs_one_line_that_says_the_request_was_served() {
        let snapshot = ServiceSnapshot::parse(SAMPLE).unwrap();
        let lines = |mode: Mode, region: &str| {
            let (served, lines) = capture::warnings(|| {
                refusal_with(mode, &snapshot, MEMORYDB, region, now()).is_none()
            });
            assert!(served || mode == Mode::Enforce, "{mode:?} in {region}");
            lines
        };
        let warned = lines(Mode::Warn, "ap-southeast-7");
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert!(
            warned[0].starts_with("served in warn mode; EMULATOR_REGION_AVAILABILITY=enforce would refuse this request: MemoryDB is not offered in ap-southeast-7:"),
            "{warned:?}"
        );
        assert!(warned[0].contains("of 2026-11-18"), "{warned:?}");
        assert!(
            lines(Mode::Warn, "us-east-1").is_empty(),
            "an offered pair logs nothing"
        );
        assert!(
            lines(Mode::Off, "ap-southeast-7").is_empty(),
            "off logs nothing"
        );
        assert!(
            lines(Mode::Enforce, "ap-southeast-7").is_empty(),
            "a refusal is answered, not logged"
        );
    }

    /// A small `tracing` subscriber that keeps the message of every WARN event, for the tests.
    mod capture {
        use std::sync::{Arc, Mutex};
        use tracing::field::{Field, Visit};
        use tracing::span::{Attributes, Id, Record};
        use tracing::{Event, Level, Metadata, Subscriber};

        struct Keep(Arc<Mutex<Vec<String>>>);

        struct Message(String);

        impl Visit for Message {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }

        impl Subscriber for Keep {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &Attributes<'_>) -> Id {
                Id::from_u64(1)
            }
            fn record(&self, _: &Id, _: &Record<'_>) {}
            fn record_follows_from(&self, _: &Id, _: &Id) {}
            fn event(&self, event: &Event<'_>) {
                if *event.metadata().level() == Level::WARN {
                    let mut message = Message(String::new());
                    event.record(&mut message);
                    self.0.lock().unwrap().push(message.0);
                }
            }
            fn enter(&self, _: &Id) {}
            fn exit(&self, _: &Id) {}
        }

        /// Run `f` with the subscriber in place for this thread; its result and the warnings.
        pub fn warnings<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
            let kept = Arc::new(Mutex::new(Vec::new()));
            let result = tracing::subscriber::with_default(Keep(Arc::clone(&kept)), f);
            let lines = kept.lock().unwrap().clone();
            (result, lines)
        }
    }

    #[test]
    fn the_code_is_the_one_the_notes_name() {
        assert_eq!(REFUSAL_CODE, "UnknownEndpoint");
    }
}
