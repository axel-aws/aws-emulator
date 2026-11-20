// SPDX-License-Identifier: CC0-1.0

//! The emulator's request router, with real services mounted, refuses a request to a service the
//! signed Region does not offer, and serves every other request as it did before.
//!
//! Every test sends HTTP requests through `MultiServiceRouter::dispatch`, the path the emulator's
//! listener and its in-process client share, to services the emulator really ships. The Region
//! comes from the request's SigV4 credential scope, as in a client's own SDK.
//!
//! The mode is read from `EMULATOR_REGION_AVAILABILITY` on every request, and a process has one
//! environment, so each test holds `ENV` while it runs. The router's default mode is `warn`, so
//! the tests that look at refusals set `enforce`, as a user who wants them does.

use bytes::Bytes;
use region_gate::service_availability::ServiceSnapshot;
use smithy_server_runtime::MultiServiceRouter;
use std::sync::{Arc, Mutex, MutexGuard};

const MODE_ENV: &str = "EMULATOR_REGION_AVAILABILITY";
static ENV: Mutex<()> = Mutex::new(());

/// Holds the environment for one test, with the mode set to `enforce`.
fn env() -> MutexGuard<'static, ()> {
    let guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var(MODE_ENV, "enforce");
    guard
}

/// Holds the environment for one test, with the mode unset: the default applies.
fn env_unset() -> MutexGuard<'static, ()> {
    let guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var(MODE_ENV);
    guard
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wire {
    Json11,
    RestJson,
    Query,
    Cbor,
}

#[derive(Clone, Copy, Debug)]
struct Svc {
    name: &'static str,
    shape: &'static str,
    signing: &'static str,
    wire: Wire,
}

const MEMORYDB: Svc = Svc {
    name: "MemoryDB",
    shape: "com.amazonaws.memorydb#AmazonMemoryDB",
    signing: "memorydb",
    wire: Wire::Json11,
};
const GRAFANA: Svc = Svc {
    name: "Grafana",
    shape: "com.amazonaws.grafana#AWSGrafanaControlPlane",
    signing: "grafana",
    wire: Wire::RestJson,
};
const PIPES: Svc = Svc {
    name: "Pipes",
    shape: "com.amazonaws.pipes#Pipes",
    signing: "pipes",
    wire: Wire::RestJson,
};
const APPSYNC: Svc = Svc {
    name: "AppSync",
    shape: "com.amazonaws.appsync#AWSDeepdishControlPlaneService",
    signing: "appsync",
    wire: Wire::RestJson,
};
const SES: Svc = Svc {
    name: "SES",
    shape: "com.amazonaws.ses#SimpleEmailService",
    signing: "ses",
    wire: Wire::Query,
};
const INTERCONNECT: Svc = Svc {
    name: "Interconnect",
    shape: "com.amazonaws.interconnect#Interconnect",
    signing: "interconnect",
    wire: Wire::Cbor,
};
const IOT_DATA: Svc = Svc {
    name: "IoT Data Plane",
    shape: "com.amazonaws.iotdataplane#IotMoonrakerService",
    signing: "iotdata",
    wire: Wire::RestJson,
};
const ALL: [Svc; 7] = [
    MEMORYDB,
    GRAFANA,
    PIPES,
    APPSYNC,
    SES,
    INTERCONNECT,
    IOT_DATA,
];

fn router() -> MultiServiceRouter {
    let engine = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.register_service(
        service_com_amazonaws_memorydb_amazonmemorydb::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_grafana_awsgrafanacontrolplane::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    router.register_service(service_com_amazonaws_pipes_pipes::EmulatedService::new(
        Arc::clone(&engine),
    ));
    router.register_service(
        service_com_amazonaws_appsync_awsdeepdishcontrolplaneservice::EmulatedService::new(
            Arc::clone(&engine),
        ),
    );
    router.register_service(
        service_com_amazonaws_ses_simpleemailservice::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_interconnect_interconnect::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_iotdataplane_iotmoonrakerservice::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    router
}

/// A request to `svc`, signed for `scope_region`, addressed to a host in `host_region`.
fn request_to(svc: Svc, scope_region: &str, host_region: &str) -> http::request::Builder {
    let builder = http::Request::builder().header(
        "authorization",
        format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261119/{scope_region}/{}/aws4_request, \
             SignedHeaders=host, Signature=0123456789abcdef",
            svc.signing
        ),
    );
    let host = format!("{}.{host_region}.amazonaws.com", svc.signing);
    match svc.wire {
        Wire::Json11 => builder
            .method("POST")
            .uri(format!("https://{host}/"))
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amz-target", "AmazonMemoryDB.DescribeClusters"),
        Wire::RestJson => {
            let path = match svc.name {
                "Grafana" => "/workspaces",
                "Pipes" => "/v1/pipes",
                "IoT Data Plane" => "/retainedMessage",
                _ => "/v1/apis",
            };
            builder.method("GET").uri(format!("https://{host}{path}"))
        }
        Wire::Query => builder
            .method("POST")
            .uri(format!("https://{host}/"))
            .header("content-type", "application/x-www-form-urlencoded"),
        Wire::Cbor => builder
            .method("POST")
            .uri(format!(
                "https://{host}/service/Interconnect/operation/ListConnections"
            ))
            .header("smithy-protocol", "rpc-v2-cbor")
            .header("content-type", "application/cbor")
            .header("accept", "application/cbor"),
    }
}

fn body_of(svc: Svc) -> Bytes {
    match svc.wire {
        Wire::Json11 => Bytes::from_static(b"{}"),
        Wire::RestJson => Bytes::new(),
        Wire::Query => Bytes::from_static(b"Action=GetSendQuota&Version=2010-12-01"),
        Wire::Cbor => Bytes::from_static(&[0xA0]),
    }
}

fn request(svc: Svc, region: &str) -> http::Request<Bytes> {
    request_to(svc, region, region)
        .body(body_of(svc))
        .expect("a well-formed request")
}

struct Answer {
    status: u16,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The emulator's Region refusal: a 403 that carries the code `UnknownEndpoint`.
    fn is_the_region_refusal(&self) -> bool {
        self.status == 403
            && self
                .body
                .windows(b"UnknownEndpoint".len())
                .any(|w| w == b"UnknownEndpoint")
    }
}

async fn send(router: &MultiServiceRouter, request: http::Request<Bytes>) -> Answer {
    let response = router.dispatch(request).await;
    Answer {
        status: response.status().as_u16(),
        headers: response.headers().clone(),
        body: response.into_body().to_vec(),
    }
}

async fn ask(router: &MultiServiceRouter, svc: Svc, region: &str) -> Answer {
    send(router, request(svc, region)).await
}

/// A Region the data lists and says `svc` is not offered in.
fn a_region_without(svc: Svc) -> String {
    let snapshot = ServiceSnapshot::bundled();
    snapshot
        .regions()
        .iter()
        .find(|region| {
            snapshot.service(region, svc.shape) == region_gate::basics::Verdict::Unavailable
        })
        .unwrap_or_else(|| panic!("the data says {} is offered everywhere", svc.name))
        .clone()
}

#[tokio::test]
async fn the_seven_cases_of_the_feature_request_are_refused_and_the_control_is_served() {
    let _env = env();
    let router = router();
    let bangkok = "ap-southeast-7";
    let auckland = "ap-southeast-6";
    let refused = [
        (MEMORYDB, bangkok),
        (MEMORYDB, auckland),
        (GRAFANA, bangkok),
        (GRAFANA, auckland),
        (PIPES, bangkok),
        (PIPES, auckland),
        (APPSYNC, auckland),
    ];
    for (svc, region) in refused {
        let answer = ask(&router, svc, region).await;
        assert!(
            answer.is_the_region_refusal(),
            "{} in {region} should be refused: {} {}",
            svc.name,
            answer.status,
            answer.text()
        );
        let text = answer.text();
        assert!(text.contains(&format!("not offered in {region}")), "{text}");
        assert!(
            text.contains("AWS Regional availability data of 20"),
            "{text}"
        );
        assert!(text.contains("EMULATOR_REGION_AVAILABILITY=off"), "{text}");
    }
    // The control: AppSync is offered in Bangkok, and every service in the oldest Region.
    let control = ask(&router, APPSYNC, bangkok).await;
    assert!(!control.is_the_region_refusal(), "{}", control.text());
    for svc in ALL {
        let answer = ask(&router, svc, "us-east-1").await;
        assert!(
            !answer.is_the_region_refusal(),
            "{} in us-east-1: {}",
            svc.name,
            answer.text()
        );
    }
}

/// For every Region the data lists and each of four services, the router refuses exactly when the
/// data says the service is not offered.
#[tokio::test]
async fn every_listed_region_is_decided_as_the_data_says() {
    let _env = env();
    let router = router();
    let snapshot = ServiceSnapshot::bundled();
    let (mut refused, mut served) = (0, 0);
    for svc in [MEMORYDB, GRAFANA, PIPES, APPSYNC] {
        for region in snapshot.regions() {
            let answer = ask(&router, svc, region).await;
            let unavailable =
                snapshot.service(region, svc.shape) == region_gate::basics::Verdict::Unavailable;
            assert_eq!(
                answer.is_the_region_refusal(),
                unavailable,
                "{} in {region}: {} {}",
                svc.name,
                answer.status,
                answer.text()
            );
            if unavailable {
                refused += 1;
            } else {
                served += 1;
            }
        }
    }
    assert!(
        refused > 40 && served > 40,
        "{refused} refused, {served} served"
    );
    println!(
        "4 services x {} Regions: {refused} refused, {served} served",
        snapshot.regions().len()
    );
}

/// The refusal is written in the envelope of the protocol the request was made in.
#[tokio::test]
async fn each_protocol_gets_the_error_in_its_own_envelope() {
    let _env = env();
    let router = router();

    let region = a_region_without(MEMORYDB);
    let json11 = ask(&router, MEMORYDB, &region).await;
    assert_eq!(json11.status, 403);
    assert_eq!(json11.headers["content-type"], "application/x-amz-json-1.1");
    let body: serde_json::Value = serde_json::from_slice(&json11.body).expect("a JSON body");
    assert_eq!(body["__type"], "UnknownEndpoint");
    assert!(
        body["message"].as_str().unwrap().contains("MemoryDB"),
        "{body}"
    );

    let region = a_region_without(GRAFANA);
    let rest = ask(&router, GRAFANA, &region).await;
    assert_eq!(rest.status, 403);
    assert_eq!(rest.headers["x-amzn-errortype"], "UnknownEndpoint");
    let body: serde_json::Value = serde_json::from_slice(&rest.body).expect("a JSON body");
    assert!(
        body["message"].as_str().unwrap().contains(&region),
        "{body}"
    );

    let region = a_region_without(SES);
    let query = ask(&router, SES, &region).await;
    assert_eq!(query.status, 403);
    assert_eq!(query.headers["content-type"], "text/xml");
    let text = query.text();
    assert!(text.contains("<Code>UnknownEndpoint</Code>"), "{text}");
    assert!(text.contains(&format!("not offered in {region}")), "{text}");

    let region = a_region_without(INTERCONNECT);
    let cbor = ask(&router, INTERCONNECT, &region).await;
    assert_eq!(cbor.status, 403);
    assert_eq!(cbor.headers["smithy-protocol"], "rpc-v2-cbor");
    assert_eq!(cbor.headers["content-type"], "application/cbor");
    assert!(cbor.is_the_region_refusal(), "{:?}", cbor.body);
}

/// The Region is the one in the credential scope. The host the request names, or a Region the
/// URL carries, decides nothing.
#[tokio::test]
async fn the_region_is_the_one_the_request_is_signed_for() {
    let _env = env();
    let router = router();
    let signed_for_bangkok_to_a_virginia_host = request_to(MEMORYDB, "ap-southeast-7", "us-east-1")
        .body(body_of(MEMORYDB))
        .unwrap();
    assert!(send(&router, signed_for_bangkok_to_a_virginia_host)
        .await
        .is_the_region_refusal());
    let signed_for_virginia_to_a_bangkok_host = request_to(MEMORYDB, "us-east-1", "ap-southeast-7")
        .body(body_of(MEMORYDB))
        .unwrap();
    assert!(!send(&router, signed_for_virginia_to_a_bangkok_host)
        .await
        .is_the_region_refusal());
}

/// A request with no usable Region is served as it always was: there is nothing to check.
#[tokio::test]
async fn a_request_with_no_usable_region_is_not_refused() {
    let _env = env();
    let router = router();
    // A Region that is not spelled as one is no Region: the emulator's default applies.
    for scope in [
        "AP-SOUTHEAST-7",
        "ap southeast 7",
        "ap-southeast-7-and-a-name-over-32-characters",
    ] {
        let odd = request_to(MEMORYDB, scope, "us-east-1")
            .body(body_of(MEMORYDB))
            .unwrap();
        let answer = send(&router, odd).await;
        assert!(
            !answer.is_the_region_refusal(),
            "{scope}: {}",
            answer.text()
        );
    }
    // A Region the data does not list: a partition it omits, a Region newer than it.
    for region in ["cn-north-1", "xx-test-1", "ap-southeast-9"] {
        let answer = ask(&router, MEMORYDB, region).await;
        assert!(
            !answer.is_the_region_refusal(),
            "{region}: {}",
            answer.text()
        );
    }
    // No Authorization header at all: the host names the service and no Region is signed, so
    // the router has no Region to check. The request is claimed (it is not an unknown service)
    // and served as before.
    let unsigned = http::Request::builder()
        .method("GET")
        .uri("https://grafana.ap-southeast-7.amazonaws.com/workspaces")
        .body(Bytes::new())
        .unwrap();
    let answer = send(&router, unsigned).await;
    assert!(!answer.is_the_region_refusal(), "{}", answer.text());
    assert!(
        !answer.text().contains("UnknownService"),
        "the request was not claimed: {}",
        answer.text()
    );
}

/// A presigned request carries its Region in the query, not in a header, and is checked by it.
#[tokio::test]
async fn a_presigned_request_is_checked_by_the_region_in_its_query() {
    let _env = env();
    let router = router();
    let presigned = |region: &str| {
        http::Request::builder()
            .method("GET")
            .uri(format!(
                "https://grafana.{region}.amazonaws.com/workspaces?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Credential=AKIDEXAMPLE%2F20261119%2F{region}%2Fgrafana%2Faws4_request\
                 &X-Amz-Date=20261119T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host\
                 &X-Amz-Signature=0123456789abcdef"
            ))
            .body(Bytes::new())
            .unwrap()
    };
    let refused = send(&router, presigned("ap-southeast-7")).await;
    assert!(
        refused.is_the_region_refusal(),
        "{} {}",
        refused.status,
        refused.text()
    );
    let served = send(&router, presigned("us-east-1")).await;
    assert!(!served.is_the_region_refusal(), "{}", served.text());
    assert!(
        !served.text().contains("UnknownService"),
        "{}",
        served.text()
    );
}

/// The check runs before the body is read, so a request that streams its body is refused without
/// the framing being decoded, and one to an offered service is decoded exactly as before.
#[tokio::test]
async fn a_streaming_body_is_not_read_for_a_refusal() {
    let _env = env();
    let router = router();
    let stream = |region: &str| {
        request_to(GRAFANA, region, region)
            .header("content-encoding", "aws-chunked")
            .header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
            .header("x-amz-decoded-content-length", "5")
            .body(Bytes::from_static(b"this is not chunk framing"))
            .unwrap()
    };
    let refused = send(&router, stream("ap-southeast-7")).await;
    assert!(refused.is_the_region_refusal(), "{}", refused.text());
    let offered = send(&router, stream("us-east-1")).await;
    assert!(!offered.is_the_region_refusal());
    assert_eq!(
        offered.status,
        400,
        "the bad framing is still a client error: {}",
        offered.text()
    );
}

/// A request no service claims keeps the router's own answer.
#[tokio::test]
async fn a_request_no_service_claims_keeps_its_own_answer() {
    let _env = env();
    let router = router();
    let request = http::Request::builder()
        .method("GET")
        .uri("https://nosuchservice.ap-southeast-7.amazonaws.com/")
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261119/ap-southeast-7/nosuchservice/aws4_request, \
             SignedHeaders=host, Signature=0123456789abcdef",
        )
        .body(Bytes::new())
        .unwrap();
    let answer = send(&router, request).await;
    assert_eq!(answer.status, 404);
    assert!(
        answer.text().contains("UnknownService"),
        "{}",
        answer.text()
    );
}

/// With the setting unset the router serves everything and only logs: its default is `warn`.
/// Known real offers that the bundled table gets wrong (IoT Data Plane outside us-east-1) are
/// served, and so are the seven cases of the feature request until a user asks for `enforce`.
#[tokio::test]
async fn by_default_the_router_serves_and_only_warns() {
    let _env = env_unset();
    let router = router();
    for region in ["eu-west-1", "us-west-2", "us-east-1"] {
        let answer = ask(&router, IOT_DATA, region).await;
        assert!(
            !answer.is_the_region_refusal(),
            "IoT Data Plane in {region}: {}",
            answer.text()
        );
        assert!(
            !answer.text().contains("UnknownService"),
            "{}",
            answer.text()
        );
    }
    for (svc, region) in [(MEMORYDB, "ap-southeast-7"), (APPSYNC, "ap-southeast-6")] {
        let answer = ask(&router, svc, region).await;
        assert!(
            !answer.is_the_region_refusal(),
            "{} in {region}: {}",
            svc.name,
            answer.text()
        );
    }
    // Under `enforce` a row that is right is refused. (The IoT Data Plane rows are not asserted
    // under `enforce`: the table has them wrong, and a fix to the table must not break this test.)
    std::env::set_var(MODE_ENV, "enforce");
    assert!(ask(&router, MEMORYDB, "ap-southeast-7")
        .await
        .is_the_region_refusal());
    std::env::remove_var(MODE_ENV);
}

/// `off`, `warn` and `enforce` in any letter case; a setting that is not one keeps the default,
/// which is `warn`, so a typo never refuses and never turns the warning off.
#[tokio::test]
async fn the_mode_is_read_from_the_environment_on_every_request() {
    let _env = env_unset();
    let router = router();
    let refused = |answer: &Answer| answer.is_the_region_refusal();
    // Unset: the default.
    assert!(
        !refused(&ask(&router, MEMORYDB, "ap-southeast-7").await),
        "the default is warn"
    );
    let cases = [
        ("off", false),
        ("OFF", false),
        (" Off ", false),
        ("warn", false),
        ("Warn", false),
        ("enforce", true),
        ("ENFORCE", true),
        // Not a mode: the default (warn) applies, so the request is served.
        ("of", false),
        ("disabled", false),
        ("", false),
        ("0", false),
    ];
    for (value, expect_refusal) in cases {
        std::env::set_var(MODE_ENV, value);
        let answer = ask(&router, MEMORYDB, "ap-southeast-7").await;
        assert_eq!(
            refused(&answer),
            expect_refusal,
            "{MODE_ENV}={value:?}: {}",
            answer.text()
        );
        // A listed, offered pair is never refused, whatever the mode.
        assert!(
            !refused(&ask(&router, MEMORYDB, "us-east-1").await),
            "{value:?}"
        );
    }
    std::env::remove_var(MODE_ENV);
    assert!(
        !refused(&ask(&router, MEMORYDB, "ap-southeast-6").await),
        "unset again"
    );
    std::env::set_var(MODE_ENV, "enforce");
    assert!(
        refused(&ask(&router, MEMORYDB, "ap-southeast-6").await),
        "enforce again"
    );
    std::env::remove_var(MODE_ENV);
}
