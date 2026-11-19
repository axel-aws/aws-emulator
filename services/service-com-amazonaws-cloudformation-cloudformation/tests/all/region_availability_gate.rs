// SPDX-License-Identifier: CC0-1.0

//! A template that declares a resource type AWS does not offer in the Region the request is
//! signed for is refused, over the awsQuery wire.
//!
//! RULE: **`CreateStack`, `UpdateStack` and `CreateChangeSet` refuse a template whose
//! `Resources` declare a type AWS's published Regional availability data lists as not
//! available in the request's Region**, with HTTP 400, `ValidationError` and CloudFormation's
//! own sentence for a type it does not know, `Template format error: Unrecognized resource
//! types: [<types>]`, followed by the Region and the date of the data. Nothing is created and
//! a refused update leaves the stack alone. What the data does not list is admitted: a Region
//! it does not know, a custom resource.
//!
//! The rows span the cases the rule exists for. Bangkok (`ap-southeast-7`) and Auckland
//! (`ap-southeast-6`) lack MemoryDB, Managed Grafana and EventBridge Pipes, and Auckland lacks
//! AppSync, which Bangkok has: the same type is admitted in one Region and refused in the
//! next. Every row also runs in `us-east-1`, which offers all of them.
//!
//! The suite runs in the default mode, `enforce`. It does not set `EMULATOR_REGION_AVAILABILITY`
//! (the process-wide switch would leak into the suites that run beside it), and so assumes the
//! variable is unset. `service_common::region_availability` owns the `warn` and `off` rows.

use crate::stack_lifecycle::{call_in, member, router, wait_for_the_transition, xml_text, REGION};
use smithy_server_runtime::MultiServiceRouter;

const MEMORYDB: &str = r#"{"Resources":{"Db":{"Type":"AWS::MemoryDB::Cluster","Properties":{"ClusterName":"c","NodeType":"db.t4g.small","ACLName":"open-access"}}}}"#;
const GRAFANA: &str = r#"{"Resources":{"W":{"Type":"AWS::Grafana::Workspace","Properties":{"AccountAccessType":"CURRENT_ACCOUNT","AuthenticationProviders":["AWS_SSO"],"PermissionType":"SERVICE_MANAGED"}}}}"#;
const PIPES: &str = r#"{"Resources":{"P":{"Type":"AWS::Pipes::Pipe","Properties":{"Source":"arn:aws:sqs:us-east-1:000000000000:a","Target":"arn:aws:sqs:us-east-1:000000000000:b","RoleArn":"arn:aws:iam::000000000000:role/r"}}}}"#;
const APPSYNC: &str = r#"{"Resources":{"Api":{"Type":"AWS::AppSync::GraphQLApi","Properties":{"Name":"api","AuthenticationType":"API_KEY"}}}}"#;
const QUEUE: &str =
    r#"{"Resources":{"Q":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"q"}}}}"#;
/// A stack of this settles into `CREATE_COMPLETE`, so it can be updated.
const TOPIC: &str =
    r#"{"Resources":{"T":{"Type":"AWS::SNS::Topic","Properties":{"TopicName":"kept"}}}}"#;

async fn create(
    router: &MultiServiceRouter,
    region: &str,
    name: &str,
    template: &str,
) -> (u16, String) {
    call_in(
        router,
        region,
        "CreateStack",
        &[member("StackName", name), member("TemplateBody", template)],
    )
    .await
}

/// Assert a refusal that names `types`, the Region and a dated source.
fn assert_refused(case: &str, region: &str, types: &[&str], status: u16, body: &str) {
    assert_eq!(
        status, 400,
        "{case}: expected HTTP 400, got {status} with {body}"
    );
    assert_eq!(
        xml_text(body, "Code").as_deref(),
        Some("ValidationError"),
        "{case}: expected ValidationError in {body}"
    );
    let message = xml_text(body, "Message").unwrap_or_default();
    let expected = format!(
        "Template format error: Unrecognized resource types: [{}] (AWS Regional availability \
         data of 20",
        types.join(", ")
    );
    assert!(
        message.starts_with(&expected),
        "{case}: expected a message starting {expected:?}, got {message:?}"
    );
    assert!(
        message.contains(&format!("as not available in {region};")),
        "{case}: expected the message to name {region}, got {message:?}"
    );
    assert!(
        message.ends_with("set EMULATOR_REGION_AVAILABILITY=off to skip this check)"),
        "{case}: expected the way to skip the check, got {message:?}"
    );
}

#[tokio::test]
async fn a_type_the_region_lacks_is_refused_and_the_same_type_is_admitted_where_it_exists() {
    let refused: &[(&str, &str, &str, &str)] = &[
        (
            "MemoryDB in Bangkok",
            "ap-southeast-7",
            MEMORYDB,
            "AWS::MemoryDB::Cluster",
        ),
        (
            "MemoryDB in Auckland",
            "ap-southeast-6",
            MEMORYDB,
            "AWS::MemoryDB::Cluster",
        ),
        (
            "Grafana in Bangkok",
            "ap-southeast-7",
            GRAFANA,
            "AWS::Grafana::Workspace",
        ),
        (
            "Grafana in Auckland",
            "ap-southeast-6",
            GRAFANA,
            "AWS::Grafana::Workspace",
        ),
        (
            "Pipes in Bangkok",
            "ap-southeast-7",
            PIPES,
            "AWS::Pipes::Pipe",
        ),
        (
            "Pipes in Auckland",
            "ap-southeast-6",
            PIPES,
            "AWS::Pipes::Pipe",
        ),
        (
            "AppSync in Auckland",
            "ap-southeast-6",
            APPSYNC,
            "AWS::AppSync::GraphQLApi",
        ),
    ];
    let admitted: &[(&str, &str, &str)] = &[
        (
            "AppSync in Bangkok, where it exists",
            "ap-southeast-7",
            APPSYNC,
        ),
        ("a queue in Bangkok", "ap-southeast-7", QUEUE),
        ("a queue in Auckland", "ap-southeast-6", QUEUE),
        ("MemoryDB in us-east-1", REGION, MEMORYDB),
        ("Grafana in us-east-1", REGION, GRAFANA),
        ("Pipes in us-east-1", REGION, PIPES),
        ("AppSync in us-east-1", REGION, APPSYNC),
        // A Region the data does not list, as a new Region is until the data catches up.
        (
            "MemoryDB in a Region the data does not list",
            "xx-test-1",
            MEMORYDB,
        ),
    ];
    let router = router();
    for (index, (case, region, template, resource_type)) in refused.iter().enumerate() {
        let name = format!("refused-{index}");
        let (status, body) = create(&router, region, &name, template).await;
        assert_refused(case, region, &[resource_type], status, &body);
        // Nothing was created.
        let (status, body) = call_in(
            &router,
            region,
            "DescribeStacks",
            &[member("StackName", &name)],
        )
        .await;
        assert_eq!(
            status, 400,
            "{case}: expected no stack, got {status} with {body}"
        );
    }
    for (index, (case, region, template)) in admitted.iter().enumerate() {
        let (status, body) = create(&router, region, &format!("admitted-{index}"), template).await;
        assert_eq!(
            status, 200,
            "{case}: expected the stack to be accepted, got {body}"
        );
    }
}

/// Every type the Region lacks is named, once each, in declaration order, beside the ones it
/// has and a custom resource, and a resource under a false condition is held to it too.
#[tokio::test]
async fn every_missing_type_is_named_once_and_present_ones_are_not() {
    let template = r#"AWSTemplateFormatVersion: "2010-09-09"
Conditions:
  Never: !Equals [a, b]
Resources:
  Queue:
    Type: AWS::SQS::Queue
  Db:
    Type: AWS::MemoryDB::Cluster
  Db2:
    Type: AWS::MemoryDB::Cluster
  Pipe:
    Type: AWS::Pipes::Pipe
    Condition: Never
  Hook:
    Type: Custom::Thing
    Properties:
      ServiceToken: arn:aws:lambda:ap-southeast-7:000000000000:function:f
"#;
    let router = router();
    let (status, body) = create(&router, "ap-southeast-7", "several", template).await;
    assert_refused(
        "several types",
        "ap-southeast-7",
        &["AWS::MemoryDB::Cluster, AWS::Pipes::Pipe"],
        status,
        &body,
    );
    let (status, body) = create(&router, REGION, "several", template).await;
    assert_eq!(status, 200, "the same YAML in us-east-1: {body}");
}

/// `UpdateStack` and `CreateChangeSet` hold a template to the Region too, and a refused update
/// leaves the stack's template as it was.
#[tokio::test]
async fn an_update_or_change_set_declaring_a_missing_type_is_refused() {
    const REGION_IN_USE: &str = "ap-southeast-7";
    let router = router();
    let (status, body) = create(&router, REGION_IN_USE, "target", TOPIC).await;
    assert_eq!(status, 200, "setup: {body}");
    // An update is refused outright while the create is in progress, which would hide the
    // refusal under test.
    wait_for_the_transition().await;

    let operations: &[(&str, Vec<(String, String)>)] = &[
        (
            "UpdateStack",
            vec![
                member("StackName", "target"),
                member("TemplateBody", MEMORYDB),
            ],
        ),
        (
            "CreateChangeSet",
            vec![
                member("StackName", "target"),
                member("ChangeSetName", "update-set"),
                member("TemplateBody", MEMORYDB),
            ],
        ),
        (
            "CreateChangeSet",
            vec![
                member("StackName", "brand-new"),
                member("ChangeSetName", "create-set"),
                member("ChangeSetType", "CREATE"),
                member("TemplateBody", MEMORYDB),
            ],
        ),
    ];
    for (action, members) in operations {
        let (status, body) = call_in(&router, REGION_IN_USE, action, members).await;
        assert_refused(
            action,
            REGION_IN_USE,
            &["AWS::MemoryDB::Cluster"],
            status,
            &body,
        );
    }
    let (status, body) = call_in(
        &router,
        REGION_IN_USE,
        "GetTemplate",
        &[member("StackName", "target")],
    )
    .await;
    assert_eq!(status, 200, "GetTemplate: {body}");
    assert_eq!(xml_text(&body, "TemplateBody").as_deref(), Some(TOPIC));

    // The same update is accepted for a type the Region has.
    let (status, body) = call_in(
        &router,
        REGION_IN_USE,
        "UpdateStack",
        &[
            member("StackName", "target"),
            member("TemplateBody", APPSYNC),
        ],
    )
    .await;
    assert_eq!(status, 200, "UpdateStack with a type Bangkok has: {body}");
}

/// The name the child run below gives, so it runs the one row that a home-folder cache would
/// change.
const BANGKOK_ROW: &str = "region_availability_gate::a_type_the_region_lacks_is_refused_and_the_same_type_is_admitted_where_it_exists";
const HOME_PROBE_ENV: &str = "REGION_AVAILABILITY_GATE_HOME_PROBE";

/// The harness never reads a cache from `$HOME`. A valid, sealed cache, newer than the bundled
/// data and offering every type in Bangkok and Auckland, is put in a temporary home folder. The
/// control shows the loader would use it. Then the Bangkok row runs in a child process with that
/// home folder (and the cache variable unset): it still sees the refusals, so the cache was not
/// read.
#[test]
fn the_suites_ignore_a_cache_in_the_home_folder() {
    use service_common::availability_source::{choose, convert_cfn, load_cache_file, CACHE_FILE};
    use service_common::region_availability::{Snapshot, Verdict};
    if std::env::var_os(HOME_PROBE_ENV).is_some() {
        return; // the child run of this test itself: nothing to do.
    }
    let bundled = Snapshot::bundled();
    let regions: Vec<String> = bundled.regions().to_vec();
    let everywhere: serde_json::Map<String, serde_json::Value> = regions
        .iter()
        .map(|r| (r.clone(), serde_json::Value::from("Available")))
        .collect();
    // Full size, so it clears the floor: every bundled type, available everywhere.
    let mut services: std::collections::BTreeMap<&str, Vec<serde_json::Value>> =
        std::collections::BTreeMap::new();
    for name in bundled.resource_types() {
        let mut parts = name.split("::").skip(1);
        let (service, kind) = (parts.next().unwrap(), parts.next().unwrap());
        services.entry(service).or_default().push(
            serde_json::json!({"resourceTypeName": kind, "regionalAvailability": everywhere}),
        );
    }
    let cfn = serde_json::to_vec(&serde_json::json!(services
        .iter()
        .map(|(s, t)| serde_json::json!({"serviceName": s, "resourceTypes": t}))
        .collect::<Vec<_>>()))
    .unwrap();
    let region_rows = serde_json::to_vec(&serde_json::json!(regions
        .iter()
        .map(|r| serde_json::json!({ "Region": r }))
        .collect::<Vec<_>>()))
    .unwrap();
    // Just after the bundled data: it wins, and for a real snapshot it is never in the future.
    let stamp = format!("{}.999999999+00:00", &bundled.last_updated()[..19]);
    let poison = convert_cfn(
        "v1",
        &stamp,
        &region_rows,
        &cfn,
        std::time::SystemTime::now(),
    )
    .expect("a valid poisoned cache");
    let home = std::env::temp_dir().join(format!("gate-home-probe-{}", std::process::id()));
    let cache_dir = home.join(".aws/emulator/region-availability");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::write(cache_dir.join(CACHE_FILE), poison).unwrap();

    // The control: the poisoned cache loads, wins over the bundled data, and admits Grafana in
    // Bangkok, which the bundled data refuses.
    let loaded = load_cache_file(&cache_dir.join(CACHE_FILE)).expect("the cache loads");
    let bundled = Snapshot::bundled();
    let chosen = choose(bundled, Some(&loaded));
    assert!(std::ptr::eq(chosen, &loaded), "the cache would win");
    assert_eq!(
        chosen.cfn_resource_type("ap-southeast-7", "AWS::Grafana::Workspace"),
        Verdict::Available
    );
    assert_eq!(
        bundled.cfn_resource_type("ap-southeast-7", "AWS::Grafana::Workspace"),
        Verdict::Unavailable
    );

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([BANGKOK_ROW, "--exact", "--test-threads=1"])
        .env("HOME", &home)
        .env(HOME_PROBE_ENV, "1")
        .env_remove("EMULATOR_REGION_AVAILABILITY_CACHE")
        .env_remove("EMULATOR_REGION_AVAILABILITY")
        .output()
        .expect("the child test run starts");
    let text = String::from_utf8_lossy(&output.stdout);
    std::fs::remove_dir_all(&home).unwrap();
    assert!(
        output.status.success() && text.contains("1 passed"),
        "with a poisoned cache in $HOME the Bangkok row must still pass: {text}{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
