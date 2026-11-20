// SPDX-License-Identifier: CC0-1.0

//! The API service table, refreshed from the dataset's `apis.json`.
//!
//! `region_gate::service_availability` holds the table the request router reads, bundled in the
//! crate. This module lets a refresh replace it, the way [`crate::availability_source`] does for
//! the CloudFormation types: fetch `apis.json` and `regions.json` through the same fetcher, join
//! them to the services this emulator knows, write a sealed cache file, and hand the new table to
//! the router's slot.
//!
//! ## The join
//!
//! The dataset names a service by its SDK name, which is the `sdkId` column of the bundled table.
//! The router knows a service by its Smithy shape id. The bundled table carries both, so a
//! refresh keeps the shape ids and the SDK names it already has and takes the Regions from the new
//! data. A service the new data does not list is left out of the new table, and a service left out
//! is never refused. A service the new data lists that the bundled table lacks cannot be joined
//! (its shape id is unknown here) and is ignored.
//!
//! ## What it will not take
//!
//! A dataset that lists a Region or a value it does not understand, one that joins fewer than nine
//! tenths of the bundled services, one dated in the future, or one not newer than what is in use
//! is refused whole and nothing changes. The cache file is sealed like the CloudFormation one: a
//! `# services N` count and a final `# end <sha-256>`; a file that is cut short or edited is
//! ignored. The corrections `region_gate` applies when it reads a table (IoT Data Plane and three
//! others the data lists too narrowly) apply to a refreshed table as well.
//!
//! shortcut: service level only, as the bundled table is: a service counts as offered in a Region
//! when any of its operations is.

use crate::availability_source::{
    data_error, fetch_header, fetch_object, not_in_the_future, parse_stamp, read_capped,
    read_regions, sealed_text_is_whole, sha256_hex, write_atomically, FetchError, ObjectFetcher,
    RefreshError, Refreshed, ACCESS_POINT_ALIAS, MAX_APIS_BYTES, MAX_CACHE_BYTES,
    MAX_REGIONS_BYTES, WRITING,
};
use region_gate::service_availability::{self, ServiceSnapshot};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The service table's cache file, next to the CloudFormation one.
pub const SERVICE_CACHE_FILE: &str = "service_availability.txt";

#[derive(Deserialize)]
struct ApiService {
    #[serde(rename = "sdkServiceName")]
    sdk_service_name: String,
    apis: Vec<Api>,
}

#[derive(Deserialize)]
struct Api {
    #[serde(rename = "regionalAvailability")]
    availability: BTreeMap<String, String>,
}

/// Nine tenths of the services of `table`: the fewest a refreshed table may list.
pub fn service_floor(table: &ServiceSnapshot) -> usize {
    table.service_count() / 10 * 9
}

/// Turn the dataset's `regions.json` and `apis.json` into the service table's cache text, keeping
/// the shape ids of `base`. Strict, like [`crate::availability_source::convert_cfn`]: a value it
/// does not know is an error, so the data is not used at all instead of being half understood.
pub fn convert_apis(
    version: &str,
    last_updated: &str,
    regions_json: &[u8],
    apis_json: &[u8],
    base: &ServiceSnapshot,
    now: SystemTime,
) -> Result<String, RefreshError> {
    match parse_stamp(last_updated) {
        None => return Err(RefreshError::Data(format!("last_updated {last_updated:?}"))),
        Some(stamp) if !not_in_the_future(stamp, now) => {
            return Err(RefreshError::Data(format!(
                "last_updated {last_updated:?} is in the future"
            )))
        }
        Some(_) => {}
    }
    let regions = read_regions(regions_json)?;
    let services: Vec<ApiService> =
        serde_json::from_slice(apis_json).map_err(|e| data_error("apis.json", e))?;
    let mut masks: BTreeMap<String, u64> = BTreeMap::new();
    for service in &services {
        let name = &service.sdk_service_name;
        if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
            return Err(RefreshError::Data(format!("service name {name:?}")));
        }
        let mask = masks.entry(name.clone()).or_insert(0);
        for api in &service.apis {
            for (region, value) in &api.availability {
                let Some(bit) = regions.iter().position(|listed| listed == region) else {
                    return Err(RefreshError::Data(format!(
                        "{name}: Region {region:?} is not in regions.json"
                    )));
                };
                match value.as_str() {
                    "Available" => *mask |= 1 << bit,
                    "Unavailable" => {}
                    other => {
                        return Err(RefreshError::Data(format!(
                            "{name} in {region}: unknown value {other:?}"
                        )))
                    }
                }
            }
        }
    }
    if masks.is_empty() {
        return Err(RefreshError::Data("no services".to_string()));
    }
    let mut rows: Vec<(&str, u64, &str)> = base
        .rows()
        .filter_map(|(shape_id, sdk_id)| masks.get(sdk_id).map(|mask| (shape_id, *mask, sdk_id)))
        .collect();
    rows.sort();
    let floor = service_floor(base);
    if rows.len() < floor {
        return Err(RefreshError::Data(format!(
            "only {} of the {} services this emulator knows are in the data, expected at least {floor}",
            rows.len(),
            base.service_count()
        )));
    }
    let fetched = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut text = String::new();
    text.push_str(
        "# AWS Regional availability data: services (an API service is offered in a Region when any of its operations is)\n",
    );
    text.push_str(&format!(
        "# source s3://{ACCESS_POINT_ALIAS}/public/{version}/json/apis.json\n"
    ));
    text.push_str(&format!("# source-sha256 {}\n", sha256_hex(apis_json)));
    text.push_str(&format!("# last_updated {last_updated}\n"));
    text.push_str(&format!("# fetched_unix {fetched}\n"));
    text.push_str(&format!("# regions {}\n", regions.join(" ")));
    text.push_str(&format!("# services {}\n", rows.len()));
    for (shape_id, mask, sdk_id) in &rows {
        text.push_str(&format!("{shape_id} {mask:x} {sdk_id}\n"));
    }
    let end = sha256_hex(text.as_bytes());
    text.push_str(&format!("# end {end}\n"));
    Ok(text)
}

/// Fetch `apis.json`, check and convert it, and write the service cache in `cache_dir`. Does
/// nothing to the cache when it already holds data at least as new. Returns the new table too when
/// the data is newer than `held` (the table in use), so the caller can put it in use.
pub fn refresh_services(
    fetcher: &dyn ObjectFetcher,
    cache_dir: &Path,
    now: SystemTime,
    held: &ServiceSnapshot,
) -> Result<(Refreshed, Option<ServiceSnapshot>), RefreshError> {
    let header = fetch_header(fetcher)?;
    let version = &header.version;
    let regions = fetch_object(
        fetcher,
        format!("public/{version}/json/regions.json"),
        MAX_REGIONS_BYTES,
    )?;
    let apis = fetch_object(
        fetcher,
        format!("public/{version}/json/apis.json"),
        MAX_APIS_BYTES,
    )?;
    let text = convert_apis(
        version,
        &header.manifest.last_updated,
        &regions,
        &apis,
        held,
        now,
    )?;
    let table = ServiceSnapshot::parse(&text).map_err(RefreshError::Data)?;
    let counted = |entity: &str| header.manifest.entities.get(entity).map(|e| e.record_count);
    if counted("regions") != Some(table.regions().len() as u64) {
        return Err(RefreshError::Data(format!(
            "the manifest counts {:?} Regions and the data has {}",
            counted("regions"),
            table.regions().len()
        )));
    }
    if counted("apis").unwrap_or(0) == 0 {
        return Err(RefreshError::Data(
            "the manifest has no count for the APIs".to_string(),
        ));
    }
    let refreshed = |written| Refreshed {
        last_updated: table.last_updated().to_string(),
        types: table.service_count(),
        regions: table.regions().len(),
        written,
    };
    let path = cache_dir.join(SERVICE_CACHE_FILE);
    let ours = parse_stamp(table.last_updated());
    let in_cache = || {
        load_service_cache(&path).is_some_and(|old| {
            parse_stamp(old.last_updated()).is_some_and(|theirs| Some(theirs) >= ours)
        })
    };
    let newer_than_held = parse_stamp(held.last_updated()).is_some_and(|old| Some(old) < ours);
    let _one_at_a_time = WRITING.lock().unwrap_or_else(|e| e.into_inner());
    let written = if in_cache() {
        false
    } else {
        write_atomically(&path, text.as_bytes(), &|| !in_cache()).map_err(RefreshError::Cache)?
    };
    let report = refreshed(written);
    Ok((report, newer_than_held.then_some(table)))
}

/// The service cache at `path`, when it is a regular file, whole, parses, and names the access
/// point as its source. A file that is there but unusable is logged and ignored.
pub fn load_service_cache(path: &Path) -> Option<ServiceSnapshot> {
    let ignore = |why: &dyn std::fmt::Display| {
        tracing::warn!(
            "ignoring the service availability cache {}: {why}",
            path.display()
        );
    };
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => {
            ignore(&"it is not a regular file");
            return None;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            ignore(&error);
            return None;
        }
    }
    let bytes = match read_capped(path, MAX_CACHE_BYTES) {
        Ok(bytes) => bytes,
        Err(FetchError::NotFound) => return None,
        Err(error) => {
            ignore(&error);
            return None;
        }
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(error) => {
            ignore(&error);
            return None;
        }
    };
    if let Err(why) = sealed_text_is_whole(text, "# services ") {
        ignore(&why);
        return None;
    }
    let source = format!("# source s3://{ACCESS_POINT_ALIAS}/public/");
    if !text.lines().any(|line| line.starts_with(&source)) {
        ignore(&"its source is not the access point");
        return None;
    }
    match ServiceSnapshot::parse(text) {
        Ok(table) => Some(table),
        Err(error) => {
            ignore(&error);
            None
        }
    }
}

/// Put `table` in use when it is complete and newer than the table in use now. Returns whether it
/// was installed.
pub fn install(table: ServiceSnapshot, now: SystemTime) -> bool {
    if !wins(&table, &service_availability::current(), now) {
        return false;
    }
    service_availability::install(Arc::new(table));
    true
}

/// Whether `new` should replace `held`: complete (see [`service_floor`]), dated after it, and not
/// dated more than a day ahead of `now`.
pub fn wins(new: &ServiceSnapshot, held: &ServiceSnapshot, now: SystemTime) -> bool {
    matches!(
        (parse_stamp(new.last_updated()), parse_stamp(held.last_updated())),
        (Some(new), Some(old)) if new > old && not_in_the_future(new, now)
    ) && new.service_count() >= service_floor(ServiceSnapshot::bundled())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::availability_refresh::fixtures::{
        apis_json, dataset_after, temp, write_tree, FIRST,
    };
    use crate::availability_source::{
        tests::{after_bundled, bundled_as_json, now},
        DirFetcher,
    };
    use crate::region_availability::Verdict;

    const MEMORYDB: &str = "com.amazonaws.memorydb#AmazonMemoryDB";

    fn convert(apis: &[u8], date: &str) -> Result<String, RefreshError> {
        let (regions, _, _) = bundled_as_json();
        convert_apis(
            "v1",
            date,
            &regions,
            apis,
            ServiceSnapshot::bundled(),
            now(),
        )
    }

    fn why(result: Result<String, RefreshError>) -> String {
        match result {
            Err(RefreshError::Data(why)) => why,
            other => panic!("expected a data error, got {other:?}"),
        }
    }

    /// `text` without its end line, changed by `edit`, and sealed again.
    fn resealed(text: &str, edit: impl Fn(&str) -> String) -> String {
        let body = &text[..text.rfind("# end ").unwrap()];
        let body = edit(body);
        format!("{body}# end {}\n", sha256_hex(body.as_bytes()))
    }

    #[test]
    fn a_dataset_converts_to_a_whole_table_that_keeps_the_shape_ids_and_takes_the_new_regions() {
        let text = convert(&apis_json(true), &after_bundled(FIRST)).unwrap();
        assert_eq!(sealed_text_is_whole(&text, "# services "), Ok(()));
        let table = ServiceSnapshot::parse(&text).unwrap();
        assert_eq!(table.last_updated(), after_bundled(FIRST));
        assert_eq!(
            table.service("ap-southeast-7", MEMORYDB),
            Verdict::Available
        );
        // Where the data is unchanged, so is the answer.
        assert_eq!(
            table.service("ap-southeast-6", MEMORYDB),
            Verdict::Unavailable
        );
        assert_eq!(table.service("us-east-1", MEMORYDB), Verdict::Available);
        assert_eq!(
            table.service_count(),
            ServiceSnapshot::bundled().service_count()
        );
        assert!(
            text.contains("# source s3://aws-capabilities-pub-"),
            "{text}"
        );
    }

    #[test]
    fn data_it_does_not_understand_is_refused_whole() {
        let date = after_bundled(FIRST);
        let edited = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut apis: serde_json::Value = serde_json::from_slice(&apis_json(false)).unwrap();
            change(&mut apis);
            serde_json::to_vec(&apis).unwrap()
        };
        // A value that is not Available or Unavailable.
        let odd = edited(&|apis| {
            apis[0]["apis"][0]["regionalAvailability"]["us-east-1"] = "Maybe".into()
        });
        assert!(why(convert(&odd, &date)).contains("unknown value"));
        // A Region regions.json does not list.
        let region = edited(&|apis| {
            apis[0]["apis"][0]["regionalAvailability"]["xx-test-9"] = "Available".into()
        });
        assert!(why(convert(&region, &date)).contains("xx-test-9"));
        // A name that would break the cache's lines.
        let name = edited(&|apis| apis[0]["sdkServiceName"] = "two\nlines".into());
        assert!(why(convert(&name, &date)).contains("service name"));
        // Not JSON, an empty list, a date in the future, a date that is not one.
        assert!(why(convert(b"{", &date)).contains("apis.json"));
        assert!(why(convert(b"[]", &date)).contains("no services"));
        let future = after_bundled(10 * 86_400);
        assert!(why(convert(&apis_json(false), &future)).contains("in the future"));
        assert!(why(convert(&apis_json(false), "yesterday")).contains("last_updated"));
    }

    #[test]
    fn a_dataset_that_joins_too_few_of_the_services_is_refused() {
        let all: Vec<serde_json::Value> = serde_json::from_slice(&apis_json(false)).unwrap();
        let most = &all[..all.len() * 8 / 10];
        let text = why(convert(
            &serde_json::to_vec(most).unwrap(),
            &after_bundled(FIRST),
        ));
        assert!(text.contains("expected at least"), "{text}");
        // 95 per cent is fine: a few services may leave the data, and are then never refused.
        let nearly = &all[..all.len() * 95 / 100];
        let table = ServiceSnapshot::parse(
            &convert(&serde_json::to_vec(nearly).unwrap(), &after_bundled(FIRST)).unwrap(),
        )
        .unwrap();
        assert!(table.service_count() < ServiceSnapshot::bundled().service_count());
    }

    #[test]
    fn a_refresh_writes_a_sealed_cache_and_a_cut_edited_or_foreign_cache_is_ignored() {
        let root = temp("svc-cache");
        write_tree(&root, &dataset_after(FIRST, true));
        let cache = root.join("cache");
        let held = ServiceSnapshot::bundled();
        let (done, table) = refresh_services(&DirFetcher::new(&root), &cache, now(), held).unwrap();
        assert!(done.written);
        assert!(table.is_some(), "newer than the table in use");
        let path = cache.join(SERVICE_CACHE_FILE);
        let loaded = load_service_cache(&path).expect("whole");
        assert_eq!(
            loaded.service("ap-southeast-7", MEMORYDB),
            Verdict::Available
        );

        // The same data again writes nothing.
        let (again, _) = refresh_services(&DirFetcher::new(&root), &cache, now(), held).unwrap();
        assert!(!again.written);

        let text = std::fs::read_to_string(&path).unwrap();
        let damaged = [
            ("cut", text[..text.len() / 2].to_string()),
            ("edited", text.replacen("MemoryDB", "MemoryDX", 1)),
            (
                "extra row",
                text.replacen("# end ", "com.amazonaws.x#Y 1 Y\n# end ", 1),
            ),
            (
                "not resealed",
                text.replace("# source s3://", "# source file://"),
            ),
            (
                "another source, resealed",
                resealed(&text, |body| {
                    body.replace("# source s3://", "# source file://")
                }),
            ),
        ];
        for (name, bad) in damaged {
            std::fs::write(&path, &bad).unwrap();
            assert!(load_service_cache(&path).is_none(), "{name}");
        }
        std::fs::write(&path, &text).unwrap();
        assert!(load_service_cache(&path).is_some());
        // A missing file is simply none.
        std::fs::remove_file(&path).unwrap();
        assert!(load_service_cache(&path).is_none());
    }

    #[test]
    fn older_data_never_replaces_a_newer_cache() {
        let root = temp("svc-older");
        let cache = root.join("cache");
        let held = ServiceSnapshot::bundled();
        write_tree(&root, &dataset_after(2 * 86_400, true));
        let (done, _) = refresh_services(&DirFetcher::new(&root), &cache, now(), held).unwrap();
        assert!(done.written);
        let path = cache.join(SERVICE_CACHE_FILE);
        let before = std::fs::read(&path).unwrap();
        // The access point now serves data from a day earlier (a rolled-back publish, say).
        write_tree(&root, &dataset_after(FIRST, false));
        let (again, _) = refresh_services(&DirFetcher::new(&root), &cache, now(), held).unwrap();
        assert!(!again.written);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "the newer cache stays"
        );
    }

    #[test]
    fn a_table_wins_only_when_complete_and_newer_and_not_from_the_future() {
        let held = ServiceSnapshot::bundled();
        let text = convert(&apis_json(false), &after_bundled(FIRST)).unwrap();
        let newer = ServiceSnapshot::parse(&text).unwrap();
        assert!(wins(&newer, held, now()));
        assert!(!wins(held, held, now()), "not newer than itself");
        assert!(!wins(&newer, &newer, now()));
        // A table from the far future never wins, whatever its content.
        let far = ServiceSnapshot::parse(
            &text.replace(&after_bundled(FIRST), "2099-01-01T00:00:00+00:00"),
        )
        .unwrap();
        assert!(!wins(&far, held, now()));
        // A table with a handful of services is not complete.
        let small = ServiceSnapshot::parse(
            "# last_updated 2026-11-20T00:00:00+00:00\n# regions us-east-1\n\
             com.amazonaws.memorydb#AmazonMemoryDB 1 MemoryDB\n",
        )
        .unwrap();
        assert!(!wins(&small, held, now()));
    }
}
