// SPDX-License-Identifier: CC0-1.0

//! Getting AWS's Regional availability data through its S3 access point, and keeping a copy.
//!
//! [`crate::region_availability`] answers "does Region R offer CloudFormation type T" from a
//! snapshot bundled in the crate. This module lets a user who has AWS credentials replace that
//! snapshot with a newer one, and says which one is in use.
//!
//! ## The access point
//!
//! AWS publishes the data through an S3 access point, [`ACCESS_POINT_ALIAS`] (ARN
//! [`ACCESS_POINT_ARN`], Region [`ACCESS_POINT_REGION`]). It **refuses anonymous reads**: a
//! request has to be signed with Signature Version 4 by an AWS identity. So the emulator never
//! fetches the data on its own. A user who opts in supplies a fetcher that signs with their own
//! credentials; a user with no credentials keeps the bundled snapshot.
//!
//! ## Pieces
//!
//! - [`ObjectFetcher`]: fetch one object. The only bucket it is ever asked for is the access
//!   point alias, and the keys are the four fixed ones under `public/`, built here from a
//!   checked version string and never taken from the data.
//! - [`DirFetcher`]: a fetcher over a local tree laid out like the access point, for a user who
//!   filled it with `aws s3 sync` using their own CLI.
//! - [`refresh`]: fetch, check, convert and write the cache. It fails, and leaves the old cache
//!   and the bundled data in use, on any value it does not know.
//! - [`current`]: the snapshot the gate uses. The cache wins only if it parses, names the access
//!   point as its source, and is dated later than the bundled snapshot.
//!
//! ## The cache file is all or nothing
//!
//! It carries a type count (`# types N`) and ends with `# end <sha-256 of everything before it>`.
//! A file that was cut short, edited, or never fully written has no matching end line, so it is
//! refused whole and the bundled snapshot is used. It is written to a temp file of a unique name
//! (created, never reopened, so a planted link is not followed), flushed to disk, and renamed.
//!
//! shortcut: the data is chosen once per process, so a refresh takes effect at the next start.
//! Nothing in the emulator calls [`refresh`] yet: a command that runs it, and a fetcher that
//! signs requests, are separate changes, so today no user can produce a cache.
//! shortcut: two processes can still interleave between the last check and the rename. The file is
//! then still a whole, valid cache, only possibly the older of two; the next refresh fixes it.

use crate::region_availability::{days_from_date, Snapshot};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// The alias of the AWS Regional availability access point. Used as the bucket name.
pub const ACCESS_POINT_ALIAS: &str =
    "aws-capabilities-pub-ybkxdwgxrkfhwmq8b1neoq8ny6ua4use1b-s3alias";
/// The ARN of the same access point, as AWS publishes it.
pub const ACCESS_POINT_ARN: &str =
    "arn:aws:s3:us-east-1:686591367145:accesspoint/aws-capabilities-public";
/// The Region the access point lives in.
pub const ACCESS_POINT_REGION: &str = "us-east-1";
/// The environment variable naming the directory that holds the cache file.
pub const CACHE_DIR_ENV: &str = "EMULATOR_REGION_AVAILABILITY_CACHE";
/// The cache file's name, inside the cache directory.
pub const CACHE_FILE: &str = "cfn_resource_availability.txt";

const INDEX_KEY: &str = "public/index.json";
const MAX_INDEX_BYTES: usize = 64 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_REGIONS_BYTES: usize = 1024 * 1024;
const MAX_CFN_BYTES: usize = 64 * 1024 * 1024;
const MAX_CACHE_BYTES: usize = 8 * 1024 * 1024;

/// One object to fetch. The bucket is always the access point alias.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRequest {
    pub bucket: &'static str,
    pub region: &'static str,
    pub key: String,
}

impl ObjectRequest {
    fn new(key: String) -> ObjectRequest {
        ObjectRequest {
            bucket: ACCESS_POINT_ALIAS,
            region: ACCESS_POINT_REGION,
            key,
        }
    }
}

/// Why one object could not be fetched.
#[derive(Debug, PartialEq, Eq)]
pub enum FetchError {
    /// The caller is not allowed to read it (for example, not signed). The text says what is
    /// known: the source's own reason and, from S3, the request id.
    Denied(String),
    NotFound,
    /// The object is larger than the cap.
    TooLarge,
    Transport(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Denied(why) if why.is_empty() => write!(f, "access denied"),
            FetchError::Denied(why) => write!(f, "access denied: {why}"),
            FetchError::NotFound => write!(f, "not found"),
            FetchError::TooLarge => write!(f, "larger than the size cap"),
            FetchError::Transport(why) => write!(f, "{why}"),
        }
    }
}

/// Fetches one object, at most `max_bytes` of it.
pub trait ObjectFetcher {
    fn get(&self, request: &ObjectRequest, max_bytes: usize) -> Result<Vec<u8>, FetchError>;
}

/// Reads objects from a local tree laid out like the access point: `<root>/public/index.json`
/// and so on.
pub struct DirFetcher {
    root: PathBuf,
}

impl DirFetcher {
    pub fn new(root: impl Into<PathBuf>) -> DirFetcher {
        DirFetcher { root: root.into() }
    }
}

impl ObjectFetcher for DirFetcher {
    fn get(&self, request: &ObjectRequest, max_bytes: usize) -> Result<Vec<u8>, FetchError> {
        if request
            .key
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(FetchError::Transport(format!("bad key {:?}", request.key)));
        }
        read_capped(&self.root.join(&request.key), max_bytes)
    }
}

fn read_capped(path: &Path, max_bytes: usize) -> Result<Vec<u8>, FetchError> {
    let file = std::fs::File::open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => FetchError::NotFound,
        std::io::ErrorKind::PermissionDenied => FetchError::Denied(error.to_string()),
        _ => FetchError::Transport(error.to_string()),
    })?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| FetchError::Transport(error.to_string()))?;
    if bytes.len() > max_bytes {
        return Err(FetchError::TooLarge);
    }
    Ok(bytes)
}

/// Why a refresh did not produce a cache.
#[derive(Debug)]
pub enum RefreshError {
    Fetch {
        key: String,
        error: FetchError,
    },
    /// The data is not what this code understands. The old cache stays.
    Data(String),
    Cache(String),
}

impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefreshError::Fetch { key, error } => write!(f, "could not fetch {key}: {error}"),
            RefreshError::Data(why) => write!(f, "unusable availability data: {why}"),
            RefreshError::Cache(why) => write!(f, "could not write the cache: {why}"),
        }
    }
}

/// What a successful refresh found.
#[derive(Debug, PartialEq, Eq)]
pub struct Refreshed {
    /// The dataset's `last_updated` time.
    pub last_updated: String,
    pub types: usize,
    pub regions: usize,
    /// False when the cache already held data at least as new.
    pub written: bool,
}

#[derive(Deserialize)]
struct Index {
    latest_version: String,
    versions: BTreeMap<String, IndexVersion>,
}

#[derive(Deserialize)]
struct IndexVersion {
    manifest: String,
    last_updated: Option<String>,
}

#[derive(Deserialize)]
struct Manifest {
    last_updated: String,
    entities: BTreeMap<String, Entity>,
}

#[derive(Deserialize)]
struct Entity {
    record_count: u64,
}

#[derive(Deserialize)]
struct RegionRow {
    #[serde(rename = "Region")]
    region: String,
}

#[derive(Deserialize)]
struct CfnService {
    #[serde(rename = "serviceName")]
    service_name: String,
    #[serde(rename = "resourceTypes")]
    resource_types: Vec<CfnType>,
}

#[derive(Deserialize)]
struct CfnType {
    #[serde(rename = "resourceTypeName")]
    name: String,
    #[serde(rename = "regionalAvailability")]
    availability: BTreeMap<String, String>,
}

fn data_error(what: &str, error: impl fmt::Display) -> RefreshError {
    RefreshError::Data(format!("{what}: {error}"))
}

fn alphanumeric(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// Turn the dataset's `regions.json` and `cfn_resources.json` into snapshot text.
///
/// Strict on purpose: a value it does not know, a type missing a listed Region, a repeated type
/// or an odd name is an error, so the data is not used at all instead of being half understood.
pub fn convert_cfn(
    version: &str,
    last_updated: &str,
    regions_json: &[u8],
    cfn_json: &[u8],
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
    let rows: Vec<RegionRow> =
        serde_json::from_slice(regions_json).map_err(|e| data_error("regions.json", e))?;
    let regions: BTreeSet<String> = rows.into_iter().map(|row| row.region).collect();
    if regions.is_empty() || regions.len() > 64 {
        return Err(RefreshError::Data(format!("{} Regions", regions.len())));
    }
    // A Region name is written into the cache's `# regions` line, split on spaces when read.
    if let Some(bad) = regions.iter().find(|name| {
        name.is_empty()
            || name.len() > 32
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }) {
        return Err(RefreshError::Data(format!("Region name {bad:?}")));
    }
    let regions: Vec<String> = regions.into_iter().collect();
    let services: Vec<CfnService> =
        serde_json::from_slice(cfn_json).map_err(|e| data_error("cfn_resources.json", e))?;
    let mut masks: BTreeMap<String, u64> = BTreeMap::new();
    for service in &services {
        for resource in &service.resource_types {
            if !alphanumeric(&service.service_name) || !alphanumeric(&resource.name) {
                return Err(RefreshError::Data(format!(
                    "type name {:?} {:?}",
                    service.service_name, resource.name
                )));
            }
            let name = format!("AWS::{}::{}", service.service_name, resource.name);
            let mut mask = 0u64;
            for (bit, region) in regions.iter().enumerate() {
                match resource.availability.get(region).map(String::as_str) {
                    Some("Available") => mask |= 1 << bit,
                    Some("Unavailable") => {}
                    other => {
                        return Err(RefreshError::Data(format!(
                            "{name} in {region}: unknown value {other:?}"
                        )))
                    }
                }
            }
            if masks.insert(name.clone(), mask).is_some() {
                return Err(RefreshError::Data(format!("{name} is listed twice")));
            }
        }
    }
    if masks.is_empty() {
        return Err(RefreshError::Data("no resource types".to_string()));
    }
    let digest: String = Sha256::digest(cfn_json)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let fetched = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut text = String::new();
    text.push_str("# AWS Regional availability data: CloudFormation resource types\n");
    text.push_str(&format!(
        "# source s3://{ACCESS_POINT_ALIAS}/public/{version}/json/cfn_resources.json\n"
    ));
    text.push_str(&format!("# source-sha256 {digest}\n"));
    text.push_str(&format!("# last_updated {last_updated}\n"));
    text.push_str(&format!("# fetched_unix {fetched}\n"));
    text.push_str(&format!("# regions {}\n", regions.join(" ")));
    text.push_str(&format!("# types {}\n", masks.len()));
    for (name, mask) in &masks {
        text.push_str(&format!("{name} {mask:x}\n"));
    }
    let end = sha256_hex(text.as_bytes());
    text.push_str(&format!("# end {end}\n"));
    Ok(text)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether `text` is a whole cache file: it ends with `# end <sha-256 of everything before>`, and
/// its `# types N` is the number of type lines. Anything cut short, edited or extended fails.
fn cache_text_is_whole(text: &str) -> Result<(), String> {
    let at = text.rfind("# end ").ok_or("no end marker")?;
    if at != 0 && !text[..at].ends_with('\n') {
        return Err("the end marker is not on a line of its own".to_string());
    }
    let hash = text[at + "# end ".len()..]
        .strip_suffix('\n')
        .ok_or("the end marker is not the last line")?;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("the end marker is not a hash".to_string());
    }
    let body = &text[..at];
    if hash != sha256_hex(body.as_bytes()) {
        return Err("the file does not match its end marker".to_string());
    }
    let declared = body
        .lines()
        .find_map(|line| line.strip_prefix("# types "))
        .and_then(|count| count.parse::<usize>().ok())
        .ok_or("no type count")?;
    let found = body
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count();
    if declared != found {
        return Err(format!("{declared} types declared, {found} present"));
    }
    Ok(())
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// A dataset time stamp as an instant `(seconds, nanoseconds)` since 1970: exactly
/// `YYYY-MM-DDTHH:MM:SS`, an optional fraction of 1 to 9 digits, and `+00:00` or `Z`. Anything
/// else (another offset, a real date that does not exist, trailing text) is `None`.
pub(crate) fn parse_stamp(text: &str) -> Option<(i64, u32)> {
    let bytes = text.as_bytes();
    if !text.is_ascii() || bytes.len() < 20 {
        return None;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let digits = |from: usize, to: usize| -> Option<i64> {
        let part = &text[from..to];
        part.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (digits(0, 4)?, digits(5, 7)?, digits(8, 10)?);
    let (hour, minute, second) = (digits(11, 13)?, digits(14, 16)?, digits(17, 19)?);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => return None,
    };
    if day < 1 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let mut rest = &text[19..];
    let mut nanos = 0u32;
    if let Some(fraction) = rest.strip_prefix('.') {
        let length = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if length == 0 || length > 9 {
            return None;
        }
        nanos = fraction[..length].parse::<u32>().ok()? * 10u32.pow(9 - length as u32);
        rest = &fraction[length..];
    }
    if rest != "+00:00" && rest != "Z" {
        return None;
    }
    let days = days_from_date(&text[..10])?;
    Some((days * 86_400 + hour * 3_600 + minute * 60 + second, nanos))
}

/// A stamp no more than a day after `now`: a day of slack for clocks, no more.
fn not_in_the_future(stamp: (i64, u32), now: SystemTime) -> bool {
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    stamp.0 <= now + 86_400
}

/// `v` and one to three digits, the shape of the dataset's version names.
fn valid_version(version: &str) -> bool {
    version.len() > 1
        && version.len() <= 4
        && version.starts_with('v')
        && version[1..].bytes().all(|byte| byte.is_ascii_digit())
}

/// Fetch the dataset through `fetcher`, check and convert it, and write the cache file in
/// `cache_dir`. Does nothing to the cache when the data is not newer than what it already holds.
///
/// Refuses a dataset that looks partial: fewer than nine tenths of the bundled snapshot's types.
pub fn refresh(
    fetcher: &dyn ObjectFetcher,
    cache_dir: &Path,
    now: SystemTime,
) -> Result<Refreshed, RefreshError> {
    refresh_with(fetcher, cache_dir, now, type_floor(Snapshot::bundled()))
}

/// [`refresh`] with its own floor on the number of types, for a caller (a test) that reads a
/// small dataset.
///
/// shortcut: the manifest's `cfn_resources` record count has no stated meaning (it is 141,246 for
/// about 2,150 types), so only that it is there and not zero is checked, and the Regions count is
/// checked exactly. The floor stands in for the rest.
pub fn refresh_with(
    fetcher: &dyn ObjectFetcher,
    cache_dir: &Path,
    now: SystemTime,
    min_types: usize,
) -> Result<Refreshed, RefreshError> {
    let fetch = |key: String, max: usize| {
        fetcher
            .get(&ObjectRequest::new(key.clone()), max)
            .map_err(|error| RefreshError::Fetch { key, error })
    };
    let index: Index = serde_json::from_slice(&fetch(INDEX_KEY.to_string(), MAX_INDEX_BYTES)?)
        .map_err(|e| data_error("index.json", e))?;
    let version = index.latest_version;
    if !valid_version(&version) {
        return Err(RefreshError::Data(format!("version {version:?}")));
    }
    let manifest_key = format!("public/{version}/manifest.json");
    let Some(entry) = index
        .versions
        .get(&version)
        .filter(|entry| entry.manifest == manifest_key)
    else {
        return Err(RefreshError::Data(format!(
            "the index does not point {version} at {manifest_key}"
        )));
    };
    let manifest: Manifest = serde_json::from_slice(&fetch(manifest_key, MAX_MANIFEST_BYTES)?)
        .map_err(|e| data_error("manifest.json", e))?;
    if entry
        .last_updated
        .as_deref()
        .is_some_and(|stamp| stamp != manifest.last_updated)
    {
        return Err(RefreshError::Data(
            "the index and the manifest give different dates".to_string(),
        ));
    }
    let regions = fetch(
        format!("public/{version}/json/regions.json"),
        MAX_REGIONS_BYTES,
    )?;
    let cfn = fetch(
        format!("public/{version}/json/cfn_resources.json"),
        MAX_CFN_BYTES,
    )?;
    let text = convert_cfn(&version, &manifest.last_updated, &regions, &cfn, now)?;
    let snapshot = Snapshot::parse(&text).map_err(RefreshError::Data)?;
    let counted = |entity: &str| manifest.entities.get(entity).map(|e| e.record_count);
    if counted("regions") != Some(snapshot.regions().len() as u64) {
        return Err(RefreshError::Data(format!(
            "the manifest counts {:?} Regions and the data has {}",
            counted("regions"),
            snapshot.regions().len()
        )));
    }
    if counted("cfn_resources").unwrap_or(0) == 0 {
        return Err(RefreshError::Data(
            "the manifest has no count for the resource types".to_string(),
        ));
    }
    if snapshot.type_count() < min_types {
        return Err(RefreshError::Data(format!(
            "only {} resource types, expected at least {min_types}",
            snapshot.type_count()
        )));
    }
    let refreshed = |written| Refreshed {
        last_updated: snapshot.last_updated().to_string(),
        types: snapshot.type_count(),
        regions: snapshot.regions().len(),
        written,
    };
    let path = cache_dir.join(CACHE_FILE);
    let ours = parse_stamp(snapshot.last_updated());
    let held = || {
        load_cache_file(&path).is_some_and(|old| {
            parse_stamp(old.last_updated()).is_some_and(|theirs| Some(theirs) >= ours)
        })
    };
    static WRITING: Mutex<()> = Mutex::new(());
    let _one_at_a_time = WRITING.lock().unwrap_or_else(|e| e.into_inner());
    if held() {
        return Ok(refreshed(false));
    }
    let written =
        write_atomically(&path, text.as_bytes(), &|| !held()).map_err(RefreshError::Cache)?;
    Ok(refreshed(written))
}

/// A new file that must not exist yet (`O_EXCL`), so a link planted at its name is not followed.
fn open_new(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

fn create_temp(dir: &Path) -> Result<(PathBuf, std::fs::File), String> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let name = format!(
            ".{CACHE_FILE}.tmp-{}-{}-{nanos:x}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = dir.join(name);
        match open_new(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("could not make a temp file".to_string())
}

/// Write `bytes` to a new temp file, flush it to disk, ask `still_wanted` once more, and rename
/// it over `path`. `Ok(false)` when it was no longer wanted; the temp file is removed.
fn write_atomically(
    path: &Path,
    bytes: &[u8],
    still_wanted: &dyn Fn() -> bool,
) -> Result<bool, String> {
    let dir = path.parent().ok_or("no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let (temp, mut file) = create_temp(dir)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(error.to_string());
    }
    if !still_wanted() {
        let _ = std::fs::remove_file(&temp);
        return Ok(false);
    }
    if let Err(error) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(error.to_string());
    }
    if let Ok(directory) = std::fs::File::open(dir) {
        let _ = directory.sync_all();
    }
    Ok(true)
}

/// The cache file at `path`, when it is a regular file, whole (see [`cache_text_is_whole`]),
/// parses, and names the access point as its source. A file that is there but unusable is logged
/// and ignored, and the bundled snapshot stays in use.
pub fn load_cache_file(path: &Path) -> Option<Snapshot> {
    let ignore = |why: &dyn fmt::Display| {
        tracing::warn!("ignoring the availability cache {}: {why}", path.display());
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
    let snapshot = std::str::from_utf8(&bytes)
        .map_err(|e| e.to_string())
        .and_then(|text| cache_text_is_whole(text).map(|()| text))
        .and_then(Snapshot::parse);
    match snapshot {
        Ok(snapshot) if names_the_access_point(&snapshot) => Some(snapshot),
        Ok(_) => {
            ignore(&"its source is not the access point");
            None
        }
        Err(error) => {
            ignore(&error);
            None
        }
    }
}

fn names_the_access_point(snapshot: &Snapshot) -> bool {
    snapshot
        .source()
        .is_some_and(|source| source.starts_with(&format!("s3://{ACCESS_POINT_ALIAS}/public/")))
}

/// The cache wins only when its date is a real instant later than the bundled snapshot's, and it
/// lists at least the floor of [`type_floor`] types: a sealed but near-empty cache never wins.
pub fn choose<'a>(bundled: &'a Snapshot, cached: Option<&'a Snapshot>) -> &'a Snapshot {
    match cached {
        Some(cached)
            if cached.type_count() >= type_floor(bundled)
                && matches!(
                    (parse_stamp(cached.last_updated()), parse_stamp(bundled.last_updated())),
                    (Some(cached), Some(bundled)) if cached > bundled
                ) =>
        {
            cached
        }
        _ => bundled,
    }
}

/// Nine tenths of the bundled snapshot's types: the fewest a refreshed dataset or a cache in use
/// may hold.
pub fn type_floor(bundled: &Snapshot) -> usize {
    bundled.type_count() / 10 * 9
}

/// The cache in `dir` when it is usable and not dated in the future.
fn cache_in_use(dir: &Path, now: SystemTime) -> Option<Snapshot> {
    load_cache_file(&dir.join(CACHE_FILE)).filter(|cache| {
        parse_stamp(cache.last_updated()).is_some_and(|stamp| not_in_the_future(stamp, now))
    })
}

fn cache_dir_from_env() -> Option<PathBuf> {
    match std::env::var_os(CACHE_DIR_ENV) {
        Some(dir) if !dir.is_empty() => Some(PathBuf::from(dir)),
        _ => std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .map(|home| PathBuf::from(home).join(".aws/emulator/region-availability")),
    }
}

/// The snapshot the gate uses: see [`choose`]. Read once per process. Logs a warning, once,
/// when the data in use is over the age limit (`region_availability::STALE_AFTER_DAYS`).
/// With no cache file this is the bundled snapshot and makes no network call.
pub fn current() -> &'static Snapshot {
    static CURRENT: OnceLock<&'static Snapshot> = OnceLock::new();
    CURRENT.get_or_init(|| {
        static CACHED: OnceLock<Option<Snapshot>> = OnceLock::new();
        let cached = CACHED
            .get_or_init(|| {
                cache_dir_from_env().and_then(|dir| cache_in_use(&dir, SystemTime::now()))
            })
            .as_ref();
        let chosen = choose(Snapshot::bundled(), cached);
        if let Some(note) = chosen.staleness_note(SystemTime::now()) {
            tracing::warn!(
                "the AWS Regional availability data in use is dated {}: {note}",
                chosen.data_date()
            );
        }
        chosen
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const BUNDLED_TEXT: &str = include_str!("../data/cfn_resource_availability.txt");
    const REGIONS: [&str; 3] = ["us-east-1", "ap-southeast-7", "ap-southeast-6"];
    /// The real `index.json` and `manifest.json` of the access point, read with a signed request
    /// on 2026-11-19 and saved as they came.
    const INDEX_FIXTURE: &[u8] = include_bytes!("../data/fixtures/index.json");
    const MANIFEST_FIXTURE: &[u8] = include_bytes!("../data/fixtures/manifest.json");

    /// [`refresh_with`] with no floor, for the small datasets most tests use.
    fn refresh_small(
        fetcher: &dyn ObjectFetcher,
        dir: &Path,
        now: SystemTime,
    ) -> Result<Refreshed, RefreshError> {
        refresh_with(fetcher, dir, now, 0)
    }

    /// A cache file's body, sealed with its end marker.
    fn seal(body: &str) -> String {
        let mut text = body.to_string();
        text.push_str(&format!("# end {}\n", sha256_hex(text.as_bytes())));
        text
    }

    /// The bundled snapshot's date, in seconds since 1970. Test dates and the test clock are set
    /// from it, so a regenerated snapshot does not age the tests.
    fn bundled_secs() -> i64 {
        parse_stamp(Snapshot::bundled().last_updated())
            .expect("the bundled date parses")
            .0
    }

    /// A dataset stamp `seconds` after the bundled snapshot's date, in the dataset's format.
    pub(crate) fn after_bundled(seconds: i64) -> String {
        let at = bundled_secs() + seconds;
        let (days, rest) = (at.div_euclid(86_400), at.rem_euclid(86_400));
        // Days since 1970 to a civil date (Howard Hinnant's algorithm).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}+00:00",
            rest / 3_600,
            rest / 60 % 60,
            rest % 60
        )
    }

    const HOUR: i64 = 3_600;
    const DAY: i64 = 86_400;

    /// The test clock: two days and five hours after the bundled snapshot's date.
    pub(crate) fn now() -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs((bundled_secs() + 2 * DAY + 5 * HOUR) as u64)
    }

    /// The dates the tests use, as offsets from the bundled date: a day later, two days later.
    fn day_after() -> String {
        after_bundled(DAY)
    }
    fn two_days_after() -> String {
        after_bundled(2 * DAY)
    }

    /// The bundled date's second with a fraction just under one: later than the bundled data and,
    /// for any real snapshot, not later than the real clock.
    fn just_after_bundled() -> String {
        format!(
            "{}.999999999+00:00",
            &Snapshot::bundled().last_updated()[..19]
        )
    }

    #[test]
    fn the_test_dates_follow_the_bundled_date() {
        assert_eq!(
            parse_stamp(&after_bundled(0)).unwrap().0,
            bundled_secs(),
            "{}",
            after_bundled(0)
        );
        for offset in [DAY, 2 * DAY + 5 * HOUR + 7, 400 * DAY, 4 * 365 * DAY] {
            let stamp = after_bundled(offset);
            assert_eq!(
                parse_stamp(&stamp).unwrap().0,
                bundled_secs() + offset,
                "{stamp}"
            );
        }
        assert!(parse_stamp(&day_after()) < parse_stamp(&two_days_after()));
    }

    fn temp_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "availability-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn json(value: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&value).unwrap()
    }

    fn kind(name: &str, available: [&str; 3]) -> serde_json::Value {
        let map: BTreeMap<&str, &str> = REGIONS.iter().copied().zip(available).collect();
        serde_json::json!({"resourceTypeName": name, "regionalAvailability": map})
    }

    fn regions_file() -> Vec<u8> {
        json(serde_json::json!(REGIONS
            .iter()
            .map(|r| serde_json::json!({
                "Region": r, "Partition": "aws", "RegionStatus": "GA", "RequireRegionOptIn": false
            }))
            .collect::<Vec<_>>()))
    }

    fn cfn_file() -> Vec<u8> {
        json(serde_json::json!([
            {"serviceName": "MemoryDB", "resourceTypes": [
                kind("Cluster", ["Available", "Unavailable", "Unavailable"])]},
            {"serviceName": "AppSync", "resourceTypes": [
                kind("GraphQLApi", ["Available", "Available", "Unavailable"])]},
            {"serviceName": "SQS", "resourceTypes": [
                kind("Queue", ["Available", "Available", "Available"])]},
        ]))
    }

    /// A small dataset laid out like the access point: three types, three Regions. The index and
    /// the manifest are the real ones, with the date and the Regions count changed.
    pub(crate) fn dataset(last_updated: &str) -> BTreeMap<String, Vec<u8>> {
        dataset_with(last_updated, 3, regions_file(), cfn_file())
    }

    fn dataset_with(
        last_updated: &str,
        region_count: u64,
        regions: Vec<u8>,
        cfn: Vec<u8>,
    ) -> BTreeMap<String, Vec<u8>> {
        let mut index: serde_json::Value = serde_json::from_slice(INDEX_FIXTURE).unwrap();
        index["versions"]["v1"]["last_updated"] = last_updated.into();
        let mut manifest: serde_json::Value = serde_json::from_slice(MANIFEST_FIXTURE).unwrap();
        manifest["last_updated"] = last_updated.into();
        manifest["entities"]["regions"]["record_count"] = region_count.into();
        let mut files = BTreeMap::new();
        files.insert("public/index.json".to_string(), json(index));
        files.insert("public/v1/manifest.json".to_string(), json(manifest));
        files.insert("public/v1/json/regions.json".to_string(), regions);
        files.insert("public/v1/json/cfn_resources.json".to_string(), cfn);
        files
    }

    /// The bundled snapshot turned back into the dataset's own JSON: `regions.json`,
    /// `cfn_resources.json`, and the dataset's date.
    fn bundled_as_json() -> (Vec<u8>, Vec<u8>, String) {
        let regions: Vec<&str> = BUNDLED_TEXT
            .lines()
            .find_map(|l| l.strip_prefix("# regions "))
            .unwrap()
            .split_whitespace()
            .collect();
        let last_updated = BUNDLED_TEXT
            .lines()
            .find_map(|l| l.strip_prefix("# last_updated "))
            .unwrap()
            .to_string();
        let mut services: BTreeMap<&str, Vec<serde_json::Value>> = BTreeMap::new();
        for line in BUNDLED_TEXT
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let (name, mask) = line.rsplit_once(' ').unwrap();
            let mask = u64::from_str_radix(mask, 16).unwrap();
            let mut parts = name.split("::");
            let (_, service, kind) = (parts.next(), parts.next().unwrap(), parts.next().unwrap());
            let availability: BTreeMap<&str, &str> = regions
                .iter()
                .enumerate()
                .map(|(bit, r)| {
                    (
                        *r,
                        if mask >> bit & 1 == 1 {
                            "Available"
                        } else {
                            "Unavailable"
                        },
                    )
                })
                .collect();
            services
                .entry(service)
                .or_default()
                .push(serde_json::json!({
                    "resourceTypeName": kind, "regionalAvailability": availability
                }));
        }
        let cfn = json(serde_json::json!(services
            .iter()
            .map(|(s, types)| serde_json::json!({"serviceName": s, "resourceTypes": types}))
            .collect::<Vec<_>>()));
        let regions_file = json(serde_json::json!(regions
            .iter()
            .rev()
            .map(|r| serde_json::json!({"Region": r}))
            .collect::<Vec<_>>()));
        (regions_file, cfn, last_updated)
    }

    /// The cache text a conversion of the full bundled data gives.
    fn full_cache_text() -> String {
        let (regions, cfn, last_updated) = bundled_as_json();
        convert_cfn("v1", &last_updated, &regions, &cfn, now()).unwrap()
    }

    /// Serves a fixed set of objects and records every request.
    struct Recording {
        files: BTreeMap<String, Vec<u8>>,
        seen: RefCell<Vec<ObjectRequest>>,
    }

    impl Recording {
        fn new(files: BTreeMap<String, Vec<u8>>) -> Recording {
            Recording {
                files,
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl ObjectFetcher for Recording {
        fn get(&self, request: &ObjectRequest, max_bytes: usize) -> Result<Vec<u8>, FetchError> {
            self.seen.borrow_mut().push(request.clone());
            let bytes = self.files.get(&request.key).ok_or(FetchError::NotFound)?;
            if bytes.len() > max_bytes {
                return Err(FetchError::TooLarge);
            }
            Ok(bytes.clone())
        }
    }

    /// Refuses everything, the way the access point refuses an unsigned request.
    struct Refusing;

    impl ObjectFetcher for Refusing {
        fn get(&self, _: &ObjectRequest, _: usize) -> Result<Vec<u8>, FetchError> {
            Err(FetchError::Denied(String::new()))
        }
    }

    fn goes_to_the_access_point(request: &ObjectRequest) -> bool {
        (request.bucket == ACCESS_POINT_ALIAS || request.bucket == ACCESS_POINT_ARN)
            && request.region == "us-east-1"
            && request.key.starts_with("public/")
    }

    /// If these strings change, the fetch no longer goes to the AWS Regional availability access
    /// point, and this test says so. Change it only on purpose.
    #[test]
    fn the_source_is_the_published_access_point() {
        assert_eq!(
            ACCESS_POINT_ALIAS,
            "aws-capabilities-pub-ybkxdwgxrkfhwmq8b1neoq8ny6ua4use1b-s3alias"
        );
        assert_eq!(
            ACCESS_POINT_ARN,
            "arn:aws:s3:us-east-1:686591367145:accesspoint/aws-capabilities-public"
        );
        assert_eq!(ACCESS_POINT_REGION, "us-east-1");
        let plain = ObjectRequest {
            bucket: "some-bucket",
            region: "us-east-1",
            key: "public/index.json".to_string(),
        };
        assert!(
            !goes_to_the_access_point(&plain),
            "a plain bucket is not the access point"
        );
        assert!(goes_to_the_access_point(&ObjectRequest::new(
            "public/index.json".to_string()
        )));
    }

    /// Every request a refresh makes goes to the access point alias, in us-east-1, for one of
    /// the four fixed keys under `public/`, and nothing else is asked for.
    #[test]
    fn a_refresh_reads_only_the_access_point() {
        let dir = temp_dir("source");
        let fetcher = Recording::new(dataset(&day_after()));
        refresh_small(&fetcher, &dir, now()).unwrap();
        let seen = fetcher.seen.borrow();
        let keys: Vec<&str> = seen.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "public/index.json",
                "public/v1/manifest.json",
                "public/v1/json/regions.json",
                "public/v1/json/cfn_resources.json"
            ]
        );
        for request in seen.iter() {
            assert!(goes_to_the_access_point(request), "{request:?}");
            assert_eq!(request.bucket, ACCESS_POINT_ALIAS);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_refresh_writes_a_cache_the_loader_reads_and_that_names_the_access_point() {
        let dir = temp_dir("write");
        let fetcher = Recording::new(dataset(&day_after()));
        let report = refresh_small(&fetcher, &dir, now()).unwrap();
        assert_eq!(
            report,
            Refreshed {
                last_updated: day_after(),
                types: 3,
                regions: 3,
                written: true
            }
        );
        let cached = load_cache_file(&dir.join(CACHE_FILE)).expect("a readable cache");
        assert!(cached
            .source()
            .unwrap()
            .starts_with(&format!("s3://{ACCESS_POINT_ALIAS}/public/v1/")));
        use crate::region_availability::Verdict::{Available, Unavailable};
        assert_eq!(
            cached.cfn_resource_type("ap-southeast-7", "AWS::MemoryDB::Cluster"),
            Unavailable
        );
        assert_eq!(
            cached.cfn_resource_type("us-east-1", "AWS::MemoryDB::Cluster"),
            Available
        );
        assert_eq!(
            cached.cfn_resource_type("ap-southeast-6", "AWS::AppSync::GraphQLApi"),
            Unavailable
        );
        assert_eq!(
            cached.cfn_resource_type("ap-southeast-7", "AWS::AppSync::GraphQLApi"),
            Available
        );
        let leftovers: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        assert_eq!(leftovers.len(), 1, "no temp file is left: {leftovers:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The converter gives, for the dataset that the bundled snapshot was made from, the same
    /// snapshot. The dataset is rebuilt here from the bundled text.
    #[test]
    fn converting_the_dataset_the_bundled_snapshot_came_from_gives_the_same_snapshot() {
        let text = full_cache_text();
        let data = |text: &str| -> Vec<String> {
            text.lines()
                .filter(|l| {
                    !["# fetched_unix", "# source-sha256", "# types", "# end"]
                        .iter()
                        .any(|skip| l.starts_with(skip))
                })
                .map(str::to_string)
                .collect()
        };
        assert_eq!(data(&text), data(BUNDLED_TEXT));
        assert!(text.lines().count() > 2000);
    }

    fn converted(regions: &[u8], cfn: &[u8]) -> Result<String, RefreshError> {
        convert_cfn("v1", &day_after(), regions, cfn, now())
    }

    /// Data the code does not understand is refused whole, so nothing half-read is used.
    #[test]
    fn data_the_code_does_not_understand_is_refused_whole() {
        let good_regions = regions_file();
        let with = |availability: serde_json::Value| {
            json(serde_json::json!([{"serviceName": "SQS", "resourceTypes": [
                {"resourceTypeName": "Queue", "regionalAvailability": availability}]}]))
        };
        let all = |word: &str| {
            with(serde_json::json!({
                "us-east-1": word, "ap-southeast-7": "Available", "ap-southeast-6": "Available"
            }))
        };
        assert!(converted(&good_regions, &all("Available")).is_ok());
        let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
            ("a new status word", good_regions.clone(), all("Preview")),
            (
                "a lower case status",
                good_regions.clone(),
                all("available"),
            ),
            (
                "a type missing a listed Region",
                good_regions.clone(),
                with(serde_json::json!({"us-east-1": "Available", "ap-southeast-7": "Available"})),
            ),
            (
                "a repeated type",
                good_regions.clone(),
                json(serde_json::json!([
                    {"serviceName": "SQS", "resourceTypes": [kind("Queue", ["Available"; 3]), kind("Queue", ["Available"; 3])]}
                ])),
            ),
            (
                "a name with a space",
                good_regions.clone(),
                json(serde_json::json!([
                    {"serviceName": "S Q S", "resourceTypes": [kind("Queue", ["Available"; 3])]}
                ])),
            ),
            (
                "a name that would add a line",
                good_regions.clone(),
                json(serde_json::json!([
                    {"serviceName": "SQS", "resourceTypes": [kind("Queue\nAWS::X::Y", ["Available"; 3])]}
                ])),
            ),
            (
                "no types",
                good_regions.clone(),
                json(serde_json::json!([])),
            ),
            ("not JSON", good_regions.clone(), b"<html>".to_vec()),
            ("no Regions", json(serde_json::json!([])), cfn_file()),
            (
                "a Region name that is not one",
                json(serde_json::json!([{"Region": "us east 1"}])),
                cfn_file(),
            ),
            (
                "more than 64 Regions",
                json(serde_json::json!((0..65)
                    .map(|n| serde_json::json!({"Region": format!("xx-test-{n}")}))
                    .collect::<Vec<_>>())),
                cfn_file(),
            ),
        ];
        for (case, regions, cfn) in cases {
            let outcome = converted(&regions, &cfn);
            assert!(
                matches!(outcome, Err(RefreshError::Data(_))),
                "{case}: expected a refusal, got {outcome:?}"
            );
        }
        for stamp in ["", "yesterday", "2026-13-40T00:00:00Z", "2026-11-18\n"] {
            let outcome = convert_cfn("v1", stamp, &good_regions, &cfn_file(), now());
            assert!(
                matches!(outcome, Err(RefreshError::Data(_))),
                "stamp {stamp:?}"
            );
        }
    }

    /// 64 Regions fit the cache's 64-bit masks; a 65th is refused by the count check itself,
    /// even when every type lists it.
    #[test]
    fn more_regions_than_a_mask_holds_are_refused() {
        let with = |count: usize| {
            let names: Vec<String> = (0..count).map(|n| format!("xx-test-{n}")).collect();
            let regions = json(serde_json::json!(names
                .iter()
                .map(|r| serde_json::json!({"Region": r}))
                .collect::<Vec<_>>()));
            let map: BTreeMap<&str, &str> =
                names.iter().map(|r| (r.as_str(), "Available")).collect();
            let cfn = json(serde_json::json!([{"serviceName": "SQS", "resourceTypes": [
                {"resourceTypeName": "Queue", "regionalAvailability": map}]}]));
            converted(&regions, &cfn)
        };
        assert!(with(64).is_ok(), "64 Regions fit");
        match with(65) {
            Err(RefreshError::Data(why)) => assert_eq!(why, "65 Regions"),
            other => panic!("expected a refusal of 65 Regions, got {other:?}"),
        }
    }

    /// A Region name that is not one is refused by the name check itself: each type below lists
    /// the bad name too, so no other check can refuse it.
    #[test]
    fn a_region_name_that_is_not_one_is_refused_even_when_every_type_lists_it() {
        let regions_with = |extra: &str| {
            let mut names: Vec<&str> = REGIONS.to_vec();
            names.push(extra);
            json(serde_json::json!(names
                .iter()
                .map(|r| serde_json::json!({"Region": r}))
                .collect::<Vec<_>>()))
        };
        let cfn_with = |extra: &str| {
            let mut map: BTreeMap<&str, &str> = REGIONS.iter().map(|r| (*r, "Available")).collect();
            map.insert(extra, "Available");
            json(serde_json::json!([{"serviceName": "SQS", "resourceTypes": [
                {"resourceTypeName": "Queue", "regionalAvailability": map}]}]))
        };
        assert!(
            converted(&regions_with("eu-west-3"), &cfn_with("eu-west-3")).is_ok(),
            "the control: a real name is admitted"
        );
        let too_long = "x".repeat(33);
        for bad in [
            "us east 1",
            "us-east-1\nAWS::X::Y 1",
            "eu-west-3\n",
            "",
            "US-EAST-1",
            "us_east_1",
            "us-east-1 ",
            too_long.as_str(),
        ] {
            let outcome = converted(&regions_with(bad), &cfn_with(bad));
            match outcome {
                Err(RefreshError::Data(why)) => {
                    assert!(why.starts_with("Region name"), "{bad:?}: {why}")
                }
                other => panic!("{bad:?}: expected a refusal of the name, got {other:?}"),
            }
        }
    }

    /// The index and manifest are not trusted for where to read: a version that is not `v<digits>`
    /// or a manifest path that is not the expected one stops the refresh before any other read.
    #[test]
    fn the_index_cannot_send_the_refresh_to_another_object() {
        let bad = [
            serde_json::json!({"latest_version": "../x", "versions": {"../x": {"manifest": "public/../x/manifest.json"}}}),
            serde_json::json!({"latest_version": "v1/../../x", "versions": {"v1/../../x": {"manifest": "public/v1/../../x/manifest.json"}}}),
            serde_json::json!({"latest_version": "latest", "versions": {"latest": {"manifest": "public/latest/manifest.json"}}}),
            serde_json::json!({"latest_version": "v12345", "versions": {"v12345": {"manifest": "public/v12345/manifest.json"}}}),
            serde_json::json!({"latest_version": "v1", "versions": {"v1": {"manifest": "other/manifest.json"}}}),
            serde_json::json!({"latest_version": "v1", "versions": {}}),
        ];
        for index in bad {
            let dir = temp_dir("index");
            let mut files = dataset(&day_after());
            files.insert("public/index.json".to_string(), json(index.clone()));
            let fetcher = Recording::new(files);
            let outcome = refresh_small(&fetcher, &dir, now());
            assert!(
                matches!(outcome, Err(RefreshError::Data(_))),
                "{index}: {outcome:?}"
            );
            assert_eq!(
                fetcher.seen.borrow().len(),
                1,
                "{index}: read past the index"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn a_refused_or_failed_fetch_leaves_the_cache_as_it_was() {
        let dir = temp_dir("failed");
        refresh_small(&Recording::new(dataset(&day_after())), &dir, now()).unwrap();
        let before = std::fs::read(dir.join(CACHE_FILE)).unwrap();
        // The access point answers an unsigned request with a refusal.
        match refresh_small(&Refusing, &dir, now()) {
            Err(RefreshError::Fetch { key, error }) => {
                assert_eq!(key, "public/index.json");
                assert_eq!(error, FetchError::Denied(String::new()));
                assert_eq!(error.to_string(), "access denied");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // A later object fails, and so does an object over its cap.
        let mut files = dataset(&two_days_after());
        files.remove("public/v1/json/cfn_resources.json");
        assert!(matches!(
            refresh_small(&Recording::new(files), &dir, now()),
            Err(RefreshError::Fetch {
                error: FetchError::NotFound,
                ..
            })
        ));
        let mut files = dataset(&two_days_after());
        files.insert(
            "public/index.json".to_string(),
            vec![b' '; MAX_INDEX_BYTES + 1],
        );
        assert!(matches!(
            refresh_small(&Recording::new(files), &dir, now()),
            Err(RefreshError::Fetch {
                error: FetchError::TooLarge,
                ..
            })
        ));
        assert_eq!(std::fs::read(dir.join(CACHE_FILE)).unwrap(), before);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_refresh_never_replaces_the_cache_with_older_data() {
        let dir = temp_dir("older");
        let write =
            |stamp: &str| refresh_small(&Recording::new(dataset(stamp)), &dir, now()).unwrap();
        assert!(write(&day_after()).written);
        let kept = std::fs::read(dir.join(CACHE_FILE)).unwrap();
        assert!(!write(&after_bundled(0)).written, "older data");
        assert!(!write(&day_after()).written, "the same data");
        assert_eq!(std::fs::read(dir.join(CACHE_FILE)).unwrap(), kept);
        let newer = write(&two_days_after());
        assert!(newer.written);
        assert_eq!(
            load_cache_file(&dir.join(CACHE_FILE))
                .unwrap()
                .last_updated(),
            two_days_after()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A user fills a directory with `aws s3 sync`, and the same refresh reads it.
    #[test]
    fn a_directory_laid_out_like_the_access_point_can_be_refreshed_from() {
        let source = temp_dir("tree");
        for (key, bytes) in dataset(&day_after()) {
            let path = source.join(&key);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        let cache = temp_dir("tree-cache");
        let report = refresh_small(&DirFetcher::new(&source), &cache, now()).unwrap();
        assert!(report.written);
        assert_eq!(report.types, 3);
        // A key that climbs out of the tree is not read.
        let escape = ObjectRequest::new("public/../../etc/passwd".to_string());
        assert!(matches!(
            DirFetcher::new(&source).get(&escape, 1024),
            Err(FetchError::Transport(_))
        ));
        // An empty directory is "not found", not a crash.
        let empty = temp_dir("tree-empty");
        assert!(matches!(
            refresh_small(&DirFetcher::new(&empty), &cache, now()),
            Err(RefreshError::Fetch {
                error: FetchError::NotFound,
                ..
            })
        ));
        for dir in [source, cache, empty] {
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn a_cache_file_is_used_only_when_it_is_sound_and_names_the_access_point() {
        let dir = temp_dir("cachefile");
        let path = dir.join(CACHE_FILE);
        let body = |source: &str| {
            format!(
                "# source {source}\n# last_updated 2026-11-18T00:05:07+00:00\n# regions us-east-1\n# types 1\nAWS::SQS::Queue 1\n"
            )
        };
        let stamped = |source: &str| seal(&body(source));
        let good = format!("s3://{ACCESS_POINT_ALIAS}/public/v1/json/cfn_resources.json");
        let cases = [
            ("sound", stamped(&good), true),
            ("another bucket", stamped("s3://some-other-bucket/public/v1/json/cfn_resources.json"), false),
            ("no source", seal("# last_updated 2026-11-18T00:05:07+00:00\n# regions us-east-1\n# types 1\nAWS::SQS::Queue 1\n"), false),
            ("sound but never sealed", body(&good), false),
            ("the alias as a prefix of another name", stamped(&format!("s3://{ACCESS_POINT_ALIAS}x/public/v1/x")), false),
            ("not a snapshot", "hello".to_string(), false),
            ("empty", String::new(), false),
        ];
        for (case, text, usable) in cases {
            std::fs::write(&path, text).unwrap();
            assert_eq!(load_cache_file(&path).is_some(), usable, "{case}");
        }
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        assert!(load_cache_file(&path).is_none(), "not text");
        std::fs::write(&path, vec![b'#'; MAX_CACHE_BYTES + 1]).unwrap();
        assert!(load_cache_file(&path).is_none(), "over the size cap");
        std::fs::remove_file(&path).unwrap();
        assert!(load_cache_file(&path).is_none(), "no file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The snapshot bundled in the crate passes the same provenance check the cache does.
    #[test]
    fn the_bundled_snapshot_names_the_access_point_too() {
        let bundled = Snapshot::bundled();
        assert!(names_the_access_point(bundled), "{:?}", bundled.source());
    }

    #[test]
    fn the_cache_wins_only_when_it_is_dated_later() {
        let at = |stamp: &str| {
            Snapshot::parse(&format!(
                "# last_updated {stamp}\n# regions us-east-1\nAWS::SQS::Queue 1\n"
            ))
            .unwrap()
        };
        let bundled = at("2026-11-17T00:03:09.441208+00:00");
        let newer = at("2026-11-18T00:05:07+00:00");
        let same = at("2026-11-17T00:03:09.441208+00:00");
        let older = at("2026-11-16T00:00:00+00:00");
        assert!(std::ptr::eq(choose(&bundled, Some(&newer)), &newer));
        assert!(std::ptr::eq(choose(&bundled, Some(&same)), &bundled));
        assert!(std::ptr::eq(choose(&bundled, Some(&older)), &bundled));
        assert!(std::ptr::eq(choose(&bundled, None), &bundled));
    }

    /// A file of exactly the cap is read, and one byte more is refused.
    #[test]
    fn reading_stops_at_the_cap() {
        let dir = temp_dir("cap");
        let path = dir.join("object");
        std::fs::write(&path, vec![b'x'; 100]).unwrap();
        assert_eq!(read_capped(&path, 100).unwrap().len(), 100);
        assert_eq!(read_capped(&path, 99), Err(FetchError::TooLarge));
        assert_eq!(read_capped(&path, 0), Err(FetchError::TooLarge));
        assert_eq!(
            read_capped(&dir.join("missing"), 100),
            Err(FetchError::NotFound)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `current()` reads the cache from the directory the environment names, and picks it when it
    /// is newer than the bundled snapshot. It is chosen once per process, so this is the only
    /// test in this crate that calls `current()`.
    #[test]
    fn the_snapshot_in_use_comes_from_the_cache_directory_the_environment_names() {
        let dir = temp_dir("current");
        // current() checks the date against the real clock, so this one is dated just after the
        // bundled data (never in the future), and is full size, so it clears the floor.
        let (regions, cfn, _) = bundled_as_json();
        let stamp = just_after_bundled();
        refresh_small(
            &Recording::new(dataset_with(&stamp, 37, regions, cfn)),
            &dir,
            now(),
        )
        .unwrap();
        std::env::set_var(CACHE_DIR_ENV, &dir);
        let chosen = current();
        assert_eq!(chosen.last_updated(), stamp);
        assert!(!std::ptr::eq(chosen, Snapshot::bundled()));
        assert!(std::ptr::eq(chosen, current()), "chosen once");
        std::env::remove_var(CACHE_DIR_ENV);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ---- integrity of the data and the cache ---------------------------------------------------

    /// The real files, unchanged, are read by the structs the refresh uses.
    #[test]
    fn the_real_index_and_manifest_are_read_as_they_are() {
        let index: Index = serde_json::from_slice(INDEX_FIXTURE).unwrap();
        assert_eq!(index.latest_version, "v1");
        let entry = &index.versions["v1"];
        assert_eq!(entry.manifest, "public/v1/manifest.json");
        let manifest: Manifest = serde_json::from_slice(MANIFEST_FIXTURE).unwrap();
        assert_eq!(
            entry.last_updated.as_deref(),
            Some(manifest.last_updated.as_str())
        );
        assert!(parse_stamp(&manifest.last_updated).is_some());
        assert_eq!(manifest.entities["regions"].record_count, 37);
        assert!(manifest.entities["cfn_resources"].record_count > 0);
    }

    fn data_error_of(outcome: Result<Refreshed, RefreshError>) -> String {
        match outcome {
            Err(RefreshError::Data(why)) => why,
            other => panic!("expected a refusal of the data, got {other:?}"),
        }
    }

    /// Counts and dates that disagree with each other refuse the whole dataset.
    #[test]
    fn a_dataset_whose_counts_or_dates_disagree_is_refused() {
        let stamp = &day_after();
        let run = |files: BTreeMap<String, Vec<u8>>| {
            let dir = temp_dir("counts");
            let outcome = refresh_small(&Recording::new(files), &dir, now());
            assert_eq!(
                outcome.is_ok(),
                dir.join(CACHE_FILE).exists(),
                "{outcome:?}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
            outcome
        };
        assert!(run(dataset(stamp)).is_ok());
        let why = data_error_of(run(dataset_with(stamp, 36, regions_file(), cfn_file())));
        assert!(why.contains("counts"), "{why}");
        let mut files = dataset(stamp);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&files["public/v1/manifest.json"]).unwrap();
        manifest["entities"]["cfn_resources"]["record_count"] = 0.into();
        files.insert(
            "public/v1/manifest.json".to_string(),
            json(manifest.clone()),
        );
        assert!(data_error_of(run(files)).contains("no count"));
        let mut files = dataset(stamp);
        manifest["entities"]
            .as_object_mut()
            .unwrap()
            .remove("cfn_resources");
        files.insert("public/v1/manifest.json".to_string(), json(manifest));
        assert!(data_error_of(run(files)).contains("no count"));
        let mut files = dataset(stamp);
        files.insert(
            "public/v1/manifest.json".to_string(),
            json(serde_json::json!({"last_updated": stamp})),
        );
        assert!(data_error_of(run(files)).contains("manifest.json"));
        let mut files = dataset(stamp);
        let mut index: serde_json::Value =
            serde_json::from_slice(&files["public/index.json"]).unwrap();
        index["versions"]["v1"]["last_updated"] = after_bundled(DAY + 1).into();
        files.insert("public/index.json".to_string(), json(index));
        assert!(data_error_of(run(files)).contains("different dates"));
    }

    /// Removes whole services, from the end, until at least `at_least` types are gone.
    fn without_types(cfn: &[u8], at_least: usize) -> Vec<u8> {
        let mut services: Vec<serde_json::Value> = serde_json::from_slice(cfn).unwrap();
        let mut removed = 0;
        while removed < at_least {
            removed += services.pop().unwrap()["resourceTypes"]
                .as_array()
                .unwrap()
                .len();
        }
        json(serde_json::Value::Array(services))
    }

    /// A dataset with far fewer types than the bundled one is refused by `refresh`, and one that
    /// is nearly as big is not.
    #[test]
    fn a_partial_dataset_is_refused_unless_it_is_nearly_the_bundled_size() {
        let (regions, cfn, last_updated) = bundled_as_json();
        let total = Snapshot::bundled().type_count();
        let tries = |cfn: Vec<u8>| {
            let dir = temp_dir("floor");
            let files = dataset_with(&last_updated, 37, regions.clone(), cfn);
            let outcome = refresh(&Recording::new(files), &dir, now());
            let written = dir.join(CACHE_FILE).exists();
            std::fs::remove_dir_all(&dir).unwrap();
            (outcome, written)
        };
        let (outcome, written) = tries(cfn.clone());
        assert_eq!(outcome.unwrap().types, total);
        assert!(written);
        let (outcome, written) = tries(without_types(&cfn, total / 20));
        assert!(outcome.is_ok() && written, "5% fewer types is allowed");
        let (outcome, written) = tries(without_types(&cfn, total / 5));
        assert!(data_error_of(outcome).contains("only"));
        assert!(!written, "20% fewer types is refused");
        let (outcome, _) = {
            let dir = temp_dir("floor-small");
            let outcome = refresh(&Recording::new(dataset(&day_after())), &dir, now());
            std::fs::remove_dir_all(&dir).unwrap();
            (outcome, ())
        };
        assert!(data_error_of(outcome).contains("only 3 resource types"));
    }

    /// A sealed, newer cache with far fewer types than the bundled data never wins (the same
    /// floor as `refresh`); one at the floor does.
    #[test]
    fn a_near_empty_cache_never_beats_the_bundled_data() {
        let (regions, cfn, _) = bundled_as_json();
        let bundled = Snapshot::bundled();
        let cache_of = |cfn: &[u8]| {
            Snapshot::parse(&convert_cfn("v1", &day_after(), &regions, cfn, now()).unwrap())
                .unwrap()
        };
        let whole = cache_of(&cfn);
        assert!(std::ptr::eq(choose(bundled, Some(&whole)), &whole));
        let near_floor = cache_of(&without_types(&cfn, bundled.type_count() / 20));
        assert!(near_floor.type_count() >= type_floor(bundled));
        assert!(std::ptr::eq(
            choose(bundled, Some(&near_floor)),
            &near_floor
        ));
        let below = cache_of(&without_types(&cfn, bundled.type_count() / 5));
        assert!(below.type_count() < type_floor(bundled));
        assert!(std::ptr::eq(choose(bundled, Some(&below)), bundled));
        let one = Snapshot::parse(
            &convert_cfn("v1", &day_after(), &regions_file(), &cfn_file(), now()).unwrap(),
        )
        .unwrap();
        assert_eq!(one.type_count(), 3);
        assert!(std::ptr::eq(choose(bundled, Some(&one)), bundled));
        assert_eq!(type_floor(bundled), bundled.type_count() / 10 * 9);
    }

    #[test]
    fn the_cache_file_carries_a_type_count_and_an_end_marker_over_everything_before_it() {
        let text = full_cache_text();
        let types = Snapshot::bundled().type_count();
        assert!(text.lines().any(|l| l == format!("# types {types}")));
        let last = text.lines().last().unwrap();
        assert_eq!(last.len(), "# end ".len() + 64);
        assert!(last.starts_with("# end "));
        assert!(text.ends_with('\n'));
        assert_eq!(cache_text_is_whole(&text), Ok(()));
    }

    /// Cut a cache file anywhere and it is refused, so the bundled data stays in use. Edit a mask,
    /// drop a line, add one, or seal a wrong count, and it is refused too.
    #[test]
    fn a_cache_file_that_was_cut_short_edited_or_extended_is_refused_whole() {
        let text = full_cache_text();
        let mut cuts: Vec<usize> = text
            .bytes()
            .enumerate()
            .filter(|(at, b)| *b == b'\n' && at + 1 < text.len())
            .map(|(at, _)| at + 1)
            .collect();
        let line_cuts = cuts.len();
        cuts.extend(text.len().saturating_sub(4096)..text.len());
        cuts.extend(0..400);
        for at in &cuts {
            assert!(
                cache_text_is_whole(&text[..*at]).is_err(),
                "a file cut at byte {at} of {} was accepted",
                text.len()
            );
        }
        println!(
            "cache cuts refused: {} ({line_cuts} at line ends)",
            cuts.len()
        );
        let data_line = text.lines().position(|l| l.starts_with("AWS::")).unwrap();
        let edit = |change: &dyn Fn(&mut Vec<String>)| {
            let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
            change(&mut lines);
            let mut edited = lines.join("\n");
            edited.push('\n');
            edited
        };
        let flipped = edit(&|lines| {
            let line = &mut lines[data_line];
            let last = line.pop().unwrap();
            line.push(if last == 'f' { 'e' } else { 'f' });
        });
        let dropped = edit(&|lines| {
            lines.remove(data_line);
        });
        let extra_before = edit(&|lines| lines.insert(data_line, "AWS::Made::Up 1".to_string()));
        let extra_after = format!("{text}AWS::Made::Up 1\n");
        let doubled = format!("{text}{}", text.lines().last().unwrap().to_string() + "\n");
        for (case, edited) in [
            ("a mask digit changed", &flipped),
            ("a line dropped", &dropped),
            ("a line added", &extra_before),
            ("a line after the end marker", &extra_after),
            ("the end marker twice", &doubled),
        ] {
            assert!(cache_text_is_whole(edited).is_err(), "{case}");
        }
        // Sealed again by someone who recomputes the hash, a wrong count is still caught.
        let body = text.rsplit_once("# end ").unwrap().0;
        let miscounted = seal(&body.replace(
            &format!("# types {}", Snapshot::bundled().type_count()),
            &format!("# types {}", Snapshot::bundled().type_count() + 1),
        ));
        assert!(cache_text_is_whole(&miscounted)
            .unwrap_err()
            .contains("declared"));
        assert!(cache_text_is_whole(&seal(&body.replace("# types", "# kinds"))).is_err());
        // An end marker glued onto the last data line is not on a line of its own.
        let glued_body = body.trim_end_matches('\n');
        let glued = format!("{glued_body}# end {}\n", sha256_hex(glued_body.as_bytes()));
        assert!(cache_text_is_whole(&glued)
            .unwrap_err()
            .contains("line of its own"));
    }

    /// The same, through the file loader and `choose`: a cut cache never beats the bundled data.
    #[test]
    fn a_cut_cache_file_is_ignored_and_the_bundled_snapshot_stays_in_use() {
        let text = full_cache_text();
        let dir = temp_dir("cut");
        let path = dir.join(CACHE_FILE);
        std::fs::write(&path, &text).unwrap();
        let whole = load_cache_file(&path).expect("the whole file loads");
        assert_eq!(whole.type_count(), Snapshot::bundled().type_count());
        for at in [
            0,
            10,
            text.len() / 3,
            text.len() / 2,
            text.len() - 80,
            text.len() - 1,
        ] {
            std::fs::write(&path, &text.as_bytes()[..at]).unwrap();
            let loaded = load_cache_file(&path);
            assert!(loaded.is_none(), "cut at {at}");
            assert!(std::ptr::eq(
                choose(Snapshot::bundled(), loaded.as_ref()),
                Snapshot::bundled()
            ));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dates_are_read_as_instants_and_only_in_the_dataset_format() {
        for ok in [
            "2026-11-17T00:03:09.441208+00:00",
            "2026-11-17T00:03:09+00:00",
            "2026-11-17T00:03:09Z",
            "2026-11-17T00:03:09.1Z",
            "2026-11-17T00:03:09.123456789Z",
            "2024-02-29T00:00:00Z",
        ] {
            assert!(parse_stamp(ok).is_some(), "{ok}");
        }
        for bad in [
            "",
            "2026-11-19xxxxxxxx",
            "2026-11-19T00:00:00+00:00xx",
            "2026-11-17T01:00:00+14:00",
            "2026-11-17T00:03:09-05:00",
            "2026-02-30T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-11-00T00:00:00Z",
            "2026-11-19T24:00:00Z",
            "2026-11-19T00:60:00Z",
            "2026-11-19T00:00:60Z",
            "2026-11-19 00:00:00Z",
            "2026-11-19T00:00:00.Z",
            "2026-11-19T00:00:00.1234567890Z",
            "+026-11-19T00:00:00Z",
            "2026-1-19T00:00:00Z\u{0}",
            "２０２６-11-19T00:00:00Z",
        ] {
            assert!(parse_stamp(bad).is_none(), "{bad:?}");
        }
        let at = |s: &str| parse_stamp(s).unwrap();
        assert_eq!(at("2026-11-17T00:03:09Z"), at("2026-11-17T00:03:09+00:00"));
        let ordered = [
            "2026-11-17T00:03:09.441208+00:00",
            "2026-11-17T00:03:09.5Z",
            "2026-11-17T00:03:10Z",
            "2026-11-18T00:00:00Z",
            "2027-01-01T00:00:00Z",
        ];
        for pair in ordered.windows(2) {
            assert!(at(pair[0]) < at(pair[1]), "{pair:?}");
        }
        assert_eq!(at("1970-01-01T00:00:00Z"), (0, 0));
    }

    /// A dataset dated more than a day ahead of the clock is refused, and does not block a later
    /// real one.
    #[test]
    fn a_dataset_dated_in_the_future_is_refused_and_blocks_nothing() {
        let (regions, cfn) = (regions_file(), cfn_file());
        let convert = |stamp: &str| convert_cfn("v1", stamp, &regions, &cfn, now());
        assert!(
            convert(&after_bundled(2 * DAY + 28 * HOUR)).is_ok(),
            "23 hours ahead"
        );
        for far in [
            after_bundled(2 * DAY + 30 * HOUR),
            after_bundled(400 * DAY),
            "2999-01-01T00:00:00+00:00".to_string(),
        ] {
            let Err(RefreshError::Data(why)) = convert(&far) else {
                panic!("{far} was accepted");
            };
            assert!(why.contains("future"), "{why}");
        }
        let dir = temp_dir("future");
        let fetcher = Recording::new(dataset("2999-01-01T00:00:00+00:00"));
        assert!(refresh_small(&fetcher, &dir, now()).is_err());
        assert!(!dir.join(CACHE_FILE).exists());
        let real = Recording::new(dataset(&day_after()));
        assert!(refresh_small(&real, &dir, now()).unwrap().written);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An odd date, the same instant spelled another way, or one that is not later never wins.
    #[test]
    fn the_cache_wins_only_by_a_real_later_instant() {
        let at = |stamp: &str| {
            Snapshot::parse(&format!(
                "# last_updated {stamp}\n# regions us-east-1\nAWS::SQS::Queue 1\n"
            ))
            .unwrap()
        };
        let bundled = at("2026-11-17T00:03:09.441208+00:00");
        for (case, cached, wins) in [
            (
                "a microsecond later",
                "2026-11-17T00:03:09.441209+00:00",
                true,
            ),
            ("a day later, spelled Z", "2026-11-18T00:03:09Z", true),
            (
                "the same instant, spelled Z",
                "2026-11-17T00:03:09.441208Z",
                false,
            ),
            (
                "earlier but sorts later as text",
                "2026-11-17T01:00:00+14:00",
                false,
            ),
            ("text after a date", "2026-11-19xxxxxxxx", false),
            ("not a date", "yesterday", false),
        ] {
            let cached = at(cached);
            let chosen = choose(&bundled, Some(&cached));
            assert_eq!(std::ptr::eq(chosen, &cached), wins, "{case}");
        }
    }

    /// The cache `current()` reads is ignored when it is dated in the future.
    #[test]
    fn a_cache_dated_in_the_future_is_not_the_one_in_use() {
        let dir = temp_dir("in-use");
        let write = |stamp: &str| {
            let body = format!(
                "# source s3://{ACCESS_POINT_ALIAS}/public/v1/json/cfn_resources.json\n# last_updated {stamp}\n# regions us-east-1\n# types 1\nAWS::SQS::Queue 1\n"
            );
            std::fs::write(dir.join(CACHE_FILE), seal(&body)).unwrap();
        };
        write(&after_bundled(2 * DAY + 28 * HOUR));
        assert!(cache_in_use(&dir, now()).is_some(), "within a day");
        write(&after_bundled(2 * DAY + 30 * HOUR));
        assert!(cache_in_use(&dir, now()).is_none(), "more than a day ahead");
        write("2999-01-01T00:00:00+00:00");
        assert!(cache_in_use(&dir, now()).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A temp file is made with `O_EXCL`: an existing file, or a link planted at its name, is
    /// never opened or written through.
    #[cfg(unix)]
    #[test]
    fn a_new_file_is_never_opened_through_an_existing_path() {
        let dir = temp_dir("exclusive");
        let target = dir.join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_new(&link).is_err());
        assert!(open_new(&target).is_err());
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(dir.join("nowhere"), &dangling).unwrap();
        assert!(open_new(&dangling).is_err());
        assert!(!dir.join("nowhere").exists());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        assert!(open_new(&dir.join("fresh")).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn temp_names_are_unique_and_a_write_leaves_no_temp_file() {
        let dir = temp_dir("temps");
        let (first, _a) = create_temp(&dir).unwrap();
        let (second, _b) = create_temp(&dir).unwrap();
        assert_ne!(first, second);
        std::fs::remove_file(&first).unwrap();
        std::fs::remove_file(&second).unwrap();
        let path = dir.join(CACHE_FILE);
        assert_eq!(write_atomically(&path, b"one", &|| true), Ok(true));
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        // Not wanted at the last moment: the old file stays, no temp file is left.
        assert_eq!(write_atomically(&path, b"two", &|| false), Ok(false));
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        assert_eq!(names.len(), 1, "{names:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A pipe at the cache path is skipped, not waited on.
    #[cfg(unix)]
    #[test]
    fn a_pipe_at_the_cache_path_is_ignored_without_waiting() {
        let dir = temp_dir("pipe");
        let path = dir.join(CACHE_FILE);
        let made = std::process::Command::new("mkfifo").arg(&path).status();
        if !made.is_ok_and(|status| status.success()) {
            std::fs::remove_dir_all(&dir).unwrap();
            return;
        }
        let (sender, receiver) = std::sync::mpsc::channel();
        let looked = path.clone();
        std::thread::spawn(move || {
            let _ = sender.send(load_cache_file(&looked).is_none());
        });
        assert_eq!(
            receiver.recv_timeout(std::time::Duration::from_secs(5)),
            Ok(true)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Many threads refresh the same cache while another reads it. Every read is a whole cache or
    /// nothing, nothing is left behind, and the newest data ends up in the file.
    #[test]
    fn refreshes_from_many_threads_leave_one_whole_newest_cache() {
        use std::sync::atomic::AtomicBool;
        let dir = temp_dir("threads");
        let stamp = |n: u64| after_bundled(DAY + n as i64);
        let done = AtomicBool::new(false);
        let reads = AtomicU64::new(0);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(Ordering::Relaxed) {
                    if let Some(cache) = load_cache_file(&dir.join(CACHE_FILE)) {
                        assert_eq!(cache.type_count(), 3, "a partial cache was read");
                        reads.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
            let writers: Vec<_> = (0..8u64)
                .map(|thread| {
                    let dir = &dir;
                    let stamp = &stamp;
                    scope.spawn(move || {
                        for step in 0..15u64 {
                            let n = (thread * 15 + step) % 120;
                            let fetcher = Recording::new(dataset(&stamp(n)));
                            refresh_small(&fetcher, dir, now()).unwrap();
                        }
                    })
                })
                .collect();
            for writer in writers {
                writer.join().unwrap();
            }
            done.store(true, Ordering::Relaxed);
        });
        let last = load_cache_file(&dir.join(CACHE_FILE)).expect("a cache");
        assert_eq!(last.last_updated(), stamp(119), "the newest data won");
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        assert_eq!(names.len(), 1, "temp files left: {names:?}");
        println!(
            "threads: {} whole reads, 120 refreshes",
            reads.load(Ordering::Relaxed)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
