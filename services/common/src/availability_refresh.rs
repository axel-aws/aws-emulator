// SPDX-License-Identifier: CC0-1.0

//! Keeping the Regional availability data fresh while the emulator runs: once at start-up, in the
//! background, and again on a timer.
//!
//! The emulator program calls [`start`] once, after its logging is up. What happens, in order:
//!
//! 1. **Local data first, no network.** The cache files written by an earlier refresh are read and
//!    put in use if they are newer than the bundled data. Nothing waits for anything else.
//! 2. **A background thread** checks whether a refresh is due: no check in the last
//!    [`START_MIN_AGE`] (6 hours). If it is, the thread builds the AWS SDK's default credential chain. With
//!    credentials it reads the access point's small `index.json`; only when that names data newer
//!    than what is in use does it fetch the large files, convert them, write the caches and put
//!    the new data in use for the next request. Then it sleeps [`RECHECK_EVERY`] (12 hours) and
//!    looks again, for as long as the program runs.
//! 3. **Every failure is soft.** No credentials, no network, a proxy, a refused or slow reply,
//!    data that is partial, older or not understood: the data already in use stays in use, one
//!    `info` line says why (the first time only; later identical failures are `debug`), and the
//!    emulator carries on. Nothing here can make a request slower or fail, panic the program, or
//!    delay start-up: the work is on its own threads, each reply has a time limit, and the whole
//!    run has one ([`WHOLE_RUN_LIMIT`]).
//!
//! ## Switches
//!
//! - `EMULATOR_REGION_AVAILABILITY=off` turns every Regional availability check off, and the
//!   refresh with them: nothing is read from the cache and nothing is fetched.
//! - `EMULATOR_REGION_AVAILABILITY_REFRESH=off` turns off only the network refresh. The checks
//!   still run, on the bundled data or on a cache an earlier `refresh-region-data` wrote.
//!   `off`, `false`, `0`, `no`, `disable` and `disabled` mean off; `on`, `true`, `1`, `yes`,
//!   `enable`, `enabled`, empty or unset mean on. Any other text means off, and says so once: a
//!   switch that stops network traffic should not guess in favour of making it.
//!
//! ## No account, no network
//!
//! A user with no AWS account has no credentials, so step 2 stops at the credential chain and the
//! bundled data stays in use. The checks need neither an account nor a network. The refresh runs
//! only in the emulator program (`core/router`), never in embedded mode or in a test that builds
//! the router, so a test run makes no network call of its own.
//!
//! shortcut: a run that is cut off by [`WHOLE_RUN_LIMIT`] is abandoned, not stopped: its thread
//! ends when its current request times out (30 s at most). Upgrade when the fetcher can be
//! cancelled.
//! shortcut: with no cache folder (no `HOME`, no `XDG_CACHE_HOME`, no
//! `EMULATOR_REGION_AVAILABILITY_CACHE`) there is nowhere to keep a check time or a cache, so the
//! refresh does not run. Upgrade if an in-memory-only refresh is wanted.

use crate::availability_services::{
    self, load_service_cache, refresh_services, SERVICE_CACHE_FILE,
};
use crate::availability_source::{
    self, cache_dir, latest_stamp, load_cache_file, parse_stamp, read_capped, refresh,
    write_atomically, ObjectFetcher, RefreshError, CACHE_FILE,
};
use crate::region_availability::{Mode, Snapshot, MODE_ENV};
use region_gate::service_availability::{self, ServiceSnapshot};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The environment variable that turns off only the network refresh.
pub const REFRESH_ENV: &str = "EMULATOR_REGION_AVAILABILITY_REFRESH";
/// A refresh is not due when the last successful check is newer than this.
pub const START_MIN_AGE: Duration = Duration::from_secs(6 * 3_600);
/// How long the background thread sleeps between checks. The dataset is updated about daily.
pub const RECHECK_EVERY: Duration = Duration::from_secs(12 * 3_600);
/// The most one run (credentials, every read, conversion, writing) may take.
pub const WHOLE_RUN_LIMIT: Duration = Duration::from_secs(300);
/// The file in the cache folder that holds the time of the last successful check.
pub const CHECKED_FILE: &str = "last_checked";

/// Builds the fetcher for one run. An error is plain text and holds no secret.
pub type FetcherFactory = dyn Fn() -> Result<Box<dyn ObjectFetcher>, String> + Send + Sync;
/// The clock.
pub type Clock = dyn Fn() -> SystemTime + Send + Sync;

/// What the switches say.
#[derive(Debug, PartialEq, Eq)]
pub struct Switches {
    /// Whether the refresh may touch the network.
    pub refresh: bool,
    /// Whether the checks run at all.
    pub checks: bool,
    /// A line to log once: a value that was not understood.
    pub note: Option<String>,
}

/// Read the two switches from their raw values.
pub fn switches(mode: Option<&str>, refresh: Option<&str>) -> Switches {
    let checks = Mode::from_setting(mode, Mode::DEFAULT) != Mode::Off;
    let (refresh, note) = match refresh.map(|raw| raw.trim().to_ascii_lowercase()) {
        None => (true, None),
        Some(raw) => match raw.as_str() {
            "" | "on" | "true" | "1" | "yes" | "enable" | "enabled" => (true, None),
            "off" | "false" | "0" | "no" | "disable" | "disabled" => (false, None),
            other => (
                false,
                Some(format!(
                    "{REFRESH_ENV}={other:?} is not on or off, so the network refresh stays off"
                )),
            ),
        },
    };
    Switches {
        refresh: checks && refresh,
        checks,
        note,
    }
}

/// The data in use, and where a refresh puts newer data.
pub trait DataInUse: Send + Sync {
    fn cfn(&self) -> Arc<Snapshot>;
    fn put_cfn(&self, snapshot: Snapshot) -> bool;
    fn services(&self) -> Arc<ServiceSnapshot>;
    fn put_services(&self, table: ServiceSnapshot, now: SystemTime) -> bool;
}

/// The process-wide data the checks read.
pub struct Global;

impl DataInUse for Global {
    fn cfn(&self) -> Arc<Snapshot> {
        availability_source::current()
    }
    fn put_cfn(&self, snapshot: Snapshot) -> bool {
        availability_source::install(snapshot)
    }
    fn services(&self) -> Arc<ServiceSnapshot> {
        service_availability::current()
    }
    fn put_services(&self, table: ServiceSnapshot, now: SystemTime) -> bool {
        availability_services::install(table, now)
    }
}

/// When and where a refresh runs.
#[derive(Clone, Debug)]
pub struct Plan {
    pub cache_dir: Option<PathBuf>,
    pub min_age: Duration,
    pub every: Duration,
    pub run_limit: Duration,
}

impl Plan {
    /// The settings above, with the cache folder the environment names.
    pub fn from_environment() -> Plan {
        Plan {
            cache_dir: cache_dir(),
            min_age: START_MIN_AGE,
            every: RECHECK_EVERY,
            run_limit: WHOLE_RUN_LIMIT,
        }
    }
}

/// What one run found.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The last successful check is recent: nothing was read or sent.
    NotDue,
    /// There is no cache folder, so nothing can be kept.
    NoCacheFolder,
    /// The access point has nothing newer than what is in use.
    UpToDate,
    /// Newer data is now in use: what, in words.
    Changed(Vec<String>),
    /// The run did not finish: why, in words. The data in use is unchanged except for any part
    /// the text says was refreshed.
    Failed(String),
}

fn failure_text(error: &RefreshError) -> String {
    error.to_string()
}

fn due(dir: &Path, now: SystemTime, min_age: Duration) -> bool {
    let Ok(bytes) = read_capped(&dir.join(CHECKED_FILE), 64) else {
        return true;
    };
    let Some(then) = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
    else {
        return true;
    };
    let now = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    // A time in the future is a clock that moved: check again rather than wait for it.
    then > now || now - then >= min_age.as_secs()
}

fn record_check(dir: &Path, now: SystemTime) {
    let seconds = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let _ = write_atomically(
        &dir.join(CHECKED_FILE),
        format!("{seconds}\n").as_bytes(),
        &|| true,
    );
}

/// One run, on the calling thread, with no time limit of its own: see [`run_once`].
fn work(dir: &Path, factory: &FetcherFactory, clock: &Clock, data: &dyn DataInUse) -> Outcome {
    let now = clock();
    let fetcher = match factory() {
        Ok(fetcher) => fetcher,
        Err(why) => return Outcome::Failed(why),
    };
    let fetcher = fetcher.as_ref();
    let stamp = match latest_stamp(fetcher) {
        Ok(stamp) => stamp.as_deref().and_then(parse_stamp),
        Err(error) => return Outcome::Failed(failure_text(&error)),
    };
    // A date the index does not give is a reason to look, not to skip.
    let newer_than = |held: &str| match (stamp, parse_stamp(held)) {
        (Some(offered), Some(held)) => offered > held,
        _ => true,
    };
    let mut changed = Vec::new();
    let mut failures = Vec::new();

    let cfn = data.cfn();
    if newer_than(cfn.last_updated()) {
        match refresh(fetcher, dir, now) {
            Ok(_) => {
                if let Some(snapshot) = load_cache_file(&dir.join(CACHE_FILE)) {
                    let date = snapshot.data_date().to_string();
                    if data.put_cfn(snapshot) {
                        changed.push(format!("CloudFormation resource types of {date}"));
                    }
                }
            }
            Err(error) => failures.push(failure_text(&error)),
        }
    }
    let held = data.services();
    if newer_than(held.last_updated()) {
        match refresh_services(fetcher, dir, now, &held) {
            Ok((_, Some(table))) => {
                let date = table.data_date().to_string();
                if data.put_services(table, now) {
                    changed.push(format!("API services of {date}"));
                }
            }
            Ok((_, None)) => {}
            Err(error) => failures.push(failure_text(&error)),
        }
    }
    if failures.is_empty() {
        record_check(dir, now);
        if changed.is_empty() {
            Outcome::UpToDate
        } else {
            Outcome::Changed(changed)
        }
    } else if changed.is_empty() {
        Outcome::Failed(failures.join("; "))
    } else {
        Outcome::Failed(format!(
            "{}; the part that was fetched is in use: {}",
            failures.join("; "),
            changed.join(", ")
        ))
    }
}

/// Run a refresh now if one is due: on its own thread, so a panic or a hang cannot reach the
/// caller, and for at most `plan.run_limit`.
pub fn run_once(
    plan: &Plan,
    factory: &Arc<FetcherFactory>,
    clock: &Arc<Clock>,
    data: &Arc<dyn DataInUse>,
) -> Outcome {
    let Some(dir) = plan.cache_dir.clone() else {
        return Outcome::NoCacheFolder;
    };
    if !due(&dir, clock(), plan.min_age) {
        return Outcome::NotDue;
    }
    let (send, receive) = mpsc::channel();
    let (factory, clock, data) = (Arc::clone(factory), Arc::clone(clock), Arc::clone(data));
    let spawned = std::thread::Builder::new()
        .name("region-data-refresh-run".to_string())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                work(&dir, factory.as_ref(), clock.as_ref(), data.as_ref())
            }))
            .unwrap_or_else(|_| Outcome::Failed("the refresh stopped unexpectedly".to_string()));
            let _ = send.send(outcome);
        });
    if let Err(error) = spawned {
        return Outcome::Failed(format!("could not start a thread: {error}"));
    }
    match receive.recv_timeout(plan.run_limit) {
        Ok(outcome) => outcome,
        Err(_) => Outcome::Failed(format!(
            "no answer within {} s",
            plan.run_limit.as_secs().max(1)
        )),
    }
}

/// A running background refresh. Dropping it leaves the thread running; [`Handle::stop`] ends it.
pub struct Handle {
    signal: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Handle {
    /// Ask the thread to stop at its next wake and wait for it. A run in progress is waited for
    /// up to its own time limit.
    pub fn stop(mut self) {
        {
            let (stopped, wake) = &*self.signal;
            *stopped.lock().unwrap_or_else(|e| e.into_inner()) = true;
            wake.notify_all();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// What the thread has already said, so a failure that repeats is not said again.
struct Told {
    failed: bool,
}

fn in_use_words(data: &dyn DataInUse) -> String {
    let cfn = data.cfn();
    let services = data.services();
    format!(
        "CloudFormation resource types dated {}, API services dated {}",
        cfn.data_date(),
        services.data_date()
    )
}

fn report(outcome: &Outcome, told: &mut Told, data: &dyn DataInUse) {
    match outcome {
        Outcome::Changed(parts) => {
            told.failed = false;
            tracing::info!(
                "refreshed the AWS Regional availability data: {}",
                parts.join(", ")
            );
        }
        Outcome::Failed(why) if !told.failed => {
            told.failed = true;
            tracing::info!(
                "the AWS Regional availability data was not refreshed ({why}); using {}. \
                 The checks work without it. Set {REFRESH_ENV}=off to stop trying.",
                in_use_words(data)
            );
        }
        Outcome::Failed(why) => tracing::debug!("availability refresh failed again: {why}"),
        Outcome::NoCacheFolder if !told.failed => {
            told.failed = true;
            tracing::info!(
                "the AWS Regional availability data is not refreshed: there is no cache folder \
                 (set EMULATOR_REGION_AVAILABILITY_CACHE, XDG_CACHE_HOME or HOME); using {}",
                in_use_words(data)
            );
        }
        Outcome::NoCacheFolder => {}
        Outcome::UpToDate => {
            told.failed = false;
            tracing::debug!("the AWS Regional availability data is current");
        }
        Outcome::NotDue => {
            tracing::debug!("the AWS Regional availability data was checked recently")
        }
    }
}

/// Start the background refresh thread with the given parts. The thread runs a refresh at once
/// when one is due, then again every `plan.every`. Returns without waiting for anything.
pub fn spawn(
    plan: Plan,
    factory: Arc<FetcherFactory>,
    clock: Arc<Clock>,
    data: Arc<dyn DataInUse>,
) -> Option<Handle> {
    let signal = Arc::new((Mutex::new(false), Condvar::new()));
    let thread_signal = Arc::clone(&signal);
    let thread = std::thread::Builder::new()
        .name("region-data-refresh".to_string())
        .spawn(move || {
            let mut told = Told { failed: false };
            loop {
                let outcome = run_once(&plan, &factory, &clock, &data);
                report(&outcome, &mut told, data.as_ref());
                let (stopped, wake) = &*thread_signal;
                let guard = stopped.lock().unwrap_or_else(|e| e.into_inner());
                let (guard, _) = wake
                    .wait_timeout_while(guard, plan.every, |stopped| !*stopped)
                    .unwrap_or_else(|e| e.into_inner());
                if *guard {
                    return;
                }
            }
        })
        .ok()?;
    Some(Handle {
        signal,
        thread: Some(thread),
    })
}

/// Put the caches an earlier run wrote in use: a local read, no network, quick. The
/// CloudFormation data reads its own cache the first time a template is checked
/// ([`availability_source::current`]); this reads the service table's. Says in one line what is
/// in use when it is not the bundled data.
pub fn use_caches(dir: Option<&Path>, now: SystemTime, data: &dyn DataInUse) {
    let mut told = Vec::new();
    let cfn = data.cfn();
    if !std::ptr::eq(&*cfn, Snapshot::bundled()) {
        told.push(format!(
            "CloudFormation resource types dated {}",
            cfn.data_date()
        ));
    }
    let cached = dir.and_then(|dir| load_service_cache(&dir.join(SERVICE_CACHE_FILE)));
    if let Some(table) = cached {
        let date = table.data_date().to_string();
        if data.put_services(table, now) {
            told.push(format!("API services dated {date}"));
        }
    }
    if !told.is_empty() {
        tracing::info!(
            "using AWS Regional availability data refreshed earlier: {}",
            told.join(", ")
        );
    }
}

/// [`start`] with its parts handed in. Returns the handle of the background thread when one was
/// started: none when the checks are off, none when the refresh is off.
pub fn start_with(
    switches: &Switches,
    plan: Plan,
    factory: Arc<FetcherFactory>,
    clock: Arc<Clock>,
    data: Arc<dyn DataInUse>,
) -> Option<Handle> {
    if !switches.checks {
        return None;
    }
    if let Some(note) = &switches.note {
        tracing::info!("{note}");
    }
    use_caches(plan.cache_dir.as_deref(), clock(), data.as_ref());
    if !switches.refresh {
        return None;
    }
    spawn(plan, factory, clock, data)
}

/// What the emulator program calls once, after its logging is set up. Never blocks and never
/// fails: see the module notes. Returns the handle of the background thread when one was started.
pub fn start() -> Option<Handle> {
    let env = |name: &str| std::env::var(name).ok();
    let switches = switches(env(MODE_ENV).as_deref(), env(REFRESH_ENV).as_deref());
    let factory: Arc<FetcherFactory> = Arc::new(|| {
        crate::availability_fetch::sdk_fetcher(None)
            .map(|fetcher| Box::new(fetcher) as Box<dyn ObjectFetcher>)
    });
    start_with(
        &switches,
        Plan::from_environment(),
        factory,
        Arc::new(SystemTime::now),
        Arc::new(Global),
    )
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! A dataset laid out like the access point, built from the bundled snapshots, and the
    //! fetchers and data holders the tests share. No test here makes a network call.
    use super::*;
    use crate::availability_source::{
        self,
        tests::{after_bundled, bundled_as_json, dataset_with, json, now, temp_dir},
        DirFetcher, FetchError, ObjectRequest,
    };
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(crate) const DAY: i64 = 86_400;
    /// Dates after the bundled CloudFormation data, both clear of the service table's own date
    /// (a day and two minutes later) and of the test clock (two days and five hours later).
    pub(crate) const FIRST: i64 = DAY + 3_600;
    pub(crate) const SECOND: i64 = 2 * DAY;

    /// `apis.json` for the bundled service table. `newer` also offers MemoryDB in Bangkok.
    pub(crate) fn apis_json(newer: bool) -> Vec<u8> {
        let table = ServiceSnapshot::bundled();
        let mut by_sdk: BTreeMap<String, BTreeMap<String, &str>> = BTreeMap::new();
        for (shape_id, sdk_id) in table.rows() {
            let offered = by_sdk.entry(sdk_id.to_string()).or_default();
            for region in table.regions() {
                if table.service(region, shape_id) == crate::region_availability::Verdict::Available
                {
                    offered.insert(region.clone(), "Available");
                }
            }
        }
        if newer {
            by_sdk
                .get_mut("MemoryDB")
                .expect("MemoryDB is a bundled service")
                .insert("ap-southeast-7".to_string(), "Available");
        }
        json(serde_json::json!(by_sdk
            .iter()
            .map(|(sdk, offered)| serde_json::json!({
                "sdkServiceName": sdk,
                "apis": [{"apiName": "Op", "apiAction": "x:Op", "regionalAvailability": offered}],
            }))
            .collect::<Vec<_>>()))
    }

    /// `cfn_resources.json` for the bundled snapshot; `newer` also offers MemoryDB clusters in Bangkok.
    fn cfn_json(newer: bool) -> (Vec<u8>, Vec<u8>) {
        let (regions, cfn, _) = bundled_as_json();
        if !newer {
            return (regions, cfn);
        }
        let mut value: serde_json::Value = serde_json::from_slice(&cfn).unwrap();
        let mut hit = false;
        for service in value.as_array_mut().unwrap() {
            if service["serviceName"] == "MemoryDB" {
                for kind in service["resourceTypes"].as_array_mut().unwrap() {
                    if kind["resourceTypeName"] == "Cluster" {
                        kind["regionalAvailability"]["ap-southeast-7"] = "Available".into();
                        hit = true;
                    }
                }
            }
        }
        assert!(hit);
        (regions, json(value))
    }

    /// The whole dataset, dated `seconds` after the bundled data's date.
    pub(crate) fn dataset_after(seconds: i64, newer: bool) -> BTreeMap<String, Vec<u8>> {
        let (regions, cfn) = cfn_json(newer);
        let count = Snapshot::bundled().regions().len() as u64;
        let mut files = dataset_with(&after_bundled(seconds), count, regions, cfn);
        files.insert("public/v1/json/apis.json".to_string(), apis_json(newer));
        files
    }

    pub(crate) fn write_tree(root: &Path, files: &BTreeMap<String, Vec<u8>>) {
        for (key, bytes) in files {
            let path = root.join(key);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
    }

    /// A dataset on disk, and a fetcher over it that remembers every key it was asked for.
    pub(crate) struct Counting {
        pub(crate) inner: DirFetcher,
        pub(crate) keys: Arc<Mutex<Vec<String>>>,
    }

    impl ObjectFetcher for Counting {
        fn get(&self, request: &ObjectRequest, max: usize) -> Result<Vec<u8>, FetchError> {
            self.keys.lock().unwrap().push(request.key.clone());
            self.inner.get(request, max)
        }
    }

    /// Always fails the way the test says.
    pub(crate) struct Failing(pub(crate) fn() -> FetchError);

    impl ObjectFetcher for Failing {
        fn get(&self, _: &ObjectRequest, _: usize) -> Result<Vec<u8>, FetchError> {
            Err((self.0)())
        }
    }

    /// Answers after a delay, with a failure.
    pub(crate) struct Slow(pub(crate) Duration, pub(crate) Arc<AtomicUsize>);

    impl ObjectFetcher for Slow {
        fn get(&self, _: &ObjectRequest, _: usize) -> Result<Vec<u8>, FetchError> {
            self.1.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.0);
            Err(FetchError::Transport("slow".to_string()))
        }
    }

    /// The data in use, held in this test only.
    pub(crate) struct Local {
        cfn: Mutex<Arc<Snapshot>>,
        services: Mutex<Arc<ServiceSnapshot>>,
    }

    impl Local {
        pub(crate) fn new() -> Arc<Local> {
            Arc::new(Local {
                cfn: Mutex::new(Arc::clone(Snapshot::bundled_arc())),
                services: Mutex::new(Arc::clone(service_availability::bundled_arc())),
            })
        }
    }

    impl DataInUse for Local {
        fn cfn(&self) -> Arc<Snapshot> {
            Arc::clone(&self.cfn.lock().unwrap())
        }
        fn put_cfn(&self, snapshot: Snapshot) -> bool {
            let mut held = self.cfn.lock().unwrap();
            if !availability_source::wins(&snapshot, &held) {
                return false;
            }
            *held = Arc::new(snapshot);
            true
        }
        fn services(&self) -> Arc<ServiceSnapshot> {
            Arc::clone(&self.services.lock().unwrap())
        }
        fn put_services(&self, table: ServiceSnapshot, now: SystemTime) -> bool {
            let mut held = self.services.lock().unwrap();
            if !availability_services::wins(&table, &held, now) {
                return false;
            }
            *held = Arc::new(table);
            true
        }
    }

    pub(crate) fn plan(dir: &Path) -> Plan {
        Plan {
            cache_dir: Some(dir.join("cache")),
            min_age: START_MIN_AGE,
            every: RECHECK_EVERY,
            run_limit: Duration::from_secs(60),
        }
    }

    pub(crate) fn clock_at(seconds: i64) -> Arc<Clock> {
        let base = now();
        Arc::new(move || base + Duration::from_secs(seconds as u64))
    }

    pub(crate) fn dir_factory(root: &Path) -> Arc<FetcherFactory> {
        let root = root.to_path_buf();
        Arc::new(move || Ok(Box::new(DirFetcher::new(root.clone())) as Box<dyn ObjectFetcher>))
    }

    pub(crate) fn temp(name: &str) -> PathBuf {
        temp_dir(name)
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::availability_source::{tests::after_bundled, FetchError};
    use crate::region_availability::Verdict;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const MEMORYDB_CFN: &str = "AWS::MemoryDB::Cluster";
    const MEMORYDB: &str = "com.amazonaws.memorydb#AmazonMemoryDB";

    fn run(plan: &Plan, factory: &Arc<FetcherFactory>, seconds: i64, data: &Arc<Local>) -> Outcome {
        let data: Arc<dyn DataInUse> = data.clone();
        run_once(plan, factory, &clock_at(seconds), &data)
    }

    #[test]
    fn the_two_switches_mean_what_the_notes_say() {
        let s = |mode, refresh| switches(mode, refresh);
        assert_eq!(
            s(None, None),
            Switches {
                refresh: true,
                checks: true,
                note: None
            }
        );
        for on in ["on", "ON", " true ", "1", "yes", "enabled", ""] {
            assert!(s(None, Some(on)).refresh, "{on:?}");
        }
        for off in ["off", "Off", "false", "0", "no", "disabled"] {
            let got = s(None, Some(off));
            assert!(!got.refresh && got.checks && got.note.is_none(), "{off:?}");
        }
        // Text that is neither: off, and said so, because this switch stops network traffic.
        let odd = s(None, Some("sometimes"));
        assert!(!odd.refresh && odd.checks);
        assert!(odd.note.unwrap().contains("stays off"));
        // The mode switch turns everything off, the refresh with it.
        let all_off = s(Some("off"), None);
        assert!(!all_off.checks && !all_off.refresh);
        assert!(s(Some("warn"), None).refresh && s(Some("enforce"), None).refresh);
    }

    #[test]
    fn a_check_is_due_unless_a_recent_one_was_recorded() {
        let dir = temp("due");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let hours = |h: u64| Duration::from_secs(h * 3_600);
        assert!(due(&dir, now, hours(6)), "no file");
        let mark = |text: &str| std::fs::write(dir.join(CHECKED_FILE), text).unwrap();
        mark("not a number");
        assert!(due(&dir, now, hours(6)), "garbage");
        mark("1000001");
        assert!(due(&dir, now, hours(6)), "a time in the future");
        mark(&format!("{}", 1_000_000 - 3_600));
        assert!(!due(&dir, now, hours(6)), "an hour ago");
        mark(&format!("{}", 1_000_000 - 7 * 3_600));
        assert!(due(&dir, now, hours(6)), "seven hours ago");
    }

    #[test]
    fn a_good_refresh_puts_newer_data_in_use_for_both_tables_and_records_the_check() {
        let root = temp("good");
        write_tree(&root, &dataset_after(FIRST, true));
        let data = Local::new();
        let p = plan(&root);
        assert_eq!(
            data.cfn().cfn_resource_type("ap-southeast-7", MEMORYDB_CFN),
            Verdict::Unavailable
        );
        assert_eq!(
            data.services().service("ap-southeast-7", MEMORYDB),
            Verdict::Unavailable
        );

        let outcome = run(&p, &dir_factory(&root), 0, &data);
        let Outcome::Changed(parts) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(parts.len(), 2, "{parts:?}");

        assert_eq!(
            data.cfn().cfn_resource_type("ap-southeast-7", MEMORYDB_CFN),
            Verdict::Available
        );
        assert_eq!(
            data.services().service("ap-southeast-7", MEMORYDB),
            Verdict::Available
        );
        let cache = p.cache_dir.clone().unwrap();
        assert!(cache.join(CACHE_FILE).is_file());
        assert!(cache
            .join(availability_services::SERVICE_CACHE_FILE)
            .is_file());
        assert!(cache.join(CHECKED_FILE).is_file());
        // The refreshed table keeps the corrections for the services the data lists too narrowly.
        assert_eq!(
            data.services().service(
                "eu-west-1",
                "com.amazonaws.iotdataplane#IotMoonrakerService"
            ),
            Verdict::Available
        );
    }

    #[test]
    fn a_recent_check_sends_nothing_and_an_old_one_reads_only_the_index_when_nothing_is_newer() {
        let root = temp("quiet");
        write_tree(&root, &dataset_after(FIRST, true));
        let data = Local::new();
        let p = plan(&root);
        let factory = dir_factory(&root);
        assert!(matches!(run(&p, &factory, 0, &data), Outcome::Changed(_)));
        assert_eq!(run(&p, &factory, 3_600, &data), Outcome::NotDue);

        let keys = Arc::new(Mutex::new(Vec::new()));
        let counted: Arc<FetcherFactory> = {
            let (root, keys) = (root.clone(), Arc::clone(&keys));
            Arc::new(move || {
                Ok(Box::new(Counting {
                    inner: crate::availability_source::DirFetcher::new(root.clone()),
                    keys: Arc::clone(&keys),
                }) as Box<dyn ObjectFetcher>)
            })
        };
        assert_eq!(run(&p, &counted, 8 * 3_600, &data), Outcome::UpToDate);
        assert_eq!(
            *keys.lock().unwrap(),
            vec!["public/index.json".to_string()],
            "only the index"
        );
    }

    #[test]
    fn data_that_is_not_newer_changes_nothing() {
        let root = temp("same");
        write_tree(&root, &dataset_after(0, true));
        let data = Local::new();
        let outcome = run(&plan(&root), &dir_factory(&root), 0, &data);
        assert_eq!(outcome, Outcome::UpToDate);
        assert_eq!(
            data.cfn().cfn_resource_type("ap-southeast-7", MEMORYDB_CFN),
            Verdict::Unavailable
        );
    }

    #[test]
    fn no_credentials_leaves_the_data_and_the_check_time_alone() {
        let root = temp("nocreds");
        let data = Local::new();
        let p = plan(&root);
        let factory: Arc<FetcherFactory> =
            Arc::new(|| Err("no AWS credentials: the credential chain found none".to_string()));
        let outcome = run(&p, &factory, 0, &data);
        assert_eq!(
            outcome,
            Outcome::Failed("no AWS credentials: the credential chain found none".to_string())
        );
        assert!(std::ptr::eq(&*data.cfn(), Snapshot::bundled()));
        assert!(
            !p.cache_dir.unwrap().join(CHECKED_FILE).exists(),
            "the next start tries again"
        );
    }

    #[test]
    fn a_refused_read_an_offline_machine_and_a_proxy_are_failures_not_errors() {
        for (name, fail) in [
            (
                "denied",
                (|| FetchError::Denied("HTTP 403 AccessDenied".to_string())) as fn() -> FetchError,
            ),
            ("offline", || {
                FetchError::Transport("the request failed: dns error".to_string())
            }),
            ("proxy", || FetchError::Transport("HTTP 407".to_string())),
            ("missing", || FetchError::NotFound),
        ] {
            let root = temp(name);
            let data = Local::new();
            let factory: Arc<FetcherFactory> =
                Arc::new(move || Ok(Box::new(Failing(fail)) as Box<dyn ObjectFetcher>));
            let outcome = run(&plan(&root), &factory, 0, &data);
            assert!(matches!(outcome, Outcome::Failed(_)), "{name}: {outcome:?}");
            assert!(std::ptr::eq(&*data.cfn(), Snapshot::bundled()), "{name}");
            assert!(
                std::ptr::eq(
                    &*data.services(),
                    service_availability::bundled_arc().as_ref()
                ),
                "{name}"
            );
        }
    }

    /// The real fetcher stack (the signer and the transport are fakes, the rest is the code that
    /// ships): fake credentials that S3 answers with 403, and a machine that is offline.
    #[test]
    fn the_real_fetcher_stack_turns_a_403_and_a_dead_network_into_failures() {
        use crate::availability_fetch::{HttpReply, HttpTransport, SignedFetcher, Signer};
        struct Signs;
        impl Signer for Signs {
            fn sign(&self, request: &mut http::Request<()>, _: &str) -> Result<(), String> {
                request
                    .headers_mut()
                    .insert("authorization", "FAKE-SIGNATURE".parse().unwrap());
                Ok(())
            }
        }
        type Reply = Result<(u16, &'static str), &'static str>;
        struct Replies(Reply);
        impl HttpTransport for Replies {
            fn get(&self, _: &http::Request<()>, _: usize) -> Result<HttpReply, String> {
                match self.0 {
                    Ok((status, body)) => Ok(HttpReply {
                        status,
                        body: body.as_bytes().to_vec(),
                    }),
                    Err(why) => Err(why.to_string()),
                }
            }
        }
        let cases: [(&str, Reply, &str); 3] = [
            (
                "fake credentials",
                Ok((403, "<Error><Code>InvalidAccessKeyId</Code><Message>The AWS Access Key Id you provided does not exist</Message></Error>")),
                "could not fetch public/index.json",
            ),
            ("offline", Err("the request failed: dns error: no such host"), "the request failed"),
            ("a proxy", Ok((407, "")), "HTTP 407"),
        ];
        for (name, reply, expect) in cases {
            let root = temp(name);
            let data = Local::new();
            let factory: Arc<FetcherFactory> = Arc::new(move || {
                Ok(Box::new(SignedFetcher::new(Signs, Replies(reply))) as Box<dyn ObjectFetcher>)
            });
            let outcome = run(&plan(&root), &factory, 0, &data);
            let Outcome::Failed(why) = outcome else {
                panic!("{name}: {outcome:?}")
            };
            assert!(why.contains(expect), "{name}: {why}");
            assert!(!why.contains("FAKE-SIGNATURE"), "{name}: {why}");
            assert!(std::ptr::eq(&*data.cfn(), Snapshot::bundled()), "{name}");
        }
    }

    #[test]
    fn a_file_that_is_not_understood_leaves_what_was_in_use_and_the_good_part_is_kept() {
        let root = temp("badfile");
        let mut files = dataset_after(FIRST, true);
        files.insert(
            "public/v1/json/apis.json".to_string(),
            b"{\"not\": \"a list\"}".to_vec(),
        );
        write_tree(&root, &files);
        let data = Local::new();
        let p = plan(&root);
        let outcome = run(&p, &dir_factory(&root), 0, &data);
        let Outcome::Failed(why) = outcome else {
            panic!("{outcome:?}")
        };
        assert!(why.contains("apis.json"), "{why}");
        assert!(
            why.contains("in use: CloudFormation resource types"),
            "{why}"
        );
        assert_eq!(
            data.cfn().cfn_resource_type("ap-southeast-7", MEMORYDB_CFN),
            Verdict::Available
        );
        assert_eq!(
            data.services().service("ap-southeast-7", MEMORYDB),
            Verdict::Unavailable
        );
        let cache = p.cache_dir.unwrap();
        assert!(!cache
            .join(availability_services::SERVICE_CACHE_FILE)
            .exists());
        assert!(
            !cache.join(CHECKED_FILE).exists(),
            "a run with a failure is not a check"
        );
    }

    #[test]
    fn a_partial_service_file_is_refused() {
        let root = temp("partial");
        let mut files = dataset_after(FIRST, true);
        let full: Vec<serde_json::Value> = serde_json::from_slice(&apis_json(true)).unwrap();
        let few = serde_json::to_vec(&full[..full.len() / 5]).unwrap();
        files.insert("public/v1/json/apis.json".to_string(), few);
        write_tree(&root, &files);
        let data = Local::new();
        let outcome = run(&plan(&root), &dir_factory(&root), 0, &data);
        let Outcome::Failed(why) = outcome else {
            panic!("{outcome:?}")
        };
        assert!(why.contains("expected at least"), "{why}");
        assert_eq!(
            data.services().last_updated(),
            ServiceSnapshot::bundled().last_updated()
        );
    }

    #[test]
    fn a_slow_endpoint_does_not_hold_up_the_caller() {
        let root = temp("slow");
        let asked = Arc::new(AtomicUsize::new(0));
        let factory: Arc<FetcherFactory> = {
            let asked = Arc::clone(&asked);
            Arc::new(move || {
                Ok(
                    Box::new(Slow(Duration::from_millis(1500), Arc::clone(&asked)))
                        as Box<dyn ObjectFetcher>,
                )
            })
        };
        let data = Local::new();
        let started = std::time::Instant::now();
        let handle = spawn(
            plan(&root),
            factory,
            clock_at(0),
            data.clone() as Arc<dyn DataInUse>,
        )
        .expect("the thread starts");
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "start-up waited for the endpoint"
        );
        assert!(std::ptr::eq(&*data.cfn(), Snapshot::bundled()));
        handle.stop();
        assert!(asked.load(Ordering::SeqCst) >= 1, "the endpoint was asked");
    }

    #[test]
    fn a_run_is_cut_off_at_its_time_limit() {
        let root = temp("limit");
        let asked = Arc::new(AtomicUsize::new(0));
        let factory: Arc<FetcherFactory> = {
            let asked = Arc::clone(&asked);
            Arc::new(move || {
                Ok(
                    Box::new(Slow(Duration::from_millis(1500), Arc::clone(&asked)))
                        as Box<dyn ObjectFetcher>,
                )
            })
        };
        let mut p = plan(&root);
        p.run_limit = Duration::from_millis(150);
        let started = std::time::Instant::now();
        let outcome = run(&p, &factory, 0, &Local::new());
        assert!(
            started.elapsed() < Duration::from_millis(1200),
            "waited for the slow endpoint"
        );
        let Outcome::Failed(why) = outcome else {
            panic!("{outcome:?}")
        };
        assert!(why.starts_with("no answer within"), "{why}");
    }

    #[test]
    fn a_panic_inside_a_run_is_a_failure() {
        let root = temp("panic");
        let factory: Arc<FetcherFactory> =
            Arc::new(|| -> Result<Box<dyn ObjectFetcher>, String> {
                panic!("a bug in a credential helper")
            });
        let outcome = run(&plan(&root), &factory, 0, &Local::new());
        assert_eq!(
            outcome,
            Outcome::Failed("the refresh stopped unexpectedly".to_string())
        );
    }

    #[test]
    fn no_cache_folder_means_no_refresh() {
        let mut p = plan(&temp("nofolder"));
        p.cache_dir = None;
        assert_eq!(
            run(&p, &dir_factory(&temp("unused")), 0, &Local::new()),
            Outcome::NoCacheFolder
        );
    }

    /// The timer: the thread looks again after `every`, and picks up data that appeared since.
    #[test]
    fn the_timer_picks_up_data_published_after_start() {
        let root = temp("timer");
        write_tree(&root, &dataset_after(FIRST, false));
        let data = Local::new();
        let mut p = plan(&root);
        p.min_age = Duration::from_secs(0);
        p.every = Duration::from_millis(50);
        let handle = spawn(
            p,
            dir_factory(&root),
            clock_at(0),
            data.clone() as Arc<dyn DataInUse>,
        )
        .unwrap();
        let wait_for = |what: &dyn Fn() -> bool| {
            let until = std::time::Instant::now() + Duration::from_secs(20);
            while !what() {
                assert!(
                    std::time::Instant::now() < until,
                    "the timer did not get there"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        let first = after_bundled(FIRST);
        wait_for(&|| data.cfn().last_updated() == first);
        assert_eq!(
            data.cfn().cfn_resource_type("ap-southeast-7", MEMORYDB_CFN),
            Verdict::Unavailable
        );
        // A day later the access point has newer data.
        write_tree(&root, &dataset_after(SECOND, true));
        let second = after_bundled(SECOND);
        wait_for(&|| {
            data.cfn().last_updated() == second && data.services().last_updated() == second
        });
        assert_eq!(
            data.cfn().cfn_resource_type("ap-southeast-7", MEMORYDB_CFN),
            Verdict::Available
        );
        assert_eq!(
            data.services().service("ap-southeast-7", MEMORYDB),
            Verdict::Available
        );
        handle.stop();
    }

    /// The data in use as the program holds it: the service table in its process-wide slot (the one
    /// the router reads) and the CloudFormation data in a `Local`, because the CloudFormation slot
    /// reads the process environment at its first use and another test owns that.
    struct Mixed(Arc<Local>);

    impl DataInUse for Mixed {
        fn cfn(&self) -> Arc<Snapshot> {
            self.0.cfn()
        }
        fn put_cfn(&self, snapshot: Snapshot) -> bool {
            self.0.put_cfn(snapshot)
        }
        fn services(&self) -> Arc<ServiceSnapshot> {
            Global.services()
        }
        fn put_services(&self, table: ServiceSnapshot, now: SystemTime) -> bool {
            Global.put_services(table, now)
        }
    }

    /// The real service slot, once: a cache an earlier run wrote is put in use at start, and a
    /// refresh replaces the table the router reads. Only this test touches the process-wide table.
    #[test]
    fn the_real_service_slot_takes_cached_and_refreshed_data() {
        let root = temp("slots");
        write_tree(&root, &dataset_after(FIRST, true));
        let p = plan(&root);
        let cache = p.cache_dir.clone().unwrap();
        // An earlier run: refresh into the cache, with holders that are not the real slot.
        assert!(matches!(
            run(&p, &dir_factory(&root), 0, &Local::new()),
            Outcome::Changed(_)
        ));
        assert_eq!(
            service_availability::current().service("ap-southeast-7", MEMORYDB),
            Verdict::Unavailable,
            "nothing is installed yet"
        );
        // A fresh start: the cache is read, and the router's table holds the newer data.
        let program = Mixed(Local::new());
        use_caches(Some(&cache), now_for_slots(), &program);
        assert_eq!(
            service_availability::current().service("ap-southeast-7", MEMORYDB),
            Verdict::Available
        );
        // And a refresh into the real slot, from data newer still.
        write_tree(&root, &dataset_after(SECOND, true));
        let data: Arc<dyn DataInUse> = Arc::new(Mixed(Local::new()));
        let outcome = run_once(
            &p_with_min_age_zero(&p),
            &dir_factory(&root),
            &clock_at(0),
            &data,
        );
        assert!(matches!(outcome, Outcome::Changed(_)), "{outcome:?}");
        assert_eq!(
            service_availability::current().last_updated(),
            after_bundled(SECOND)
        );
    }

    fn now_for_slots() -> SystemTime {
        crate::availability_source::tests::now()
    }

    fn p_with_min_age_zero(plan: &Plan) -> Plan {
        Plan {
            min_age: Duration::from_secs(0),
            ..plan.clone()
        }
    }

    /// A small subscriber that keeps the message of every INFO event, for the log tests.
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
                if *event.metadata().level() == Level::INFO {
                    let mut message = Message(String::new());
                    event.record(&mut message);
                    self.0.lock().unwrap().push(message.0);
                }
            }
            fn enter(&self, _: &Id) {}
            fn exit(&self, _: &Id) {}
        }

        pub fn infos<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
            let kept = Arc::new(Mutex::new(Vec::new()));
            let result = tracing::subscriber::with_default(Keep(Arc::clone(&kept)), f);
            let lines = kept.lock().unwrap().clone();
            (result, lines)
        }
    }

    /// Only the CloudFormation data is newer than what is in use here: the service table, dated
    /// later than the CloudFormation snapshot, is not fetched and not written.
    #[test]
    fn a_table_that_is_not_newer_is_left_alone_when_only_the_other_one_is() {
        let root = temp("one-newer");
        let between = DAY - 3_600;
        write_tree(&root, &dataset_after(between, true));
        let data = Local::new();
        let p = plan(&root);
        let outcome = run(&p, &dir_factory(&root), 0, &data);
        let Outcome::Changed(parts) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(parts.len(), 1, "{parts:?}");
        assert!(
            parts[0].starts_with("CloudFormation resource types"),
            "{parts:?}"
        );
        assert_eq!(
            data.services().last_updated(),
            ServiceSnapshot::bundled().last_updated()
        );
        let cache = p.cache_dir.unwrap();
        assert!(!cache
            .join(availability_services::SERVICE_CACHE_FILE)
            .exists());
        assert!(
            cache.join(CHECKED_FILE).is_file(),
            "the run itself went well"
        );
    }

    /// A failure is said once at `info` and, while it keeps failing the same way, no more; a
    /// success is said, and the next failure is said again.
    #[test]
    fn a_failure_that_repeats_is_told_once() {
        let data = Local::new();
        let fail = || Outcome::Failed("no AWS credentials: none found".to_string());
        let ((), lines) = capture::infos(|| {
            let mut told = Told { failed: false };
            for _ in 0..3 {
                report(&fail(), &mut told, data.as_ref());
            }
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("was not refreshed (no AWS credentials: none found)"),
            "{lines:?}"
        );
        assert!(
            lines[0].contains("using CloudFormation resource types dated 2026-11-17"),
            "{lines:?}"
        );
        assert!(
            lines[0].contains(&format!("{REFRESH_ENV}=off")),
            "{lines:?}"
        );
        let ((), lines) = capture::infos(|| {
            let mut told = Told { failed: false };
            report(&fail(), &mut told, data.as_ref());
            report(
                &Outcome::Changed(vec!["API services of 2026-11-20".into()]),
                &mut told,
                data.as_ref(),
            );
            report(&fail(), &mut told, data.as_ref());
            report(&Outcome::UpToDate, &mut told, data.as_ref());
            report(&Outcome::NotDue, &mut told, data.as_ref());
        });
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[1].starts_with("refreshed the AWS Regional availability data: API services"));
    }

    #[test]
    fn with_the_refresh_off_the_cache_is_still_used_and_no_thread_starts() {
        let root = temp("off");
        write_tree(&root, &dataset_after(FIRST, true));
        let data = Local::new();
        assert!(matches!(
            run(&plan(&root), &dir_factory(&root), 0, &data),
            Outcome::Changed(_)
        ));
        let fresh = Local::new();
        let factory: Arc<FetcherFactory> =
            Arc::new(|| -> Result<Box<dyn ObjectFetcher>, String> {
                panic!("the factory must not be called when the refresh is off")
            });
        let started = start_with(
            &switches(None, Some("off")),
            plan(&root),
            factory.clone(),
            clock_at(0),
            fresh.clone() as Arc<dyn DataInUse>,
        );
        assert!(started.is_none());
        assert_eq!(
            fresh.services().service("ap-southeast-7", MEMORYDB),
            Verdict::Available
        );
        // And with every check off, nothing is read at all.
        let none = Local::new();
        let started = start_with(
            &switches(Some("off"), None),
            plan(&root),
            factory,
            clock_at(0),
            none.clone() as Arc<dyn DataInUse>,
        );
        assert!(started.is_none());
        assert_eq!(
            none.services().service("ap-southeast-7", MEMORYDB),
            Verdict::Unavailable
        );
    }
}
