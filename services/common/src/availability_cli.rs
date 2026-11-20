// SPDX-License-Identifier: CC0-1.0

//! The `refresh-region-data` command: fetch newer Regional availability data with the user's own
//! AWS credentials and say which data is in use.
//!
//! **Nothing here runs unless a user asks.** The emulator never refreshes at start-up and never
//! on a request; `availability_source::current()` has no fetcher to call. The command is the one
//! way to refresh, and it is a separate program, `refresh-region-data`, built from this crate
//! (`cargo run -p service-common --bin refresh-region-data`). Adding it to the emulator's own
//! command line is one call to [`main`], in code the maintainers own.
//!
//! The command does what the earlier changes built: it signs the reads with the SDK's default
//! credential chain ([`crate::availability_fetch::sdk_fetcher`]) and writes the cache through the
//! sealed writer ([`crate::availability_source::refresh`]). A failure of any kind leaves the
//! cache as it was, so the data in use stays what it was.
//!
//! shortcut: it refreshes the CloudFormation resource types only. The API service table that the
//! request router's check reads is bundled and is not refreshed (the dataset's `apis.json` is
//! about forty times larger and needs a converter of its own); upgrade when that converter
//! exists.

use crate::availability_fetch::sdk_fetcher;
use crate::availability_source::{
    cache_dir, choose, current_cache_status, refresh, CacheStatus, ObjectFetcher, CACHE_FILE,
};
use crate::region_availability::{age_days, Mode, Snapshot, MODE_ENV};
use crate::service_availability::ServiceSnapshot;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

const USAGE: &str = "\
Usage: refresh-region-data [--profile NAME] [--status]

Fetches AWS's Regional availability data through its S3 access point, signed with your own
AWS credentials (the AWS SDK's default credential chain), and keeps it in a cache file the
emulator reads next time it starts. Nothing is fetched unless you run this.

  --profile NAME   read credentials from this AWS profile
                   (or set EMULATOR_REGION_AVAILABILITY_PROFILE)
  --status         only say which data is in use; make no request
  --help           this text

The cache folder is EMULATOR_REGION_AVAILABILITY_CACHE, else $XDG_CACHE_HOME/aws-emulator/
region-availability, else ~/.cache/aws-emulator/region-availability. Nothing is written to ~/.aws.

With no credentials the emulator keeps using the data bundled with it.
";

/// Gives the fetcher for a profile, or says why there is none. A real run signs with the AWS
/// credential chain; a test hands in one that makes no network call.
pub type FetcherFactory<'a> = &'a dyn Fn(Option<&str>) -> Result<Box<dyn ObjectFetcher>, String>;

/// What the command was asked to do.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    Help,
    Status,
    Refresh { profile: Option<String> },
}

fn parse(args: &[String]) -> Result<Request, String> {
    let mut profile = None;
    let mut status = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(Request::Help),
            "--status" => status = true,
            "--profile" => match iter.next() {
                Some(name) if !name.is_empty() && !name.starts_with('-') => {
                    profile = Some(name.clone())
                }
                _ => return Err("--profile needs a profile name".to_string()),
            },
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(match (status, profile) {
        (true, None) => Request::Status,
        (true, Some(_)) => {
            return Err("--status makes no request, so --profile has no use".to_string())
        }
        (false, profile) => Request::Refresh { profile },
    })
}

/// Run the command with `args` (without the program name), writing what it says to `out`.
/// Returns the exit code: 0 done, 1 the refresh failed (the data in use is unchanged), 2 the
/// arguments were not understood.
pub fn run(
    args: &[String],
    out: &mut dyn Write,
    fetcher_for: FetcherFactory<'_>,
    cache_folder: Option<&Path>,
    now: SystemTime,
) -> i32 {
    let request = match parse(args) {
        Ok(request) => request,
        Err(why) => {
            let _ = write!(out, "refresh-region-data: {why}\n\n{USAGE}");
            return 2;
        }
    };
    match request {
        Request::Help => {
            let _ = write!(out, "{USAGE}");
            0
        }
        Request::Status => {
            let _ = write!(out, "{}", status_text(cache_folder, now));
            0
        }
        Request::Refresh { profile } => {
            let Some(folder) = cache_folder else {
                let _ = writeln!(
                    out,
                    "Could not refresh: there is no cache folder. Set EMULATOR_REGION_AVAILABILITY_CACHE \
                     to one, or set XDG_CACHE_HOME or HOME. The bundled data stays in use."
                );
                return 1;
            };
            let fetcher = match fetcher_for(profile.as_deref()) {
                Ok(fetcher) => fetcher,
                Err(why) => {
                    let _ = writeln!(
                        out,
                        "Could not refresh: {why}. The bundled data stays in use."
                    );
                    return 1;
                }
            };
            match refresh(fetcher.as_ref(), folder, now) {
                Ok(done) if done.written => {
                    let _ = writeln!(
                        out,
                        "Refreshed: data dated {}, {} resource types, {} Regions, written to {}.",
                        done.last_updated,
                        done.types,
                        done.regions,
                        folder.join(CACHE_FILE).display()
                    );
                }
                Ok(done) => {
                    let _ = writeln!(
                        out,
                        "Nothing to do: the cache already holds this data (dated {}) or newer.",
                        done.last_updated
                    );
                }
                Err(why) => {
                    let _ = writeln!(
                        out,
                        "Could not refresh: {why}. The data in use is unchanged."
                    );
                    return 1;
                }
            }
            let _ = write!(out, "{}", status_text(cache_folder, now));
            0
        }
    }
}

/// The command as a program's `main` runs it: the SDK credential chain, the real clock and the
/// cache folder the environment names. Returns the exit code.
pub fn main(args: &[String]) -> i32 {
    let factory = |profile: Option<&str>| -> Result<Box<dyn ObjectFetcher>, String> {
        sdk_fetcher(profile).map(|fetcher| Box::new(fetcher) as Box<dyn ObjectFetcher>)
    };
    run(
        args,
        &mut std::io::stdout(),
        &factory,
        cache_dir().as_deref(),
        SystemTime::now(),
    )
}

/// How old a dataset is, in words.
fn age_in_words(last_updated: &str, now: SystemTime) -> String {
    match age_days(last_updated, now) {
        Some(0) => "today".to_string(),
        Some(1) => "1 day old".to_string(),
        Some(days) if days > 1 => format!("{days} days old"),
        Some(_) => "dated in the future".to_string(),
        None => "age unknown".to_string(),
    }
}

/// Which Regional availability data is in use: the CloudFormation types (the cache or the bundled
/// snapshot, with its date and age and the reason a cache is not used), the API service table (always
/// bundled), and the mode the checks run in.
pub fn status_text(cache_folder: Option<&Path>, now: SystemTime) -> String {
    let bundled = Snapshot::bundled();
    let services = ServiceSnapshot::bundled();
    let mut text = String::from("Regional availability data in use:\n");
    let (status, cache) = current_cache_status(cache_folder, now);
    let chosen = choose(bundled, cache.as_ref());
    let (what, snapshot) = if std::ptr::eq(chosen, bundled) {
        ("the bundled snapshot", bundled)
    } else {
        ("the refreshed cache", chosen)
    };
    text.push_str(&format!(
        "  CloudFormation resource types: {what}, dated {} ({})\n",
        snapshot.last_updated(),
        age_in_words(snapshot.last_updated(), now)
    ));
    text.push_str(&format!(
        "    bundled snapshot: dated {} ({})\n",
        bundled.last_updated(),
        age_in_words(bundled.last_updated(), now)
    ));
    let cache_line = match (&status, cache_folder) {
        (CacheStatus::NoFolder, _) | (_, None) => "no cache folder is set".to_string(),
        (CacheStatus::Missing, Some(folder)) => format!("no cache file in {}", folder.display()),
        (CacheStatus::Unusable, Some(folder)) => format!(
            "{} cannot be used (cut, edited, from another source or not a regular file), so it is ignored",
            folder.join(CACHE_FILE).display()
        ),
        (CacheStatus::Ignored(why), Some(folder)) => {
            format!("{} is ignored: {why}", folder.join(CACHE_FILE).display())
        }
        (CacheStatus::InUse, Some(folder)) => format!("{} is in use", folder.join(CACHE_FILE).display()),
    };
    text.push_str(&format!("    cache: {cache_line}\n"));
    text.push_str(&format!(
        "  API services: the bundled snapshot, dated {} ({}); this command does not refresh it\n",
        services.last_updated(),
        age_in_words(services.last_updated(), now)
    ));
    let name = |mode: Mode| match mode {
        Mode::Off => "off",
        Mode::Warn => "warn",
        Mode::Enforce => "enforce",
    };
    text.push_str(&format!(
        "  Checks ({MODE_ENV}): CloudFormation templates {}, API requests {}.\n",
        name(Mode::from_env()),
        name(Mode::from_env_or(Mode::ROUTER_DEFAULT)),
    ));
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::availability_fetch::{HttpReply, HttpTransport, SignedFetcher, Signer};
    use crate::availability_source::{
        convert_cfn, load_cache_file,
        tests::{after_bundled, bundled_as_json, dataset, dataset_with, now, temp_dir},
        ACCESS_POINT_ALIAS,
    };
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    const DAY: i64 = 86_400;

    /// What the fake chain saw: how many requests it signed, the hosts the transport was sent
    /// to, and the profile the credential chain was asked for.
    #[derive(Default)]
    struct Seen {
        signed: usize,
        hosts: Vec<String>,
        paths: Vec<String>,
        profile: Vec<Option<String>>,
    }

    struct FakeSigner(Rc<RefCell<Seen>>);

    impl Signer for FakeSigner {
        fn sign(&self, request: &mut http::Request<()>, _region: &str) -> Result<(), String> {
            self.0.borrow_mut().signed += 1;
            request
                .headers_mut()
                .insert("authorization", "FAKE-SIGNATURE".parse().unwrap());
            Ok(())
        }
    }

    struct FakeTransport {
        files: BTreeMap<String, Vec<u8>>,
        error: Option<(u16, String)>,
        seen: Rc<RefCell<Seen>>,
    }

    impl HttpTransport for FakeTransport {
        fn get(&self, request: &http::Request<()>, _max: usize) -> Result<HttpReply, String> {
            let mut seen = self.seen.borrow_mut();
            seen.hosts
                .push(request.uri().host().unwrap_or("").to_string());
            seen.paths.push(request.uri().path().to_string());
            if let Some((status, body)) = &self.error {
                return Ok(HttpReply {
                    status: *status,
                    body: body.clone().into_bytes(),
                });
            }
            let key = request.uri().path().trim_start_matches('/').to_string();
            Ok(match self.files.get(&key) {
                Some(bytes) => HttpReply {
                    status: 200,
                    body: bytes.clone(),
                },
                None => HttpReply {
                    status: 404,
                    body: b"<Error><Code>NoSuchKey</Code></Error>".to_vec(),
                },
            })
        }
    }

    /// A full-size dataset dated `seconds` after the bundled snapshot.
    fn full_dataset(seconds: i64) -> BTreeMap<String, Vec<u8>> {
        let (regions, cfn, _) = bundled_as_json();
        dataset_with(&after_bundled(seconds), 37, regions, cfn)
    }

    /// A factory whose fetcher signs with a fake signer and reads from `files`, or answers every
    /// read with `error`. Nothing leaves the process.
    fn chain<'a>(
        seen: &'a Rc<RefCell<Seen>>,
        files: BTreeMap<String, Vec<u8>>,
        error: Option<(u16, String)>,
    ) -> impl Fn(Option<&str>) -> Result<Box<dyn ObjectFetcher>, String> + 'a {
        move |profile| {
            seen.borrow_mut().profile.push(profile.map(str::to_string));
            Ok(Box::new(SignedFetcher::new(
                FakeSigner(Rc::clone(seen)),
                FakeTransport {
                    files: files.clone(),
                    error: error.clone(),
                    seen: Rc::clone(seen),
                },
            )))
        }
    }

    fn never(_: Option<&str>) -> Result<Box<dyn ObjectFetcher>, String> {
        panic!("this command must not look for credentials");
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    fn run_with(
        args: &[&str],
        factory: FetcherFactory<'_>,
        folder: Option<&Path>,
    ) -> (i32, String) {
        let mut out = Vec::new();
        let code = run(&strings(args), &mut out, factory, folder, now());
        (code, String::from_utf8(out).unwrap())
    }

    #[test]
    fn status_alone_makes_no_request_and_names_the_bundled_data() {
        let folder = temp_dir("cli-status");
        let (code, text) = run_with(&["--status"], &never, Some(&folder));
        assert_eq!(code, 0, "{text}");
        let bundled = Snapshot::bundled();
        assert!(
            text.contains(&format!(
                "CloudFormation resource types: the bundled snapshot, dated {} (2 days old)",
                bundled.last_updated()
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!("no cache file in {}", folder.display())),
            "{text}"
        );
        assert!(
            text.contains("API services: the bundled snapshot, dated"),
            "{text}"
        );
        assert!(text.contains("this command does not refresh it"), "{text}");
        assert!(
            text.contains("Checks (EMULATOR_REGION_AVAILABILITY): CloudFormation templates "),
            "{text}"
        );
        if std::env::var_os(MODE_ENV).is_none() {
            assert!(
                text.contains("CloudFormation templates enforce, API requests warn."),
                "the two defaults: {text}"
            );
        }
        std::fs::remove_dir_all(&folder).unwrap();
    }

    #[test]
    fn a_refresh_signs_every_read_writes_the_cache_and_the_cache_is_then_in_use() {
        let folder = temp_dir("cli-refresh");
        let seen = Rc::new(RefCell::new(Seen::default()));
        let stamp = after_bundled(DAY);
        let factory = chain(&seen, full_dataset(DAY), None);
        let (code, text) = run_with(&[], &factory, Some(&folder));
        assert_eq!(code, 0, "{text}");
        assert!(
            text.contains(&format!("Refreshed: data dated {stamp}, ")),
            "{text}"
        );
        assert!(
            text.contains(&folder.join(CACHE_FILE).display().to_string()),
            "{text}"
        );
        assert!(
            text.contains("CloudFormation resource types: the refreshed cache"),
            "{text}"
        );
        assert!(text.contains("is in use"), "{text}");
        // The cache is a sealed file the loader reads.
        let cache = load_cache_file(&folder.join(CACHE_FILE)).expect("a whole cache");
        assert_eq!(cache.last_updated(), stamp);
        // Four reads, each signed first, each to the access point host and nothing else.
        let seen = seen.borrow();
        assert_eq!(seen.signed, 4);
        assert_eq!(seen.hosts.len(), 4);
        for host in &seen.hosts {
            assert_eq!(
                host,
                &format!("{ACCESS_POINT_ALIAS}.s3.us-east-1.amazonaws.com")
            );
        }
        assert!(
            seen.paths.iter().all(|p| p.starts_with("/public/")),
            "{:?}",
            seen.paths
        );
        assert_eq!(seen.profile, vec![None]);
        drop(seen);
        // Status alone now agrees, and makes no request.
        let (code, text) = run_with(&["--status"], &never, Some(&folder));
        assert_eq!(code, 0);
        assert!(text.contains("the refreshed cache"), "{text}");
        std::fs::remove_dir_all(&folder).unwrap();
    }

    #[test]
    fn a_second_refresh_with_the_same_data_changes_nothing() {
        let folder = temp_dir("cli-twice");
        let seen = Rc::new(RefCell::new(Seen::default()));
        let factory = chain(&seen, full_dataset(DAY), None);
        assert_eq!(run_with(&[], &factory, Some(&folder)).0, 0);
        let before = std::fs::read(folder.join(CACHE_FILE)).unwrap();
        let (code, text) = run_with(&[], &factory, Some(&folder));
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("Nothing to do"), "{text}");
        assert_eq!(std::fs::read(folder.join(CACHE_FILE)).unwrap(), before);
        std::fs::remove_dir_all(&folder).unwrap();
    }

    #[test]
    fn a_refused_read_says_why_and_leaves_the_data_in_use_as_it_was() {
        let folder = temp_dir("cli-refused");
        let seen = Rc::new(RefCell::new(Seen::default()));
        assert_eq!(
            run_with(&[], &chain(&seen, full_dataset(DAY), None), Some(&folder)).0,
            0
        );
        let before = std::fs::read(folder.join(CACHE_FILE)).unwrap();
        let expired = "<Error><Code>ExpiredToken</Code><RequestId>ABC123</RequestId></Error>";
        let factory = chain(&seen, BTreeMap::new(), Some((400, expired.to_string())));
        let (code, text) = run_with(&[], &factory, Some(&folder));
        assert_eq!(code, 1, "{text}");
        assert!(
            text.contains(
                "forbidden: the AWS credentials have expired (ExpiredToken, request id ABC123)"
            ),
            "{text}"
        );
        assert!(text.contains("The data in use is unchanged."), "{text}");
        assert_eq!(std::fs::read(folder.join(CACHE_FILE)).unwrap(), before);
        std::fs::remove_dir_all(&folder).unwrap();
    }

    #[test]
    fn no_credentials_means_no_request_and_no_cache() {
        let folder = temp_dir("cli-nocreds");
        let factory = |_: Option<&str>| -> Result<Box<dyn ObjectFetcher>, String> {
            Err(
                "no AWS credentials: the AWS credential chain did not answer within 30 s"
                    .to_string(),
            )
        };
        let (code, text) = run_with(&[], &factory, Some(&folder));
        assert_eq!(code, 1, "{text}");
        assert!(
            text.contains("Could not refresh: no AWS credentials"),
            "{text}"
        );
        assert!(text.contains("The bundled data stays in use."), "{text}");
        assert!(!folder.join(CACHE_FILE).exists());
        std::fs::remove_dir_all(&folder).unwrap();
    }

    #[test]
    fn the_profile_reaches_the_credential_chain_and_only_when_given() {
        let folder = temp_dir("cli-profile");
        let seen = Rc::new(RefCell::new(Seen::default()));
        let factory = chain(&seen, full_dataset(DAY), None);
        assert_eq!(
            run_with(&["--profile", "dev"], &factory, Some(&folder)).0,
            0
        );
        assert_eq!(run_with(&[], &factory, Some(&folder)).0, 0);
        assert_eq!(seen.borrow().profile, vec![Some("dev".to_string()), None]);
        std::fs::remove_dir_all(&folder).unwrap();
    }

    #[test]
    fn arguments_that_are_not_understood_get_the_usage_and_exit_two() {
        for args in [
            &["--bogus"][..],
            &["--profile"],
            &["--profile", "--status"],
            &["--status", "--profile", "dev"],
            &["extra"],
        ] {
            let (code, text) = run_with(args, &never, None);
            assert_eq!(code, 2, "{args:?}: {text}");
            assert!(
                text.contains("Usage: refresh-region-data"),
                "{args:?}: {text}"
            );
        }
        let (code, text) = run_with(&["--help"], &never, None);
        assert_eq!(code, 0);
        assert!(text.starts_with("Usage: refresh-region-data"), "{text}");
        assert!(
            text.contains("Nothing is fetched unless you run this."),
            "{text}"
        );
    }

    #[test]
    fn without_a_cache_folder_there_is_nowhere_to_write() {
        let factory = |_: Option<&str>| -> Result<Box<dyn ObjectFetcher>, String> {
            panic!("no request is made without a folder to write")
        };
        let (code, text) = run_with(&[], &factory, None);
        assert_eq!(code, 1);
        assert!(text.contains("there is no cache folder"), "{text}");
        let (code, text) = run_with(&["--status"], &never, None);
        assert_eq!(code, 0);
        assert!(text.contains("no cache folder is set"), "{text}");
    }

    /// A cache that is there and not used is named, with the reason.
    #[test]
    fn a_cache_that_is_not_used_says_why() {
        let folder = temp_dir("cli-ignored");
        let path = folder.join(CACHE_FILE);
        let (regions, cfn, _) = bundled_as_json();
        let sealed = |stamp: String, clock: SystemTime, regions: &[u8], cfn: &[u8]| {
            convert_cfn("v1", &stamp, regions, cfn, clock).unwrap()
        };
        let later = now() + std::time::Duration::from_secs(10 * DAY as u64);
        let status = |expect: &str| {
            let (code, text) = run_with(&["--status"], &never, Some(&folder));
            assert_eq!(code, 0);
            assert!(text.contains(expect), "wanted {expect:?} in {text}");
            assert!(
                text.contains("CloudFormation resource types: the bundled snapshot, dated"),
                "{text}"
            );
        };
        std::fs::write(&path, "not a cache").unwrap();
        status("cannot be used");
        let whole = sealed(after_bundled(DAY), now(), &regions, &cfn);
        // Cut at the end of a line, so only the seal can tell the file is not whole.
        let at = whole.len() / 2 + whole[whole.len() / 2..].find('\n').unwrap() + 1;
        std::fs::write(&path, &whole[..at]).unwrap();
        status("cannot be used");
        std::fs::write(&path, sealed(after_bundled(-DAY), now(), &regions, &cfn)).unwrap();
        status("is ignored: it is not newer than the bundled data");
        std::fs::write(&path, sealed(after_bundled(5 * DAY), later, &regions, &cfn)).unwrap();
        status("is ignored: it is dated");
        let tiny = dataset(&after_bundled(DAY));
        let small = sealed(
            after_bundled(DAY),
            now(),
            &tiny["public/v1/json/regions.json"],
            &tiny["public/v1/json/cfn_resources.json"],
        );
        std::fs::write(&path, small).unwrap();
        status("under the floor of");
        std::fs::write(&path, sealed(after_bundled(DAY), now(), &regions, &cfn)).unwrap();
        let (_, text) = run_with(&["--status"], &never, Some(&folder));
        assert!(text.contains("the refreshed cache"), "{text}");
        std::fs::remove_dir_all(&folder).unwrap();
    }

    /// A dataset with most of its types missing is not taken, however well it is signed.
    #[test]
    fn a_dataset_with_most_types_missing_is_refused_and_leaves_no_cache() {
        let folder = temp_dir("cli-partial");
        let seen = Rc::new(RefCell::new(Seen::default()));
        let factory = chain(&seen, dataset(&after_bundled(DAY)), None);
        let (code, text) = run_with(&[], &factory, Some(&folder));
        assert_eq!(code, 1, "{text}");
        assert!(text.contains("only 3 resource types"), "{text}");
        assert!(text.contains("The data in use is unchanged."), "{text}");
        assert!(!folder.join(CACHE_FILE).exists());
        std::fs::remove_dir_all(&folder).unwrap();
    }

    #[test]
    fn age_is_said_in_days() {
        let bundled = Snapshot::bundled().last_updated().to_string();
        assert_eq!(age_in_words(&bundled, now()), "2 days old");
        assert_eq!(age_in_words(&after_bundled(2 * DAY), now()), "today");
        assert_eq!(age_in_words(&after_bundled(DAY), now()), "1 day old");
        assert_eq!(
            age_in_words(&after_bundled(30 * DAY), now()),
            "dated in the future"
        );
        assert_eq!(age_in_words("soon", now()), "age unknown");
    }
}
