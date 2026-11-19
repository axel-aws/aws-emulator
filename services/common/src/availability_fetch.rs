// SPDX-License-Identifier: CC0-1.0

//! The fetcher that reads the Regional availability data from its S3 access point with the
//! user's own AWS credentials.
//!
//! The access point refuses an unsigned request (see [`crate::availability_source`]), so a read
//! has to be signed with Signature Version 4. This module is the pieces of that, each behind a
//! small trait so a test can replace it and no test makes a real call:
//!
//! - [`CredentialSource`]: where the credentials come from. [`SdkCredentials`] asks the AWS SDK's
//!   **default credential chain** (environment, profile, SSO, process, container and instance
//!   metadata, in the SDK's own order). This code never reads a credential file and keeps no
//!   store of its own.
//! - [`Signer`]: signs one request. [`SigV4Signer`] does it with `aws-sigv4`.
//! - [`HttpTransport`]: sends one request. [`ReqwestTransport`] is https only, follows no
//!   redirect, and has a time limit and a size cap.
//! - [`SignedFetcher`]: puts them together as an [`ObjectFetcher`]. It asks for nothing but
//!   `https://<access point alias>.s3.us-east-1.amazonaws.com/public/...`, and it sends nothing
//!   when it could not sign: an unsigned request never goes out.
//!
//! **Credentials never leave the signer.** They are used to sign and are not stored in a
//! struct that prints, logged, or put in an error. The one place a credential's text reaches a
//! request is the `Authorization` header, which is the signature and the key id, not the secret
//! key.
//!
//! shortcut: the SDK chain is resolved on a runtime of this module's own, so it has to be called
//! from a thread that is not already inside an async runtime (a command, or a thread made for
//! the refresh). It is not called from a request handler.

use crate::availability_source::{
    FetchError, ObjectFetcher, ObjectRequest, ACCESS_POINT_ALIAS, ACCESS_POINT_REGION,
};
use ::aws_credential_types::provider::ProvideCredentials;
use ::aws_credential_types::Credentials;
use ::aws_sigv4::http_request::{
    sign, PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings,
};
use std::io::Read;
use std::time::{Duration, SystemTime};

/// The environment variable that overrides which AWS profile the credential chain uses. Without
/// it the SDK's own rules apply (`AWS_PROFILE` and the rest).
pub const PROFILE_ENV: &str = "EMULATOR_REGION_AVAILABILITY_PROFILE";
const SIGNING_NAME: &str = "s3";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ERROR_BODY_BYTES: usize = 2048;

/// Where signing credentials come from.
pub trait CredentialSource {
    /// The credentials to sign with. The error is plain text and must not hold a secret.
    fn credentials(&self) -> Result<Credentials, String>;
}

/// Signs one request in place: adds the headers that make it a signed request.
pub trait Signer {
    fn sign(&self, request: &mut http::Request<()>, region: &str) -> Result<(), String>;
}

/// What came back.
#[derive(Debug, PartialEq, Eq)]
pub struct HttpReply {
    pub status: u16,
    /// At most the cap plus one byte, so the caller can tell the body was too long.
    pub body: Vec<u8>,
}

/// Sends one request.
pub trait HttpTransport {
    fn get(&self, request: &http::Request<()>, max_bytes: usize) -> Result<HttpReply, String>;
}

/// Which profile to use: an explicit one, then the environment override, else none (the SDK's
/// own rules).
pub fn profile_override(explicit: Option<&str>, env: Option<&str>) -> Option<String> {
    [explicit, env]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|name| !name.is_empty())
        .map(str::to_string)
}

/// [`profile_override`] with the value of [`PROFILE_ENV`].
pub fn profile_from_env(explicit: Option<&str>) -> Option<String> {
    profile_override(explicit, std::env::var(PROFILE_ENV).ok().as_deref())
}

/// How long the credential chain may take to answer. A `credential_process` in the user's own
/// config that hangs would otherwise hang the refresh.
pub const CREDENTIALS_TIME_LIMIT: Duration = Duration::from_secs(30);
const MIN_CREDENTIALS_TIME_LIMIT: Duration = Duration::from_secs(1);

/// The AWS SDK's default credential chain, behind a runtime of its own.
pub struct SdkCredentials {
    runtime: tokio::runtime::Runtime,
    provider: ::aws_config::default_provider::credentials::DefaultCredentialsChain,
    limit: Duration,
}

fn inside_a_runtime() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}

impl SdkCredentials {
    /// Build the chain, with `profile` when given. Must not be called from inside an async
    /// runtime.
    pub fn new(profile: Option<&str>) -> Result<SdkCredentials, String> {
        SdkCredentials::with_time_limit(profile, CREDENTIALS_TIME_LIMIT)
    }

    /// [`SdkCredentials::new`] with another time limit for the chain's answer. A limit under one
    /// second is raised to one second, so even a quick helper has time to answer.
    pub fn with_time_limit(
        profile: Option<&str>,
        limit: Duration,
    ) -> Result<SdkCredentials, String> {
        let limit = limit.max(MIN_CREDENTIALS_TIME_LIMIT);
        if inside_a_runtime() {
            return Err(
                "the credential chain has to be built from a thread outside the async runtime"
                    .to_string(),
            );
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("could not start a runtime: {error}"))?;
        let provider = runtime.block_on(async {
            let mut builder =
                ::aws_config::default_provider::credentials::DefaultCredentialsChain::builder();
            if let Some(profile) = profile {
                builder = builder.profile_name(profile);
            }
            builder.build().await
        });
        Ok(SdkCredentials {
            runtime,
            provider,
            limit,
        })
    }
}

impl CredentialSource for SdkCredentials {
    fn credentials(&self) -> Result<Credentials, String> {
        if inside_a_runtime() {
            return Err("credentials have to be resolved outside the async runtime".to_string());
        }
        // The timer is made inside the runtime: it needs its clock.
        // shortcut: when the limit fires, a `credential_process` helper keeps running. The SDK
        // starts it without `kill_on_drop` and gives no handle to it, so it cannot be stopped
        // from here. The refresh is meant to run from a command or once at start-up, not per
        // request, so at most one stuck helper is left per refresh. Upgrade when the SDK offers a
        // way to stop it, or run the chain in a child process of its own.
        let answer = self.runtime.block_on(async {
            tokio::time::timeout(self.limit, self.provider.provide_credentials()).await
        });
        match answer {
            Ok(answer) => answer.map_err(|error| format!("no AWS credentials: {error}")),
            Err(_) => Err(format!(
                "no AWS credentials: the AWS credential chain did not answer within {} s \
                 (check credential_process and SSO in your AWS config)",
                self.limit.as_secs()
            )),
        }
    }
}

/// Signs with Signature Version 4 for S3, using credentials from a [`CredentialSource`].
pub struct SigV4Signer<C> {
    credentials: C,
    clock: Box<dyn Fn() -> SystemTime + Send + Sync>,
}

impl<C: CredentialSource> SigV4Signer<C> {
    pub fn new(credentials: C) -> SigV4Signer<C> {
        SigV4Signer::with_clock(credentials, SystemTime::now)
    }

    /// With a clock of the caller's, so a test can pin the time of the signature.
    pub fn with_clock(
        credentials: C,
        clock: impl Fn() -> SystemTime + Send + Sync + 'static,
    ) -> SigV4Signer<C> {
        SigV4Signer {
            credentials,
            clock: Box::new(clock),
        }
    }
}

impl<C> std::fmt::Debug for SigV4Signer<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigV4Signer { .. }")
    }
}

impl<C: CredentialSource> Signer for SigV4Signer<C> {
    fn sign(&self, request: &mut http::Request<()>, region: &str) -> Result<(), String> {
        let credentials = self.credentials.credentials()?;
        let identity: ::aws_smithy_runtime_api::client::identity::Identity = credentials.into();
        let mut settings = SigningSettings::default();
        // S3 wants the hash of the (empty) body in a header.
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let params = ::aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name(SIGNING_NAME)
            .settings(settings)
            .time((self.clock)())
            .build()
            .map_err(|_| "could not set up the signature".to_string())?;
        let headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let signable = SignableRequest::new(
            request.method().as_str(),
            request.uri().to_string(),
            headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            SignableBody::Bytes(&[]),
        )
        .map_err(|_| "could not read the request to sign".to_string())?;
        let (instructions, _signature) = sign(signable, &params.into())
            .map_err(|_| "could not sign the request".to_string())?
            .into_parts();
        instructions.apply_to_request_http1x(request);
        Ok(())
    }
}

/// Sends requests with `reqwest`: https only, no redirect, a time limit, and a cap on the body.
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    pub fn new() -> Result<ReqwestTransport, String> {
        ReqwestTransport::build(true, REQUEST_TIMEOUT)
    }

    /// The two settings are parameters only so a test can talk to a server on this machine; the
    /// transport a user gets is [`ReqwestTransport::new`]: https only, with the full time limit.
    fn build(https_only: bool, timeout: Duration) -> Result<ReqwestTransport, String> {
        let client = reqwest::blocking::Client::builder()
            .https_only(https_only)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|error| format!("could not build the http client: {error}"))?;
        Ok(ReqwestTransport { client })
    }
}

impl HttpTransport for ReqwestTransport {
    fn get(&self, request: &http::Request<()>, max_bytes: usize) -> Result<HttpReply, String> {
        let mut builder = self.client.get(request.uri().to_string());
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        let response = builder
            .send()
            .map_err(|error| format!("the request failed: {}", describe(error)))?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        response
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|error| format!("could not read the reply: {error}"))?;
        Ok(HttpReply { status, body })
    }
}

/// An http error with its causes (the address is left out), for example `builder error: URL
/// scheme is not allowed`.
fn describe(error: reqwest::Error) -> String {
    use std::error::Error;
    let error = error.without_url();
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        text.push_str(": ");
        text.push_str(&next.to_string());
        cause = next.source();
    }
    text
}

/// `https://<alias>.s3.<region>.amazonaws.com/<key>`, for the access point alias and a key made
/// of letters, digits and `. _ - /` with no empty or dot-only part. Anything else is `None`.
fn object_url(request: &ObjectRequest) -> Option<String> {
    let key_ok = request.key.starts_with("public/")
        && request.key.len() <= 256
        && request
            .key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
        && request
            .key
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if request.bucket != ACCESS_POINT_ALIAS || request.region != ACCESS_POINT_REGION || !key_ok {
        return None;
    }
    Some(format!(
        "https://{}.s3.{}.amazonaws.com/{}",
        request.bucket, request.region, request.key
    ))
}

/// One plain word in an S3 error body (`<Code>AccessDenied</Code>`), when it is one.
fn xml_word(body: &[u8], tag: &str) -> Option<String> {
    let text = std::str::from_utf8(&body[..body.len().min(ERROR_BODY_BYTES)]).ok()?;
    let open = format!("<{tag}>");
    let start = text.find(&open)? + open.len();
    let word = &text[start..start + text[start..].find(&format!("</{tag}>"))?];
    (!word.is_empty() && word.len() <= 64 && word.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| word.to_string())
}

/// The S3 error code in an error body.
fn error_code(body: &[u8]) -> Option<String> {
    xml_word(body, "Code")
}

/// What a 400, 401 or 403 means, told apart by S3's error code where it can be, with the
/// request id so the user can quote it. `None` for a 400 this does not know: the caller reports
/// it as it is. S3 answers an expired or bad session token with 400, not 403.
fn refusal(status: u16, body: &[u8]) -> Option<FetchError> {
    let code = error_code(body);
    let request_id = xml_word(body, "RequestId")
        .map_or("no request id".to_string(), |id| format!("request id {id}"));
    let why = match code.as_deref() {
        Some("AccessDenied") if status != 400 => {
            return Some(FetchError::Denied(format!(
                "this AWS identity may not read the access point; check its policies and any \
                 SCP or permissions boundary (AccessDenied, {request_id})"
            )))
        }
        Some("ExpiredToken" | "TokenRefreshRequired") => "the AWS credentials have expired",
        Some("RequestTimeTooSkewed") => "this computer's clock is too far from AWS's time",
        Some("InvalidAccessKeyId" | "InvalidToken") => "AWS does not know these credentials",
        Some("SignatureDoesNotMatch") => "the signature does not match the secret key",
        _ if status == 400 => return None,
        Some(other) => {
            return Some(FetchError::Transport(format!(
                "forbidden (HTTP {status} {other}, {request_id})"
            )))
        }
        None => {
            return Some(FetchError::Transport(format!(
                "forbidden (HTTP {status}, {request_id})"
            )))
        }
    };
    Some(FetchError::Transport(format!(
        "forbidden: {why} ({}, {request_id})",
        code.unwrap_or_default()
    )))
}

/// Reads objects from the access point, signed.
pub struct SignedFetcher<S, T> {
    signer: S,
    transport: T,
}

impl<S: Signer, T: HttpTransport> SignedFetcher<S, T> {
    pub fn new(signer: S, transport: T) -> SignedFetcher<S, T> {
        SignedFetcher { signer, transport }
    }
}

impl<S, T> std::fmt::Debug for SignedFetcher<S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignedFetcher { .. }")
    }
}

impl<S: Signer, T: HttpTransport> ObjectFetcher for SignedFetcher<S, T> {
    fn get(&self, request: &ObjectRequest, max_bytes: usize) -> Result<Vec<u8>, FetchError> {
        let url = object_url(request).ok_or_else(|| {
            FetchError::Transport("not a read of the access point's public objects".to_string())
        })?;
        let host = format!("{}.s3.{}.amazonaws.com", request.bucket, request.region);
        let mut signed = http::Request::builder()
            .method("GET")
            .uri(url)
            .header("host", host)
            .body(())
            .map_err(|_| FetchError::Transport("could not build the request".to_string()))?;
        // If it cannot be signed, nothing is sent.
        self.signer
            .sign(&mut signed, request.region)
            .map_err(FetchError::Transport)?;
        let reply = self
            .transport
            .get(&signed, max_bytes)
            .map_err(FetchError::Transport)?;
        match reply.status {
            200 if reply.body.len() > max_bytes => Err(FetchError::TooLarge),
            200 => Ok(reply.body),
            404 => Err(FetchError::NotFound),
            400 if String::from_utf8_lossy(
                &reply.body[..reply.body.len().min(ERROR_BODY_BYTES)],
            )
            .contains("Signature Version 4") =>
            {
                Err(FetchError::Denied(
                    "the access point wants a request signed with Signature Version 4".to_string(),
                ))
            }
            400 | 401 | 403 => Err(refusal(reply.status, &reply.body)
                .unwrap_or_else(|| plain_error(reply.status, &reply.body))),
            301 | 302 | 303 | 307 | 308 => Err(FetchError::Transport(
                "a redirect, which is not followed".to_string(),
            )),
            status => Err(plain_error(status, &reply.body)),
        }
    }
}

/// `HTTP <status> <S3 error code>`, or `HTTP <status>` when the body names no plain code.
fn plain_error(status: u16, body: &[u8]) -> FetchError {
    FetchError::Transport(match error_code(body) {
        Some(code) => format!("HTTP {status} {code}"),
        None => format!("HTTP {status}"),
    })
}

/// The fetcher a user's own credentials give: the SDK default chain (with the profile override),
/// SigV4, and https. Must be called from outside the async runtime.
pub fn sdk_fetcher(
    profile: Option<&str>,
) -> Result<SignedFetcher<SigV4Signer<SdkCredentials>, ReqwestTransport>, String> {
    let credentials = SdkCredentials::new(profile_from_env(profile).as_deref())?;
    Ok(SignedFetcher::new(
        SigV4Signer::new(credentials),
        ReqwestTransport::new()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::availability_source::{refresh_with, tests};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::time::UNIX_EPOCH;
    use tests::dataset;

    const KEY_ID: &str = "AKIDFAKEEXAMPLE000";
    const SECRET: &str = "SECRETFAKEKEY1234567890abcdefghij";
    const TOKEN: &str = "SESSIONTOKENFAKE0987654321";
    const HOST: &str = "aws-capabilities-pub-ybkxdwgxrkfhwmq8b1neoq8ny6ua4use1b-s3alias.s3.us-east-1.amazonaws.com";

    type Events = Rc<RefCell<Vec<String>>>;

    fn at() -> SystemTime {
        // 2026-11-19 05:00:00 UTC
        UNIX_EPOCH + Duration::from_secs(20_776 * 86_400 + 5 * 3_600)
    }

    fn object(key: &str) -> ObjectRequest {
        ObjectRequest {
            bucket: ACCESS_POINT_ALIAS,
            region: ACCESS_POINT_REGION,
            key: key.to_string(),
        }
    }

    fn url_of(key: &str) -> String {
        format!("https://{HOST}/{key}")
    }

    fn unsigned(key: &str) -> http::Request<()> {
        http::Request::builder()
            .method("GET")
            .uri(url_of(key))
            .header("host", HOST)
            .body(())
            .unwrap()
    }

    /// Credentials made up for the test, or none.
    struct Fake {
        secret: &'static str,
        token: Option<&'static str>,
        fails: bool,
    }

    impl CredentialSource for Fake {
        fn credentials(&self) -> Result<Credentials, String> {
            if self.fails {
                return Err("no AWS credentials: nothing configured".to_string());
            }
            Ok(Credentials::new(
                KEY_ID,
                self.secret,
                self.token.map(str::to_string),
                None,
                "test",
            ))
        }
    }

    fn fake() -> Fake {
        Fake {
            secret: SECRET,
            token: None,
            fails: false,
        }
    }

    /// A signer that only marks the request, and says it was asked.
    struct FakeSigner {
        events: Events,
    }

    impl Signer for FakeSigner {
        fn sign(&self, request: &mut http::Request<()>, region: &str) -> Result<(), String> {
            self.events.borrow_mut().push(format!("sign {region}"));
            request
                .headers_mut()
                .insert("authorization", "FAKE-SIGNATURE".parse().unwrap());
            Ok(())
        }
    }

    /// Serves objects by URL and records every request it is sent.
    struct FakeTransport {
        events: Events,
        objects: BTreeMap<String, HttpReply>,
        sent: RefCell<Vec<http::Request<()>>>,
    }

    impl FakeTransport {
        fn new(events: &Events) -> FakeTransport {
            FakeTransport {
                events: events.clone(),
                objects: BTreeMap::new(),
                sent: RefCell::new(Vec::new()),
            }
        }

        fn serving(events: &Events, files: BTreeMap<String, Vec<u8>>) -> FakeTransport {
            let mut transport = FakeTransport::new(events);
            for (key, body) in files {
                transport
                    .objects
                    .insert(url_of(&key), HttpReply { status: 200, body });
            }
            transport
        }

        fn replying(events: &Events, status: u16, body: &str) -> FakeTransport {
            let mut transport = FakeTransport::new(events);
            transport.objects.insert(
                url_of("public/index.json"),
                HttpReply {
                    status,
                    body: body.as_bytes().to_vec(),
                },
            );
            transport
        }
    }

    impl HttpTransport for FakeTransport {
        fn get(&self, request: &http::Request<()>, _max: usize) -> Result<HttpReply, String> {
            self.events.borrow_mut().push("send".to_string());
            self.sent.borrow_mut().push(request.clone());
            match self.objects.get(&request.uri().to_string()) {
                Some(reply) => Ok(HttpReply {
                    status: reply.status,
                    body: reply.body.clone(),
                }),
                None => Ok(HttpReply {
                    status: 404,
                    body: Vec::new(),
                }),
            }
        }
    }

    fn events() -> Events {
        Rc::new(RefCell::new(Vec::new()))
    }

    fn header<'a>(request: &'a http::Request<()>, name: &str) -> &'a str {
        request
            .headers()
            .get(name)
            .map(|value| value.to_str().unwrap())
            .unwrap_or_default()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("availability-fetch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_read_is_signed_first_and_then_sent_once_to_the_access_point_host() {
        let log = events();
        let fetcher = SignedFetcher::new(
            FakeSigner {
                events: log.clone(),
            },
            FakeTransport::serving(
                &log,
                BTreeMap::from([("public/index.json".to_string(), b"{}".to_vec())]),
            ),
        );
        assert_eq!(
            fetcher.get(&object("public/index.json"), 100),
            Ok(b"{}".to_vec())
        );
        assert_eq!(*log.borrow(), ["sign us-east-1", "send"]);
        let sent = fetcher.transport.sent.borrow();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].method(), "GET");
        assert_eq!(sent[0].uri().to_string(), url_of("public/index.json"));
        assert_eq!(header(&sent[0], "host"), HOST);
        assert_eq!(header(&sent[0], "authorization"), "FAKE-SIGNATURE");
    }

    /// A whole refresh through the signed fetcher: every request is a signed https read of the
    /// access point host.
    #[test]
    fn a_refresh_through_the_signed_fetcher_reads_only_the_access_point_host() {
        let log = events();
        let fetcher = SignedFetcher::new(
            FakeSigner {
                events: log.clone(),
            },
            FakeTransport::serving(&log, dataset(&tests::after_bundled(86_400))),
        );
        let dir = temp_dir("refresh");
        let report = refresh_with(&fetcher, &dir, tests::now(), 0).unwrap();
        assert!(report.written);
        let sent = fetcher.transport.sent.borrow();
        assert_eq!(sent.len(), 4);
        for request in sent.iter() {
            assert_eq!(request.uri().scheme_str(), Some("https"));
            assert_eq!(request.uri().host(), Some(HOST));
            assert_eq!(header(request, "authorization"), "FAKE-SIGNATURE");
        }
        let signs = log
            .borrow()
            .iter()
            .filter(|e| e.starts_with("sign"))
            .count();
        assert_eq!(signs, 4, "every request is signed");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn what_the_access_point_answers_becomes_the_matching_fetch_result() {
        let cases: Vec<(u16, &str, Result<Vec<u8>, FetchError>)> = vec![
            (200, "ok", Ok(b"ok".to_vec())),
            (403, "<Error><Code>AccessDenied</Code></Error>", Err(FetchError::Denied("this AWS identity may not read the access point; check its policies and any SCP or permissions boundary (AccessDenied, no request id)".to_string()))),
            (401, "", Err(FetchError::Transport("forbidden (HTTP 401, no request id)".to_string()))),
            (404, "<Error><Code>NoSuchKey</Code></Error>", Err(FetchError::NotFound)),
            (
                400,
                "<Error><Code>InvalidRequest</Code><Message>Please use Signature Version 4.</Message></Error>",
                Err(FetchError::Denied("the access point wants a request signed with Signature Version 4".to_string())),
            ),
            (400, "<Error><Code>InvalidArgument</Code></Error>", Err(FetchError::Transport("HTTP 400 InvalidArgument".to_string()))),
            (503, "<Error><Code>SlowDown</Code></Error>", Err(FetchError::Transport("HTTP 503 SlowDown".to_string()))),
            (500, "not xml", Err(FetchError::Transport("HTTP 500".to_string()))),
            (500, "<Code>has space</Code>", Err(FetchError::Transport("HTTP 500".to_string()))),
            (301, "", Err(FetchError::Transport("a redirect, which is not followed".to_string()))),
            (307, "", Err(FetchError::Transport("a redirect, which is not followed".to_string()))),
        ];
        for (status, body, expected) in cases {
            let log = events();
            let fetcher = SignedFetcher::new(
                FakeSigner {
                    events: log.clone(),
                },
                FakeTransport::replying(&log, status, body),
            );
            assert_eq!(
                fetcher.get(&object("public/index.json"), 1000),
                expected,
                "{status} {body}"
            );
        }
        let log = events();
        let fetcher = SignedFetcher::new(
            FakeSigner {
                events: log.clone(),
            },
            FakeTransport::replying(&log, 200, "0123456789"),
        );
        assert_eq!(
            fetcher.get(&object("public/index.json"), 9),
            Err(FetchError::TooLarge)
        );
        assert!(fetcher.get(&object("public/index.json"), 10).is_ok());
    }

    /// A 403 says what S3 said when it can be told apart, and always gives the request id.
    #[test]
    fn a_refusal_says_why_when_the_reply_tells() {
        let body = |code: &str| {
            format!(
                "<?xml version=\"1.0\"?><Error><Code>{code}</Code><Message>m</Message>\
                 <RequestId>4442587FB7D0A2F9</RequestId><HostId>h/x=</HostId></Error>"
            )
        };
        let cases: Vec<(u16, String, Result<Vec<u8>, FetchError>)> = vec![
            (403, body("AccessDenied"), Err(FetchError::Denied("this AWS identity may not read the access point; check its policies and any SCP or permissions boundary (AccessDenied, request id 4442587FB7D0A2F9)".to_string()))),
            (
                403,
                body("ExpiredToken"),
                Err(FetchError::Transport(
                    "forbidden: the AWS credentials have expired (ExpiredToken, request id 4442587FB7D0A2F9)".to_string(),
                )),
            ),
            (
                400,
                body("ExpiredToken"),
                Err(FetchError::Transport(
                    "forbidden: the AWS credentials have expired (ExpiredToken, request id 4442587FB7D0A2F9)".to_string(),
                )),
            ),
            (
                400,
                body("InvalidToken"),
                Err(FetchError::Transport(
                    "forbidden: AWS does not know these credentials (InvalidToken, request id 4442587FB7D0A2F9)".to_string(),
                )),
            ),
            (
                400,
                body("TokenRefreshRequired"),
                Err(FetchError::Transport(
                    "forbidden: the AWS credentials have expired (TokenRefreshRequired, request id 4442587FB7D0A2F9)".to_string(),
                )),
            ),
            (400, body("AccessDenied"), Err(FetchError::Transport("HTTP 400 AccessDenied".to_string()))),
            (400, body("MalformedXML"), Err(FetchError::Transport("HTTP 400 MalformedXML".to_string()))),
            (403, body(&"C".repeat(64)), Err(FetchError::Transport(format!("forbidden (HTTP 403 {}, request id 4442587FB7D0A2F9)", "C".repeat(64))))),
            (403, body(&"C".repeat(65)), Err(FetchError::Transport("forbidden (HTTP 403, request id 4442587FB7D0A2F9)".to_string()))),
            (
                403,
                body("RequestTimeTooSkewed"),
                Err(FetchError::Transport(
                    "forbidden: this computer's clock is too far from AWS's time (RequestTimeTooSkewed, request id 4442587FB7D0A2F9)".to_string(),
                )),
            ),
            (
                403,
                body("InvalidAccessKeyId"),
                Err(FetchError::Transport(
                    "forbidden: AWS does not know these credentials (InvalidAccessKeyId, request id 4442587FB7D0A2F9)".to_string(),
                )),
            ),
            (
                403,
                body("SignatureDoesNotMatch"),
                Err(FetchError::Transport(
                    "forbidden: the signature does not match the secret key (SignatureDoesNotMatch, request id 4442587FB7D0A2F9)".to_string(),
                )),
            ),
            (
                403,
                body("AllAccessDisabled"),
                Err(FetchError::Transport(
                    "forbidden (HTTP 403 AllAccessDisabled, request id 4442587FB7D0A2F9)"
                        .to_string(),
                )),
            ),
            (
                403,
                "<html>blocked by a proxy</html>".to_string(),
                Err(FetchError::Transport(
                    "forbidden (HTTP 403, no request id)".to_string(),
                )),
            ),
            (
                403,
                "<Code>ExpiredToken</Code><RequestId>bad id\n</RequestId>".to_string(),
                Err(FetchError::Transport(
                    "forbidden: the AWS credentials have expired (ExpiredToken, no request id)"
                        .to_string(),
                )),
            ),
        ];
        for (status, body, expected) in cases {
            let log = events();
            let fetcher = SignedFetcher::new(
                FakeSigner {
                    events: log.clone(),
                },
                FakeTransport::replying(&log, status, &body),
            );
            assert_eq!(
                fetcher.get(&object("public/index.json"), 1000),
                expected,
                "{status} {body}"
            );
        }
    }

    /// Only the access point alias, in its Region, and plain keys under `public/` are read.
    /// Anything else is refused before it is signed or sent.
    #[test]
    fn nothing_else_than_the_access_point_is_ever_asked_for() {
        let other_bucket = ObjectRequest {
            bucket: "some-bucket",
            ..object("public/index.json")
        };
        let arn = ObjectRequest {
            bucket: crate::availability_source::ACCESS_POINT_ARN,
            ..object("public/index.json")
        };
        let other_region = ObjectRequest {
            region: "eu-west-1",
            ..object("public/index.json")
        };
        let mut bad = vec![other_bucket, arn, other_region];
        for key in [
            "index.json",
            "private/index.json",
            "public/../secret",
            "public//index.json",
            "public/./index.json",
            "public/index.json?versionId=1",
            "public/index.json#x",
            "public/in dex.json",
            "public/index.json\n",
            "public/%2e%2e/x",
            "public/@host/x",
            "",
        ] {
            bad.push(object(key));
        }
        bad.push(object(&format!("public/{}", "a".repeat(300))));
        for request in bad {
            let log = events();
            let fetcher = SignedFetcher::new(
                FakeSigner {
                    events: log.clone(),
                },
                FakeTransport::new(&log),
            );
            let outcome = fetcher.get(&request, 100);
            assert!(
                matches!(outcome, Err(FetchError::Transport(_))),
                "{request:?}: {outcome:?}"
            );
            assert!(log.borrow().is_empty(), "{request:?} was signed or sent");
        }
    }

    #[test]
    fn the_signature_carries_the_scope_the_body_hash_and_the_time_and_follows_the_secret() {
        let sign = |credentials: Fake, region: &str| {
            let signer = SigV4Signer::with_clock(credentials, at);
            let mut request = unsigned("public/index.json");
            signer.sign(&mut request, region).unwrap();
            request
        };
        let request = sign(fake(), "us-east-1");
        let authorization = header(&request, "authorization");
        assert!(
            authorization.starts_with(&format!(
                "AWS4-HMAC-SHA256 Credential={KEY_ID}/20261119/us-east-1/s3/aws4_request, SignedHeaders="
            )),
            "{authorization}"
        );
        let signed_headers = authorization
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .unwrap();
        for name in ["host", "x-amz-content-sha256", "x-amz-date"] {
            assert!(
                signed_headers.split(';').any(|h| h == name),
                "{signed_headers}"
            );
        }
        assert_eq!(header(&request, "x-amz-date"), "20261119T050000Z");
        assert_eq!(
            header(&request, "x-amz-content-sha256"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            header(&request, "x-amz-security-token"),
            "",
            "no token, no header"
        );
        let signature = authorization.rsplit("Signature=").next().unwrap();
        assert_eq!(signature.len(), 64);
        assert!(signature.bytes().all(|b| b.is_ascii_hexdigit()));
        // The same inputs give the same signature; another secret, another Region or another
        // key give another.
        assert_eq!(
            header(&sign(fake(), "us-east-1"), "authorization"),
            authorization
        );
        let other = |c, region| header(&sign(c, region), "authorization").to_string();
        let changed = Fake {
            secret: "ANOTHERSECRETFAKE",
            ..fake()
        };
        assert_ne!(other(changed, "us-east-1"), authorization);
        assert_ne!(other(fake(), "us-west-2"), authorization);
        // A session token is sent and signed.
        let with_token = sign(
            Fake {
                token: Some(TOKEN),
                ..fake()
            },
            "us-east-1",
        );
        assert_eq!(header(&with_token, "x-amz-security-token"), TOKEN);
        assert!(header(&with_token, "authorization").contains("x-amz-security-token"));
    }

    /// The secret key is not in anything that is sent, printed or returned as an error.
    #[test]
    fn the_secret_key_appears_nowhere_it_should_not() {
        let log = events();
        let fetcher = SignedFetcher::new(
            SigV4Signer::with_clock(
                Fake {
                    token: Some(TOKEN),
                    ..fake()
                },
                at,
            ),
            FakeTransport::replying(&log, 403, "<Code>AccessDenied</Code>"),
        );
        let outcome = fetcher.get(&object("public/index.json"), 100);
        assert!(matches!(&outcome, Err(FetchError::Denied(why)) if why.contains("AccessDenied")));
        let sent = fetcher.transport.sent.borrow();
        let on_the_wire = format!("{:?}", sent[0]);
        assert!(
            on_the_wire.contains(KEY_ID),
            "the key id is the public half"
        );
        for text in [
            on_the_wire,
            format!("{fetcher:?}"),
            format!("{outcome:?}"),
            outcome.as_ref().unwrap_err().to_string(),
        ] {
            assert!(!text.contains(SECRET), "the secret leaked: {text}");
        }
        // Credentials that cannot be had: the reason is plain, the secret is not in it, and
        // nothing is sent.
        let log = events();
        let fetcher = SignedFetcher::new(
            SigV4Signer::with_clock(
                Fake {
                    fails: true,
                    ..fake()
                },
                at,
            ),
            FakeTransport::new(&log),
        );
        let outcome = fetcher.get(&object("public/index.json"), 100);
        let Err(FetchError::Transport(reason)) = &outcome else {
            panic!("expected a refusal to send, got {outcome:?}");
        };
        assert!(reason.starts_with("no AWS credentials"), "{reason}");
        assert!(!reason.contains(SECRET) && !format!("{fetcher:?}").contains(SECRET));
        assert!(
            log.borrow().is_empty(),
            "an unsigned request must never be sent"
        );
        assert!(fetcher.transport.sent.borrow().is_empty());
    }

    #[test]
    fn the_profile_override_is_the_explicit_name_then_the_environment_then_nothing() {
        assert_eq!(profile_override(Some("a"), Some("b")).as_deref(), Some("a"));
        assert_eq!(profile_override(None, Some("b")).as_deref(), Some("b"));
        assert_eq!(profile_override(Some(""), Some("b")).as_deref(), Some("b"));
        assert_eq!(profile_override(Some("  "), None), None);
        assert_eq!(profile_override(Some(" a "), None).as_deref(), Some("a"));
        assert_eq!(profile_override(None, None), None);
    }

    /// A server on this machine only (loopback, a port the system picks), for the transport tests.
    /// `/redirect` answers 302 to `/final`, `/final` answers 200, `/big` answers 1000 bytes and
    /// `/slow` says nothing for three seconds.
    fn local_server() -> String {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
                        if stream.read(&mut byte).unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let head = String::from_utf8_lossy(&head).to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let reply: Vec<u8> = match path.as_str() {
                        "/redirect" => b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                        "/final" => b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfinal".to_vec(),
                        "/big" => [
                            b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n".to_vec(),
                            vec![b'x'; 1000],
                        ]
                        .concat(),
                        _ => {
                            std::thread::sleep(Duration::from_secs(3));
                            return;
                        }
                    };
                    let _ = stream.write_all(&reply);
                });
            }
        });
        base
    }

    fn get_from(base: &str, path: &str) -> http::Request<()> {
        http::Request::builder()
            .method("GET")
            .uri(format!("{base}{path}"))
            .body(())
            .unwrap()
    }

    /// The transport a user gets refuses a plain http address, and says why, before it opens any
    /// connection.
    #[test]
    fn the_transport_will_not_send_over_plain_http() {
        let base = local_server();
        let transport = ReqwestTransport::new().unwrap();
        let error = transport.get(&get_from(&base, "/final"), 10).unwrap_err();
        assert!(error.contains("scheme"), "{error}");
    }

    #[test]
    fn the_transport_does_not_follow_a_redirect() {
        let base = local_server();
        let transport = ReqwestTransport::build(false, Duration::from_secs(5)).unwrap();
        let reply = transport.get(&get_from(&base, "/redirect"), 100).unwrap();
        assert_eq!(reply.status, 302);
        assert!(reply.body.is_empty());
        // Through the fetcher this is an error, never a read of wherever it pointed.
        assert_eq!(
            transport
                .get(&get_from(&base, "/final"), 100)
                .unwrap()
                .status,
            200
        );
    }

    #[test]
    fn the_transport_gives_up_when_the_time_limit_passes() {
        let base = local_server();
        let transport = ReqwestTransport::build(false, Duration::from_millis(300)).unwrap();
        let started = std::time::Instant::now();
        let error = transport.get(&get_from(&base, "/slow"), 100).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_millis(2500),
            "{:?}",
            started.elapsed()
        );
        assert!(error.starts_with("the request failed"), "{error}");
    }

    /// The body is read up to the cap and one byte more, so the caller can see it was too long
    /// without holding all of it.
    #[test]
    fn the_transport_stops_reading_past_the_cap() {
        let base = local_server();
        let transport = ReqwestTransport::build(false, Duration::from_secs(5)).unwrap();
        let reply = transport.get(&get_from(&base, "/big"), 100).unwrap();
        assert_eq!((reply.status, reply.body.len()), (200, 101));
        let reply = transport.get(&get_from(&base, "/big"), 1000).unwrap();
        assert_eq!(reply.body.len(), 1000);
    }

    #[tokio::test]
    async fn the_credential_chain_is_not_built_inside_an_async_runtime() {
        let Err(message) = SdkCredentials::new(None) else {
            panic!("expected a refusal");
        };
        assert!(message.contains("outside the async runtime"), "{message}");
    }

    #[test]
    fn the_chain_a_user_gets_has_the_thirty_second_limit() {
        assert_eq!(CREDENTIALS_TIME_LIMIT, Duration::from_secs(30));
        let chain = SdkCredentials::new(Some("no-such-profile")).unwrap();
        assert_eq!(chain.limit, CREDENTIALS_TIME_LIMIT);
        for short in [Duration::ZERO, Duration::from_millis(999)] {
            let chain = SdkCredentials::with_time_limit(Some("no-such-profile"), short).unwrap();
            assert_eq!(chain.limit, Duration::from_secs(1), "{short:?} is raised");
        }
        let long = SdkCredentials::with_time_limit(None, Duration::from_secs(90)).unwrap();
        assert_eq!(long.limit, Duration::from_secs(90));
    }

    const CHAIN_PROBE_ENV: &str = "AVAILABILITY_FETCH_CHAIN_PROBE_OUT";
    const CHAIN_PROBE_TEST: &str =
        "availability_fetch::tests::a_credential_helper_that_hangs_is_given_up_on_and_nothing_is_cached";

    /// What the child run does: a quick helper's answer is used, a hanging helper is given up on
    /// at the limit, the refresh fails with a plain reason, and no cache is written, so the
    /// bundled data stays in use.
    #[cfg(unix)]
    fn chain_probe(out: &std::ffi::OsStr) {
        let quick = SdkCredentials::with_time_limit(Some("quick"), Duration::from_secs(2))
            .unwrap()
            .credentials()
            .map(|c| c.access_key_id().to_string());
        let started = std::time::Instant::now();
        let fetcher = SignedFetcher::new(
            SigV4Signer::new(
                SdkCredentials::with_time_limit(Some("slow"), Duration::from_secs(2)).unwrap(),
            ),
            ReqwestTransport::new().unwrap(),
        );
        let cache = temp_dir("chain-probe-cache");
        let outcome = refresh_with(&fetcher, &cache, SystemTime::now(), 0);
        let elapsed = started.elapsed().as_millis();
        let cached = std::fs::read_dir(&cache).unwrap().count();
        std::fs::remove_dir_all(&cache).unwrap();
        let reason = match outcome {
            Ok(_) => "a refresh happened".to_string(),
            Err(error) => error.to_string(),
        };
        std::fs::write(out, format!("{quick:?}\n{elapsed}\n{cached}\n{reason}\n")).unwrap();
    }

    /// A `credential_process` that hangs is given up on at the time limit. The test runs itself
    /// in a child process whose AWS config holds two helpers (one answers at once, one sleeps),
    /// with no credentials in its environment and no home folder of the user's.
    #[cfg(unix)]
    #[test]
    fn a_credential_helper_that_hangs_is_given_up_on_and_nothing_is_cached() {
        use std::os::unix::fs::PermissionsExt;
        if let Some(out) = std::env::var_os(CHAIN_PROBE_ENV) {
            chain_probe(&out);
            return;
        }
        let dir = temp_dir("chain-probe");
        let helper = |name: &str, body: &str| {
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            path.display().to_string()
        };
        let quick = helper(
            "quick.sh",
            &format!(
                "echo '{{\"Version\":1,\"AccessKeyId\":\"{KEY_ID}\",\"SecretAccessKey\":\"{SECRET}\"}}'"
            ),
        );
        let slow = helper("slow.sh", "exec sleep 20");
        std::fs::write(
            dir.join("config"),
            format!(
                "[profile quick]\ncredential_process = {quick}\n\n\
                 [profile slow]\ncredential_process = {slow}\n"
            ),
        )
        .unwrap();
        std::fs::write(dir.join("credentials"), "").unwrap();
        let out = dir.join("result.txt");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([CHAIN_PROBE_TEST, "--exact", "--test-threads=1"])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &dir)
            .env("AWS_CONFIG_FILE", dir.join("config"))
            .env("AWS_SHARED_CREDENTIALS_FILE", dir.join("credentials"))
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env(CHAIN_PROBE_ENV, &out)
            // The sleeping helper outlives the child; do not wait on its pipes.
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        let result = std::fs::read_to_string(&out).unwrap_or_default();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(status.success(), "the child run failed: {result}");
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 4, "{result}");
        assert_eq!(
            lines[0],
            format!("Ok({KEY_ID:?})"),
            "the quick helper is used"
        );
        let elapsed: u128 = lines[1].parse().unwrap();
        assert!(
            (1900..8000).contains(&elapsed),
            "the slow helper is waited on up to the limit only: {elapsed} ms"
        );
        assert_eq!(lines[2], "0", "no cache file is written");
        assert_eq!(
            lines[3],
            "could not fetch public/index.json: no AWS credentials: the AWS credential chain \
             did not answer within 2 s (check credential_process and SSO in your AWS config)"
        );
        assert!(!result.contains(SECRET));
    }
}
