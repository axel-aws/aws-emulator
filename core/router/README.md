# aws-emulator-router

The emulator binary. It owns no service logic: it constructs the single shared
`InMemoryEngine` per tenant and mounts every `service-*` crate on one endpoint,
keyed by each service's SigV4 signing name (`ROUTE_KEY`).

```bash
cargo run -p aws-emulator-router
```

Binds the emulator API and its `GET /__admin/health` readiness endpoint on
`:9297` (self-signed HTTPS); override with `EMULATOR_DATA_PORT` or `-p`.
Options (after `--` with `cargo run`): `-h` help, `-v` version, `-b <ip>` / `-p <port>`
(override the variables above), `-a on|off` SigV4 request authentication with this run's
keys (default on), `-t on|off` usage telemetry for this run, `--idle-timeout 900` exit after 900 seconds
without an API call.

## Regional availability checks

The emulator checks each request against AWS's published Regional availability data, so a call
or a template that AWS would refuse in the Region it names does not quietly work here.

- **API requests.** Right after the router picks the service, it asks whether AWS offers that
  service in the Region the request is signed for. With `EMULATOR_REGION_AVAILABILITY` unset the
  request is served and one `warn` line says what `enforce` would have done. A service or a Region
  the data does not list is never refused.
- **CloudFormation.** `CreateStack`, `UpdateStack` and `CreateChangeSet` refuse a template that
  declares a resource type the Region does not offer, with CloudFormation's own wording for an
  unknown type. This check defaults to `enforce`.

| Setting | Effect |
|---|---|
| `EMULATOR_REGION_AVAILABILITY=off` | Every check is off, and so is the refresh below. Nothing is read from the cache and nothing is fetched. |
| `EMULATOR_REGION_AVAILABILITY=warn` or `enforce` | Sets the mode of both checks. A value that is none of `off`, `warn` and `enforce` is logged once and the default of each check is used. |
| `EMULATOR_REGION_AVAILABILITY_REFRESH=off` | Turns off only the network refresh. The checks run on the bundled data, or on a cache an earlier refresh wrote. `off`, `false`, `0`, `no` and `disabled` mean off; `on`, `true`, `1`, `yes`, `enabled`, empty or unset mean on. Any other text means off, and is logged once. |
| `EMULATOR_REGION_AVAILABILITY_CACHE` | The folder that holds the cache files. Default: `$XDG_CACHE_HOME/aws-emulator/region-availability`, else `~/.cache/aws-emulator/region-availability`. Nothing is written under `~/.aws`. |
| `EMULATOR_REGION_AVAILABILITY_PROFILE` | The AWS profile the refresh reads credentials from. |

**The data.** A snapshot is bundled, so the checks work offline and with no AWS account. When the
emulator starts it reads the cache an earlier refresh wrote and uses it if it is newer than the
bundled data. In the background, without delaying start-up, it then looks for newer data: only when
the AWS SDK's default credential chain finds credentials, and only when the last successful check
is more than 6 hours old. While it runs it looks again every 12 hours. The data comes from the
public Regional availability S3 access point, which AWS publishes about daily, and a new copy
replaces the old one only when it is complete and newer. Every failure (no credentials, no network,
a proxy, access denied, a bad or older file) leaves the data in use as it was and logs one `info`
line the first time. `cargo run -p service-common --bin refresh-region-data` does the same refresh
in the foreground and prints what it did (`--status` prints which data is in use).

The refresh runs only in this program, never in embedded mode.

## How a service gets mounted

`src/lib.rs` is **re-rendered on every service add** — edits there are overwritten. `src/main.rs` is emitted once and must not be edited — only `tests/` is editable here. For each service it does one thing:

- `router.register_service(<service>::EmulatedService::new(engine.clone()))` —
  construct the service from the single shared engine and mount it. Each operation
  receives the engine through its constructor and reaches the shared store through
  `self.engine`.

`MultiServiceRouter` then picks the service whose `can_handle` claims each request
(seeded from the model's SigV4 signing name), and the service's protocol names the
operation.

## Tests

`router/tests/` is for CROSS-service behaviour (e.g. one service invoking
another). Single-service tests belong in that service's own crate, where they
run without rebuilding the rest of the workspace.

Put a router suite at `router/tests/all/<name>.rs` and nothing else: every `.rs` file
in that directory is a suite of the `all` target, so there is nothing to declare, and
its root `router/tests/all/main.rs` is not editable. That is the router's only test
target: every target links all services, so a file directly under `router/tests/` fails
the build.
