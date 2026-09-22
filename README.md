# Cachew

Cachew (pronounced "cashew") is a tiered, protocol-aware, caching HTTP proxy for software engineering infrastructure. It understands higher-level protocols (Git, Docker, Go modules, etc.) and makes smarter caching decisions than a naive HTTP proxy.

## Strategies

### Git

Caches Git repositories with two complementary techniques:

1. **Snapshots** — periodic `.tar.zst` archives that restore 4–5x faster than `git clone`.
2. **Pack caching** — passthrough caching of packs from `git-upload-pack` for incremental pulls.

Redirect Git traffic through cachew:

```ini
[url "https://cachew.example.com/git/github.com/"]
  insteadOf = https://github.com/
```

Restore a repository from a snapshot (with automatic delta bundle to reach HEAD):

```sh
cachew git restore https://github.com/org/repo ./repo
```

Snapshot creation and extraction require `tar` and `pzstd` on `PATH`.
Restores use `pzstd` to decode the parallel frames produced by Cachew's
snapshot writer. `--zstd-threads` controls decompression workers (zero uses
the process CPU budget); ordinary zstd archives remain readable, but a
single-frame archive does not gain frame-level parallelism.

```hcl
git {
  snapshot-interval = "1h"
  repack-interval   = "1h"
}
```

### GitHub Releases

Caches public and private GitHub release assets. Private orgs use a token or GitHub App for authentication.

**URL pattern:** `/github-releases/{owner}/{repo}/{tag}/{asset}`

```hcl
github-releases {
  token        = "${GITHUB_TOKEN}"
  private-orgs = ["myorg"]
}
```

### Go Modules

Go module proxy (`GOPROXY`-compatible). Private modules are fetched via git clone.

**URL pattern:** `/gomod/...`

```sh
export GOPROXY=http://cachew.example.com/gomod,direct
```

```hcl
gomod {
  proxy         = "https://proxy.golang.org"
  private-paths = ["github.com/myorg/*"]

  package-policy {
    mode = "audit" # start here; omitted mode defaults to enforce

    socket {
      api-url      = "https://api.socket.dev"
      organization = "my-socket-org"
      token        = "${SOCKET_SECURITY_API_TOKEN}"
    }
  }
}
```

In `audit` or `enforce` mode, Cachew evaluates the PURL for each
canonical-version public module `GET`, including cached module files, before
it serves or downloads them. Branch and revision `.info` queries pass through so
the Go proxy can resolve them; the resulting canonical version's module files are
evaluated before download. The `socket` provider sends the PURL to Socket;
modules matching `private-paths` are not sent. Verdicts are reused for
up to `verdict-ttl`, subject to the verdict cache capacity described below.
`private-paths` uses the same module-prefix globs as `GOPRIVATE` for both fetch
routing and policy exclusion: a pattern matches the module itself and every module
nested beneath it, so `github.com/myorg/*` also covers `github.com/myorg/repo/sub`.

In `enforce` mode, pending analysis and provider failures fail open by default,
but newly downloaded module files are not cached. Their policy results can be
reused briefly under `pending-ttl`; they are not approvals. In `audit` mode,
policy results do not change serving or artifact caching. See the shared
[package-policy contract](#package-policy-modes-and-outcomes) below.
Go module `HEAD` requests return `405 Method Not Allowed`, whether or not package
policy is enabled, so bodyless requests cannot trigger uncached module downloads.

### Hermit

Caches [Hermit](https://cashapp.github.io/hermit/) package downloads. GitHub release URLs are automatically routed through the `github-releases` strategy.

**URL pattern:** `/hermit/{host}/{path...}`

```hcl
hermit {}
```

### Artifactory

Caches artifacts from JFrog Artifactory with host-based or path-based routing.

```hcl
artifactory "example.jfrog.io" {
  target = "https://example.jfrog.io"
}
```

### AWS CodeArtifact

Proxies read-only package requests to an AWS CodeArtifact repository. Cachew
assumes the configured IAM role and refreshes CodeArtifact authorization tokens
without exposing them to clients. Requests use host-based routing.

CodeArtifact deployments may opt into `immutable-fallback-ttl = "1h"` (allowed:
1 second through 24 hours; default `0`, disabled). This supplies a local freshness
budget only for `public, immutable` artifacts that omit both `max-age`/`s-maxage`
and `Expires`. Explicit stale or invalid freshness is never overridden. Rewritten
package metadata is excluded. Origin `Age` and `Date` reduce the budget, and cache
hits retain the origin policy and validators while reporting their current age.
Disabling or shortening the option also restricts existing fallback entries.
Requests with `Cache-Control` or `Pragma` directives bypass artifact reuse and storage.
This is an operator-selected policy: enabling it can delay visibility of artifact
removal or access revocation by up to the configured lifetime.

```hcl
codeartifact "example-111122223333.d.codeartifact.us-east-1.amazonaws.com" {
  target         = "https://example-111122223333.d.codeartifact.us-east-1.amazonaws.com"
  proxy-base-url = "https://cachew.example.com"
  domain         = "example"
  domain-owner   = "111122223333"
  region         = "us-east-1"
  role-arn       = "arn:aws:iam::111122223333:role/cachew-codeartifact-read"

  credential-timeout       = "15s"
  origin-header-timeout    = "30s"
  origin-read-idle-timeout = "30s"

  package-policy {
    mode          = "audit" # start here; default is enforce for compatibility
    exclude-purls = ["pkg:npm/%40myorg/*"]
    verdict-ttl   = "10m"   # default; 0 disables definitive verdict reuse
    pending-ttl   = "15s"   # default; 0 disables pending/provider-error reuse
    on-failure    = "allow" # default; audit records what enforce would do

    socket {
      api-url      = "https://api.socket.dev"
      organization = "my-socket-org"
      token        = "${SOCKET_SECURITY_API_TOKEN}"
      label        = "cachew" # optional existing Socket policy label
      timeout      = "200ms" # default; total policy-evaluation budget
      queue-timeout = "5s"    # default; local provider-slot wait
    }
  }
}
```

`proxy-base-url` is the public Cachew origin. Cachew uses it to replace
CodeArtifact URLs in npm, Cargo, NuGet, and Swift package metadata so clients
continue downloading through the unauthenticated proxy.

Metadata requests to npm, Cargo, and NuGet origins negotiate gzip independently
of the client. Cachew decodes the response before rewriting, enforcing the 64 MiB
metadata limit on decompressed bytes, and compresses rewritten metadata when
the client's `Accept-Encoding` permits gzip. Responses vary on both the origin's
existing dimensions and `Accept-Encoding`; upstream validators are not reused
for rewritten bytes. `HEAD` responses omit the transformed length and body.
Archive and range requests retain their existing encoding behavior. Swift
origin requests retain identity encoding because extensionless URLs can return
either JSON metadata or archives; rewritten Swift metadata can still be gzipped
for clients. Compression does not change metadata freshness or cache admission.

The role needs `codeartifact:GetAuthorizationToken` and its underlying principal
needs `sts:GetServiceBearerToken`. Repository read permissions remain governed by
the CodeArtifact resource policy.

Credential refresh, including time spent waiting for another required refresh,
has a whole-operation deadline. The origin header deadline begins after the
request is written; dial and TLS setup retain the HTTP transport's own bounds.
Each origin body `Read` has an idle deadline, so downstream client or cache writes
do not count as origin stalls and large downloads have no fixed total-duration
limit. A body read timeout cancels the origin request and is reported as
`status=read_idle_timeout` in the CodeArtifact origin metrics.

Authorization tokens are reused in-process. The default 12-hour token enters
proactive refresh one hour before expiration; one request performs each refresh
attempt under a detached, bounded context while concurrent requests continue
using the valid token. Shorter-lived tokens enter proactive refresh halfway
through their lifetime.

Omitting a timeout or setting it to zero uses the documented default. Negative
timeout values are rejected.

#### Package-policy modes and outcomes

The optional `package-policy` block checks standard Package URLs (PURLs) against
the configured organization's [Socket package
policy](https://docs.socket.dev/reference/batchpackagefetchbyorg). It runs before
Cachew returns an artifact body, including a cache hit, or requests origin
credentials. Omitting the block disables policy checks.
Package-policy evaluation currently supports only npm through CodeArtifact and
Go modules through `/gomod/`. PyPI, Maven, Cargo, and other CodeArtifact formats
retain their existing proxy/cache behavior but are not evaluated by Socket.

| Setting | Default | Behavior |
| --- | --- | --- |
| `mode` | `enforce` | `disabled` makes no provider queries and requires no Socket configuration; `audit` evaluates but never blocks or changes artifact caching; `enforce` applies the decision before serving. |
| `on-failure` | `allow` | Maps pending analysis and provider errors to fail-open behavior; `deny` maps them to denial. Audit reports the same mapping without enforcing it. |
| `verdict-ttl` | `10m` | Maximum reuse of definitive allow/deny results; `0` disables this reuse. |
| `pending-ttl` | `15s` | Short reuse of pending results and provider errors; `0` disables this reuse. It never turns them into approvals. |
| `socket.label` | omitted | Selects one existing Socket policy-label slug using the API's `labels` parameter. Confirm the label's intended policy before rollout. |
| `socket.timeout` | `200ms` | Total Socket evaluation budget, including queueing, shared-call waits, retries, and HTTP response reading. Accepts positive durations up to `20m`, including subsecond values. Zero selects the default. |
| `socket.queue-timeout` | `5s` | Maximum local wait for a provider slot, also bounded by the remaining total evaluation budget; zero selects the default. Negative values are rejected. |

Override `timeout` in each strategy's `package-policy.socket` HCL block (for
example, `timeout = "500ms"`), then restart Cachew to apply it. An explicit value
overrides the default; changing the default does not replace existing settings.

`mode = "audit"` adds `X-Cachew-Package-Policy: audit-would_allow` or
`audit-would_deny` to evaluated responses and records `would_allow` or
`would_deny` outcomes. Excluded and out-of-scope packages carry no policy header
in any mode. Ordinary origin/cache errors and existing authorization
rules still apply. Audit is not an asynchronous background check: a cold request
can still wait for evaluation. `on-failure = "allow"` in `enforce` mode is
**not audit**: a definitive Socket denial still blocks the download.

| Result | Enforce, `on-failure = "allow"` | Enforce, `on-failure = "deny"` | Audit |
| --- | --- | --- | --- |
| Socket allows | Serve; normal cache rules | Serve; normal cache rules | Serve normally; `would_allow` |
| Socket denies (`error` action) | `403`, policy header `deny` | `403`, policy header `deny` | Serve normally; `would_deny` |
| Pending/unindexed package | Serve cached bytes or fetch without storing new bytes; header `pending` | `403`, policy header `deny` | Serve normally; `would_allow` / `would_deny` according to `on-failure` |
| Provider error, evaluation timeout during an active provider call, malformed response, or open breaker | Serve cached bytes or fetch without storing new bytes; header `unavailable` | `403`, policy header `deny` | Serve normally; `would_allow` / `would_deny` according to `on-failure` |
| Unsafe or unmappable npm body path | `403` | `403` | Serve normally; `would_deny` |
| Provider-slot queue deadline or total budget exhausted while waiting for a slot | `503`, policy header `overloaded` | `503`, policy header `overloaded` | Serve normally; `would_deny` |

Disabled policy and privacy exclusions retain normal proxy/cache behavior without
provider queries. Client cancellation ends the request; it is not an audit
result or a provider outage. Local queue overload is not a Socket failure and
does not become fail-open merely because `on-failure = "allow"`.

`exclude-purls` accepts Go-style path glob patterns for npm PURLs only; npm scopes
may be written as `@scope` or `%40scope`. Matching packages are recorded as
`not_applicable` and continue through normal cache/origin handling without sending
their names or versions to the policy provider. Use it
for private packages that share a CodeArtifact repository with public
dependencies. Use `private-paths` for Go module exclusions. Repository metadata
and all non-npm CodeArtifact formats pass through unevaluated.
Query strings make CodeArtifact responses uncacheable but do not bypass policy
evaluation for recognized package asset paths. The PURL is derived from the
escaped request path, so a percent-encoded slash cannot change which package is
evaluated: `@scope%2Fname` in the package-name position is evaluated as the
scoped npm package, and any other encoded separator under the npm format is
denied in `enforce` mode because the origin would receive a path Cachew did not evaluate.
For CodeArtifact VPC endpoint origins (`vpce.amazonaws.com`), Cachew normalizes
`/npm/d/domain-owner/repository/` to `/npm/repository/` before deriving the PURL.
Recognized npm bodies that cannot be mapped are also denied in `enforce` mode,
independent of `on-failure`. Audit records these denials without enforcing them.
CodeArtifact `HEAD` requests are never evaluated and never admit a body to the cache.

#### Package audit files

An optional top-level block emits one structured NDJSON record for each npm
artifact `GET` handled by an enabled CodeArtifact package policy:

```hcl
package-audit {
  directory = "/var/log/cachew-package-audit"
}
```

The directory must be private (`0700`), dedicated to one Cachew process, and
absolute. Files are `0600`; run a separate collector under the same UID. Omitting
the block disables collection. This does not send logs to any external service.
Use a collector such as Fluent Bit to tail `package-audit-*.ndjson` and batch them
to your approved destination with a persistent checkpoint and upload buffer.
Mount the audit directory read-only in the collector. Collectors must never
delete, rename, or truncate files, including after upload: any segment may still
be open for writing. Cachew alone owns rotation and deletion.

Records include a schema version, unique event ID, completion timestamp, PURL,
policy mode and verdict, classified error, actual policy action, verdict-cache
hit, response source, HTTP status, and policy/request durations. Audit denials
have action `allow`; pending or failed-open results are not reported as provider
approvals.
`verdict_cache_hit = false` does not prove this request made a provider call:
requests can share an evaluation, hit a breaker, or be excluded. Response source
`origin` means the origin-handling path, including credential and upstream errors.
An HTTP `200` does not prove a complete download or package installation.

Excluded packages have `package_redacted = true`; unmappable paths have no PURL
but are not privacy-redacted. Local mapping failures and overload are `deny`,
not provider unavailability. Canceled requests preserve a known original verdict;
without one they are `not_evaluated`, not a provider denial or approval.
Records never include raw
URLs, queries, headers, provider response text, or asserted caller names. The
actor is explicitly `unknown`: this proxy cannot authenticate an individual from
caller-supplied headers. PURLs are untrusted request-derived coordinates, not
validated public package metadata; their text can contain caller-chosen data.
Other private packages still need exclusion before
external delivery. Go modules, non-npm formats, metadata, `HEAD`, disabled policy,
generic object API calls, and requests satisfied by a client's local cache are
not included in this initial audit stream.

Delivery is bounded and best-effort, not a lossless security ledger. Request
handlers do not wait for disk, S3, or the SIEM. The queue holds 4,096 records;
records whose PURL and policy fields exceed 4 KiB, or whose encoded line exceeds
8 KiB, are dropped as invalid. Normally at most sixteen 16 MiB nonempty segments
are retained. A pending segment does not evict history until its first
successful write. Disk write failures retain the same file and back off for one
second. If eviction fails, at most one extra segment remains and further writes
pause until pruning succeeds. New filenames use increasing sequences,
independent of wall-clock changes across restarts. Older timestamp-named files
are preserved ahead of new segments, but their historical order cannot be
reconstructed. Old files can be removed before a stalled collector reads them.
Node loss can lose local records and upload buffers; downstream retries may
duplicate records, so deduplicate on `event_id`. Graceful shutdown reserves up
to five seconds inside `shutdown-timeout` (at most half a shorter budget) for
audit drain, after HTTP shutdown. If HTTP draining exceeds its initial budget,
handlers may use the remaining shutdown budget before the sink closes. At the
overall deadline, remaining connections are closed and queued records are
abandoned. A blocked disk syscall cannot be forcibly interrupted: cleanup,
directory lock release, and `dropped_shutdown_timeout` accounting wait for the
worker to resume or the process to exit. The caller still returns by its
deadline. Abrupt termination can lose queued or unsynced records.

The audit directory must be owned by the daemon's effective user with mode 0700.
Ancestors must be owned by root or that user, and must not be group/world writable
unless sticky. Leaf symlinks are rejected; trusted relative descendant aliases
(such as macOS `/tmp`) are supported, but absolute or `..` aliases are not.

Monitor `cachew.package_audit.events_total` by `result` for writes and drops,
`cachew.package_audit.retention_evictions_total` for files evicted with delivery
unknown, `cachew.package_audit.sync_errors_total` for disk-sync errors,
`cachew.package_audit.retention_errors_total` for failed pruning,
`cachew.package_audit.shutdown_timeouts_total` for abandoned drains, and the
aggregated warning logs. A local write or collector success
counter is not proof of SIEM ingestion: verify S3 arrivals, buffer disk use, and
SIEM ingestion lag separately before relying on coverage.

#### Verdict reuse and overload

Every eligible `GET`, including an artifact-cache hit, consults the verdict
cache. An unexpired definitive result avoids Socket; after expiry or eviction,
Cachew waits for a new result before returning the body. Socket requests explicitly
use `poll=false` to return the current known state without waiting for pending
analysis to complete. An allow reflects Socket's available analysis, not proof of
a fresh or completed scan. Explicit `pendingScan` and `notFound` results still
follow `on-failure`; setting it to `deny` does not make available-analysis allows
wait for a fresh scan.

Available-analysis allow/deny results retain `verdict-ttl` (default `10m`), so an
allow can delay reevaluation for that duration even if additional Socket analysis
finishes sooner. Requests remain bounded by `socket.timeout` (default `200ms`).

Pending analysis (`pendingScan` or `notFound`) and provider errors are reused for
`pending-ttl` to avoid repeatedly calling Socket for the same unresolved package.
The original pending/error semantics remain intact, including the prohibition on
storing new artifact bytes under fail-open enforcement. Open-breaker responses,
local overload, and caller cancellations are not cached. A provider deadline
error may be reused only when the requesting client is still active.

Each strategy instance keeps at most 100,000 results in an in-memory LRU and
coalesces concurrent misses for the same PURL. There is no reuse or coalescing
across strategies, replicas, or restarts. A large working set, simultaneous TTL
expiry, or rollout can therefore amplify provider traffic even when artifact
bytes are warm. Each provider request contains one PURL.

Every Socket evaluation has one `socket.timeout` budget covering provider-slot
queueing, waiting for a shared call, retries after a shared call's owner cancels,
and the full HTTP response. Retries do not reset this deadline, and there is no
additional HTTP grace period. This budget applies only to policy evaluation, not
the subsequent artifact download. If the budget expires while Socket is being
queried (including a shared query), the result follows `on-failure`, which defaults
to fail-open.

Socket's [API](https://docs.socket.dev/reference/batchpackagefetchbyorg) accepts
`timeoutSec` only in whole seconds, so that parameter is rounded up while Cachew
still enforces the exact local budget. A short budget can increase fail-open
responses and breaker openings when Socket cannot respond within it.

At most 16 provider calls run concurrently across all strategies in one process.
Other callers wait for a slot for at most `socket.queue-timeout` or the remaining
evaluation budget, whichever is shorter. At the defaults, the total budget limits
local queueing to at most 200ms, not 5s. Exhausting either limit while waiting for
local capacity remains overload, not a fail-open provider error: it returns
`503` with `Retry-After: 1` in enforce mode. The `go` command treats any proxy error other
than `404` or `410` as terminal and does not retry, so size the deadline for the
largest expected cold install rather than relying on client retries. This limits
wait duration, not the number of arrivals or requests per second. Configure [HTTP admission](#request-admission)
to bound total in-process requests as well; it is disabled by default.

Five consecutive transport or HTTP failures open the strategy's breaker for
30 seconds. Malformed responses, pending analysis, and local overload do not
trip it. The breaker closes after cooldown without a single-probe recovery phase.
In fail-open enforcement, an open breaker permits unchecked traffic; in fail-closed
enforcement it denies traffic. Audit still reports the corresponding hypothetical
outcome. A temporary error-cache hit does not make another provider call or
advance the breaker.

Checking Socket only on an artifact-body miss would be **admission-only** policy:
a later denial could not stop already-cached bytes. Serving an expired allow
while refreshing in the background would be **stale-while-revalidate** policy:
requests during refresh could still receive a newly denied package. Neither is
implemented. The current synchronous check preserves policy changes independently
of artifact retention, subject to verdict TTLs and the chosen failure mode.

#### Package identity and privileged cache access

A later policy change does not remove an admitted object's bytes from the cache.
Keep the generic `/api/v1/object/{namespace}/{key}` API restricted to trusted
operators and cache peers. It bypasses package-policy evaluation and can read or
replace entries in the `codeartifact` and `gomod` namespaces. Do not grant package
consumers generic object reads or writes to these namespaces; the default OPA
policy's remote `/api` restriction must be preserved in any shared policy.

Cachew's generic `delete` operation accepts one exact cache key, but CodeArtifact
can store multiple representations of one URL. The unhashed key material is the
origin URL followed by these optional lines, in this order:

```text
https://codeartifact.example.com/npm/repository/package/-/package-1.0.0.tgz
Accept=<comma-joined request values>
Accept-Encoding=<comma-joined request values>
```

`cachew delete codeartifact <key-material>` hashes that material and deletes the
matching object from every backend configured in that Cachew deployment. Run it
against every deployment that may hold a local tier. A separate key exists for
every observed header combination, and Cachew cannot currently list or delete
keys by package path or PURL. The command is therefore a complete targeted purge
only when every request variant is known. Otherwise operators must clear every
backing tier with deployment-specific tooling or wait for the origin TTL; Cachew
does not currently provide a reliable targeted purge for that incident.

Socket receives the public ecosystem, package name, and version from the
request path, plus the configured policy label when present. This identifies a
public package coordinate, **not the identity of the bytes returned by
CodeArtifact**: Cachew does not prove those bytes match Socket's analyzed artifact.
Private or republished packages sharing a public name/version need an explicit
exclusion or a separate identity policy. Cachew does not send package contents,
CodeArtifact credentials, repository names, or AWS identity to Socket. Operators should
still treat the package name and version as data crossing from their
CodeArtifact environment to Socket's SaaS boundary.

The Socket token needs only the `packages:list` scope. Keep it out of the HCL
file by using an environment placeholder as shown above and inject
`SOCKET_SECURITY_API_TOKEN` into the Cachew container from the deployment's
secret manager. For example, Kubernetes can source the environment variable
from a `Secret` with `env[].valueFrom.secretKeyRef`; the secret does not need to
be exposed to package-manager clients.
For enabled policy, omitted `mode`, `on-failure`, and `socket.api-url` use their
HCL defaults; explicit empty values, including unset required environment
placeholders, fail startup. `mode = "disabled"` does not require a provider or token.

#### Provider quota and rollout

Socket's published [rate-limit guide](https://docs.socket.dev/reference/rate-limits)
states 600 requests per minute and notes that unsuccessful requests also count.
The [org-scoped PURL endpoint](https://docs.socket.dev/reference/batchpackagefetchbyorg)
documents 100 quota units per request, a default maximum batch of 1,024 PURLs,
and one optional policy label. Cachew currently sends only one PURL per request.
The [quota guide](https://docs.socket.dev/reference/quota) separately describes
token quota exhaustion returning `429` with `Retry-After`. These published
numbers are not confirmation of this deployment's organization/token limits.
Cachew does not provide a fleet-wide rate limiter, batch requests, or schedule
retries from Socket's `Retry-After`; its bounded concurrency and breaker do not
replace quota budgeting.

Before enforcement:

1. Confirm the Socket organization, token scopes and actual quota/rate limits,
   intended label policy, approved public-coordinate disclosure, and private
   package exclusions with their owners. Deployment and secret provisioning are
   separate, explicitly authorized work; changing this example does not roll out
   the service or provision credentials.
2. Start with `mode = "audit"` and the intended `on-failure` setting. Verify known
   allow/deny, private exclusions, and cached-body cases. Exercise provider error,
   pending, overload, and cancellation behavior in an isolated test environment,
   not by disrupting the live provider.
3. Measure provider-call rate, verdict hit ratio, queue wait, in-flight calls,
   overloads, and end-to-end latency under representative warm, cold, expired,
   and restart workloads. Budget all replicas and other token consumers against
   confirmed limits; review `would_deny` outcomes and require headroom before
   proceeding. No production-QPS or organization-quota validation is implied by
   the unit tests.
4. Roll out `mode = "enforce"` gradually through the deployment's normal change
   controls, verify cached-body denials and failure-mode behavior, and monitor
   admission failures and provider quota. Keep an explicit rollback to `audit`
   (same evaluation load, no enforcement) or `disabled` (no provider traffic).

A persistent approval store, batching, separate pending/unavailable policies,
or a different freshness model should be added only if measured traffic or an
explicit security requirement justifies them. They are not current features.

#### Policy metrics

All names below use the `cachew.package_policy.` prefix. Attributes are bounded;
package coordinates, URLs, and policy-label slugs are not metric labels.

| Suffix | Meaning | Attributes |
| --- | --- | --- |
| `evaluations_total` | Completed request-level policy outcomes, including reused results and singleflight waiters | `provider`, `outcome` |
| `provider_calls_total` | Actual provider evaluations, not request-level policy checks | `provider`, `outcome` |
| `evaluation_duration_seconds` | Provider duration, excluding local queue wait | `provider`, `outcome` |
| `queue_wait_seconds` | Each provider-slot attempt, including immediate acquisition, timeout, and cancellation; excludes coalesced waiters | `provider` |
| `inflight` | Active provider evaluations | `provider` |
| `verdict_cache_total` | Lookups when result reuse is enabled, including definitive and temporary results | `provider`, `result` (`hit` or `miss`) |
| `breaker_skips_total` | Evaluations skipped while the circuit is open | `provider` |

Each request that joins an in-flight evaluation is counted separately, but requests
abandoned by the client before evaluation completes have no final request outcome.
Provider calls that already started still contribute their call count and duration.
Counter outcomes describe the final policy decision: with `on-failure = "deny"`, pending analysis
and provider failures count as `deny`; audit records `would_allow` or `would_deny`
instead. Local queue rejection counts as `overloaded` in enforce mode and
`would_deny` in audit. Provider-call and latency outcomes retain the provider result, not the
audit or fail-closed mapping. Verdict-cache hits and circuit-breaker skips do not
produce provider-call or provider-duration samples. Unsupported ecosystems,
non-package metadata, and excluded private Go modules
record `not_applicable` so gaps in enforcement coverage remain visible. Metadata
GETs can dominate that outcome, so dashboards should chart it separately and
exclude it from allow/deny availability ratios. Encoded-separator and unmappable-body
denials are logged rather than counted, including audit's corresponding
`audit-would_deny` responses. `HEAD` requests are not counted
because they cannot admit a package body. Compare provider-call totals with
request outcomes rather than treating every evaluation-counter increment as a
Socket request.

Cachew checks its cache for every full CodeArtifact `GET` without a query string,
range, or encoded path separator. On a miss, it stores only a successful,
complete response with a positive shared freshness lifetime and an origin policy
that includes both `public` and `immutable`. Responses with `private`, `no-cache`,
`no-store`, `Set-Cookie`, or unsupported `Vary` fields remain authenticated
pass-through reads. Supported `Accept` and `Accept-Encoding` representations use
separate cache keys, and concurrent cold fills for the same representation are
coalesced. This keeps cache eligibility independent of package-format path
conventions without overriding HTTP shared-cache safety. CodeArtifact generic
packages use AWS CLI or SDK asset APIs rather than a package repository endpoint,
so they are outside this HTTP proxy strategy.

### Host

Generic reverse-proxy caching for arbitrary HTTP hosts, with optional custom headers.

```hcl
host "https://ghcr.io" {
  headers = {
    "Authorization": "Bearer QQ=="
  }
}

host "https://w3.org" {}
```

### HTTP Proxy

Caching proxy for clients that use absolute-form HTTP requests (e.g. Android `sdkmanager --proxy_host`).

```hcl
proxy {}
```

## Cache Backends

Multiple backends can be configured simultaneously — they are automatically combined into a tiered cache. Cache blocks
are ordered from lowest/nearest to highest/authoritative. Reads check each tier in order and backfill lower tiers on a
hit. Writes go to all tiers in parallel. Replica invalidations evict only non-authoritative tiers; the final cache block
is authoritative. Tiered caches use the metadata backend to track authoritative ETags and invalidate stale lower-tier
copies before falling through to the authoritative tier.

Tier-zero backfills are opportunistic and never delay the source response. Cachew
coalesces concurrent fills for the same namespace, key, and source ETag, runs at
most eight fills at once, and permits at most 32 MiB of aggregate queued body
data per process. Fills have a five-minute lifetime. A duplicate request or a
fill that reaches any ceiling is served normally without populating tier zero;
a later request can retry the fill. Only a body read completely through EOF and
then closed successfully is committed.

### Memory

In-memory sharded CLOCK cache with bounded admission and eviction work. Cache
hits lock only the shard containing the requested key. Each trim pass scans at
most 64 entries per shard and commits at most 64 victims, regardless of cache
cardinality. Recently referenced entries receive a CLOCK second chance. If one
bounded pass cannot find enough cold entries, Cachew declines the optional
memory copy instead of extending the scan or blocking unrelated hits; later
admissions continue from the advanced CLOCK hands.

`limit-mb` is a hard accounted-memory ceiling, not a process RSS
limit. Accounting includes object buffers, estimated metadata, and buffers held
by active readers. Every retained entry and incomplete writer has a minimum
4 KiB charge so collections of tiny objects cannot leave Go object and map
overhead unbounded. This means a 1 GiB cache retains at most roughly 262,000
objects even when their payloads are smaller. `Stats.Capacity` reports the hard
accounting ceiling; `Stats.Size` reports payload bytes and can differ because it
excludes charged metadata and spare buffer capacity. Go runtime and allocator
overhead can make RSS differ from both values. `limit-mb = 0` disables the hard
ceiling and permits unlimited retained accounting.

Incomplete writes remain unbounded when `inflight-limit-mb` is zero, preserving
the behavior of configurations written before this option existed. For a
finite `limit-mb`, a positive `inflight-limit-mb` must be smaller and reserves
that amount inside the hard ceiling: retained entries are trimmed toward
`limit-mb - inflight-limit-mb`, and retained plus incomplete accounting cannot
exceed `limit-mb`. With unlimited retention, a positive inflight limit still
bounds incomplete writes independently. Writes that cannot obtain capacity
within the bounded admission work bypass the memory tier without interrupting
other cache tiers. The `cachew.memory.admission_declines_total` counter reports
these events by low-cardinality `reason`.

Declared content lengths are validated against the limits, but buffers grow
only as body bytes arrive and never beyond the declared length. Unknown-length
bodies use a 4 KiB minimum growth allocation for smaller writes and then grow
geometrically; this can retain spare capacity but avoids another full-body copy
at publication, and all spare capacity remains charged. Buffer growth transfers
the existing accounting reservation to the larger capacity; the allocator may
briefly retain both allocations, so process RSS can transiently exceed the
accounting ceiling by the old buffer's capacity.

```hcl
memory {
  limit-mb          = 1024 # default
  inflight-limit-mb = 0    # disabled for compatibility
  max-ttl           = "1h" # default
}
```

### Disk

On-disk LRU cache with TTL-based eviction.

Disk reads are isolated behind fixed operation budgets. Separate pools, each
sized by `read-concurrency`, bound `Stat`/`Open`/body `Read` calls and reader
`Close` calls rather than client-paced stream lifetimes. Idle clients therefore
consume no operation slot while stalled filesystem calls can strand only
bounded resources, and a stuck read cannot prevent its close from running.
`open-reader-limit` bounds all concurrent `Open` lifecycles, including live
readers, readers returned after a timed-out `Open`, and readers waiting in the
fixed close dispatcher. This also bounds file descriptors and cleanup ownership
when `Close` itself stalls.
`operation-timeout` applies to setup and the full close lifecycle, including
queue wait and post-close cleanup; `read-idle-timeout` applies only while a body
`Read` is blocked and does not cap the total transfer duration. A timeout marks
reads degraded for 30 seconds. During that window a tiered cache
tries deeper storage, while an unavailable authoritative disk is treated as a
miss so the caller can regenerate or fetch the object upstream instead of
returning HTTP 500. The request whose body stalls still fails because its
response may already have started. `cachew.disk.read_events_total` attributes
breaker trips, open-reader-limit rejections, and authoritative misses by
operation and tier.

Git snapshot bundle responses expose an untouched file to `http.ServeContent`
so the kernel sendfile path remains available. Those transfers intentionally
bypass per-`Read` isolation, but still hold an `open-reader-limit` slot until the
response closes the file.

```hcl
disk {
  limit-mb          = 250000
  max-ttl           = "8h"
  read-concurrency  = 64
  open-reader-limit = 4096
  operation-timeout = "2s"
  read-idle-timeout = "30s"
}
```

### S3

S3-compatible object storage (AWS S3, MinIO, etc.).

```hcl
s3 {
  bucket   = "my-cache-bucket"
  endpoint = "s3.amazonaws.com"
  region   = "us-east-1"
}
```

## Authorization (OPA)

Cachew uses [Open Policy Agent](https://www.openpolicyagent.org/) for request authorization. The default policy allows all requests from localhost and restricts remote access to non-admin paths (`/api/*`, `/admin/*`).

Policies must be in `package cachew.authz` and define an `allow` rule. If `allow` is true the request proceeds; otherwise it is rejected with 403.

```hcl
opa {
  policy = <<EOF
    package cachew.authz
    default allow := false
    allow if input.headers["authorization"]
  EOF
}
```

Or reference an external file with optional data:

```hcl
opa {
  policy-file = "./policy.rego"
  data-file   = "./opa-data.json"
}
```

**Input fields:** `input.method`, `input.path` (string array), `input.headers`, `input.remote_addr` (includes port — use `startswith` to match by IP).

### Testing policies

The `test` field holds a Rego test module that is run against the policy when `cachewd` starts. Any rule prefixed with `test_` is executed; if a test fails, `cachewd` exits.

```hcl
opa {
  policy = <<EOF
    package cachew.authz
    default allow := false
    allow if input.method == "POST"
  EOF
  test = <<EOF
    package cachew.authz_test
    import data.cachew.authz

    test_post_allowed if authz.allow with input as {"method": "POST"}
    test_get_denied if not authz.allow with input as {"method": "GET"}
  EOF
}
```

## GitHub App Authentication

For private Git repositories and GitHub release assets, configure a GitHub App:

```hcl
github-app {
  app-id           = "12345"
  private-key-path = "./github-app.pem"
  installations    = { "myorg": "67890" }
}
```

Installations can also be discovered dynamically via the GitHub API.

## CLI

### Server (`cachewd`)

```sh
cachewd --config cachew.hcl
cachewd --schema  # print config schema
```

### Client (`cachew`)

```sh
# Object operations
cachew get <namespace> <key> [-o file]
cachew put <namespace> <key> [file] [--ttl 1h]
cachew stat <namespace> <key>
cachew delete <namespace> <key>
cachew namespaces

# Directory snapshots
cachew save <namespace> <directory> [paths...] (--key <key> | -H <glob>) [--ttl 1h] [--exclude pattern]
cachew restore <namespace> <directory> (--key <key> | -H <glob>)  # exit 0 hit, 2 miss, 1 error

# Git
cachew git restore <repo-url> <directory> [--no-bundle]
```

**Global flags:** `--url` (`CACHEW_URL`), `--authorization` (`CACHEW_AUTHORIZATION`), `--platform` (prefix keys with `os-arch`), `--daily`/`--hourly` (prefix keys with date).

## Request Admission

Request admission is disabled by default for compatibility. A positive limit
adds a non-blocking process-wide ceiling held through response completion.
Normal traffic is capped at `limit - reserved` slots. Liveness, readiness, and
authorized `/admin` requests may use any available slot up to `limit`; the
reserve is protected capacity for those requests, not a cap on them. Saturated
requests receive HTTP 503 with `Retry-After: 1` instead of waiting in-process.

```hcl
request-admission {
  limit    = 512
  reserved = 8
}
```

`reserved` defaults to zero and must be smaller than a positive `limit`.

## Observability

```hcl
log {
  level = "info"  # debug, info, warn, error
}

metrics {
  service-name = "cachew"
}
```

Admin endpoints: `/_liveness`, `/_readiness`, `PUT /admin/log/level`, `/admin/pprof/`.

Memory-cache readiness is local and shard-aware. Cachew keeps one private
sentinel object in each memory shard and assigns one persistent probe worker to
each shard. `/_readiness` fails when any sentinel has not traversed the normal
memory `Open` path successfully within five seconds. A stuck shard can strand
only its existing worker; readiness checks read atomic probe timestamps and do
not launch additional goroutines. `/_liveness` remains process-only.

## Full Configuration Example

```hcl
state = "./state"
bind  = "0.0.0.0:8080"
url   = "http://cachew.example.com:8080/"

request-admission {
  limit    = 512
  reserved = 8
}

log {
  level = "info"
}

opa {
  policy = <<EOF
    package cachew.authz
    default allow := false
    allow if startswith(input.remote_addr, "127.0.0.1:")
  EOF
}

metrics {}

github-app {
  app-id           = "12345"
  private-key-path = "./github-app.pem"
}

git-clone {}

git {
  snapshot-interval = "1h"
  repack-interval   = "1h"
}

github-releases {
  token        = "${GITHUB_TOKEN}"
  private-orgs = ["myorg"]
}

gomod {
  proxy         = "https://proxy.golang.org"
  private-paths = ["github.com/myorg/*"]
}

hermit {}

host "https://ghcr.io" {
  headers = {
    "Authorization": "Bearer ${GHCR_TOKEN}"
  }
}

disk {
  limit-mb          = 250000
  max-ttl           = "8h"
  read-concurrency  = 64
  open-reader-limit = 4096
  operation-timeout = "2s"
  read-idle-timeout = "30s"
}

proxy {}
```
