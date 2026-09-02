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
}
```

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
}
```

`proxy-base-url` is the public Cachew origin. Cachew uses it to replace
CodeArtifact URLs in npm, Cargo, NuGet, and Swift package metadata so clients
continue downloading through the unauthenticated proxy.

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

```hcl
disk {
  limit-mb = 250000
  max-ttl  = "8h"
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
  limit-mb = 250000
  max-ttl  = "8h"
}

proxy {}
```
