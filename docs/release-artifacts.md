# Verified release artifacts

The optional `release-artifacts` strategy serves immutable artifacts from a private
S3 source using the server's AWS credential chain. It never redirects clients to
S3 and never uses client credentials to select an origin.

```hcl
s3 {
  endpoint = "s3.us-east-1.amazonaws.com"
  region = "us-east-1"
  use-ssl = true
}

strategy release-artifacts {
  bucket = "example-release-source"
  prefix = "published"
  artifacts = ["example/tool"]
  classes = ["releases"]
  max-blob-bytes = 1073741824
  max-concurrent-fills = 4
  fetch-timeout = "2m"
}
```

A public blob is addressed as
`/artifacts/example/tool/blob/sha256/<digest>`. Private `builds` and `previews`
classes add that segment before `blob`. Classes and artifact registrations must
be explicitly configured; Host, query parameters and forwarding headers cannot
expand them. SHA-256, SHA-512 and BLAKE3 are supported. Artifact registrations have
one or two lowercase segments and cannot contain reserved route keywords.

For each blob the source contains two objects:

```
published/<class>/<artifact>/blobs/<hash>/<digest>/complete.json
published/<class>/<artifact>/blobs/<hash>/<digest>/payload
```

The completion object is bounded to 64 KiB and has this schema:

```json
{
  "schema_version": 1,
  "artifact": "example/tool",
  "class": "releases",
  "hash": "sha256",
  "digest": "<lowercase hex digest>",
  "size": 123,
  "ready": true
}
```

The publisher must write immutable final bytes, verify artifact-specific readiness,
then write the completion object. A missing, mismatched or unsupported completion
is never served. Duplicate/unknown fields are rejected. Publisher IAM and object
retention are responsible for keeping completed content immutable.

On a cold GET, Cachew downloads the entire bounded payload to a private temporary
file and verifies its declared size and digest **before** committing a cache entry
or returning bytes. This also applies to cold range and conditional requests.
HEAD validates completion and S3 object size without fetching or caching the body.
A HEAD success is not evidence that the payload's digest was verified.

Cache keys include the source endpoint, bucket, prefix, class, artifact and digest.
Only entries carrying the strategy's verified metadata are accepted. Generic object
cache entries cannot establish readiness. Warm GET/HEAD, ranges and ETag conditions
work without contacting the source. Cache write failures do not prevent serving the
already verified temporary file. Incomplete/error responses are never cached.

Bound temporary storage by `max-blob-bytes * max-concurrent-fills`, plus cache-tier
budgets, and provision filesystem capacity accordingly. Fills time out; excess fills
return 503. Temporary files are removed when each request completes; a process crash
can leave files behind, so use disposable, capacity-limited storage for the temp path.

## Deployment boundary

Run separate public and private deployments with isolated cache storage. Give the
public deployment source reads only for public classes. The private deployment
needs authentication at its ingress, before all cache hits, as well as restricted
origin network access. Changing artifact/class configuration also constrains warm
entries. Credentials must never be embedded in artifact URLs.

Use a custom default-deny OPA policy and route only the approved GET/HEAD paths.
Do not expose Cachew's generic object API, write APIs, statistics or administrative
routes on a release hostname. Generic cache write access is incompatible with
trusting cached verification metadata. Health/metrics should remain private.
Keep edge caching disabled: responses use `Cache-Control: private, no-store` so
an upstream cache cannot bypass private admission. Approved public upstream
strategies can be configured separately; no generic fallback is installed by this
strategy. Existing deployments are unchanged until the strategy is configured.
