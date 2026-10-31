# PHP Runtime, Transport And Operations

Start with [PHP deployment and routing](php.md) for a working site. This guide
covers what happens between Fluxheim and PHP-FPM. The complete field/default
inventory is [PHP options](../reference/php-options.md).

PHP is a separately installed interpreter. Fluxheim implements the FastCGI
RESPONDER role, one request at a time per connection. It does not embed PHP,
multiplex simultaneous FastCGI requests on a connection, or implement the
AUTHORIZER/FILTER roles. HTTP application servers written in PHP belong behind
a normal [reverse proxy](reverse-proxy.md), not a FastCGI endpoint.

## Connections And Keepalive

External mode chooses exactly one socket, TCP endpoint or list of TCP endpoints.
For a multi-pool deployment, replace the FPM block with:

```toml
[vhosts.php.fpm]
mode = "external"
tcp_upstreams = ["127.0.0.1:9000", "127.0.0.1:9001"]
allow_private_tcp_upstreams = true
keepalive = false
connect_timeout_secs = 2
read_timeout_secs = 10
write_timeout_secs = 10
retry_methods = []
```

The list is bounded to 64 distinct authorities. Initial selection rotates
through it; this is not the HTTP load balancer's health/weight/stickiness system.
Keep PHP sessions, deployed code and application state consistent across pools.
Numeric private addresses require explicit opt-in. DNS endpoints use the host
resolver; this setting is not an egress firewall or DNS rebinding defense.

With `keepalive = false` (default), each attempt opens a new FastCGI connection.
To enable reuse, replace that setting and add:

```toml
keepalive = true
pool_max_idle = 4
idle_timeout_secs = 30
```

The idle cap is **per endpoint, per PHP handler**, not a total connection cap.
Idle entries are pruned when checking a connection in or out, not by a background
expiry timer. Active requests are separately bounded by `php.max_in_flight`.
Do not configure more retained connections than PHP workers can sensibly serve.
FastCGI transport errors/timeouts discard the checked-out connection. Application
response validation happens after collection; do not assume every rejected CGI
header or retryable status discards a successfully collected connection.

## Timeouts Are Currently Phase Budgets

`php.request_timeout_secs` defaults to 30. The native implementation uses:

- Connect budget: the smaller of request timeout and configured connect timeout.
- Exchange budget: the smallest of request timeout, read timeout and write
  timeout. This covers sending FastCGI input and collecting the complete output,
  not separate idle read/write timers.
- Retry window: checked before starting an additional attempt. It does not
  interrupt an attempt already running.

Connect and exchange have separate timeout wrappers. Upload collection, spooling
and a sequence of retries are not covered by one PHP-specific total deadline.
**Current limitation:** tracks the misleading total-deadline contract. The
wire smoke demonstrates a 200 response after a one-second retry window expires.
Use outer HTTP limits and conservative attempt counts; do not size resources
assuming `request_timeout_secs` is an end-to-end elapsed-time ceiling.

## Retries And Application Side Effects

For an allowed retry method, the retry count is the greater of `max_retries`
and the number of alternative endpoints. Thus `max_retries = 0` does **not**
disable failover with multiple endpoints. Set `retry_methods = []` to disable
automatic retries altogether.

Defaults permit GET, HEAD and OPTIONS. Configuration permits only GET, HEAD,
OPTIONS and TRACE in that list, never POST/PUT/PATCH/DELETE. Applications must
still avoid side effects on methods they permit to be replayed. A method name
alone cannot prove that repeating a request is harmless.

Explicit response retries look like this:

```toml
[vhosts.php.fpm]
tcp_upstreams = ["127.0.0.1:9000", "127.0.0.1:9001"]
allow_private_tcp_upstreams = true
max_retries = 1
retry_methods = ["GET", "HEAD"]
retry_statuses = [502, 503, 504]
retry_invalid_response = false
retry_timeout_secs = 5
```

Leave response retries off unless your application tolerates replay. A received
503 can follow completed application work. `retry_invalid_response` similarly
permits replay after invalid CGI output or a configured STDERR failure match.
Connect timeouts are retryable; exchange timeouts are not. Error classification
depends on the transport error actually returned; library errors converted to
generic I/O errors are not equivalent to a known pre-dispatch connection failure.

## Bodies, Spooling And Memory

The HTTP stack collects a request before the PHP handler sees it. The handler
checks its PHP body limit and either copies it into replay memory or writes it
to a temporary spool file. **Spooling is replay storage, not streaming upload
ingress.** The original HTTP request allocation remains alive during dispatch.

The existing `server.limits.max_buffered_request_body_bytes` admission budget
still bounds shared HTTP collection. This finding is about the additional memory
savings that spooling was claimed to provide, not absence of HTTP memory limits.

For bounded replay storage:

```toml
[vhosts.php]
enabled = true
root = "/srv/site/public"
max_request_body_bytes = "8MiB"
request_body_spool_threshold_bytes = "1MiB"
request_body_spool_dir = "/var/lib/fluxheim/php-spool/site"
max_in_flight = 4
max_response_bytes = "8MiB"
max_response_header_bytes = "32KiB"
```

This is a fragment; retain your FPM endpoint and outer HTTP body limits. The two
spool settings must appear together, threshold must be positive and lower than
the PHP limit when both are supplied. Above the threshold, the runtime creates
the directory if missing and rejects unsafe writable paths.

Unix spool files are created exclusively with mode 0600 relative to an opened
directory and immediately unlinked. Windows uses an exclusive handle, protected
confidential ACL and delete-on-close; a directory entry can remain while the
handle is live. Readers have independent offsets and bounded 64 KiB positional
reads. Replay memory and temporary read buffers use secret-clearing storage.
This does not erase previously written disk blocks: use encrypted storage or
appropriate memory-backed storage when remnants matter.

**Current limitation:** earlier docs claimed spooling avoids retaining the
whole upload. It does not currently do so. Likewise the PHP concurrency permit
is acquired after HTTP collection, not before ingress allocation. The response
is collected too: `max_response_bytes` bounds combined FastCGI STDOUT/STDERR,
not just the final HTTP body. Copies, HTTP buffers, connection state and already
returned downstream responses add overhead. It is not valid to calculate a
process-wide memory ceiling as merely max_in_flight times max_response_bytes.
Response-permit lifetime also belongs to the shared correction in the local follow-up.

## Forwarded Headers And CGI Parameters

`pass_request_headers = true` translates supported request headers to CGI
HTTP_* fields. Cookie lines are combined for PHP, and the Proxy header is
excluded to prevent HTTP_PROXY injection. Core CGI fields are generated by
Fluxheim rather than accepted from administrator-supplied parameter overrides.

```toml
[vhosts.php]
enabled = true
root = "/srv/site/public"
pass_request_headers = true
pass_request_body = true
server_port = 443

[vhosts.php.params]
APP_ENV = "production"
```

The custom parameter map permits bounded literal names/values. It cannot override
SCRIPT_FILENAME, CONTENT_LENGTH, HTTPS or other protected CGI fields, HTTP_PROXY,
PHP_VALUE or PHP_ADMIN_VALUE. Configure interpreter ini settings in PHP instead.
Turning off header forwarding does not suppress generated CGI metadata such as
CONTENT_TYPE, REQUEST_METHOD or QUERY_STRING.

SERVER_PORT normally uses an explicit Host port, otherwise 443 for downstream
TLS or 80 for cleartext. Use an explicit override for externally published ports.
HTTPS/REQUEST_SCHEME reflect the downstream TLS context, not a client-supplied
X-Forwarded-Proto assertion. Review [request headers](request-headers.md) and
[trusted client identity](access-control.md) before trusting application headers.

**Current limitation:** `pass_request_body = false` empties FastCGI STDIN
but leaves CONTENT_LENGTH at the original request length. The request still
undergoes collection, PHP limit checks and optional spool work. Keep forwarding
enabled for ordinary applications until the mismatch is corrected; disabling it
is not an upload-memory optimization.

## Response Policy And Errors

`hide_response_headers` removes named response fields case-insensitively.
Hop-by-hop headers and fields named by Connection are removed. Fluxheim computes
HTTP content length from the collected PHP body; HEAD suppresses body delivery.

```toml
[vhosts.php]
enabled = true
root = "/srv/site/public"
hide_response_headers = ["x-powered-by", "x-internal"]
ignore_origin_cache_headers = false
intercept_error_statuses = [500, 503]
```

`ignore_origin_cache_headers = true` removes PHP Cache-Control, Expires and
Pragma. Do not enable it casually: removing no-store/private can weaken the
application's privacy policy at downstream caches. This setting does not wire
FastCGI caching into Fluxheim.

A configured interception status becomes a generic error unless a matching
local PHP error page is supplied:

```toml
[[vhosts.php.error_pages]]
status = 503
path = "/503.html"

[vhosts.php.error_pages.web]
root = "/srv/errors"
index_files = ["index.html"]
```

The error-page status itself enables interception. The file is a static response,
not another PHP execution or arbitrary upstream fetch. PHP transport failure
returns the generic 502 path; do not assume an error-page entry catches every
transport/early validation failure.

X-Accel-Redirect, X-Sendfile and X-Accel-Expires are stripped without their
advertised effects. Native FastCGI response caching is not integrated
. See [the routing guide's open gaps](php.md#open-native-runtime-gaps).

## Diagnostics And Metrics

`stderr_failure_patterns` is a list of case-sensitive literal substring matches
against the bounded FastCGI STDERR result, not regular expressions. A match
invalidates the response even with STDERR logging disabled:

```toml
[vhosts.php]
enabled = true
root = "/srv/site/public"
stderr_failure_patterns = ["PHP Fatal error:"]
```

**Current limitation:** native output handling does not currently emit
STDERR through the documented stderr_log/stderr_log_level/stderr_max_bytes
controls. Native pools receive empty metric callbacks, and the dedicated PHP
retry/STDERR recorder functions lack production callers. Do not interpret
missing series as evidence of zero retries/errors. Generic operational PHP
failure events, PHP request counts/durations and upstream-attempt telemetry are
separate working paths; this finding does not declare all PHP observability absent.
Keep PHP-FPM's own logs available and private. Do not expose raw PHP errors in
public HTTP responses.

## Managed Process Lifecycle

Managed mode uses the same FastCGI path, but starts a private FPM master on Unix.
It generates a private pool file, pid and socket names under socket_dir. The
master runs from a validated retained executable handle in a dedicated process
group, with inherited environment cleared and a fixed system PATH. User/group
changes affect workers only as supported by PHP-FPM; configure filesystem access
for the real identities.

Startup waits for socket readiness using connect_timeout_secs or five seconds,
clamped to 1-60 seconds. The watchdog checks the child roughly once a second,
cleans the old process group and restarts with bounded exponential backoff
(capped at 30 seconds, reset after stable operation). This is availability
recovery, not a guarantee that in-flight application work is replayed safely.

Dropping the managed pool requests shutdown and schedules group cleanup. Normal
cleanup sends TERM, waits up to roughly five seconds, then escalates to KILL.
It removes generated socket/config/pid files. Error/slow logs are retained; plan
their permissions, retention and disk usage separately. Forced Fluxheim exit can
leave files/process state requiring service-manager cleanup. Never remove files
belonging to a live pool just to make a restart succeed.

Managed pool additions/removals and process-policy changes require process
replacement according to the reload classifier. Request policy/transport changes
can be snapshot-classified separately; inspect the actual diff/reload plan.
Classification is not a claim that every pool lifecycle was requalified here.
See [configuration snapshots](config-snapshots.md).

**Current limitation:** generated pools always use
security.limit_extensions=.php. Extra allowed_extensions such as phtml pass
Fluxheim validation but are rejected by the actual managed PHP pool. Keep
allowed_extensions=["php"] in managed mode. External pools need their own
consistent interpreter extension policy.

## PHP Images And Application Checks

The PHP image extension baseline is recorded in
[php-required-modules.txt](../../packaging/container/php-required-modules.txt).
Package lists are distribution-specific; do not assume a host PHP CLI describes
the FPM binary inside a container. Check for module load warnings as well as
module names, especially dependent MySQLnd/MySQLi modules.

The PHP image smoke validates modules and a real request for Wolfi, Alpine,
Debian and SUSE BCI; other SUSE profiles use Micro. Application recipes live in
[PHP application recipes](php-fpm-app-recipes.md). A new WordPress/database or
four-image smoke is a separate qualification, not implied by this source audit.

## Reproduce The Checks

```sh
cargo build --locked --bin fluxheim --features php-fpm
python3 scripts/smoke_php_examples.py
python3 scripts/smoke_php_transport.py
cargo test --locked -p fluxheim-php-fpm --lib
cargo test --locked -p fluxheim-server --features php-fpm --lib
```

The first smoke uses real installed PHP-FPM on a non-root Unix host, including
managed pools. The second uses a bounded loopback protocol fixture to inspect
FastCGI parameters, body replay, keepalive, retry timing and fatal-pattern
handling. It is not a PHP interpreter. Native Windows/macOS and a new managed
crash/respawn/reload run remain distinct required evidence for runtime changes.
