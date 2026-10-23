# Perl CGI Support

Perl CGI support is a future Fluxheim application-server milestone for legacy
tools that still depend on RFC 3875 CGI execution. It must be opt-in at compile
time and opt-in per vhost. It should not be part of the default runtime behavior
because CGI executes local programs with request-controlled input.

## Current Recommendation

The planned implementation path is `perl-cgi-cegla`:

- `cegla-cgi 0.2.3`: high-level CGI implementation for Rust, MIT.
- `tokio-cegla 0.2.3`: Tokio runtime support for CGI process execution, MIT.
- `rlimit 0.11.0`: Unix resource limits, MIT.
- `landlock 0.4.4`: optional Linux path-based sandboxing, MIT OR Apache-2.0.

The CGI module should use a normal external Perl interpreter first, for example
`/usr/bin/perl`, and should not embed Perl into Fluxheim. Process isolation is
the main security boundary.

## Compile-Time Features

Planned feature flags:

```toml
perl-cgi = []
perl-cgi-cegla = ["perl-cgi", "dep:cegla-cgi", "dep:tokio-cegla"]
perl-cgi-rlimit = ["perl-cgi", "dep:rlimit"]
perl-cgi-landlock = ["perl-cgi", "dep:landlock"]
```

The default binary should not enable Perl CGI. If a release profile later
chooses to compile the module by default, runtime execution must still remain
disabled unless a vhost explicitly enables it.

## Config Shape

Initial typed TOML target:

```toml
[[vhosts]]
name = "legacy.example.test"
hosts = ["legacy.example.test"]

[vhosts.cgi]
enabled = true
runtime = "perl"
root = "/srv/sites/legacy.example.test/cgi-bin"
interpreter = "/usr/bin/perl"
allowed_extensions = ["cgi", "pl"]
index_files = ["index.cgi"]
request_timeout_secs = 10
max_request_body_bytes = "2MiB"
max_stdout_bytes = "16MiB"
max_stderr_bytes = "64KiB"
max_response_header_bytes = "32KiB"
path_info = "disabled"

[vhosts.cgi.process]
uid = 1001
gid = 1001
working_dir = "/srv/sites/legacy.example.test/cgi-bin"
clear_env = true
env_allow = ["PATH", "TZ"]

[vhosts.cgi.limits]
cpu_secs = 2
memory_bytes = "128MiB"
open_files = 64
processes = 8

[vhosts.cgi.landlock]
enabled = true
read_paths = ["/srv/sites/legacy.example.test/cgi-bin"]
write_paths = ["/tmp/fluxheim-cgi/legacy.example.test"]
```

The CGI handler should run before normal static fallback for configured CGI
paths. If CGI execution fails, Fluxheim must return an error response and must
not serve the script source.

## Request Flow

1. Match an enabled vhost CGI route.
2. Resolve the requested script under the configured CGI root.
3. Canonicalize the root and script path.
4. Reject traversal, symlink escapes, hidden files, non-files, and scripts with
   unsafe permissions.
5. Build a strict CGI environment from the request.
6. Spawn the Perl interpreter with clean environment, configured uid/gid,
   resource limits, timeout, and optional Landlock restrictions.
7. Pipe the bounded request body to stdin.
8. Parse stdout as CGI headers plus body.
9. Capture stderr separately, cap it, sanitize it, and log it.
10. Kill the process group on timeout, client cancellation, or output limit
    violation.

## Security Requirements

Before CGI is production eligible:

- CGI must be disabled unless both compile feature and vhost config enable it.
- `SCRIPT_FILENAME` must come from canonical path resolution, not string
  concatenation.
- `PATH_INFO` is disabled by default.
- Dotfiles and hidden path segments are denied by default.
- Symlink escapes outside the CGI root are denied.
- Group/world-writable scripts are denied.
- The interpreter path must be absolute and validated at startup.
- The child environment starts empty by default.
- Only strict RFC 3875 CGI variables are passed:
  `REQUEST_METHOD`, `QUERY_STRING`, `CONTENT_TYPE`, `CONTENT_LENGTH`,
  `SCRIPT_NAME`, `SCRIPT_FILENAME`, `DOCUMENT_ROOT`, `REQUEST_URI`,
  `SERVER_NAME`, `SERVER_PORT`, `SERVER_PROTOCOL`, `REMOTE_ADDR`, and explicitly
  configured allow-list variables.
- Incoming request body limits are enforced for declared and streaming bodies.
- CGI response headers have a hard byte limit.
- Malformed CGI headers, NUL bytes, and header injection are rejected.
- `Status` and `Location` headers are parsed explicitly.
- `Set-Cookie` is preserved, but header names and values are validated.
- stdout and stderr have independent byte caps.
- stderr is sanitized before logging to avoid leaking secrets.
- Child processes are spawned in their own process group where supported.
- Timeouts kill the process group, not only the direct child.
- Resource limits should cover CPU, address space, file size, open files, and
  child processes.
- Landlock, when enabled and available, should restrict file reads/writes to
  configured paths after all required files are opened.

## Deployment Model

The preferred deployment boundary is rootless Podman plus low-privilege Unix
users inside the container. Fluxheim should not require privileged host access
for CGI. `chroot` can be documented as an advanced future option, but it should
not be the primary security boundary because it needs privileges and careful
filesystem construction.

## Testing Plan

Required tests before implementation is considered usable:

- Compile checks with and without `perl-cgi`.
- Config validation for unsafe interpreter paths, missing roots, bad limits, and
  remote/insecure writable paths.
- Path traversal and symlink escape tests.
- Denied source fallback tests.
- Environment allow-list tests.
- Timeout and process-kill tests.
- stdout/stderr limit tests.
- malformed header tests.
- request body limit tests for `Content-Length` and streaming bodies.
- rootless Podman smoke test with a tiny Perl CGI script.

## Reload And Operations

CGI runtime settings should be process-upgrade changes until the process model
is proven safe for snapshot-only reloads. Per-vhost route policy may later
become snapshot-safe if it only changes immutable config and does not alter
process pools, interpreter paths, uid/gid, Landlock policy, or resource limits.

Metrics should include CGI request totals, exit statuses, timeouts, output-limit
violations, spawn failures, and stderr counts by vhost.
