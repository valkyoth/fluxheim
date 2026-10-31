# PHP And FastCGI Options

Use [PHP deployment](../guides/php.md) for complete site examples and
[transport and operations](../guides/php-runtime-support.md) for retries,
spooling, response policy and supervision examples. These tables inventory
`PhpConfig` and `PhpFpmConfig`; accepting an option does not prove every native
runtime path implements its advertised effect. Open gaps are called out below.

Apply PHP fields under `[vhosts.php]` or `[vhosts.routes.php]`. The enabled PHP
table selects the route action; there is no `action = "php"` configuration key.
A mixed static/application site uses vhost fallback.
Use the nested `fpm` table for endpoint and process settings. Unknown fields are
rejected. Defaults below are before presets and inherited vhost-root resolution;
omit optional values rather than writing TOML null.

## Routing And Identity

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `enabled` | `false` | Enable this PHP action; the binary needs `php-fpm`. |
| `runtime` | `"php-fpm"` | Only supported interpreter protocol. |
| `preset` | `"none"` | `wordpress` supplies front-controller/upload-denial defaults; it is not PHP caching. |
| `root` | Unset | Required effective local script root; can inherit the vhost root. Fluxheim must inspect the scripts even with remote FPM. |
| `resolve_root_symlink` | `false` | Permit a trusted final root symlink, not symlinked parent traversal. |
| `fpm_root` | Unset | Backend-visible root for CGI path translation; local checks still use root. |
| `index` | `"index.php"` | Plain filename ending in `.php`, no directory path. |
| `allowed_extensions` | `["php"]` | 1-16 plain names, ASCII alphanumeric/underscore/hyphen, no leading dot or case-insensitive duplicates. Managed FPM still only permits `.php`. |
| `deny_path_prefixes` | `[]` | Up to 128 safe absolute URI prefixes denying PHP execution, not a static-file deny list. |
| `try_files` | `"front-controller"` | `front-controller`/`wordpress` fallback to index; `strict` rejects missing PHP scripts. |
| `path_info` | `"disabled"` | `split` permits safe suffixes after a script; `strict` is an alias for split. |
| `server_port` | Unset | Nonzero CGI port override; otherwise explicit Host port, then 443/80 according to downstream TLS. |
| `pass_request_headers` | `true` | Translate supported inbound headers to HTTP_* CGI fields; core CGI fields remain generated. |
| `pass_request_body` | `true` | Forward FastCGI STDIN. False currently leaves the original CONTENT_LENGTH; keep true for normal applications. |
| `params` | `{}` | Custom literal CGI map: at most 128 entries, names up to 128 bytes, values up to 16 KiB. Core CGI, HTTP_*, PHP_VALUE and PHP_ADMIN_VALUE cannot be overridden. |
| `fpm` | Default nested table | Configure one external endpoint mode or a managed pool below. |

See the [routing limitations](../guides/php.md#open-native-runtime-gaps) for
direct/fallback method differences and directory CGI/redirect behavior. Relative
configuration paths are resolved during config loading; they are not relative
to a browser URL. Examples use absolute paths to avoid deployment ambiguity.

## Bounds And Body Storage

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `request_timeout_secs` | `30` | Positive PHP phase budget, not currently one total deadline. |
| `max_in_flight` | `8` | 1-4096 active PHP dispatches per handler; does not bound pre-dispatch HTTP collection or all downstream response memory. |
| `max_request_body_bytes` | Unset | Optional positive PHP request limit, in addition to outer HTTP limits. |
| `request_body_spool_threshold_bytes` | Unset | Positive threshold for replay storage, paired with spool directory and lower than explicit PHP body limit. |
| `request_body_spool_dir` | Unset | Trusted private storage directory. Spooling does not release the collected HTTP body. |
| `max_response_bytes` | `"64MiB"` | Positive combined FastCGI STDOUT/STDERR cap, maximum 64 MiB; output is collected before delivery. |
| `max_response_header_bytes` | `"64KiB"` | Positive CGI header-block cap, maximum 1 MiB. |

Keep outer request/body/read limits and filesystem capacity limits too. A
configured response cap is not an RSS guarantee. Spool storage security and
Windows delete-on-close behavior are explained in the runtime guide.
The existing `server.limits.max_buffered_request_body_bytes` admission budget
continues to bound shared HTTP collection; spooling does not replace that budget.

## Responses And Diagnostics

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `stderr_log` | `true` | Accepted logging switch, not wired into native STDERR output. |
| `stderr_log_level` | `"warn"` | `error`, `warn`, `info`, `debug`; same native wiring gap. |
| `stderr_max_bytes` | `"2KiB"` | Accepted positive log cap up to 1 MiB, not an independent wire collection cap; same wiring gap. |
| `stderr_failure_patterns` | `[]` | Up to 32 distinct literal case-sensitive substrings, each 1-512 bytes without ASCII controls; a match invalidates the response. This path is wired. |
| `hide_response_headers` | `[]` | Up to 64 valid names; case-insensitive duplicates rejected. Removes backend fields before response policy. |
| `ignore_origin_cache_headers` | `false` | Strip Cache-Control, Expires and Pragma. Can remove privacy protections; not a cache-enable switch. |
| `intercept_error_statuses` | `[]` | Distinct 400-599 statuses; replace PHP response with a generated error or configured local page. |
| `error_pages` | `[]` | Up to 64 distinct-status entries: `status`, safe internal `path`, and required `web` root settings. Each entry also intercepts its status. |

For example, append a static failure page using
`[[vhosts.php.error_pages]]` followed by `[vhosts.php.error_pages.web]` as shown
in the [response policy example](../guides/php-runtime-support.md#response-policy-and-errors).
Do not assume that all early transport failures reach error-page interception.
Offload/expiry headers and FastCGI caching remain open the documented limitation gaps.

## FPM Endpoint, Pool And Retry Settings

Put these in `[vhosts.php.fpm]` or `[vhosts.routes.php.fpm]`.

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `mode` | `"external"` | `external` connects to an existing service; `managed` starts FPM on Unix only. Windows uses external TCP. |
| `socket` | Unset | External Unix socket, mutually exclusive with TCP settings. |
| `tcp` | Unset | One external host:port authority. FastCGI transport is not TLS. |
| `tcp_upstreams` | `[]` | Up to 64 distinct authorities, rotating initial selection and safe-method failover; not HTTP load-balancer policy. |
| `allow_private_tcp_upstreams` | `false` | Explicit opt-in for loopback/private/link-local IP literals; not DNS-resolution or firewall enforcement. |
| `keepalive` | `false` | Reuse successful FastCGI transports, one request at a time per connection. |
| `pool_max_idle` | `8` | Idle cap per endpoint/handler, 1-1024 when pooling is enabled. |
| `idle_timeout_secs` | `60` | Positive idle age limit when pooling is enabled; pruning occurs on checkout/checkin. |
| `connect_timeout_secs` | Unset | Connect cap, limited by request timeout; managed startup also uses this value (otherwise five seconds), clamped to 1-60 seconds. |
| `read_timeout_secs` | Unset | Combined exchange cap, minimum of request/read/write budgets. Not an idle read timer. |
| `write_timeout_secs` | Unset | Same combined exchange cap, not an independent write phase timer. |
| `max_retries` | `0` | 0-10 explicit retries; multiple endpoints can still trigger retries at zero. |
| `retry_timeout_secs` | Unset | Positive retry-start window; does not interrupt an in-progress attempt. |
| `retry_methods` | `["GET", "HEAD", "OPTIONS"]` | At most 16 entries, only uppercase GET/HEAD/OPTIONS/TRACE; `[]` disables retries. No POST replay. |
| `retry_invalid_response` | `false` | Allow eligible-method retry after invalid CGI or matching STDERR; application work may already have happened. |
| `retry_statuses` | `[]` | Distinct 500-599 statuses eligible for configured safe-method retry. |

External mode requires exactly one of socket/tcp/nonempty tcp_upstreams. Managed
mode rejects explicit endpoints and generates a private socket instead. Transport
timeouts, when supplied, must be positive. See the runtime guide before enabling
retries or treating pool metrics as proof of reuse.

## Managed Process Settings

These fields belong in the same FPM table, but only managed mode uses them.
External mode rejects changed managed-only settings rather than configuring
someone else's service. Paths, executable ownership and writable parents are
validated; installing PHP and granting the service account appropriate access
remain deployment tasks.

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `php_fpm_binary` | Unset | Required absolute trusted executable, not a shell command. |
| `socket_dir` | Unset | Required safe absolute directory for generated private pool files/socket. |
| `workers` | `4` | 1-256, written as pm.max_children. |
| `max_requests_per_worker` | `1000` | 0-1,000,000; zero disables request-count recycling. |
| `process_manager` | `"static"` | `static`, `dynamic`, `ondemand`. |
| `start_servers` | Unset | Dynamic only, 1..workers; omitted value derived from spare-worker bounds. Choose a value within your spare range. |
| `min_spare_servers` | Unset | Required for dynamic, 1..workers and no greater than max spare. |
| `max_spare_servers` | Unset | Required for dynamic, 1..workers. |
| `max_spawn_rate` | Unset | Dynamic only, 1-1024. |
| `process_idle_timeout_secs` | Unset | Ondemand only, 0-86400; omission leaves FPM's default. |
| `listen_backlog` | Unset | -1..65535; omission leaves FPM's default. |
| `listen_owner` | Unset | Pair with listen_group; validated Unix identity name. |
| `listen_group` | Unset | Pair with listen_owner. |
| `listen_mode` | Effective `"0600"` | Only `0600` or `0660`; use group access deliberately. |
| `request_terminate_timeout_secs` | Unset | 0-86400, independent FPM worker execution limit; zero disables it. |
| `request_terminate_timeout_track_finished` | `false` | Ask FPM to apply its termination policy after request-finish handling too. |
| `request_slowlog_timeout_secs` | Unset | 0-86400, zero disables slow tracing. |
| `request_slowlog_trace_depth` | `20` | 1-512 stack frames. |
| `clear_env` | `true` | FPM worker environment policy; the managed master is separately launched with a cleared environment. |
| `catch_workers_output` | `true` | FPM redirects worker output to its error log. Distinct from native FastCGI STDERR controls. |
| `decorate_workers_output` | `true` | FPM prefixes captured worker output. |
| `session_save_path` | Unset | Safe absolute PHP session directory, accessible by worker identity. |
| `upload_tmp_dir` | Unset | Safe absolute PHP upload temporary directory; distinct from Fluxheim replay spool. |
| `user` | Unset | Worker identity, paired with group; requires appropriate FPM master privilege. |
| `group` | Unset | Worker group, paired with user. |

Static mode rejects dynamic and ondemand-only options. Dynamic mode requires
spare bounds and rejects idle timeout; ondemand rejects dynamic sizing options.
The [managed examples](../guides/php.md) show all three modes. The
[supervision section](../guides/php-runtime-support.md#managed-process-lifecycle)
explains restart/backoff, cleanup, retained logs and process-upgrade boundaries.
