# Loading And Organizing Configuration

Fluxheim reads TOML: a text format with named tables, typed values and arrays.
A **fragment** is one TOML file contributing to the final configuration. A
**vhost** is a site selected by the HTTP host name. Each fragment is parsed,
its paths are resolved, the fragments are combined, presets are applied, and
the resulting configuration is validated before it is used.

This guide covers selecting files and composing settings. Use the
[configuration reference](../reference/config-reference.md) for individual
feature options, [vhosts](vhost-config.md) for table placement and
[routing](routing.md) for host/path selection. Configuration loading is shared
by Linux, macOS and Windows; filesystem trust is platform-specific. The live
examples below have been checked on Linux, not freshly qualified on every OS.

## Start With One File

Prerequisites: a Fluxheim build with `web` (the standard server builds include
it), readable example files and a private writable working directory owned by
the service account. The checked-in examples bind only to loopback on port 8080.
Choose an unused port before starting. They require no origin, database or CA.

From the repository root:

```sh
fluxheim --config examples/configuration/single.toml --validate-config
fluxheim --config examples/configuration/single.toml
```

In another terminal:

```sh
curl --fail --header 'Host: configuration.example.test' http://127.0.0.1:8080/
```

Expected body: `configuration-single-ok`. Stop the foreground server before
trying the next recipe. The [complete file](../../examples/configuration/single.toml)
sets local process paths, disables cache and serves the supplied `site` folder.
No configuration changes occur just because the file exists: pass its path.

`--config` / `-c` accepts a file **or a directory**. `FLUXHEIM_CONFIG` provides
the same selection when the option is omitted; an explicit option takes
precedence. Neither mechanism expands variables inside TOML values.

```sh
FLUXHEIM_CONFIG=examples/configuration/single.toml fluxheim --validate-config
```

In PowerShell, use `$env:FLUXHEIM_CONFIG = 'C:/fluxheim/config/fluxheim.toml'`
and invoke `fluxheim.exe --validate-config`. Clear or restore that variable
afterwards if it should not affect later commands. With neither the option nor
the environment variable, Fluxheim uses built-in defaults: it does not search
the current directory or automatically load `/etc/fluxheim/fluxheim.toml`.
Packaged service/container commands may supply that path explicitly.

## Split A Configuration

Use the [split example](../../examples/configuration/split/fluxheim.toml):

```text
split/
  fluxheim.toml
  conf.d/
    10-site.toml
    site/
      index.html
```

The main file begins with this **top-level** setting, before any table header:

```toml
include_conf_d = true
```

Run either of these, one at a time:

```sh
fluxheim --config examples/configuration/split/fluxheim.toml --validate-config
fluxheim --config examples/configuration/split/fluxheim.toml
# Alternatively, select the directory:
fluxheim --config examples/configuration/split
```

The same curl command now returns `configuration-split-ok`. The
[site fragment](../../examples/configuration/split/conf.d/10-site.toml) contains
the complete vhost; it is not a patch to another declaration of that vhost.

| Selection | Files loaded, in order |
| --- | --- |
| File, `include_conf_d` absent or `false` | Only that file |
| File, `include_conf_d = true` | That file, then the sibling `conf.d` files in lexical order |
| Directory | Its eligible files in lexical order, then its `conf.d` files in lexical order, regardless of flags inside them |

Important details:

- Only visible regular files with a case-insensitive `.toml` extension qualify.
  `.hidden.toml`, `site.toml.bak`, subdirectories and linked entries are ignored
  during enumeration. A directly selected hidden/non-TOML/linked file is rejected.
- Top-level files always precede `conf.d`, even when a child's name sorts earlier.
  Prefer numeric prefixes and consistent lowercase names across platforms.
- Loading a named file does not read other top-level siblings. Loading the
  directory does: do not keep active-looking backup `.toml` files there.
- There is no arbitrary `include`, glob, recursive traversal or nested
  `conf.d/conf.d` processing. A fragment's own `include_conf_d` does not recurse.
- A missing `conf.d` is allowed. An existing non-directory or linked `conf.d`
  is rejected. An empty directory is valid input to the loader and leaves
  built-in defaults; it is not an error proving that the intended site was found.
- Each file is bounded to 1 MiB of UTF-8 TOML. Directory mode allows at most
  256 eligible files across the top level and `conf.d` combined. Named-file
  mode permits the main file plus up to 256 sibling fragments.

Unknown fields, incorrect types, duplicate TOML keys/tables and invalid final
policies fail validation. A valid TOML file is not necessarily a valid Fluxheim
configuration, and accepted options still require the corresponding build features.

## Understand Merge Rules

There is no universal "last file wins" or universal recursive merge. The
[composition reference](../reference/configuration-loading.md) lists every
top-level section and the important nested exceptions.

- Some scalar fields replace earlier values only when explicitly supplied.
- Some lists replace earlier lists, while vhost declarations append.
- `server.trusted_proxies` appends exact-unique entries; `[]` does not clear it.
- Repeating `[[vhosts]] name = "guide"` creates a second vhost, not an update;
  duplicate names are rejected. Keep each vhost and its routes together.
- TOML has no null. Omitting an optional value is not a general instruction to
  erase an earlier value. Remove it from the defining file when disabling it.

**Current limitation:** a later partial table can
reset omitted settings in whole-replacement sections. This includes global
metrics, tracing, logging, headers, GeoIP and UDP, plus nested server limits,
process, HTTPS redirect and host-routing tables. Do not split these policies
between files. Keep the entire policy in one authoritative table until
[the local follow-up](../roadmap/observability-commit-plan.md#post-documentation-corrections)
is implemented and qualified.

For example, this later fragment is **not** a safe way to change only header
count while preserving an earlier body limit:

```toml
# Later file: currently replaces the whole server.limits policy.
[server.limits]
max_request_headers = 25
```

Keep both values together in the defining file instead:

```toml
# Replace the earlier server.limits table with this complete policy.
[server.limits]
max_request_headers = 25
max_request_body_bytes = "4MiB"
```

This second fragment can be added to the single-file recipe. Other fields in
that table take their defaults. The verified regression uses a smaller body
limit to demonstrate the reset without generating large requests. A later
`[logging] level = "warn"` similarly resets an earlier JSON format; it does not
only change the level. This is a local configuration-composition issue, not an
ability for HTTP clients to edit trusted configuration.

## Filesystem Paths And Permissions

Relative configured filesystem paths are joined to the directory of the
**file defining that value**, not the main file or current shell directory.
In `split/conf.d/10-site.toml`, `root = "site"` means `split/conf.d/site`.
Changing the source file's location can therefore change the resolved path.
Absolute paths remain absolute. Paths with `..` are rejected by the relevant
path validators; prefer explicit absolute paths when sharing data across folders.

`~`, `$HOME` and `${SITE_ROOT}` are literal text, not shell substitutions.
Use a configuration-management tool to generate reviewed files before startup
if you need templating. Do not put secret material into shell-expanded command
lines. URL fields and HTTP rewrite templates have their own semantics, not
filesystem-path expansion.

Configuration paths must remain controlled by the service administrator:

- On Unix, sources and existing ancestors must be owned by root or the service
  user and must not be group/world writable. Use private directories (`0700`)
  and private files (`0600`) when they contain sensitive settings. These modes
  are conservative recommendations; regular config files need integrity, while
  dedicated secret readers can impose stricter confidentiality requirements.
- On Windows, the loader uses the filesystem-trust ACL checks and rejects
  untrusted writes and link/reparse paths. NTFS ACLs, not Unix `chmod`, govern
  access. Use the intended runtime account and protected directories.
- A read-only container mount does not repair untrusted ownership or ancestor
  permissions. See [rootless config ownership](build-and-podman.md#rootless-config-ownership).
- File identity and metadata checks reject observed replacement/in-place
  changes during a read. Loading several files is **not an atomic directory
  snapshot**. Avoid concurrent deployments while validating or loading them.

Publish reviewed files in a private staging location, validate as the service
user in the actual filesystem/mount environment, and coordinate the final
deployment with your reload/restart procedure. A symlink named `current` is not
a supported way to switch the configuration source. Do not loosen permissions
to work around a failed trust check.

## Validate, Deploy And Troubleshoot

| Command | What it proves / does not prove |
| --- | --- |
| `--check-config` | Loads, validates and prints the effective Rust debug representation; checks relevant compiled modules, but does not initialize every runtime resource |
| `--validate-config` | Loads and validates, checks the build and constructs supported static/proxy/stream state; does not start serving, bind all listeners, issue certificates or prove upstream/application health |
| `--check-tls-storage` | Separate certificate/key/storage check; see the TLS and ACME guides |
| `--reload-from OLD --config NEW` | Classifies the two loaded configurations; does not apply a reload |
| `fluxheim-config-tester --config PATH --profile development --no-runtime-paths` | Structural/profile check; skips process runtime-path inspection and runtime construction, not all path/ownership checks or real deployment qualification |

Use one main-CLI checking mode per invocation and do not combine it with a
subcommand. The standalone tester's profile filter is not an exact target-build
simulation; see [CLI modes and profile limitations](command-line.md), including
the current `web-php` proxy discrepancy and ignored mixed checking flags.

Prefer `--validate-config` for routine preflight. Debug configuration output and
parse errors can contain configured values or source text: treat them as private
diagnostics, not safe public logs. Do not assume `--check-config` redacts inline
custom headers, URLs or application parameters. Run validation with the same
profile, account and mounts as the service, and test a real request after deployment.

Editing a file does not automatically reload the running server. Use the
[snapshot/reload procedures](config-snapshots.md) where supported; process-level
changes require a [restart/upgrade](zero-downtime-upgrades.md). Source-directory
merging is different from request-time global/vhost/route inheritance and from
loading an authenticated effective-config snapshot.

| Symptom | Check |
| --- | --- |
| Unknown default vhost | Was its fragment loaded? Named-file mode needs the top-level include flag |
| Unexpected old/new setting | Check file order, whole-table replacement and whether the running process was reloaded |
| Duplicate vhost | Remove repeated declarations; fragments do not patch vhosts by name |
| Wrong relative web root | Resolve from the defining fragment's directory |
| Source rejected | Check extension/hidden name, owner/ACL, all ancestors and links; use the real path |
| Build feature unavailable | Use the correct binary/profile; a tester does not add features to the deployed server |
| Preflight passes but start fails | Listener conflicts, runtime-only secrets/services and platform resources still need live checks |

Local proof: `python3 scripts/smoke_configuration_examples.py` uses the trusted
local debug binary with disposable private files and loopback ports. It checks
single-file, included and directory serving, CLI/environment selection, invalid
fragment rejection/recovery and the current partial-limit reset. It does not
modify the checked-in examples or qualify service-manager/production reloads.
