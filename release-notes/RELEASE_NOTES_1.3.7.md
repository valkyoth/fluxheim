# Fluxheim 1.3.7 Release Notes

Fluxheim 1.3.7 is the production PHP-FPM completion release for the 1.3 line.
It keeps PHP application hosting on the stable FastCGI/php-fpm path and removes
the reserved pure-Rust PHP/phprs track from the release plan.

## Highlights

- External php-fpm remains the default and fully supported deployment mode.
- Added managed php-fpm process supervision under the existing `php-fpm` feature,
  not as a new Cargo runtime feature. Managed mode now includes a watchdog that
  respawns the php-fpm master after post-start crashes with bounded backoff.
- Managed php-fpm starts with a cleared inherited environment and sanitized
  `PATH`, generates private pool state, and shuts down with SIGTERM before
  SIGKILL.
- Managed php-fpm teardown is detached from Tokio worker threads, shutdown is
  observed during respawn socket waits, and restart backoff uses the actual
  successful socket-ready timestamp so crash-loop detection is stable.
- Exposed managed mode as a runtime config choice in `[vhosts.php.fpm]`, with a
  small auditable surface for binary path, private socket directory, worker
  count, max-request recycling, static/dynamic/ondemand pool sizing, request
  lifecycle controls, slowlog diagnostics, output/env toggles, optional
  session/upload temp paths, optional worker user/group, and generated pool
  files.
- Reuses the existing FastCGI request/response path so WordPress, Laravel,
  Symfony, phpBB, XenForo, MediaWiki, MyBB, and Flarum behavior remains aligned
  with normal php-fpm deployments.
- Added clear config-tester and runtime diagnostics for missing php-fpm binaries,
  unsafe managed directories, process start failures, and FastCGI request
  failures.
- Extended `scripts/smoke_wordpress_php_fpm.sh` with `external`, `managed`,
  `both`, `managed-static`, `managed-dynamic`, `managed-ondemand`,
  `managed-respawn`, and `managed-all` coverage. The `both` mode runs the same
  WordPress install, login, cookie, redirect, and admin-dashboard flow against
  operator-managed php-fpm and all Fluxheim-managed php-fpm process manager
  modes, while `managed-respawn` kills the php-fpm master and verifies recovery
  without a Fluxheim reload.
- The recommended Wolfi PHP image now installs `php-8.5-fpm` and uses a
  managed php-fpm container config by default, making it directly usable for
  single-container PHP sites that mount content under `/srv/fluxheim`.
- The `1.4` roadmap now consolidates production proxy parity into a compact
  line: edge policy/compression, upstream resilience, TLS/protocol parity, and
  discovery/mirroring/operator hooks.

## Out Of Scope

- phprs / pure-Rust PHP integration. Managed php-fpm now covers the intended
  zero-admin PHP deployment model without adopting an immature PHP interpreter.
- Embedded PHP/libphp or Turbine-style in-process PHP runtimes. Turbine-style
  app servers remain normal HTTP upstreams for Fluxheim to reverse-proxy.
- Persistent `php-cli` stdin/stdout worker protocols for production PHP apps.
  Production mode should use php-fpm semantics and request isolation.
