#!/usr/bin/env python3
"""Human-friendly Fluxheim test launcher.

This is intentionally a menu over the maintained shell scripts. The release
gate remains the source of truth for required checks; this script makes the
optional live/container checks discoverable for humans.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class TestEntry:
    ident: str
    title: str
    category: str
    command: tuple[str, ...]
    description: str
    env: dict[str, str] = field(default_factory=dict)


TESTS: tuple[TestEntry, ...] = (
    TestEntry(
        "metadata",
        "Release metadata validation",
        "release",
        ("scripts/validate-release-metadata.sh",),
        "Checks README, release notes, docs, RPM metadata, and release invariants.",
    ),
    TestEntry(
        "stable-gate",
        "Stable release gate",
        "release",
        ("scripts/stable_release_gate.sh", "check"),
        "Runs the normal release-quality gate without publishing.",
    ),
    TestEntry(
        "deep-gate",
        "Deep release gate",
        "release",
        ("scripts/stable_release_deep_gate.sh", "check"),
        "Runs the expensive release gate profile with optional live checks enabled.",
    ),
    TestEntry(
        "images",
        "Pull/check smoke dependency images",
        "containers",
        ("scripts/check_smoke_images.sh",),
        "Pulls and prints the configured WordPress, OpenBao, database, Prometheus, and Jaeger images.",
    ),
    TestEntry(
        "fips-images",
        "FIPS backend image evidence",
        "containers",
        ("scripts/smoke_fips_backend_images.sh", "all"),
        "Builds pinned OpenSSL and rustls/AWS-LC proof images and exercises downstream and upstream TLS.",
    ),
    TestEntry(
        "core",
        "1.0 core smoke",
        "smoke",
        ("scripts/smoke_1_0_core.sh",),
        "Runs the broad local binary smoke covering core proxy, cache, LB, stream, and admin paths.",
    ),
    TestEntry(
        "native-http1",
        "Native HTTP/1 proxy smoke",
        "smoke",
        ("scripts/smoke_native_http1_proxy.sh",),
        "Exercises the native HTTP/1 proxy path after the Pingora cutover.",
    ),
    TestEntry(
        "graceful-drain",
        "Native graceful connection drain smoke",
        "operations",
        ("scripts/smoke_graceful_drain.sh",),
        "Proves SIGTERM stops new accepts while an established keep-alive request drains.",
    ),
    TestEntry(
        "systemd-socket-activation",
        "systemd socket activation smoke",
        "operations",
        ("scripts/smoke_systemd_socket_activation.sh",),
        "Passes a real TCP listener as FD 3 and proves strict fail-closed adoption.",
    ),
    TestEntry(
        "zero-downtime-upgrade",
        "Readiness-gated zero-downtime upgrade smoke",
        "operations",
        ("scripts/smoke_zero_downtime_upgrade.sh",),
        "Proves failed replacement rollback, ready-generation handoff, and old connection drain.",
    ),
    TestEntry(
        "snapshot-lifecycle",
        "Live snapshot reload and rollback smoke",
        "operations",
        ("scripts/smoke_snapshot_lifecycle.sh",),
        "Snapshots a running baseline, applies a candidate live, rolls back, and verifies restart persistence.",
    ),
    TestEntry(
        "podman-blue-green",
        "Podman blue/green upgrade smoke",
        "containers",
        ("scripts/smoke_podman_blue_green.sh",),
        "Builds two Fluxheim containers and proves handoff behind one stable front listener.",
    ),
    TestEntry(
        "proxy-cache",
        "Proxy cache smoke",
        "cache",
        ("scripts/smoke_proxy_cache.sh",),
        "Exercises memory/disk cache, range handling, stale behavior, purge, metrics, and restart HIT.",
    ),
    TestEntry(
        "storage-bin",
        "Storage-bin disk cache smoke",
        "cache",
        ("scripts/smoke_storage_bin_cache.sh",),
        "Exercises the storage-bin disk backend.",
    ),
    TestEntry(
        "cache-encryption",
        "Local encrypted cache smoke",
        "cache",
        ("scripts/smoke_cache_encryption_local.sh",),
        "Checks local encrypted cache storage behavior.",
    ),
    TestEntry(
        "openbao-cache",
        "OpenBao encrypted cache smoke",
        "cache",
        ("scripts/smoke_openbao_cache_encryption.sh",),
        "Runs the OpenBao-backed cache encryption smoke using FLUXHEIM_OPENBAO_IMAGE.",
    ),
    TestEntry(
        "acme-mount-boundary",
        "ACME mount-boundary security smoke",
        "security",
        ("scripts/smoke_acme_mount_boundary.sh",),
        "Runs the ignored ACME bind-mount regression in a user namespace or constrained container.",
    ),
    TestEntry(
        "peer-fill",
        "Peer-fill cache smoke",
        "cache",
        ("scripts/smoke_peer_fill_cache.sh",),
        "Exercises peer-fill cache behavior between Fluxheim instances.",
    ),
    TestEntry(
        "load-balancer",
        "Load balancer smoke",
        "load-balancer",
        ("scripts/smoke_load_balancer.sh",),
        "Exercises native load balancing, health, persistence, admin mutation, and failover.",
    ),
    TestEntry(
        "load-balancer-container",
        "Load balancer container smoke",
        "load-balancer",
        ("scripts/smoke_load_balancer_container.sh",),
        "Builds the load-balancer image and verifies native behavior in a container.",
    ),
    TestEntry(
        "geoip-circl",
        "CIRCL GeoIP integration smoke",
        "geoip",
        ("scripts/smoke_geoip_circl.sh",),
        "Downloads a pinned CIRCL MMDB and proves country/ASN ACLs across static, proxy, and load-balanced serving.",
    ),
    TestEntry(
        "privacy",
        "Privacy-mode smoke",
        "privacy",
        ("scripts/smoke_privacy_mode.sh",),
        "Builds the zero-retention privacy profile and verifies stripped client-IP headers plus request-log absence.",
    ),
    TestEntry(
        "redis-health",
        "Redis/Valkey health-check smoke",
        "databases",
        ("scripts/smoke_redis_health_check.sh",),
        "Runs the Redis/Valkey health-check smoke using FLUXHEIM_REDIS_IMAGE.",
    ),
    TestEntry(
        "mysql-health",
        "MySQL/MariaDB health-check smoke",
        "databases",
        ("scripts/smoke_mysql_health_check.sh",),
        "Runs the MySQL/MariaDB health-check smoke using FLUXHEIM_MYSQL_IMAGE.",
    ),
    TestEntry(
        "postgres-health",
        "PostgreSQL health-check smoke",
        "databases",
        ("scripts/smoke_postgres_health_check.sh",),
        "Runs the PostgreSQL health-check smoke using FLUXHEIM_POSTGRES_IMAGE.",
    ),
    TestEntry(
        "wordpress-php",
        "WordPress PHP-FPM smoke",
        "wordpress",
        ("scripts/smoke_wordpress_php_fpm.sh", "both"),
        "Downloads latest WordPress core and tests external plus managed PHP-FPM modes.",
    ),
    TestEntry(
        "wordpress-tls",
        "WordPress reverse-proxy TLS smoke",
        "wordpress",
        ("scripts/smoke_wordpress_proxy_tls.sh",),
        "Runs WordPress behind Fluxheim TLS reverse proxy.",
    ),
    TestEntry(
        "wasm",
        "Wasm complete smoke",
        "wasm",
        ("scripts/smoke_wasm_all.sh",),
        "Builds policy examples and validates the registry, sandbox, packaged release binary, and real-listener migration examples.",
    ),
    TestEntry(
        "wasm-release",
        "Packaged Wasm archive smoke",
        "wasm",
        ("scripts/smoke_wasm_release_asset.sh",),
        "Builds both Wasm archive formats, extracts the tarball, and runs every policy family through that release binary.",
    ),
    TestEntry(
        "wasm-irules",
        "F5 iRules-style Wasm policy smoke",
        "wasm",
        ("scripts/smoke_wasm_policy_examples.sh", "irules"),
        "Proves bounded allow/deny policy behavior and fail-closed traps on a real listener.",
    ),
    TestEntry(
        "wasm-openresty",
        "nginx Lua/OpenResty-style Wasm policy smoke",
        "wasm",
        ("scripts/smoke_wasm_policy_examples.sh", "openresty"),
        "Proves bounded request/response header mutation and forbidden-header rejection.",
    ),
    TestEntry(
        "wasm-haproxy-spoe",
        "HAProxy Lua/SPOE-style Wasm policy smoke",
        "wasm",
        ("scripts/smoke_wasm_policy_examples.sh", "haproxy-spoe"),
        "Proves bounded routing, load-balancer, persistence, and mirror decisions.",
    ),
    TestEntry(
        "wasm-vcl",
        "VCL-like Wasm cache policy smoke",
        "wasm",
        ("scripts/smoke_wasm_policy_examples.sh", "vcl"),
        "Proves bounded cache lookup, key, store-admission, TTL, tag, and header policy.",
    ),
    TestEntry(
        "observability",
        "Observability smoke",
        "observability",
        ("scripts/smoke_observability_local.sh",),
        "Checks local metrics/tracing behavior and starts disposable Prometheus/Jaeger unless URLs are configured.",
    ),
    TestEntry(
        "udp",
        "UDP proxy smoke",
        "network",
        ("scripts/smoke_udp_proxy.sh",),
        "Exercises beta UDP proxy behavior.",
    ),
    TestEntry(
        "podman",
        "Container image smoke",
        "containers",
        ("scripts/podman_smoke.sh",),
        "Builds and runs the main Fluxheim container smoke.",
    ),
    TestEntry(
        "php-wolfi",
        "PHP Wolfi container smoke",
        "containers",
        ("scripts/smoke_fluxheim_php_wolfi.sh",),
        "Builds/runs the PHP-capable Wolfi image profile.",
    ),
    TestEntry(
        "rpm-fedora",
        "RPM build smoke on Fedora",
        "rpm",
        ("scripts/build_fluxheim_rpm.py", "latest", "native", "--target", "fedora-44"),
        "Builds an RPM in a Fedora container for package-install evidence.",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Select and run Fluxheim tests")
    parser.add_argument("--list", action="store_true", help="list available tests")
    parser.add_argument("--run", action="append", default=[], help="run a test id; can be repeated")
    parser.add_argument("--category", action="append", default=[], help="run all tests in a category")
    parser.add_argument("--all", action="store_true", help="run all listed tests")
    parser.add_argument("--dry-run", action="store_true", help="print commands without running them")
    return parser.parse_args()


def list_tests() -> None:
    categories = sorted({entry.category for entry in TESTS})
    for category in categories:
        print(f"\n[{category}]")
        for entry in TESTS:
            if entry.category == category:
                print(f"  {entry.ident:24} {entry.title}")
                print(f"    {entry.description}")


def selected_from_menu() -> list[TestEntry]:
    print("Fluxheim test starter\n")
    for index, entry in enumerate(TESTS, start=1):
        print(f"{index:2d}. {entry.ident:24} {entry.title}")
    print("\nSelect numbers or ids separated by commas, or 'q' to quit.")
    raw = input("> ").strip()
    if raw.lower() in {"q", "quit", "exit"}:
        return []
    selected: list[TestEntry] = []
    by_id = {entry.ident: entry for entry in TESTS}
    for part in [item.strip() for item in raw.split(",") if item.strip()]:
        if part.isdigit():
            index = int(part)
            if index < 1 or index > len(TESTS):
                raise SystemExit(f"unknown test number: {part}")
            selected.append(TESTS[index - 1])
        elif part in by_id:
            selected.append(by_id[part])
        else:
            raise SystemExit(f"unknown test id: {part}")
    return selected


def select_tests(args: argparse.Namespace) -> list[TestEntry]:
    if args.all:
        return list(TESTS)

    selected: list[TestEntry] = []
    by_id = {entry.ident: entry for entry in TESTS}
    for ident in args.run:
        try:
            selected.append(by_id[ident])
        except KeyError:
            raise SystemExit(f"unknown test id: {ident}") from None

    for category in args.category:
        matches = [entry for entry in TESTS if entry.category == category]
        if not matches:
            raise SystemExit(f"unknown category: {category}")
        selected.extend(matches)

    if selected:
        deduped: list[TestEntry] = []
        seen: set[str] = set()
        for entry in selected:
            if entry.ident not in seen:
                deduped.append(entry)
                seen.add(entry.ident)
        return deduped

    return selected_from_menu()


def run_entry(entry: TestEntry, dry_run: bool) -> bool:
    env = os.environ.copy()
    env.update(entry.env)
    command = " ".join(entry.command)
    print(f"\n==> {entry.ident}: {entry.title}")
    print(f"    {command}")
    if dry_run:
        return True
    start = time.monotonic()
    result = subprocess.run(entry.command, cwd=ROOT, env=env, check=False)
    elapsed = time.monotonic() - start
    if result.returncode == 0:
        print(f"<== {entry.ident}: ok ({elapsed:.1f}s)")
        return True
    print(f"<== {entry.ident}: failed with exit {result.returncode} ({elapsed:.1f}s)")
    return False


def main() -> int:
    args = parse_args()
    if args.list:
        list_tests()
        return 0

    selected = select_tests(args)
    if not selected:
        return 0

    failures = [entry.ident for entry in selected if not run_entry(entry, args.dry_run)]
    if failures:
        print("\nFailed tests:")
        for ident in failures:
            print(f"  {ident}")
        return 1
    print("\nAll selected tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
