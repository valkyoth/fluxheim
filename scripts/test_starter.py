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
