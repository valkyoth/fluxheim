#!/usr/bin/env python3
"""Keep human documentation discoverable and policy inputs in their new locations."""

from pathlib import Path
import re
import tomllib
import unittest

from smoke_geoip_examples import EXAMPLES, prepare, replace_once
import smoke_load_balancer_examples as lb

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

PUBLIC_REVIEW_SUMMARIES = (
    DOCS / "roadmap/observability-commit-plan.md",
    DOCS / "reference/documentation-coverage.md",
)


def read_review_document(path):
    """Read public documentation; private review checks are maintained locally."""
    return path.read_text()


class DocumentationLayoutTests(unittest.TestCase):
    def test_public_guides_do_not_publish_the_private_correction_queue(self):
        for folder in (DOCS / "guides", DOCS / "reference"):
            for path in folder.glob("*.md"):
                text = path.read_text()
                self.assertNotRegex(text, r"DOC-[A-Z]+-[0-9]+", str(path))
                self.assertNotRegex(text, r"(?i)\bcommit (?:1[6-9]|[2-9][0-9]|1[0-9]{2,})\b", str(path))

    def test_option_references_cover_configuration_fields(self):
        pairs = {
            "config_wasm.rs": "wasm-options.md",
            "config_php.rs": "php-options.md",
            "config_proxy.rs": "proxy-transport-options.md",
            "config_tls.rs": "tls-options.md",
            "config_acme.rs": "acme-options.md",
        }
        for source, reference in pairs.items():
            path = ROOT / "crates/fluxheim-config/src" / source
            fields = set(re.findall(r"pub (\w+):", path.read_text()))
            if source == "config_proxy.rs":
                fields = {field for field in fields if field.startswith(("downstream_", "upstream_tcp_", "upstream_h2"))
                          or field in {"connect_timeout_secs", "read_timeout_secs", "send_timeout_secs",
                                       "upstream_total_connection_timeout_secs", "upstream_idle_timeout_secs",
                                       "upstream_dscp", "upstream_http_version", "upstream_proxy_protocol",
                                       "websocket", "error_pages"}}
            self.assertTrue(fields, source)
            text = (DOCS / "reference" / reference).read_text()
            for field in fields:
                self.assertIn(f"`{field}`", text, f"undocumented {source}:{field}")

    def test_functionality_guides_cover_public_configuration_fields(self):
        groups = {
            "config_web.rs": ("guides/static-files.md",),
            "config_compression.rs": ("guides/compression.md",),
            "config_udp.rs": ("guides/udp.md",),
            "config_stream.rs": ("guides/tcp-streams.md",),
            "config_route.rs": ("guides/routing.md", "reference/config-reference.md"),
            "config_access.rs": ("guides/access-control.md", "guides/rate-and-concurrency-limits.md"),
            "config_header.rs": ("guides/request-headers.md", "reference/response-header-options.md"),
            "config_header_cors.rs": ("guides/cors.md",),
            "config_fragment.rs": ("reference/configuration-loading.md",),
        }
        missing = []
        for source, guides in groups.items():
            fields = set(re.findall(r"pub(?:\(crate\))? (\w+):", (ROOT / "crates/fluxheim-config/src" / source).read_text()))
            self.assertTrue(fields, source)
            text = "\n".join((DOCS / guide).read_text() for guide in guides)
            missing.extend(f"{source}:{field}" for field in fields if f"`{field}`" not in text)
        self.assertEqual(missing, [], "missing code-to-guide field coverage")

    def header_reference_names(self):
        text = (DOCS / "reference/supported-headers.md").read_text()
        names = re.findall(r"^\| `([^`]+)` \|", text, re.MULTILINE)
        self.assertGreater(len(names), 100)
        self.assertEqual(len(names), len({name.lower() for name in names}))
        return {name.lower() for name in names}

    def test_header_reference_covers_fixed_forwarding_and_hop_sets(self):
        names = self.header_reference_names()
        for file, constant in (("lib.rs", "SPOOFABLE_CLIENT_IP_HEADERS"),
                               ("hop_by_hop.rs", "HOP_BY_HOP_REQUEST_HEADERS")):
            source = (ROOT / "crates/fluxheim-headers/src" / file).read_text()
            match = re.search(r"pub const " + constant + r":.*?= &\[(.*?)\];", source, re.S)
            self.assertIsNotNone(match)
            expected = set(re.findall(r'"([a-z-]+)"', match[1]))
            self.assertGreater(len(expected), 5)
            self.assertFalse(expected - names, f"undocumented {constant}: {expected - names}")

    def test_header_reference_covers_response_policy_and_cors_names(self):
        names = self.header_reference_names()
        source = (ROOT / "crates/fluxheim-server/src/native_http1_route_response_headers.rs").read_text()
        expected = set(re.findall(r'(?:set_header|set_optional_header)\(\s*"([a-z-]+)"', source))
        self.assertGreaterEqual(len(expected), 13)
        cors = (ROOT / "crates/fluxheim-server/src/native_http1_cors.rs").read_text()
        expected.update(re.findall(r'"(access-control-[a-z-]+|origin|vary)"', cors))
        metadata = (ROOT / "crates/fluxheim-server/src/native_http1_response_metadata.rs").read_text()
        expected.update(re.findall(r'(?:push_header|remove_header)\(\s*"([a-z-]+)"',
                                   metadata.split("#[cfg(test)]", 1)[0]))
        self.assertFalse(expected - names, f"undocumented response fields: {expected - names}")

    def test_header_reference_covers_admin_operation_parameter_names(self):
        names = self.header_reference_names()
        expected = set()
        for file in ("request_router.rs", "misc_helpers.rs"):
            source = (ROOT / "src/admin" / file).read_text()
            expected.update(re.findall(r'"(x-fluxheim-[a-z-]+)"', source))
        self.assertGreaterEqual(len(expected), 25)
        self.assertFalse(expected - names, f"undocumented admin parameters: {expected - names}")

    def test_header_reference_is_a_behavior_index_not_a_support_promise(self):
        text = (DOCS / "reference/supported-headers.md").read_text()
        for phrase in ("not a whitelist", "Forwarding a header does not mean",
                       "not a fixed default name", "not commands on",
                       "does not cover every early error", "not a signature",
                       "without native offload effect", "not implicit", "release acceptance"):
            self.assertIn(phrase, text)
        self.assertIn('href="docs/reference/supported-headers.md"', (ROOT / "README.md").read_text())
        for name in ("request-headers.md", "response-headers.md"):
            self.assertIn("../reference/supported-headers.md", (DOCS / "guides" / name).read_text())

    def test_cloudflare_design_is_separate_from_current_deployment_guidance(self):
        guide = (DOCS / "guides/cloudflare-origin-support.md").read_text()
        proposal = (DOCS / "ideas/cloudflare-origin-support.md").read_text()
        features = (DOCS / "reference/features.md").read_text()
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertFalse(any(name.startswith("cloudflare") for name in manifest["features"]))
        self.assertIn("unimplemented design", proposal)
        self.assertIn("[cloudflare.origin_ca]", proposal)
        self.assertNotIn("```toml\n[cloudflare]", guide)
        self.assertIn("../ideas/cloudflare-origin-support.md", features)
        for boundary in ("no\nCloudflare-specific module", "not a connection allowlist",
                         "not a qualified Cloudflare", "not currently guaranteed",
                         "not proof of Cloudflare AOP", "have not\nbeen qualified"):
            self.assertIn(boundary, guide.replace("**", ""))

    def test_public_review_summaries_do_not_enumerate_unfixed_findings(self):
        for path in PUBLIC_REVIEW_SUMMARIES:
            text = path.read_text()
            self.assertNotRegex(text, r"DOC-[A-Z]+-[0-9]+")
            self.assertNotRegex(text, r"(?m)^## Commit (?:1[4-9]|[2-9][0-9]|[1-9][0-9]{2,}) -")
        plan = (DOCS / "roadmap/observability-commit-plan.md").read_text()
        self.assertIn("## Post-Documentation Corrections", plan)
        summary = (DOCS / "reference/documentation-coverage.md").read_text()
        self.assertIn("review the entire", summary.lower())
        self.assertIn("before publishing", plan)

    def test_local_review_directory_is_excluded_from_normal_staging(self):
        self.assertIn("/local-review/", (ROOT / ".gitignore").read_text().splitlines())
        self.assertIn("local-review", (ROOT / ".dockerignore").read_text().splitlines())
        self.assertIn("local-review", (ROOT / ".containerignore").read_text().splitlines())


    def test_readme_quick_start_is_a_self_contained_static_recipe(self):
        readme = (ROOT / "README.md").read_text()
        quick_start = readme.split("## Quick Start\n", 1)[1].split("## Documentation\n", 1)[0]
        recipe = ROOT / "examples/configuration/single.toml"
        config = tomllib.loads(recipe.read_text())
        self.assertEqual(config["server"]["listen"], ["127.0.0.1:8080"])
        self.assertFalse(config["cache"]["enabled"])
        self.assertNotIn("proxy", config)
        vhost, = config["vhosts"]
        self.assertNotIn("proxy", vhost)
        self.assertNotIn("php", vhost)
        self.assertIn(f"Host: {vhost['hosts'][0]}", quick_start)
        index = recipe.parent / vhost["web"]["root"] / "index.html"
        self.assertIn(f"Expected body: `{index.read_text().strip()}`", quick_start)
        for arguments in ("--validate-config --config", "--config"):
            self.assertIn(f"cargo run --locked -- {arguments} examples/configuration/single.toml",
                          quick_start)
        self.assertNotIn("examples/fluxheim.toml", quick_start)

    def test_overview_does_not_promote_known_limits(self):
        readme = (ROOT / "README.md").read_text()
        for feature in ("External authorization subrequests", "Opt-in traffic mirroring",
                        "ACME issuance and renewal: HTTP-01, EAB and ARI",
                        "CLI validation and standalone configuration tester"):
            self.assertIn(f"| {feature} | Limited", readme)
        self.assertNotIn("bounded queues and redaction", readme)
        self.assertIn("legacy or dependency log messages", readme)
        self.assertIn("a table entry is not release approval", readme)

    def test_readiness_is_current_and_uses_real_gate_switches(self):
        guide = read_review_document(DOCS / "guides/production-readiness.md")
        self.assertNotRegex(guide, r"(?m)^## (?:Stable|Not Stable|0\.5)")
        for boundary in ("not release approval", "separate commands", "not an exact simulation",
                         "skipped services", "Cross-compilation is not native execution",
                         "not durable audit persistence", "documented limits"):
            self.assertIn(boundary, guide.lower() if boundary == "documented limits" else guide)
        gate = (ROOT / "scripts/stable_release_gate.sh").read_text()
        flags = set(re.findall(r"\b(FLUXHEIM_GATE_[A-Z_]+)=1", guide))
        self.assertGreaterEqual(len(flags), 6)
        for flag in flags:
            self.assertIn("${" + flag + ":-0}", gate)

    def test_navigation_fragments_point_to_existing_headings(self):
        # These navigation pages link to ordinary GitHub Markdown headings.
        # This supplements the repository link checker, which checks paths only.
        for page in (ROOT / "README.md", DOCS / "README.md",
                     DOCS / "guides/production-readiness.md",
                     DOCS / "guides/cache-backends.md",
                     DOCS / "guides/certificate-renewal.md",
                     DOCS / "guides/cloudflare-origin-support.md",
                     DOCS / "reference/supported-headers.md"):
            for target, fragment in re.findall(r"\]\(([^)#]+\.md)#([^ )]+)\)", page.read_text()):
                if "://" in target:
                    continue
                document = (page.parent / target).read_text()
                anchors = set()
                counts = {}
                fenced = False
                for line in document.splitlines():
                    if line.startswith(("```", "~~~")):
                        fenced = not fenced
                    if fenced:
                        continue
                    match = re.match(r"^#{1,6} (.+?)(?: +#+)?$", line)
                    if match is None:
                        continue
                    heading = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", match[1])
                    slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
                    duplicate = counts.get(slug, 0)
                    anchors.add(f"{slug}-{duplicate}" if duplicate else slug)
                    counts[slug] = duplicate + 1
                self.assertIn(fragment, anchors, f"{page.name}: missing heading {target}#{fragment}")

    def test_fips_guide_distinguishes_policy_provider_and_qualification(self):
        guide = read_review_document(DOCS / "guides/fips.md")
        self.assertIn("FIPS PUB 140-3", guide)
        for section in ("fips", "iso19790"):
            for field in ("required", "require_disk_cache_encryption"):
                self.assertIn(f"| `tls.{section}.{field}` |", guide)
        for requirement in ("not a validated", "not a TOML setting",
                            "no supported required-mode OTLP bearer-token combination",
                            "not qualify native Windows/macOS", "not an acceptance gate"):
            self.assertIn(requirement, guide)
        example = tomllib.loads((ROOT / "examples/fips/proxy.toml").read_text())
        self.assertEqual(example["server"]["listen"], [])
        self.assertTrue(example["tls"]["fips"]["required"])
        self.assertTrue(example["vhosts"][0]["proxy"]["upstream_verify_hostname"])


    def test_root_is_an_index_not_an_unsorted_document_dump(self):
        self.assertEqual({path.name for path in DOCS.iterdir() if path.is_file()}, {"README.md"})
        self.assertEqual({path.name for path in DOCS.iterdir() if path.is_dir()}, {
            "guides", "reference", "architecture", "roadmap", "ideas", "evidence",
        })

    def test_index_lists_every_document_and_policy_input(self):
        links = set(re.findall(r"\]\(([^)#]+)\)", read_review_document(DOCS / "README.md")))
        files = {path.relative_to(DOCS).as_posix() for path in DOCS.rglob("*")
                 if path.is_file() and path.name != "README.md"}
        self.assertFalse(files - links, f"unindexed documentation: {sorted(files - links)}")

    def test_active_plan_keeps_backend_tests_and_neutral_runtime(self):
        plan = (DOCS / "roadmap/observability-commit-plan.md").read_text()
        for requirement in ("SigNoz", "Grafana", "No Grafana/SigNoz SDK",
                            "Wait for GitHub CI and CodeQL",
                            "Commit 12", "actual running products"):
            self.assertIn(requirement, plan)


    def test_acme_reference_covers_config_fields_and_templates_do_not_accept_terms(self):
        reference = read_review_document(DOCS / "reference/acme-options.md")
        for source in ("config_acme.rs", "config_acme_issuer.rs", "config_acme_challenge.rs"):
            content = (ROOT / "crates/fluxheim-config/src" / source).read_text()
            for field in set(re.findall(r"pub (\w+):", content)):
                self.assertIn(f"`{field}`", reference, f"undocumented ACME field {field}")
        for name in ("acme-http-01.toml", "acme-actalis.toml"):
            config = tomllib.loads((ROOT / "examples" / name).read_text())
            self.assertTrue(config["server"]["tls_listen"])
            self.assertFalse(config["tls"]["acme"]["issuers"][0]["terms_of_service_agreed"])


    def test_cache_reference_covers_root_policy_fields(self):
        reference = read_review_document(DOCS / "reference/cache-options.md")
        source = (ROOT / "crates/fluxheim-config/src/config_cache.rs").read_text()
        nested = {"range", "memory", "disk", "lock", "predictor", "origin_protection"}
        for field in set(re.findall(r"pub (\w+):", source)) - nested:
            self.assertIn(f"`{field}`", reference, f"undocumented cache field {field}")


    def test_advanced_cache_guides_cover_configuration_fields(self):
        for source, guide in (
            ("config_cache_peer.rs", "cache-peer-fill.md"),
            ("config_cache_encryption.rs", "cache-encryption.md"),
        ):
            reference = (DOCS / "guides" / guide).read_text()
            fields = re.findall(r"pub (\w+):", (ROOT / "crates/fluxheim-config/src" / source).read_text())
            for field in fields:
                self.assertTrue(
                    f"`{field}`" in reference or f"`openbao.{field}`" in reference,
                    f"undocumented {source} field {field}",
                )

    def test_readme_is_version_neutral_feature_navigation(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("## Features", readme)
        self.assertNotIn("What Works Today", readme)
        self.assertNotIn("Development: 1.9.0", readme)
        self.assertNotRegex(readme, r"\bv?1\.(?:[3-9]|10)\.\d+\b")
        features = readme.split("## Features\n", 1)[1].split("## Quick Start\n", 1)[0]
        rows = [line for line in features.splitlines() if line.startswith("| ")]
        self.assertGreater(len(rows), 50)
        for row in rows:
            if row.startswith(("| Feature |", "| --- |")):
                continue
            columns = row.strip("|").split("|")
            self.assertEqual(len(columns), 3, row)
            self.assertRegex(columns[2], r"\]\(docs/(guides|reference)/[^)]+\)", row)
        self.assertIn("not enabled in every binary", readme)
        self.assertIn("HTTP/3 is deferred", readme)

    def test_geoip_example_renderer_preserves_policies(self):
        source = (EXAMPLES / "local.toml").read_text()
        rendered = tomllib.loads(prepare(source, Path('/trusted/geo "fixture".mmdb'), 12345))
        self.assertEqual(rendered["server"]["listen"], ["127.0.0.1:12345"])
        self.assertEqual(rendered["server"]["trusted_proxies"], [])
        self.assertEqual(rendered["geoip"]["databases"][0]["path"], '/trusted/geo "fixture".mmdb')
        self.assertEqual(rendered["vhosts"][0]["access"], tomllib.loads(source)["vhosts"][0]["access"])

    def test_geoip_example_renderer_rejects_stale_or_ambiguous_templates(self):
        for text in ("missing", "needle needle"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                replace_once(text, "needle", "replacement")

    def test_load_balancer_recipe_renderer_preserves_policy(self):
        source = (lb.EXAMPLES / "local.toml").read_text()
        for advanced in (False, True):
            result = tomllib.loads(lb.prepare(source, 12345, 12346, 12347, advanced))
            self.assertEqual(result["server"]["listen"], ["127.0.0.1:12345"])
            self.assertEqual(result["proxy"]["upstreams"], ["127.0.0.1:12346", "127.0.0.1:12347"])
            expected = tomllib.loads((lb.EXAMPLES / "http-health.toml").read_text() if advanced else source)
            self.assertEqual(result["proxy"]["load_balance"]["health_check"],
                             expected["proxy"]["load_balance"]["health_check"])
        with self.assertRaises(ValueError):
            lb.prepare(source + '\n# "127.0.0.1:9001"', 12345, 12346, 12347)

    def test_load_balancer_reference_covers_public_policy_fields(self):
        reference = read_review_document(DOCS / "reference/load-balancer-options.md")
        nested = {"health_check", "passive_health", "slow_start", "retry", "persistence", "queue"}
        for name in ("config_load_balance", "config_load_balance_health",
                     "config_load_balance_passive_health", "config_load_balance_slow_start",
                     "config_load_balance_retry", "config_load_balance_queue",
                     "config_load_balance_persistence"):
            source = (ROOT / "crates/fluxheim-config/src" / f"{name}.rs").read_text()
            for field in set(re.findall(r"pub (\w+):", source)) - nested:
                self.assertIn(f"`{field}`", reference, f"undocumented field {name}.{field}")

    def test_load_balancer_documents_runtime_not_just_parsing(self):
        guide = read_review_document(DOCS / "guides/load-balancer.md")
        for statement in ("no pool", "retry.admitted", "response-header wait",
                          "not a cluster-wide", "not a standalone server configuration",
                          "30 seconds", "Cache hits supply no samples"):
            combined = " ".join((guide + read_review_document(DOCS / "reference/load-balancer-options.md")).split())
            self.assertIn(statement, combined)
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn("slow start and retry budgets", readme)
        self.assertNotIn("Passive failure/latency ejection", readme)


if __name__ == "__main__":
    unittest.main()
