#!/usr/bin/env python3
"""Keep human documentation discoverable and policy inputs in their new locations."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


class DocumentationLayoutTests(unittest.TestCase):
    def test_root_is_an_index_not_an_unsorted_document_dump(self):
        self.assertEqual({path.name for path in DOCS.iterdir() if path.is_file()}, {"README.md"})
        self.assertEqual({path.name for path in DOCS.iterdir() if path.is_dir()}, {
            "guides", "reference", "architecture", "roadmap", "ideas", "evidence",
        })

    def test_index_lists_every_document_and_policy_input(self):
        links = set(re.findall(r"\]\(([^)#]+)\)", (DOCS / "README.md").read_text()))
        files = {path.relative_to(DOCS).as_posix() for path in DOCS.rglob("*")
                 if path.is_file() and path.name != "README.md"}
        self.assertFalse(files - links, f"unindexed documentation: {sorted(files - links)}")

    def test_active_plan_keeps_backend_tests_and_neutral_runtime(self):
        plan = (DOCS / "roadmap/observability-commit-plan.md").read_text()
        for requirement in ("SigNoz", "Grafana", "No Grafana/SigNoz SDK",
                            "Wait for GitHub CI and CodeQL",
                            "Commit 12", "actual running products"):
            self.assertIn(requirement, plan)


if __name__ == "__main__":
    unittest.main()
