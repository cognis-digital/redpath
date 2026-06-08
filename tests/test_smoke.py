"""Smoke + logic tests for REDPATH. No network. Standard library only."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from redpath import TOOL_NAME, TOOL_VERSION  # noqa: E402
from redpath.cli import main  # noqa: E402
from redpath.core import (  # noqa: E402
    load_graph,
    map_attack_paths,
    remediation_priority,
    shortest_path,
)

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic",
                    "corp.json")


def _demo_graph():
    with open(DEMO, "r", encoding="utf-8") as fh:
        return load_graph(json.load(fh))


class TestMeta(unittest.TestCase):
    def test_version(self):
        self.assertEqual(TOOL_NAME, "redpath")
        self.assertTrue(TOOL_VERSION)


class TestCore(unittest.TestCase):
    def test_loads_demo(self):
        g = _demo_graph()
        self.assertEqual(g.owned, ["JDOE@CORP.LOCAL"])
        self.assertIn("DOMAIN ADMINS@CORP.LOCAL", g.targets)

    def test_finds_min_cost_path(self):
        g = _demo_graph()
        found = shortest_path(g, g.owned, "DOMAIN ADMINS@CORP.LOCAL")
        self.assertIsNotNone(found)
        cost, edges = found
        # MemberOf+AdminTo+HasSession+ForceChangePassword+MemberOf
        # = 1+2+3+4+1 = 11
        self.assertEqual(cost, 11.0)
        kinds = [e.kind for e in edges]
        self.assertEqual(
            kinds,
            ["MemberOf", "AdminTo", "HasSession",
             "ForceChangePassword", "MemberOf"],
        )

    def test_map_attack_paths_sorted_and_reachable(self):
        g = _demo_graph()
        results = map_attack_paths(g)
        self.assertTrue(all(r["reachable"] for r in results))
        costs = [r["cost"] for r in results]
        self.assertEqual(costs, sorted(costs))

    def test_remediation_identifies_chokepoint(self):
        g = _demo_graph()
        rows = remediation_priority(g)
        self.assertTrue(rows)
        # The DA path runs only through the HasSession edge; removing it
        # must break at least one target.
        self.assertTrue(any(r["targets_broken"] >= 1 for r in rows))
        self.assertGreaterEqual(rows[0]["targets_broken"], 1)

    def test_unreachable_target(self):
        g = load_graph({
            "edges": [{"src": "A", "dst": "B", "kind": "MemberOf"}],
            "owned": ["A"],
            "targets": ["ISLAND"],
        })
        results = map_attack_paths(g)
        self.assertFalse(results[0]["reachable"])

    def test_rejects_bad_graph(self):
        with self.assertRaises(ValueError):
            load_graph({"edges": []})
        with self.assertRaises(ValueError):
            load_graph({"edges": [{"src": "A", "dst": "B", "kind": "X"}]})


class TestCli(unittest.TestCase):
    def test_paths_json_exit_zero(self):
        self.assertEqual(main(["--format", "json", "paths", DEMO]), 0)

    def test_remediate_exit_zero(self):
        self.assertEqual(main(["--format", "json", "remediate", DEMO]), 0)

    def test_missing_file_nonzero(self):
        self.assertEqual(main(["paths", "/no/such/file.json"]), 2)


if __name__ == "__main__":
    unittest.main()
