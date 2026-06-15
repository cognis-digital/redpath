"""Tests for hardened input validation and error handling in REDPATH."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from redpath.cli import main  # noqa: E402
from redpath.core import (  # noqa: E402
    load_graph,
    load_graph_file,
    map_attack_paths,
    remediation_priority,
    shortest_path,
)


# ---------------------------------------------------------------------------
# Helper: build a minimal valid graph dict
# ---------------------------------------------------------------------------

def _valid_data(**overrides):
    base = {
        "edges": [{"src": "A", "dst": "B", "kind": "MemberOf"}],
        "owned": ["A"],
        "targets": ["B"],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# load_graph — validation
# ---------------------------------------------------------------------------

class TestLoadGraphValidation(unittest.TestCase):

    def test_rejects_non_dict(self):
        with self.assertRaises(ValueError):
            load_graph([{"src": "A", "dst": "B", "kind": "MemberOf"}])

    def test_rejects_empty_edges_list(self):
        with self.assertRaises(ValueError):
            load_graph({"edges": [], "owned": ["A"], "targets": ["B"]})

    def test_rejects_missing_edges_key(self):
        with self.assertRaises(ValueError):
            load_graph({"owned": ["A"], "targets": ["B"]})

    def test_rejects_owned_not_a_list(self):
        with self.assertRaises(ValueError):
            load_graph(_valid_data(owned="A"))

    def test_rejects_targets_not_a_list(self):
        with self.assertRaises(ValueError):
            load_graph(_valid_data(targets="B"))

    def test_rejects_nodes_not_a_list(self):
        with self.assertRaises(ValueError):
            load_graph(_valid_data(nodes="NODE"))

    def test_rejects_edge_with_empty_src(self):
        with self.assertRaises(ValueError):
            load_graph({
                "edges": [{"src": "", "dst": "B", "kind": "MemberOf"}],
                "owned": ["A"],
                "targets": ["B"],
            })

    def test_rejects_edge_with_empty_dst(self):
        with self.assertRaises(ValueError):
            load_graph({
                "edges": [{"src": "A", "dst": "  ", "kind": "MemberOf"}],
                "owned": ["A"],
                "targets": ["B"],
            })

    def test_rejects_edge_with_empty_kind(self):
        with self.assertRaises(ValueError):
            load_graph({
                "edges": [{"src": "A", "dst": "B", "kind": ""}],
                "owned": ["A"],
                "targets": ["B"],
            })

    def test_rejects_all_blank_owned(self):
        """owned list containing only whitespace strings => no valid principals."""
        with self.assertRaises(ValueError):
            load_graph({
                "edges": [{"src": "A", "dst": "B", "kind": "MemberOf"}],
                "owned": ["   "],
                "targets": ["B"],
            })

    def test_rejects_all_blank_targets(self):
        with self.assertRaises(ValueError):
            load_graph({
                "edges": [{"src": "A", "dst": "B", "kind": "MemberOf"}],
                "owned": ["A"],
                "targets": [""],
            })

    def test_rejects_edge_missing_field(self):
        with self.assertRaises(ValueError):
            load_graph({
                "edges": [{"src": "A", "kind": "MemberOf"}],  # missing dst
                "owned": ["A"],
                "targets": ["B"],
            })

    def test_rejects_non_object_edge(self):
        with self.assertRaises(ValueError):
            load_graph({
                "edges": ["not-an-object"],
                "owned": ["A"],
                "targets": ["B"],
            })

    def test_accepts_valid_minimal(self):
        g = load_graph(_valid_data())
        self.assertEqual(g.owned, ["A"])
        self.assertEqual(g.targets, ["B"])
        self.assertEqual(len(g.edges), 1)

    def test_accepts_unknown_edge_type(self):
        """Unknown edge types are allowed; they get DEFAULT_EDGE_COST."""
        g = load_graph({
            "edges": [{"src": "A", "dst": "B", "kind": "SomeWeirdRight"}],
            "owned": ["A"],
            "targets": ["B"],
        })
        self.assertEqual(g.edges[0].kind, "SomeWeirdRight")
        from redpath.core import DEFAULT_EDGE_COST
        self.assertEqual(g.edges[0].cost, DEFAULT_EDGE_COST)


# ---------------------------------------------------------------------------
# load_graph_file — file-level errors
# ---------------------------------------------------------------------------

class TestLoadGraphFile(unittest.TestCase):

    def test_missing_file_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_graph_file("/no/such/path/graph.json")

    def test_malformed_json_raises_json_decode_error(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("{not valid json")
            path = fh.name
        try:
            with self.assertRaises(json.JSONDecodeError):
                load_graph_file(path)
        finally:
            os.unlink(path)

    def test_valid_file_loads_correctly(self):
        data = _valid_data()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(data, fh)
            path = fh.name
        try:
            g = load_graph_file(path)
            self.assertEqual(g.owned, ["A"])
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# shortest_path edge cases
# ---------------------------------------------------------------------------

class TestShortestPathEdgeCases(unittest.TestCase):

    def test_no_sources(self):
        """Empty source set should return None (target unreachable)."""
        g = load_graph(_valid_data())
        result = shortest_path(g, [], "B")
        self.assertIsNone(result)

    def test_target_is_source(self):
        """Source == target: cost 0, empty path."""
        g = load_graph(_valid_data())
        result = shortest_path(g, ["B"], "B")
        self.assertIsNotNone(result)
        cost, path = result
        self.assertEqual(cost, 0.0)
        self.assertEqual(path, [])

    def test_nonexistent_target_returns_none(self):
        g = load_graph(_valid_data())
        result = shortest_path(g, ["A"], "GHOST")
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# map_attack_paths — single-target all-unreachable
# ---------------------------------------------------------------------------

class TestMapAttackPaths(unittest.TestCase):

    def test_all_unreachable(self):
        g = load_graph({
            "edges": [{"src": "A", "dst": "B", "kind": "MemberOf"}],
            "owned": ["C"],   # C has no outgoing edges to B
            "targets": ["B"],
        })
        results = map_attack_paths(g)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["reachable"])
        self.assertIsNone(results[0]["cost"])
        self.assertEqual(results[0]["hops"], 0)

    def test_direct_edge(self):
        g = load_graph(_valid_data())
        results = map_attack_paths(g)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["reachable"])
        self.assertGreater(results[0]["cost"], 0)


# ---------------------------------------------------------------------------
# remediation_priority — no reachable paths
# ---------------------------------------------------------------------------

class TestRemediationPriority(unittest.TestCase):

    def test_no_reachable_paths_returns_empty(self):
        g = load_graph({
            "edges": [{"src": "A", "dst": "B", "kind": "MemberOf"}],
            "owned": ["C"],
            "targets": ["B"],
        })
        rows = remediation_priority(g)
        self.assertEqual(rows, [])


# ---------------------------------------------------------------------------
# CLI — hardened error paths
# ---------------------------------------------------------------------------

class TestCliHardened(unittest.TestCase):

    def test_malformed_json_exit_2(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("{bad json !!!")
            path = fh.name
        try:
            self.assertEqual(main(["paths", path]), 2)
        finally:
            os.unlink(path)

    def test_invalid_schema_exit_2(self):
        """Valid JSON but fails graph schema validation -> exit 2."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump({"edges": [], "owned": ["A"], "targets": ["B"]}, fh)
            path = fh.name
        try:
            self.assertEqual(main(["paths", path]), 2)
        finally:
            os.unlink(path)

    def test_unreachable_targets_exit_1(self):
        """All targets unreachable -> exit 1 (not 0, not 2)."""
        data = {
            "edges": [{"src": "A", "dst": "B", "kind": "MemberOf"}],
            "owned": ["C"],
            "targets": ["B"],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(data, fh)
            path = fh.name
        try:
            self.assertEqual(main(["paths", path]), 1)
        finally:
            os.unlink(path)

    def test_remediate_no_paths_exit_1(self):
        """remediate with no reachable paths -> exit 1."""
        data = {
            "edges": [{"src": "A", "dst": "B", "kind": "MemberOf"}],
            "owned": ["C"],
            "targets": ["B"],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(data, fh)
            path = fh.name
        try:
            self.assertEqual(main(["remediate", path]), 1)
        finally:
            os.unlink(path)

    def test_missing_file_returns_2(self):
        self.assertEqual(main(["paths", "/totally/missing.json"]), 2)

    def test_valid_graph_json_format(self):
        """Sanity: valid graph with --format json returns exit 0."""
        data = _valid_data()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(data, fh)
            path = fh.name
        try:
            code = main(["--format", "json", "paths", path])
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
