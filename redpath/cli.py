"""Command line interface for REDPATH."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from redpath import TOOL_NAME, TOOL_VERSION
from redpath.core import (
    load_graph_file,
    map_attack_paths,
    remediation_priority,
)


def _print_paths_table(results: List[dict]) -> None:
    print(f"{'TARGET':<32} {'REACH':<6} {'COST':>7} {'HOPS':>5}")
    print("-" * 54)
    for r in results:
        cost = "-" if r["cost"] is None else f"{r['cost']:.2f}"
        reach = "yes" if r["reachable"] else "NO"
        print(f"{r['target']:<32} {reach:<6} {cost:>7} {r['hops']:>5}")
        for step in r["path"]:
            print(f"    {step['src']} -[{step['kind']}]-> {step['dst']}"
                  f"  (+{step['cost']:.0f})")


def _print_remediation_table(rows: List[dict]) -> None:
    print(f"{'EDGE':<48} {'PATHS':>5} {'BROKEN':>6} {'+COST':>7}")
    print("-" * 70)
    for r in rows:
        delta = "-" if r["cost_increase"] is None else f"{r['cost_increase']:.1f}"
        print(f"{r['edge']:<48} {r['on_paths']:>5} "
              f"{r['targets_broken']:>6} {delta:>7}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Active Directory attack path mapper: minimum-cost "
                    "compromise paths and remediation priority.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("--format", choices=("table", "json"),
                        default="table", help="output format")
    sub = parser.add_subparsers(dest="command", required=True)

    p_paths = sub.add_parser("paths",
                             help="map minimum-cost attack paths to targets")
    p_paths.add_argument("graph", help="path to graph JSON file")

    p_rem = sub.add_parser("remediate",
                           help="rank edges by remediation priority")
    p_rem.add_argument("graph", help="path to graph JSON file")

    args = parser.parse_args(argv)

    try:
        g = load_graph_file(args.graph)
    except FileNotFoundError:
        print(f"error: graph file not found: {args.graph}", file=sys.stderr)
        return 2
    except PermissionError:
        print(f"error: permission denied reading: {args.graph}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot read graph file: {exc}", file=sys.stderr)
        return 2
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: invalid graph: {exc}", file=sys.stderr)
        return 2

    try:
        if args.command == "paths":
            results = map_attack_paths(g)
            if args.format == "json":
                print(json.dumps({"paths": results}, indent=2))
            else:
                _print_paths_table(results)
            # Fail if no target is reachable at all (nothing actionable / bad input).
            return 0 if any(r["reachable"] for r in results) else 1

        if args.command == "remediate":
            rows = remediation_priority(g)
            if args.format == "json":
                print(json.dumps({"remediation": rows}, indent=2))
            else:
                _print_remediation_table(rows)
            return 0 if rows else 1
    except Exception as exc:  # noqa: BLE001
        print(f"error: unexpected failure during analysis: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
