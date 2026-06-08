"""Core engine for REDPATH.

Model
-----
An AD environment is a directed graph. Nodes are principals (users,
groups, computers, domains, GPOs). Edges are the rights one principal has
over another, e.g. ``MemberOf``, ``AdminTo``, ``GenericAll``,
``DCSync``. Each edge type carries an *abuse cost*: how much effort /
risk / tooling an attacker needs to traverse it. Cheaper edges are more
dangerous.

The attacker starts from one or more *owned* principals and wants to
reach one or more *high-value targets*. The minimum-cost path is the
least-effort compromise route. Remediation priority ranks edges by how
many of the discovered attack paths they appear on (chokepoints first).

All algorithms are exact (Dijkstra over non-negative edge costs).
"""

from __future__ import annotations

import heapq
import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

# Abuse cost per edge type. Lower == easier to abuse == more dangerous.
# Loosely modeled on BloodHound edge semantics; tunable per engagement.
EDGE_COSTS: Dict[str, float] = {
    "MemberOf": 1.0,        # already a member, near-free
    "AdminTo": 2.0,         # local admin -> creds/SYSTEM
    "HasSession": 3.0,      # token/cred theft from a live session
    "CanRDP": 3.0,
    "CanPSRemote": 3.0,
    "ForceChangePassword": 4.0,
    "AddMember": 4.0,
    "GenericWrite": 5.0,
    "WriteDacl": 5.0,
    "WriteOwner": 5.0,
    "GenericAll": 5.0,
    "Owns": 5.0,
    "AllowedToDelegate": 6.0,
    "AddKeyCredentialLink": 6.0,  # shadow credentials
    "GPLink": 7.0,
    "DCSync": 8.0,          # powerful but loud / detectable
    "GetChanges": 8.0,
}
DEFAULT_EDGE_COST = 10.0  # unknown edge type: traversable but expensive


@dataclass(frozen=True)
class Edge:
    """A directed abuse edge from ``src`` to ``dst``."""

    src: str
    dst: str
    kind: str

    @property
    def cost(self) -> float:
        return EDGE_COSTS.get(self.kind, DEFAULT_EDGE_COST)

    def key(self) -> str:
        return f"{self.src}-[{self.kind}]->{self.dst}"


@dataclass
class Graph:
    """Directed multigraph of AD principals and abuse edges."""

    nodes: set = field(default_factory=set)
    edges: List[Edge] = field(default_factory=list)
    _adj: Dict[str, List[Edge]] = field(default_factory=dict)
    owned: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)

    def add_edge(self, src: str, dst: str, kind: str) -> None:
        e = Edge(src, dst, kind)
        self.edges.append(e)
        self.nodes.add(src)
        self.nodes.add(dst)
        self._adj.setdefault(src, []).append(e)
        self._adj.setdefault(dst, self._adj.get(dst, []))

    def out_edges(self, node: str) -> List[Edge]:
        return self._adj.get(node, [])


def load_graph(data: dict) -> Graph:
    """Build a :class:`Graph` from a plain dict (parsed JSON).

    Expected schema::

        {
          "nodes": ["USER@DOM", "GROUP@DOM", ...],   # optional
          "edges": [{"src": "A", "dst": "B", "kind": "MemberOf"}, ...],
          "owned": ["A"],                              # attacker start set
          "targets": ["DOMAIN ADMINS@DOM"]             # high value targets
        }
    """
    if not isinstance(data, dict):
        raise ValueError("graph data must be a JSON object")
    raw_edges = data.get("edges")
    if not isinstance(raw_edges, list) or not raw_edges:
        raise ValueError("graph must contain a non-empty 'edges' list")

    g = Graph()
    for node in data.get("nodes", []) or []:
        g.nodes.add(str(node))
    for i, e in enumerate(raw_edges):
        if not isinstance(e, dict):
            raise ValueError(f"edge #{i} is not an object")
        try:
            src, dst, kind = e["src"], e["dst"], e["kind"]
        except KeyError as exc:
            raise ValueError(f"edge #{i} missing field {exc}") from None
        g.add_edge(str(src), str(dst), str(kind))

    g.owned = [str(x) for x in (data.get("owned") or [])]
    g.targets = [str(x) for x in (data.get("targets") or [])]
    if not g.owned:
        raise ValueError("graph must specify at least one 'owned' principal")
    if not g.targets:
        raise ValueError("graph must specify at least one 'targets' principal")
    return g


def shortest_path(
    g: Graph, sources: Iterable[str], target: str
) -> Optional[Tuple[float, List[Edge]]]:
    """Dijkstra from a *set* of sources to a single target.

    Returns ``(total_cost, [edges])`` or ``None`` if unreachable. A virtual
    super-source with zero-cost links to every owned principal lets one run
    cover all attacker footholds at once.
    """
    dist: Dict[str, float] = {}
    prev: Dict[str, Optional[Edge]] = {}
    pq: List[Tuple[float, str]] = []
    for s in sources:
        if s not in dist or 0.0 < dist[s]:
            dist[s] = 0.0
            prev[s] = None
            heapq.heappush(pq, (0.0, s))

    while pq:
        d, node = heapq.heappop(pq)
        if d > dist.get(node, float("inf")):
            continue
        if node == target:
            break
        for e in g.out_edges(node):
            nd = d + e.cost
            if nd < dist.get(e.dst, float("inf")):
                dist[e.dst] = nd
                prev[e.dst] = e
                heapq.heappush(pq, (nd, e.dst))

    if target not in dist:
        return None
    # Reconstruct.
    path: List[Edge] = []
    cur: Optional[str] = target
    while cur is not None and prev.get(cur) is not None:
        e = prev[cur]
        assert e is not None
        path.append(e)
        cur = e.src
    path.reverse()
    return dist[target], path


def map_attack_paths(g: Graph) -> List[dict]:
    """Find the minimum-cost path to every target. Sorted cheapest-first."""
    results: List[dict] = []
    for tgt in g.targets:
        found = shortest_path(g, g.owned, tgt)
        if found is None:
            results.append(
                {"target": tgt, "reachable": False, "cost": None,
                 "hops": 0, "path": []}
            )
            continue
        cost, edges = found
        results.append(
            {
                "target": tgt,
                "reachable": True,
                "cost": round(cost, 2),
                "hops": len(edges),
                "path": [
                    {"src": e.src, "kind": e.kind, "dst": e.dst,
                     "cost": e.cost}
                    for e in edges
                ],
            }
        )
    results.sort(key=lambda r: (not r["reachable"],
                                r["cost"] if r["cost"] is not None else 0))
    return results


def remediation_priority(g: Graph) -> List[dict]:
    """Rank edges by how many reachable attack paths they sit on.

    An edge on many minimum-cost paths is a chokepoint: removing it forces
    the attacker onto a more costly route (or breaks reachability). We also
    report the cost increase caused by removing each candidate edge.
    """
    paths = map_attack_paths(g)
    reachable = [p for p in paths if p["reachable"]]
    if not reachable:
        return []

    # Count edge occurrences across all minimum-cost paths.
    counts: Dict[str, int] = {}
    meta: Dict[str, Edge] = {}
    for p in reachable:
        for step in p["path"]:
            e = Edge(step["src"], step["dst"], step["kind"])
            counts[e.key()] = counts.get(e.key(), 0) + 1
            meta[e.key()] = e

    baseline = sum(p["cost"] for p in reachable)

    scored: List[dict] = []
    for key, count in counts.items():
        e = meta[key]
        # Measure impact: recompute paths with this edge removed.
        removed = Graph()
        removed.owned, removed.targets = g.owned, g.targets
        for oe in g.edges:
            if not (oe.src == e.src and oe.dst == e.dst and oe.kind == e.kind):
                removed.add_edge(oe.src, oe.dst, oe.kind)
        after = map_attack_paths(removed)
        broken = sum(1 for p in after if not p["reachable"])
        new_cost = sum(p["cost"] for p in after if p["reachable"])
        delta = round(new_cost - baseline, 2) if new_cost else None
        scored.append(
            {
                "edge": key,
                "kind": e.kind,
                "on_paths": count,
                "targets_broken": broken,
                "cost_increase": delta,
            }
        )

    scored.sort(
        key=lambda s: (s["targets_broken"], s["on_paths"],
                       s["cost_increase"] or 0),
        reverse=True,
    )
    return scored


def load_graph_file(path: str) -> Graph:
    with open(path, "r", encoding="utf-8") as fh:
        return load_graph(json.load(fh))
