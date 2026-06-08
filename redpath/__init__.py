"""REDPATH - Active Directory attack path mapper.

Given a graph of AD principals and the rights/edges between them
(e.g. exported from a BloodHound-style collection), REDPATH finds the
minimum-cost path an attacker would take from a set of owned principals
to high-value targets, and ranks the edges whose removal would break the
most paths (remediation priority).

Standard library only. No install required.
"""

from redpath.core import (
    Graph,
    Edge,
    EDGE_COSTS,
    load_graph,
    shortest_path,
    map_attack_paths,
    remediation_priority,
)

TOOL_NAME = "redpath"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Graph",
    "Edge",
    "EDGE_COSTS",
    "load_graph",
    "shortest_path",
    "map_attack_paths",
    "remediation_priority",
    "TOOL_NAME",
    "TOOL_VERSION",
]
