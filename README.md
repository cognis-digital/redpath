# REDPATH — Active Directory attack path mapper — minimum-cost paths + remediation priority

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `red-team`

[![PyPI](https://img.shields.io/pypi/v/cognis-redpath.svg)](https://pypi.org/project/cognis-redpath/)
[![CI](https://github.com/cognis-digital/redpath/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/redpath/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Active Directory attack path mapper — minimum-cost paths + remediation priority.

## Install

```bash
pip install cognis-redpath
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
redpath --version
redpath scan demos/                          # run against bundled demo
redpath scan demos/ --format sarif --out r.sarif --fail-on high
redpath mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-tier0-direct-path/` — see [`SCENARIO.md`](demos/01-tier0-direct-path/SCENARIO.md)
- `demos/02-clean-tiered-environment/` — see [`SCENARIO.md`](demos/02-clean-tiered-environment/SCENARIO.md)
- `demos/03-post-incident-cleanup/` — see [`SCENARIO.md`](demos/03-post-incident-cleanup/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
