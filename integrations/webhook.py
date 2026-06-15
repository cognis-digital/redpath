#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations
import argparse
import sys
import urllib.request

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Forward REDPATH JSON findings to a webhook endpoint.",
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https)")
    ap.add_argument("--header", action="append", default=[], help="Key: Value")
    args = ap.parse_args()

    if not args.url.startswith(("http://", "https://")):
        print("error: --url must start with http:// or https://", file=sys.stderr)
        return 2

    payload = sys.stdin.buffer.read()
    if not payload:
        print("error: no input on stdin; pipe JSON findings to this command",
              file=sys.stderr)
        return 2

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        k = k.strip()
        if not k:
            print(f"error: malformed --header value (no key): {h!r}",
                  file=sys.stderr)
            return 2
        req.add_header(k, v.strip())

    try:
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"webhook error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
