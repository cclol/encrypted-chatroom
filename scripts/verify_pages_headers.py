#!/usr/bin/env python3
"""Post-deployment header verification for Cloudflare Pages (geistr).

Fetches /, /index.html, /worker.js, and /pkg/web_client_bg.wasm and verifies that:
- HTTP 200 is returned for each path
- Content-Security-Policy strictly pins connect-src to the configured wss origin (no wildcards)
- Cache-Control: no-store is present on / and /index.html
"""

import sys
import urllib.request

from configure_pages_origin import parse_relay_wss_url


def verify_headers(pages_base_url: str, raw_relay_wss_url: str) -> None:
    _, expected_origin = parse_relay_wss_url(raw_relay_wss_url)
    base = pages_base_url.rstrip("/")
    paths = ["/", "/index.html", "/worker.js", "/pkg/web_client_bg.wasm"]

    for path in paths:
        url = f"{base}{path}"
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status != 200:
                raise RuntimeError(f"{url} returned HTTP {resp.status}")
            csp = resp.headers.get("Content-Security-Policy", "")
            expected_directive = f"connect-src 'self' {expected_origin};"
            if expected_directive not in csp:
                raise RuntimeError(
                    f"{url} missing expected CSP directive {expected_directive!r}; got {csp!r}"
                )
            if "wss://*." in csp:
                raise RuntimeError(f"{url} still exposes wildcard WSS in CSP: {csp!r}")
            if path in ("/", "/index.html"):
                cc = resp.headers.get("Cache-Control", "").lower()
                if "no-store" not in cc:
                    raise RuntimeError(f"{url} missing Cache-Control: no-store; got {cc!r}")
        print(f"OK {url}")


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <pages_base_url> <relay_wss_url>", file=sys.stderr)
        return 2
    verify_headers(sys.argv[1], sys.argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
