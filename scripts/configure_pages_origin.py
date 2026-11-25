#!/usr/bin/env python3
"""Strictly validates a production Relay WSS URL and injects it context-safely
into web/index.html (<meta>) and web/_headers (CSP connect-src).
"""

import html
import os
import re
import sys
import tempfile
import urllib.parse

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
PATH_RE = re.compile(r"^/[A-Za-z0-9/_-]*$")
META_RE = re.compile(r'<meta\s+name="geistr-relay-url"\s+content="[^"]*">')
CONNECT_SRC_RE = re.compile(r"connect-src\s+'self'\s+[^;]+;")


def parse_relay_wss_url(raw: str) -> tuple[str, str]:
    if not isinstance(raw, str):
        raise ValueError("Relay URL must be a string")
    cleaned = raw.strip()
    if not cleaned:
        raise ValueError("Relay URL must not be empty")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned):
        raise ValueError("Relay URL must not contain whitespace or control characters")
    if any(ch in cleaned for ch in ("'", '"', ";", "\\", "<", ">", "*", "@", "?", "#")):
        raise ValueError("Relay URL contains disallowed characters")

    parsed = urllib.parse.urlsplit(cleaned)
    if parsed.scheme != "wss":
        raise ValueError(f"Relay URL scheme must be 'wss', got {parsed.scheme!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Relay URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Relay URL must not contain query or fragment")

    host = (parsed.hostname or "").lower()
    if not HOSTNAME_RE.match(host):
        raise ValueError(f"Invalid relay DNS hostname: {host!r}")

    port = parsed.port
    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"Invalid port: {port}")

    path = parsed.path or "/ws"
    if not PATH_RE.match(path):
        raise ValueError(f"Invalid relay path: {path!r}")

    netloc = host if (port is None or port == 443) else f"{host}:{port}"
    canonical_origin = f"wss://{netloc}"
    canonical_url = f"{canonical_origin}{path}"
    return canonical_url, canonical_origin


def apply_to_web_dir(web_dir: str, raw_wss_url: str) -> tuple[str, str]:
    canonical_url, canonical_origin = parse_relay_wss_url(raw_wss_url)

    index_path = os.path.join(web_dir, "index.html")
    headers_path = os.path.join(web_dir, "_headers")

    with open(index_path, "r", encoding="utf-8") as f:
        index_html = f.read()
    escaped_url = html.escape(canonical_url, quote=True)
    new_meta = f'<meta name="geistr-relay-url" content="{escaped_url}">'
    updated_html, html_count = META_RE.subn(new_meta, index_html)
    if html_count != 1:
        raise RuntimeError(
            f"Expected exactly 1 geistr-relay-url meta tag in {index_path}, found {html_count}"
        )

    with open(headers_path, "r", encoding="utf-8") as f:
        headers_txt = f.read()
    new_connect_src = f"connect-src 'self' {canonical_origin};"
    updated_headers, csp_count = CONNECT_SRC_RE.subn(new_connect_src, headers_txt)
    if csp_count != 1:
        raise RuntimeError(
            f"Expected exactly 1 connect-src directive in {headers_path}, found {csp_count}"
        )
    if "wss://*." in updated_headers or "connect-src 'self' *" in updated_headers:
        raise RuntimeError("Wildcard connect-src remains in generated _headers")

    with open(index_path, "w", encoding="utf-8") as f:
        f.write(updated_html)
    with open(headers_path, "w", encoding="utf-8") as f:
        f.write(updated_headers)

    return canonical_url, canonical_origin


def run_self_test() -> None:
    url, origin = parse_relay_wss_url("wss://geistr-relay.koyeb.app/ws")
    assert url == "wss://geistr-relay.koyeb.app/ws"
    assert origin == "wss://geistr-relay.koyeb.app"

    url2, origin2 = parse_relay_wss_url("wss://relay.example.com:8443/ws")
    assert url2 == "wss://relay.example.com:8443/ws"
    assert origin2 == "wss://relay.example.com:8443"

    url3, origin3 = parse_relay_wss_url("wss://relay.example.com:443/ws")
    assert url3 == "wss://relay.example.com/ws"
    assert origin3 == "wss://relay.example.com"

    bad_inputs = [
        "",
        "ws://geistr-relay.koyeb.app/ws",
        "https://geistr-relay.koyeb.app/ws",
        "wss://*.koyeb.app/ws",
        "wss://relay.example.com/ws; script-src 'unsafe-inline'",
        'wss://relay.example.com/ws"><script>alert(1)</script>',
        "wss://user:pass@relay.example.com/ws",
        "wss://relay.example.com/ws?foo=bar",
        "wss://relay.example.com/ws#frag",
        "wss://localhost/ws",
        "wss://relay.example.com/ws\nX-Injected: 1",
    ]
    for bad in bad_inputs:
        try:
            parse_relay_wss_url(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Expected ValueError for invalid URL: {bad!r}")

    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "index.html"), "w", encoding="utf-8") as f:
            f.write(
                '<head><meta name="geistr-relay-url" content="wss://geistr-relay.koyeb.app/ws"></head>'
            )
        with open(os.path.join(tmp, "_headers"), "w", encoding="utf-8") as f:
            f.write(
                "/*\n  Content-Security-Policy: default-src 'none'; connect-src 'self' wss://geistr-relay.koyeb.app; frame-ancestors 'none'\n"
            )
        apply_to_web_dir(tmp, "wss://prod-relay.example.net/ws")
        with open(os.path.join(tmp, "index.html"), "r", encoding="utf-8") as f:
            assert 'content="wss://prod-relay.example.net/ws"' in f.read()
        with open(os.path.join(tmp, "_headers"), "r", encoding="utf-8") as f:
            hdrs = f.read()
            assert "connect-src 'self' wss://prod-relay.example.net;" in hdrs
            assert "wss://*." not in hdrs

    print("configure_pages_origin self-test passed")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        run_self_test()
        return 0
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <web_dir> <relay_wss_url> | --self-test",
            file=sys.stderr,
        )
        return 2
    url, origin = apply_to_web_dir(sys.argv[1], sys.argv[2])
    print(f"Configured relay URL={url} CSP origin={origin}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
