#!/usr/bin/env python3
"""PHP2Shell warning-based probe adapted from PortSwigger's PHP2Shell Bambda.

Original by Tom SL (TomLefley):
https://github.com/PortSwigger/bambdas/blob/main/CustomScanChecks/CVE-2026-109618CVE-2026-109619-PHP2Shell.bambda

This is a one-request, non-exploit fingerprint. It does not perform RCE or
attempt to trigger the underlying memory corruption vulnerabilities.

Run only against systems you own or have permission to test.
"""

import argparse
import secrets
import socket
import ssl
import string
import sys
from urllib import error, parse, request


# Exact response substrings tested by the original Bambda (case-sensitive).
STARTUP_WARNINGS = (
    "Session ID is too long or contains illegal characters",
    "Failed to read session data",
)
WRITE_WARNING = "Failed to write session data ("
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class NoRedirect(request.HTTPRedirectHandler):
    """Keep the probe on the explicitly selected URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def random_string(length):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def build_multipart_body():
    """Reproduce the Bambda's multipart payload, including part order/CRLFs."""
    boundary = "----" + random_string(32)
    token = random_string(20)
    filename = random_string(12) + ".txt"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{token}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        "Content-Type: text/plain\r\n\r\n"
        "1\r\n"
        f"--{boundary}--\r\n"
    ).encode("ascii")
    return boundary, body


def check_url(url):
    try:
        parsed = parse.urlsplit(url)
        # Force urllib to validate a possibly malformed explicit port.
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Specify a full http:// or https:// URL with a hostname")
    if parsed.username or parsed.password:
        raise ValueError("Put no username/password in the URL")
    if parsed.fragment:
        raise ValueError("URL fragments are not sent over HTTP; omit the #fragment")
    if port == 0:
        raise ValueError("Port must be nonzero")
    return url


def send_probe(url, timeout, insecure):
    boundary, body = build_multipart_body()
    req = request.Request(
        url,
        data=body,
        headers={
            "Cookie": "PHPSESSID=_",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept-Encoding": "identity",
        },
        method="POST",
    )
    # urllib sets Content-Length and Host automatically, using HTTP/1.1.
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    opener = request.build_opener(
        NoRedirect(), request.HTTPSHandler(context=ctx)
    )
    try:
        response = opener.open(req, timeout=timeout)
    except error.HTTPError as exc:
        # 3xx (redirects disabled), 4xx and 5xx still have useful bodies.
        response = exc

    with response:
        status = response.status
        location = response.headers.get("Location")
        encoding = response.headers.get("Content-Encoding", "identity").lower()
        data = response.read(MAX_RESPONSE_BYTES + 1)
        truncated = len(data) > MAX_RESPONSE_BYTES
        if truncated:
            data = data[:MAX_RESPONSE_BYTES]
    return status, location, encoding, data, truncated


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Check for PHP2Shell session-warning indicators using the exact "
            "multipart request and string checks from PortSwigger's Bambda."
        )
    )
    parser.add_argument(
        "url", help="Full target URL, e.g. http://127.0.0.1/index.php"
    )
    parser.add_argument(
        "--timeout", type=float, default=10,
        help="Network timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="Disable HTTPS certificate validation (testing only)",
    )
    parser.add_argument(
        "--show-response", action="store_true",
        help="Print up to 8192 characters of the HTTP response body",
    )
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    try:
        url = check_url(args.url)
    except ValueError as exc:
        parser.error(str(exc))

    print(f"Target:  {url}")
    print("Probe:   one multipart POST, with Cookie: PHPSESSID=_")
    try:
        status, location, encoding, data, truncated = send_probe(
            url, args.timeout, args.insecure
        )
    except (error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError) as exc:
        print(f"Result:  ERROR: {exc}")
        return 2

    print(f"HTTP:    {status}")
    if location:
        print(f"Location: {location} (redirect NOT followed)")
    if encoding not in ("identity", ""):
        print(f"Result:  INCONCLUSIVE (unexpected Content-Encoding: {encoding})")
        print("         Retry against an endpoint returning uncompressed content.")
        return 1

    found = {warning: warning.encode("ascii") in data for warning in (*STARTUP_WARNINGS, WRITE_WARNING)}
    print("Warning strings in response body:")
    for warning, present in found.items():
        print(f"  {'FOUND  ' if present else 'MISSING'}  {warning}")

    if args.show_response:
        print("\n--- Response body (up to 8192 characters) ---")
        print(data[:8192].decode("utf-8", errors="replace"))
        print("--- End response body ---")

    if all(found.values()):
        print("\nResult:  INDICATORS FOUND — matches the original Bambda's check.")
        print("         This fingerprints an unpatched session-write behavior;")
        print("         it is not proof that RCE is exploitable.")
        return 0

    print("\nResult:  INCONCLUSIVE — the Bambda's three-warning condition was not met.")
    if truncated:
        print("         The response body exceeded 2 MiB and was truncated.")
    print("         A negative response does NOT prove the PHP installation is patched.")
    print("         Check PHP version/vendor fixes, error visibility, upload-progress settings, and routing.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
