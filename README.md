# PHP2Shell Python Probe

A small, **single-request, non-exploit** HTTP fingerprint for the PHP2Shell issues **CVE-2026-109618** and **CVE-2026-109619**. This Python script reimplements the HTTP payload and response-matching logic in PortSwigger's custom scan-check Bambda so it can run independently of Burp Suite.

> **Attribution:** The original Bambda is **"CVE-2026-109618,CVE-2026-109619 - PHP2Shell"**, authored by **Tom SL** ([TomLefley](https://github.com/TomLefley)), published in the [PortSwigger/bambdas](https://github.com/PortSwigger/bambdas) repository.
>
> **Original source:** [CVE-2026-109618CVE-2026-109619-PHP2Shell.bambda](https://github.com/PortSwigger/bambdas/blob/main/CustomScanChecks/CVE-2026-109618CVE-2026-109619-PHP2Shell.bambda)
>
> This is an **independent Python adaptation** based on the original Bambda's approach, not an official PortSwigger tool.

## Requirements

- Python 3.8 or later
- Network access to an HTTP or HTTPS endpoint handled by PHP
- **No third-party dependencies**: Python's standard library only
- Permission to test the target

## Usage

Run one test against an explicitly chosen URL:

```bash
python3 php2shell_probe.py http://127.0.0.1/index.php
```

Or reproduce the Bambda's original `POST /` target:

```bash
python3 php2shell_probe.py http://127.0.0.1/
```

For HTTPS:

```bash
python3 php2shell_probe.py https://my-php-host.example/index.php
```

Optional arguments:

```text
--timeout 10      Network timeout in seconds (default 10)
--insecure        Ignore invalid HTTPS certificates (lab testing only)
--show-response   Show the first 8192 characters of the HTTP response body
```

Example of a target with a self-signed certificate:

```bash
python3 php2shell_probe.py https://127.0.0.1/index.php --insecure
```

This script makes **one POST request**, does not follow redirects, and does not upload a persistent server-side file (the file part is a one-byte multipart upload).

## How it works

The request construction is adapted **directly from the original Bambda**:

1. Generate a random multipart boundary (`----` plus 32 alphanumeric characters), upload-progress token (20 characters), and `.txt` filename (12 characters plus `.txt`).
2. Send one HTTP/1.1 `POST` request to the selected URL. The original Bambda sends to `/`; this version allows a custom path so the POST can target a known PHP endpoint.
3. Add the deliberately invalid session cookie `PHPSESSID=_`.
4. Construct a `multipart/form-data` body with precisely two parts, in the same order and with the same CRLF formatting:
   - A form field named `PHP_SESSION_UPLOAD_PROGRESS` containing the random token.
   - A file field named `f`, whose randomly named `.txt` upload contains exactly the single character `1` with content type `text/plain`.
5. Look for **all three exact, case-sensitive substrings** in the HTTP response body:

   ```text
   Session ID is too long or contains illegal characters
   Failed to read session data
   Failed to write session data (
   ```

6. Mark **INDICATORS FOUND** only when all three appear, exactly as the original Bambda does. If one or more are absent, report **INCONCLUSIVE** rather than claiming the target is safe.

### What the request looks like

The boundary, token, and filename below are illustrative: the program generates new random values for every run.

```http
POST /index.php HTTP/1.1
Host: target.example
Cookie: PHPSESSID=_
Content-Type: multipart/form-data; boundary=----exampleBoundary

------exampleBoundary
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

test-token
------exampleBoundary
Content-Disposition: form-data; name="f"; filename="probe.txt"
Content-Type: text/plain

1
------exampleBoundary--
```

The script also sets `Accept-Encoding: identity` to request an uncompressed response. The Python HTTP library supplies `Content-Length` and `Host` headers automatically.

## What the response means

| Result | Meaning |
|---|---|
| **INDICATORS FOUND** | All three PHP warning strings are present. The response matches the unpatched-session-write behavior used by the original Bambda. Investigate and patch. |
| **INCONCLUSIVE** | The response did not contain all three strings, or was encoded unexpectedly. **This does not establish that PHP is patched.** |
| **ERROR** | No usable HTTP response was obtained (for example, TLS failure or connection refused). |

### Exit codes

- `0` — all three warning strings were found
- `1` — inconclusive / warning condition not met
- `2` — connection or transport error

> Warning: do not treat exit code `1` as "not vulnerable." The Bambda checks an observable behavior, not the actual memory-corruption primitive or execution of code.

## Why the warning-based fingerprint works

The invalid `PHPSESSID` is intended to cause session startup to fail. The `PHP_SESSION_UPLOAD_PROGRESS` multipart field causes PHP's upload-progress session-handling path to be exercised when enabled. The first two warnings indicate invalid session startup; the third suggests that PHP still attempted to write session data after startup had failed. The original Bambda's author uses this final warning as the discriminator for the behavior changed by the PHP2Shell fix.

Neither this Python adaptation nor the original Bambda attempts remote code execution, out-of-memory exhaustion, heap manipulation, or a use-after-free exploit. **A matching fingerprint is not independent proof of RCE.**

## Caveats and troubleshooting

- **PHP response warnings may be hidden.** If `display_errors` is off, PHP may write errors only to logs, so the response may lack the three indicators. The original Bambda likewise inspects *only the response body*.
- **Choose a URL that reaches PHP.** A static file, non-PHP handler, redirect, or reverse-proxy error won't exercise the intended code path. The original uses `POST /`; targeting a known PHP page may be more reliable.
- **Upload-progress behavior is configuration-dependent.** Disabling `session.upload_progress.enabled`, using a different session cookie name, or modifying error reporting can prevent these exact strings from appearing.
- **No redirects followed.** HTTP 301/302 and other redirects are not followed to avoid probing a different endpoint without your knowledge.
- **No compressed response decoding.** The script asks the server for `identity` encoding. If a server ignores that and compresses responses, the result is inconclusive.
- **Response size limit.** Only the first 2 MiB of response body is examined.
- **The CVEs are broader than this test.** A negative result does not rule out CVE-2026-109618 or CVE-2026-109619. Vendor backports may also make version strings misleading.

### Patching

PHP upstream patched the issues in:

| Branch | Patched version |
|---|---|
| PHP 8.2 | 8.2.35 |
| PHP 8.3 | 8.3.36 |
| PHP 8.4 | 8.4.27 |
| PHP 8.5 | 8.5.12 |

For older branches, investigate distributor/LTS-vendor backports or move to a supported branch. Restart affected PHP workers after updating and verify the installed package security status. Configuration workarounds are only partial mitigations.

## Differences from the Bambda

| Item | Original PortSwigger Bambda | Python adaptation |
|---|---|---|
| Runtime | Burp Suite scanner / Bambda API | Python 3 standard library |
| Target | `POST /` on the scanned host | Any explicitly supplied HTTP(S) URL; `/` if no path supplied |
| Request | Invalid PHPSESSID and two-part multipart body | Same cookie, multipart parts, ordering, and content |
| Decision | Presence of three exact warnings | Same three exact, case-sensitive warning substrings |
| Finding | Burp `AuditIssue` | Terminal result and process exit code |
| Redirects | Burp-controlled request | Explicitly not followed |
| Response safety | Burp's response handling | Response capped at 2 MiB; requests identity encoding |

## References

- [Original PortSwigger Bambda (Tom SL)](https://github.com/PortSwigger/bambdas/blob/main/CustomScanChecks/CVE-2026-109618CVE-2026-109619-PHP2Shell.bambda)
- [PortSwigger Bambda repository](https://github.com/PortSwigger/bambdas)
- [PHP security announcement, October 21, 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

**Use only on systems you are authorized to test.**
