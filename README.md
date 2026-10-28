# HARShield

**Status:** Completed MVP (experimental) · SonyDev GitHub Marathon, Day 2 (October 28, 2026)

HARShield is a local Python CLI that removes common credentials from HTTP Archive (HAR) JSON files before sharing them. It does not send data over the network.

## Install

Requires Python 3.10 or later. No runtime dependencies.

```sh
python -m pip install .
```

## Usage

```sh
harshield session.har --output session.clean.har
harshield session.har --check
harshield session.har --output - > session.clean.har
```

`--check` exits with 0 when no supported redactions are needed, 1 when it finds fields to redact, and 2 for invalid input or file errors. Normal redaction exits with 0 on success and 2 on error. Without `--force`, output creation fails if the path already exists, including if another process creates it during writing. This requires a filesystem that supports hard links. With `--force`, the replacement is atomic. Input files are never modified. Files written by the CLI use mode 0600 on POSIX systems.

## Redaction rules

- Replaces values of sensitive headers and query parameters (for example, `Authorization`, `Cookie`, `access_token`, and `api_key`). Also checks request and redirect URL queries, including semicolon-separated parameters.
- Replaces all cookie values, form parameter values, request body text, and response body text. Redacts `Link`, `Refresh`, `WWW-Authenticate`, and `Proxy-Authenticate` header values and checks `Content-Location` URLs.
- Removes URL fragments, URL userinfo, HAR comments, and nonstandard fields beginning with `_`.
- Preserves other HAR metadata and non-sensitive values. The replacement string is `[REDACTED]`.

**Limitations:** This is a best-effort filter, not a guarantee that a HAR is safe to publish. Tokens embedded in URL paths, arbitrary headers, filenames, page titles, or other unrecognized fields may remain. Review the sanitized file before sharing. HAR files larger than 50 MiB, invalid JSON numbers, and excessively nested input are rejected. The tool does not interpret JavaScript, decode nested payloads, or process merged capture formats. It does not verify the HAR against a formal schema.

## Tests

```sh
python -m unittest discover -s tests -v
```

The tests use only Python's standard library. No GitHub Actions are configured.

## Development report — October 28, 2026

- 36 unit tests passed on Python 3.13.5 (Linux).
- Built and installed a wheel, then checked the installed CLI with a sample HAR and `--check`.
- Verified that a sanitized output file was created with mode 0600 on Linux.
- No tests were run on Windows or Python 3.10–3.12. The MVP remains experimental; this report does not claim a stable release.
