"""Command-line interface for HARShield."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from .redact import InvalidHAR, redact_har

MAX_BYTES = 50 * 1024 * 1024


def _write_secure(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        raise OSError("Output exists; use --force to replace it")
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=".harshield-",
            suffix=".tmp", delete=False,
        ) as temp:
            temp_name = temp.name
            os.chmod(temp_name, 0o600)
            temp.write(content)
        if path.exists() and not force:
            raise OSError("Output exists; use --force to replace it")
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="harshield", description="Redact common credentials from HTTP Archive files."
    )
    parser.add_argument("input", type=Path, help="Input HAR file (up to 50 MiB)")
    parser.add_argument("-o", "--output", help="Output HAR path, or - for stdout")
    parser.add_argument("--check", action="store_true", help="Exit 1 if redaction is needed; write nothing")
    parser.add_argument("--force", action="store_true", help="Replace an existing output file")
    args = parser.parse_args(argv)
    if args.check and (args.output or args.force):
        parser.error("--check cannot be combined with --output or --force")
    if not args.check and not args.output:
        parser.error("--output is required unless --check is used")
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InvalidHAR("Input exceeds the 50 MiB limit")
        try:
            doc = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise InvalidHAR("Invalid JSON input") from exc
        cleaned, count = redact_har(doc)
        if args.check:
            print(f"{count} fields require redaction", file=sys.stderr)
            return 1 if count else 0
        output = json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n"
        if args.output == "-":
            sys.stdout.write(output)
        else:
            dest = Path(args.output)
            if dest.resolve() == args.input.resolve():
                raise InvalidHAR("Refusing to overwrite the input")
            _write_secure(dest, output, args.force)
        print(f"Redacted {count} fields", file=sys.stderr)
        return 0
    except InvalidHAR as exc:
        print(f"harshield: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError) as exc:
        # Do not include OS error details: paths and source content may be private.
        print("harshield: could not read or write file", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
