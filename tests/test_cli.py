import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from harshield.cli import main


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "input.har"
        self.target = self.root / "output.har"
        self.source.write_text(json.dumps({"log": {"entries": [{
            "request": {"url": "https://example.test/?token=secret"},
            "response": {"content": {"text": "secret"}},
        }]}}), encoding="utf-8")

    def run_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main([str(self.source), *map(str, args)])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_write_and_check(self):
        code, _, _ = self.run_cli("--check")
        self.assertEqual(code, 1)
        code, _, _ = self.run_cli("--output", self.target)
        self.assertEqual(code, 0)
        self.assertNotIn("secret", self.target.read_text())
        self.assertIn("secret", self.source.read_text())
        self.assertEqual(main([str(self.target), "--check"]), 0)

    def test_refuse_overwrite(self):
        self.target.write_text("existing")
        code, _, _ = self.run_cli("-o", self.target)
        self.assertEqual(code, 2)
        self.assertEqual(self.target.read_text(), "existing")
        code, _, _ = self.run_cli("-o", self.target, "--force")
        self.assertEqual(code, 0)

    def test_refuse_in_place(self):
        before = self.source.read_bytes()
        code, _, _ = self.run_cli("-o", self.source, "--force")
        self.assertEqual(code, 2)
        self.assertEqual(self.source.read_bytes(), before)

    def test_invalid_json_does_not_echo_input(self):
        self.source.write_text('"secret" trailing', encoding="utf-8")
        code, out, err = self.run_cli("-o", self.target)
        self.assertEqual(code, 2)
        self.assertNotIn("secret", out + err)
        self.assertFalse(self.target.exists())

    def test_invalid_har_does_not_write(self):
        self.source.write_text('{"log":{"entries":[{}]}}', encoding="utf-8")
        code, out, err = self.run_cli("-o", self.target)
        self.assertEqual(code, 2)
        self.assertFalse(self.target.exists())
        self.assertNotIn("secret", out + err)

    def test_size_limit(self):
        from unittest.mock import patch
        with patch("harshield.cli.MAX_BYTES", 8):
            code, _, err = self.run_cli("-o", self.target)
        self.assertEqual(code, 2)
        self.assertIn("50 MiB", err)
        self.assertFalse(self.target.exists())

    def test_stdout(self):
        code, out, _ = self.run_cli("-o", "-")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["log"]["entries"][0]["response"]["content"]["text"], "[REDACTED]")

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_private_output_permissions(self):
        self.run_cli("-o", self.target)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
