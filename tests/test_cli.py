import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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

    def test_reject_nonfinite_json_without_writing(self):
        for value in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999"):
            with self.subTest(value=value):
                self.source.write_text('{"log":{"entries":[],"value":' + value + '}}', encoding="utf-8")
                code, out, err = self.run_cli("-o", self.target)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("Invalid JSON input", err)
                self.assertFalse(self.target.exists())

    def test_reject_excessively_nested_json_without_traceback(self):
        nested = "[" * 1200 + "0" + "]" * 1200
        self.source.write_text('{"log":{"entries":[],"extra":' + nested + '}}', encoding="utf-8")
        code, out, err = self.run_cli("-o", self.target)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertNotIn("Traceback", err)
        self.assertFalse(self.target.exists())

    def test_concurrent_output_creation_is_not_overwritten(self):
        original_link = os.link

        def racing_link(src, dst):
            Path(dst).write_text("created-by-another-process", encoding="utf-8")
            return original_link(src, dst)

        with patch("harshield.cli.os.link", side_effect=racing_link):
            code, _, err = self.run_cli("-o", self.target)
        self.assertEqual(code, 2)
        self.assertEqual(self.target.read_text(), "created-by-another-process")
        self.assertIn("could not read or write", err)
        self.assertEqual(list(self.root.glob(".harshield-*")), [])

    @unittest.skipUnless(os.name == "posix", "POSIX symlink behavior")
    def test_dangling_output_symlink_is_not_overwritten(self):
        self.target.symlink_to(self.root / "missing.har")
        code, _, _ = self.run_cli("-o", self.target)
        self.assertEqual(code, 2)
        self.assertTrue(self.target.is_symlink())
        self.assertFalse((self.root / "missing.har").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_private_output_permissions(self):
        self.run_cli("-o", self.target)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)


    def test_check_does_not_create_output_or_modify_input(self):
        before = self.source.read_bytes()
        code, out, err = self.run_cli("--check")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("fields require redaction", err)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertFalse(self.target.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX hard-link behavior")
    def test_force_on_hardlink_preserves_original(self):
        os.link(self.source, self.target)
        before = self.source.read_bytes()
        code, _, _ = self.run_cli("--force", "--output", self.target)
        self.assertEqual(code, 0)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertNotIn("secret", self.target.read_text())

    @unittest.skipUnless(os.name == "posix", "POSIX symlink behavior")
    def test_force_replaces_symlink_without_modifying_target(self):
        victim = self.root / "victim.txt"
        victim.write_text("keep this content", encoding="utf-8")
        self.target.symlink_to(victim)
        code, _, _ = self.run_cli("--force", "--output", self.target)
        self.assertEqual(code, 0)
        self.assertFalse(self.target.is_symlink())
        self.assertEqual(victim.read_text(), "keep this content")
        self.assertNotIn("secret", self.target.read_text())

    def test_invalid_url_does_not_write_or_echo_secret(self):
        self.source.write_text(json.dumps({"log": {"entries": [{
            "request": {"url": "http://[secret/"},
            "response": {},
        }]}}), encoding="utf-8")
        code, out, err = self.run_cli("--output", self.target)
        self.assertEqual(code, 2)
        self.assertNotIn("secret", out + err)
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
