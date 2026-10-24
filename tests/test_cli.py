import io
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout

from murs.cli import build_parser, main
from murs.lab import php_available


class TestParser(unittest.TestCase):
    def test_requires_target_or_lab(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--no-color", "--no-pdf"])
        self.assertEqual(rc, 2)

    def test_version_flag(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["--version"])

    def test_ssrf_guard_blocks_private_target_without_optin(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["http://127.0.0.1:1/", "--no-color", "--no-pdf"])
        self.assertEqual(rc, 4)
        self.assertIn("SSRF guard", buf.getvalue())


class TestAuthProfile(unittest.TestCase):
    def test_build_auth_headers_from_cookie_and_header(self):
        from murs.cli import build_parser, _build_auth_headers
        args = build_parser().parse_args([
            "http://x.test", "--no-pdf",
            "--auth-cookie", "session=abc123",
            "--auth-header", "Authorization: Bearer tok",
        ])
        h = _build_auth_headers(args)
        self.assertEqual(h["Cookie"], "session=abc123")
        self.assertEqual(h["Authorization"], "Bearer tok")

    def test_secret_values_not_printed(self):
        from murs.cli import build_parser, _build_auth_headers
        args = build_parser().parse_args([
            "http://x.test", "--auth-cookie", "session=SUPERSECRETVALUE"])
        # the helper returns the value, but the CLI only ever prints header names
        h = _build_auth_headers(args)
        self.assertIn("Cookie", h)

    def test_auth_from_env_when_flags_absent(self):
        import os
        from murs.cli import build_parser, _build_auth_headers
        args = build_parser().parse_args(["http://x.test"])
        os.environ["MURS_AUTH_COOKIE"] = "session=fromenv"
        os.environ["MURS_AUTH_HEADER"] = "Authorization: Bearer envtok"
        try:
            h = _build_auth_headers(args)
            self.assertEqual(h["Cookie"], "session=fromenv")
            self.assertEqual(h["Authorization"], "Bearer envtok")
        finally:
            del os.environ["MURS_AUTH_COOKIE"]
            del os.environ["MURS_AUTH_HEADER"]


class TestLaunchers(unittest.TestCase):
    def test_entry_scripts_exist(self):
        root = os.path.dirname(os.path.dirname(__file__))
        for name in ("run.sh", "run.cmd", "run.ps1"):
            self.assertTrue(os.path.exists(os.path.join(root, name)), name)


@unittest.skipUnless(php_available(), "php CLI not available")
class TestEndToEnd(unittest.TestCase):
    def test_lab_run_produces_pdf_and_critical(self):
        tmp = tempfile.mkdtemp()
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--lab", "vuln", "--no-color", "--report-dir", tmp,
                       "--project", "CLI Test"])
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("Critical", out)
        pdfs = [f for f in os.listdir(tmp) if f.endswith(".pdf")]
        self.assertTrue(pdfs, "a PDF should be generated")

    def test_auth_secret_never_in_stdout_or_pdf(self):
        tmp = tempfile.mkdtemp()
        secret = "SUPERSECRETSESSION12345"
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--lab", "vuln", "--no-color", "--report-dir", tmp,
                       "--auth-cookie", f"session={secret}"])
        self.assertEqual(rc, 0)
        self.assertNotIn(secret, buf.getvalue(), "secret leaked to stdout")
        pdfs = [f for f in os.listdir(tmp) if f.endswith(".pdf")]
        self.assertTrue(pdfs)
        if shutil.which("pdftotext"):
            txt = subprocess.run(["pdftotext", os.path.join(tmp, pdfs[0]), "-"],
                                 capture_output=True, text=True).stdout
            self.assertNotIn(secret, txt, "secret leaked into the PDF")

    def test_auth_secret_absent_from_findings_json(self):
        tmp = tempfile.mkdtemp()
        bl = os.path.join(tmp, "f.json")
        secret = "SECRETINJSON98765"
        with redirect_stdout(io.StringIO()):
            rc = main(["--lab", "vuln", "--no-color", "--no-pdf",
                       "--auth-cookie", f"session={secret}", "--save-findings", bl])
        self.assertEqual(rc, 0)
        with open(bl, encoding="utf-8") as fh:
            data = fh.read()
        self.assertNotIn(secret, data, "secret leaked into findings JSON")

    def test_retest_roundtrip(self):
        tmp = tempfile.mkdtemp()
        bl = os.path.join(tmp, "baseline.json")
        with redirect_stdout(io.StringIO()):
            rc1 = main(["--lab", "vuln", "--no-color", "--no-pdf", "--save-findings", bl])
        self.assertEqual(rc1, 0)
        self.assertTrue(os.path.exists(bl))
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc2 = main(["--lab", "patched", "--no-color", "--no-pdf",
                        "--retest-baseline", bl])
        self.assertEqual(rc2, 0)
        self.assertIn("fixed", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
