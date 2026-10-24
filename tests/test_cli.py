import io
import os
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
