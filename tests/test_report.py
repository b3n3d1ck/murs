import os
import shutil
import subprocess
import tempfile
import unittest

from murs.findings import FindingEngine
from murs.discovery import DiscoveryResult, Endpoint
from murs.upload import UploadAttempt
from murs.report import ReportData, generate_pdf
from murs.retest import compare, apply_retest


def sample_findings():
    d = DiscoveryResult(base_url="http://t/")
    d.missing_security_headers = ["Content-Security-Policy", "Strict-Transport-Security"]
    d.server = "nginx/1.21.0"
    d.endpoints = [Endpoint(url="http://t/.env", method="GET", status=200,
                            classification="normal", content_type="text/plain",
                            length=120, discovered_from="wordlist")]
    from murs.upload import OUT_EXECUTION_CONFIRMED
    at = UploadAttempt(probe_kind="php_extension", filename="x.php",
                       endpoint="http://t/upload.php", field_name="file", sent=True,
                       http_status=200, accepted=True,
                       stored_location="http://t/uploads/x.php", accessible=True,
                       executed=True, outcome=OUT_EXECUTION_CONFIRMED,
                       execution_url="http://t/uploads/x.php",
                       evidence={"execution_proof": "SIG"})
    return d, FindingEngine("2026-01-01T00:00:00Z").build(d, [at])


def make_data(findings, endpoints, retest=None, upload_attempts=None):
    return ReportData(
        project="Example Research", researcher="tester",
        target="http://t/", scope={"allowed_hosts": ["t"], "allowed_ports": [80],
                                    "allowed_schemes": ["http"], "mode": "assessment",
                                    "max_requests": 100, "max_depth": 2},
        findings=findings, endpoints=endpoints, technologies=["nginx/1.21.0"],
        started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:05:00Z",
        requests_made=42, retest=retest or [], upload_attempts=upload_attempts or [],
    )


class TestReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pdf_generated_and_nonempty(self):
        d, findings = sample_findings()
        path = generate_pdf(make_data(findings, d.endpoints), out_dir=self.tmp)
        self.assertTrue(os.path.exists(path))
        self.assertGreater(os.path.getsize(path), 2000)

    @unittest.skipUnless(shutil.which("pdftotext"), "pdftotext not available")
    def test_pdf_text_contains_key_sections(self):
        d, findings = sample_findings()
        path = generate_pdf(make_data(findings, d.endpoints), out_dir=self.tmp)
        txt = subprocess.run(["pdftotext", path, "-"], capture_output=True,
                             text=True, check=True).stdout
        for needle in ["MATRIX UPLOAD RESEARCH SUITE", "Executive summary",
                       "Severity summary", "Finding details", "Remediation priority",
                       "Example Research", "Critical"]:
            self.assertIn(needle, txt, needle)

    @unittest.skipUnless(shutil.which("pdfinfo"), "pdfinfo not available")
    def test_pdf_has_multiple_pages_and_metadata(self):
        d, findings = sample_findings()
        path = generate_pdf(make_data(findings, d.endpoints), out_dir=self.tmp)
        info = subprocess.run(["pdfinfo", path], capture_output=True, text=True).stdout
        self.assertIn("Pages:", info)
        pages = int([l for l in info.splitlines() if l.startswith("Pages:")][0].split()[1])
        self.assertGreaterEqual(pages, 2)

    def test_empty_findings_still_renders(self):
        path = generate_pdf(make_data([], []), out_dir=self.tmp)
        self.assertTrue(os.path.exists(path))

    @unittest.skipUnless(shutil.which("pdftotext"), "pdftotext not available")
    def test_upload_outcome_matrix_rendered(self):
        from murs.upload import UploadAttempt, OUT_INTERPRETED_UNCONFIRMED
        d, findings = sample_findings()
        at = UploadAttempt(probe_kind="php_extension", filename="x.php",
                           endpoint="http://t/upload.php", field_name="file", sent=True,
                           http_status=200, accepted=True,
                           stored_location="http://t/stripped/x.php", accessible=True,
                           interpreted=True, outcome=OUT_INTERPRETED_UNCONFIRMED)
        path = generate_pdf(make_data(findings, d.endpoints, upload_attempts=[at]),
                            out_dir=self.tmp)
        txt = subprocess.run(["pdftotext", path, "-"], capture_output=True,
                             text=True, check=True).stdout
        # pdftotext wraps cell text, so assert on tokens that survive wrapping
        self.assertIn("Upload probe outcomes", txt)
        self.assertIn("interpretation", txt)
        self.assertIn("unconfirmed", txt)
        self.assertIn("not confirmed", txt)  # URL columns, unconfirmed
        self.assertIn("Stored URL", txt)


class TestRetest(unittest.TestCase):
    def test_compare_fixed_and_still_present(self):
        d, before = sample_findings()
        # "after": drop the critical upload finding (fixed), keep headers
        after = [f for f in before if f.severity != "Critical"]
        entries = compare(before, after)
        results = {e.result for e in entries}
        self.assertIn("Fixed", results)
        self.assertIn("Still Present", results)

    def test_apply_retest_stamps_status(self):
        d, before = sample_findings()
        after = list(before)
        entries = compare(before, after)
        apply_retest(after, entries)
        self.assertTrue(all(f.retest_status == "Still Present" for f in after))


if __name__ == "__main__":
    unittest.main()
