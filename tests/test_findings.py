import unittest

from murs.findings import (
    FindingEngine, severity_counts, CRITICAL, HIGH, MEDIUM, LOW, INFO,
    V_CONFIRMED, V_INCONCLUSIVE,
)
from murs.discovery import DiscoveryResult, Endpoint
from murs.upload import (
    UploadAttempt, OUT_EXECUTION_CONFIRMED, OUT_PUBLIC_NOT_INTERPRETED,
    OUT_EXECUTION_UNCONFIRMED, OUT_INTERPRETED_UNCONFIRMED, OUT_REJECTED,
)


class TestFindingEngine(unittest.TestCase):
    def setUp(self):
        self.eng = FindingEngine(tested_at="2026-01-01T00:00:00Z")

    def test_execution_is_critical_confirmed(self):
        at = UploadAttempt(probe_kind="php_extension", filename="x.php",
                           endpoint="http://t/u", field_name="file",
                           sent=True, http_status=200, accepted=True,
                           stored_location="http://t/uploads/x.php",
                           accessible=True, executed=True,
                           outcome=OUT_EXECUTION_CONFIRMED,
                           execution_url="http://t/uploads/x.php",
                           evidence={"execution_proof": "SIG"})
        f = self.eng.build(None, [at])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, CRITICAL)
        self.assertEqual(f[0].verification_status, V_CONFIRMED)
        self.assertEqual(f[0].evidence.get("execution_url"), "http://t/uploads/x.php")

    def test_accepted_php_without_execution_is_not_critical(self):
        at = UploadAttempt(probe_kind="php_extension", filename="x.php",
                           endpoint="http://t/u", field_name="file",
                           sent=True, http_status=200, accepted=True,
                           stored_location="http://t/uploads/x.php",
                           accessible=True, executed=False,
                           outcome=OUT_PUBLIC_NOT_INTERPRETED)
        f = self.eng.build(None, [at])
        self.assertEqual(f[0].severity, MEDIUM)
        self.assertNotEqual(f[0].severity, CRITICAL)

    def test_interpreted_unconfirmed_is_high_but_no_execution_url(self):
        at = UploadAttempt(probe_kind="php_extension", filename="x.php",
                           endpoint="http://t/u", field_name="file",
                           sent=True, http_status=200, accepted=True,
                           stored_location="http://t/stripped-uploads/x.php",
                           accessible=True, interpreted=True, executed=None,
                           outcome=OUT_INTERPRETED_UNCONFIRMED)
        f = self.eng.build(None, [at])
        self.assertEqual(f[0].severity, HIGH)
        self.assertEqual(f[0].verification_status, V_INCONCLUSIVE)
        # requirement 9: no execution URL on an unconfirmed result
        self.assertIsNone(at.execution_url)
        self.assertNotIn("execution_url", f[0].evidence)

    def test_accepted_php_storage_unknown_is_inconclusive(self):
        at = UploadAttempt(probe_kind="php_extension", filename="x.php",
                           endpoint="http://t/u", field_name="file",
                           sent=True, http_status=200, accepted=True,
                           stored_location=None, accessible=None, executed=None,
                           outcome=OUT_EXECUTION_UNCONFIRMED)
        f = self.eng.build(None, [at])
        self.assertEqual(f[0].severity, LOW)
        self.assertEqual(f[0].verification_status, V_INCONCLUSIVE)

    def test_rejected_probes_give_informational(self):
        at = UploadAttempt(probe_kind="php_extension", filename="x.php",
                           endpoint="http://t/u", field_name="file",
                           sent=True, http_status=422, accepted=False,
                           outcome=OUT_REJECTED)
        f = self.eng.build(None, [at])
        self.assertEqual(f[0].severity, INFO)

    def test_discovery_headers_and_sensitive_file(self):
        d = DiscoveryResult(base_url="http://t/")
        d.missing_security_headers = ["Content-Security-Policy", "Strict-Transport-Security"]
        d.server = "nginx/1.21.0"
        d.endpoints = [Endpoint(url="http://t/.env", method="GET", status=200,
                                classification="normal", content_type="text/plain",
                                length=120, discovered_from="wordlist")]
        f = self.eng.build(d, [])
        titles = {x.title for x in f}
        self.assertIn("Missing HTTP security headers", titles)
        self.assertIn("Sensitive file or path is publicly reachable", titles)
        self.assertIn("Server version disclosed in banner", titles)

    def test_sorted_by_severity(self):
        d = DiscoveryResult(base_url="http://t/")
        d.missing_security_headers = ["Content-Security-Policy"]
        d.endpoints = [Endpoint(url="http://t/.env", method="GET", status=200,
                                classification="normal")]
        f = self.eng.build(d, [])
        sevs = [x.severity for x in f]
        self.assertEqual(sevs, sorted(sevs, key=lambda s: ["Critical","High","Medium","Low","Informational"].index(s)))

    def test_severity_counts(self):
        d = DiscoveryResult(base_url="http://t/")
        d.missing_security_headers = ["Content-Security-Policy"]
        c = severity_counts(self.eng.build(d, []))
        self.assertEqual(c[LOW], 1)


if __name__ == "__main__":
    unittest.main()
