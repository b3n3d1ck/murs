import unittest

from murs.lab import LabServer, LabUnavailable, php_available
from murs.httpclient import HttpClient
from murs.netutil import normalize_url
from murs.upload import UploadModule, OUT_EXECUTION_CONFIRMED
from murs.findings import FindingEngine, CRITICAL, V_CONFIRMED


def client_for(server):
    t = normalize_url(server.base)
    return HttpClient(
        allowed_hosts={t.host}, allowed_ports={t.port},
        allowed_schemes={"http"}, allow_private=True,
        rate_limit_per_sec=1000, max_requests=300,
    )


@unittest.skipUnless(php_available(), "php CLI not available")
class TestLab(unittest.TestCase):
    def test_vulnerable_lab_executes_canary(self):
        with LabServer("vuln") as lab:
            base = normalize_url(lab.base)
            mod = UploadModule(client_for(lab), base)
            results = mod.assess(f"{lab.base}/upload.php", "file")
            php = [r for r in results if r.probe_kind == "php_extension"][0]
            self.assertTrue(php.sent)
            self.assertTrue(php.accepted)
            self.assertTrue(php.accessible)
            self.assertEqual(php.executed, True, "vuln lab must execute the canary")
            self.assertEqual(php.outcome, OUT_EXECUTION_CONFIRMED)
            # the execution URL is set ONLY on a confirmed run
            self.assertTrue(php.execution_url)
            # finding engine escalates this to Critical/Confirmed
            findings = FindingEngine("t").build(None, results)
            crit = [f for f in findings if f.severity == CRITICAL]
            self.assertTrue(crit)
            self.assertEqual(crit[0].verification_status, V_CONFIRMED)

    def test_patched_lab_rejects_script(self):
        with LabServer("patched") as lab:
            base = normalize_url(lab.base)
            mod = UploadModule(client_for(lab), base)
            results = mod.assess(f"{lab.base}/upload.php", "file")
            php = [r for r in results if r.probe_kind == "php_extension"][0]
            self.assertTrue(php.sent)
            self.assertFalse(php.accepted, "patched lab must reject the script probe")
            self.assertNotEqual(php.executed, True)
            # no Critical finding on the patched variant
            findings = FindingEngine("t").build(None, results)
            self.assertFalse([f for f in findings if f.severity == CRITICAL])

    def test_difference_is_reproducible(self):
        # the two variants must differ on the same probe
        with LabServer("vuln") as v:
            rv = UploadModule(client_for(v), normalize_url(v.base)).assess(
                f"{v.base}/upload.php", "file")
        with LabServer("patched") as p:
            rp = UploadModule(client_for(p), normalize_url(p.base)).assess(
                f"{p.base}/upload.php", "file")
        ev = [r for r in rv if r.probe_kind == "php_extension"][0].executed
        ep = [r for r in rp if r.probe_kind == "php_extension"][0].executed
        self.assertTrue(ev)
        self.assertNotEqual(ev, ep)


class TestLabUnavailable(unittest.TestCase):
    def test_raises_when_php_missing(self):
        if php_available():
            self.skipTest("php present; cannot test the missing-php path here")
        with self.assertRaises(LabUnavailable):
            LabServer("vuln")


if __name__ == "__main__":
    unittest.main()
