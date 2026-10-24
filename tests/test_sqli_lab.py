import unittest

from murs.lab import LabServer, php_available
from murs.httpclient import HttpClient
from murs.netutil import normalize_url
from murs.sqli import SqliModule, ERROR_INDICATION, CONFIRMED, NOT_INJECTABLE


def client_for(server):
    t = normalize_url(server.base)
    return HttpClient(allowed_hosts={t.host}, allowed_ports={t.port},
                      allowed_schemes={"http"}, allow_private=True,
                      rate_limit_per_sec=1000, max_requests=300)


@unittest.skipUnless(php_available(), "php CLI not available")
class TestSqliLab(unittest.TestCase):
    def _assess(self, variant, lab_confirm):
        with LabServer(variant) as lab:
            mod = SqliModule(client_for(lab), lab_confirm=lab_confirm)
            tgt = mod.assess_form(f"{lab.base}/login.php", "post",
                                  ["username", "password"])
        return tgt

    def test_vulnerable_lab_shows_error_indication(self):
        tgt = self._assess("sqli_vuln", lab_confirm=False)
        outcomes = {r.param: r.outcome for r in tgt.results}
        self.assertIn(ERROR_INDICATION, outcomes.values())
        # the username param is the injectable one
        self.assertEqual(outcomes["username"], ERROR_INDICATION)

    def test_vulnerable_lab_confirmed_with_lab_flag(self):
        tgt = self._assess("sqli_vuln", lab_confirm=True)
        confirmed = [r for r in tgt.results if r.outcome == CONFIRMED]
        self.assertTrue(confirmed, "lab_confirm should allow a confirmed result")
        self.assertIn("error_signature", confirmed[0].evidence)

    def test_patched_lab_not_injectable(self):
        tgt = self._assess("sqli_patched", lab_confirm=True)
        for r in tgt.results:
            self.assertEqual(r.outcome, NOT_INJECTABLE, r.param)

    def test_difference_between_vuln_and_patched(self):
        v = self._assess("sqli_vuln", lab_confirm=False)
        p = self._assess("sqli_patched", lab_confirm=False)
        v_user = next(r for r in v.results if r.param == "username")
        p_user = next(r for r in p.results if r.param == "username")
        self.assertNotEqual(v_user.outcome, p_user.outcome)


if __name__ == "__main__":
    unittest.main()
