import unittest

from murs.httpclient import HttpClient
from murs.netutil import normalize_url
from murs.sqli import SqliModule, _signatures, NOT_INJECTABLE, ERROR_INDICATION
from tests.fixtures.appserver import FixtureServer


def client_for(server):
    return HttpClient(allowed_hosts={server.host}, allowed_ports={server.port},
                      allowed_schemes={"http"}, allow_private=True,
                      rate_limit_per_sec=1000, max_requests=300)


class TestSignatures(unittest.TestCase):
    def test_detects_db_signatures(self):
        self.assertTrue(_signatures("SQL error: unrecognized token: \"'\""))
        self.assertTrue(_signatures("You have an error in your SQL syntax near"))
        self.assertTrue(_signatures("ORA-00933: something"))

    def test_generic_error_has_no_signature(self):
        self.assertFalse(_signatures("Internal Server Error - something went wrong"))
        self.assertFalse(_signatures("500 error occurred"))


class TestSqliFalsePositives(unittest.TestCase):
    def test_static_login_not_injectable(self):
        with FixtureServer() as s:
            mod = SqliModule(client_for(s))
            tgt = mod.assess_form(f"{s.base}/login", "post", ["user", "pass"])
            for r in tgt.results:
                self.assertEqual(r.outcome, NOT_INJECTABLE, r.param)

    def test_generic_500_not_flagged(self):
        # a 500 with no DB signature must NOT be reported as injection
        with FixtureServer() as s:
            mod = SqliModule(client_for(s))
            tgt = mod.assess_form(f"{s.base}/sqli-generic-500", "post", ["q"])
            self.assertTrue(tgt.results)
            for r in tgt.results:
                self.assertNotEqual(r.outcome, ERROR_INDICATION)

    def test_out_of_scope_action_is_not_testable(self):
        with FixtureServer() as s:
            mod = SqliModule(client_for(s))
            tgt = mod.assess_form("http://external.example/login", "post", ["user"])
            self.assertTrue(all(r.outcome in ("not_testable",) for r in tgt.results))


if __name__ == "__main__":
    unittest.main()
