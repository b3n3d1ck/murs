import unittest

from murs.config import ScanConfig
from murs.discovery import DiscoveryEngine, DiscoveryResult, DiscoveredForm, Endpoint
from murs.httpclient import HttpClient
from murs.login import LoginDiscovery, LoginCandidate
from tests.fixtures.appserver import FixtureServer


def config_for(server):
    cfg = ScanConfig(target=server.base, allowed_hosts={server.host},
                     allowed_ports={server.port}, allowed_schemes={"http"},
                     max_depth=2, max_requests=200, rate_limit_per_sec=1000,
                     mode="assessment")
    cfg.base_scheme, cfg.base_host, cfg.base_port = "http", server.host, server.port
    cfg.base_url = f"{server.base}/"
    cfg.add_allowed_host(server.host)
    return cfg


def client_for(server):
    return HttpClient(allowed_hosts={server.host}, allowed_ports={server.port},
                      allowed_schemes={"http"}, allow_private=True,
                      rate_limit_per_sec=1000, max_requests=200)


class TestLoginClassification(unittest.TestCase):
    def test_password_form_is_login(self):
        d = DiscoveryResult(base_url="http://t/")
        d.forms = [DiscoveredForm(page_url="http://t/login", action_url="http://t/login",
                                  method="post", enctype="", file_fields=[], is_upload=False,
                                  fields=[("user", "text"), ("pass", "password")])]
        cands = LoginDiscovery(_StubCfg(), _NullClient()).find(d)
        self.assertTrue(cands)
        self.assertEqual(cands[0].password_field, "pass")
        self.assertIn("user", cands[0].param_names)

    def test_classification_threshold(self):
        c = LoginCandidate(url="http://t/x", score=5)
        self.assertTrue(c.is_login)
        self.assertFalse(LoginCandidate(url="http://t/y", score=2).is_login)

    def test_non_login_page_not_classified(self):
        d = DiscoveryResult(base_url="http://t/")
        d.endpoints = [Endpoint(url="http://t/about", method="GET", status=200,
                                classification="normal")]
        # no password form, path doesn't match -> no candidate
        found = [c for c in LoginDiscovery(_StubCfg(), _NullClient()).find(d)]
        self.assertEqual(found, [])


class _StubCfg:
    base_url = "http://t/"
    allowed_hosts = {"t"}
    allowed_ports = {80}
    allowed_schemes = {"http"}
    login_wordlist = None


class _NullClient:
    def get(self, *a, **k):
        from murs.httpclient import Response
        return Response(url="x", method="GET", blocked=True, reason="stub")


class TestLoginIntegration(unittest.TestCase):
    def test_finds_login_page_on_fixture(self):
        with FixtureServer() as s:
            disc = DiscoveryEngine(config_for(s), client_for(s)).run()
            cands = LoginDiscovery(config_for(s), client_for(s)).find(disc)
            logins = [c for c in cands if c.url.endswith("/login")]
            self.assertTrue(logins, "the /login page should be classified as login")
            c = logins[0]
            self.assertTrue(c.is_login)
            self.assertIn("pass", c.param_names)
            self.assertEqual(c.password_field, "pass")
            self.assertTrue(any("password" in e for e in c.evidence))

    def test_budget_is_respected(self):
        with FixtureServer() as s:
            cfg = config_for(s)
            # tiny budget: should not crash, just stop early
            c = HttpClient(allowed_hosts={s.host}, allowed_ports={s.port},
                           allowed_schemes={"http"}, allow_private=True,
                           rate_limit_per_sec=1000, max_requests=2)
            disc = DiscoveryResult(base_url=cfg.base_url)
            LoginDiscovery(cfg, c).find(disc)  # must not raise


if __name__ == "__main__":
    unittest.main()
