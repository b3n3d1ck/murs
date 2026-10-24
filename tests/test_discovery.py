import unittest

from murs.config import ScanConfig
from murs.discovery import DiscoveryEngine, _classify, _SoftNotFound
from murs.forms import parse_html
from murs.httpclient import HttpClient
from tests.fixtures.appserver import FixtureServer


def config_for(server):
    cfg = ScanConfig(
        target=server.base,
        allowed_hosts={server.host},
        allowed_ports={server.port},
        allowed_schemes={"http"},
        max_depth=2,
        max_requests=200,
        rate_limit_per_sec=1000,
        mode="assessment",
    )
    cfg.base_scheme, cfg.base_host, cfg.base_port = "http", server.host, server.port
    cfg.base_url = f"{server.base}/"
    cfg.add_allowed_host(server.host)
    return cfg


def client_for(server):
    return HttpClient(
        allowed_hosts={server.host}, allowed_ports={server.port},
        allowed_schemes={"http"}, allow_private=True,
        rate_limit_per_sec=1000, max_requests=200,
    )


class TestForms(unittest.TestCase):
    def test_parses_links_and_upload_form(self):
        html = ('<a href="/a">A</a>'
                '<form action="/upload" method="post" enctype="multipart/form-data">'
                '<input type="file" name="f"></form>')
        p = parse_html(html)
        self.assertIn("/a", p.links)
        self.assertEqual(len(p.forms), 1)
        self.assertTrue(p.forms[0].is_upload)
        self.assertEqual(p.forms[0].file_fields[0].name, "f")

    def test_malformed_html_does_not_crash(self):
        p = parse_html("<form><input name=x<<<>")
        self.assertIsInstance(p.links, list)


class TestSoftNotFound(unittest.TestCase):
    def test_matches_404_always(self):
        sig = _SoftNotFound(200, 100, "x")
        self.assertEqual(_classify(404, sig, b"whatever"), "not-found")

    def test_soft_200_matches_signature(self):
        body = b"page not found" * 3
        import hashlib
        sig = _SoftNotFound(200, len(body), hashlib.sha1(body[:400]).hexdigest())
        self.assertEqual(_classify(200, sig, body), "not-found")

    def test_real_200_is_normal(self):
        sig = _SoftNotFound(200, 14, "deadbeef")
        self.assertEqual(_classify(200, sig, b"<html>real distinct content here</html>"), "normal")

    def test_auth_required(self):
        self.assertEqual(_classify(401, None, b""), "auth-required")


class TestDiscoveryIntegration(unittest.TestCase):
    def test_crawl_finds_pages_and_upload_form(self):
        with FixtureServer() as s:
            eng = DiscoveryEngine(config_for(s), client_for(s))
            res = eng.run()
            urls = {e.url for e in res.endpoints}
            self.assertIn(f"{s.base}/about", urls)
            self.assertIn(f"{s.base}/upload", urls)
            self.assertTrue(res.upload_forms, "should find the multipart upload form")
            self.assertEqual(res.upload_forms[0].action_url, f"{s.base}/upload")

    def test_secret_classified_auth_required(self):
        with FixtureServer() as s:
            res = DiscoveryEngine(config_for(s), client_for(s)).run()
            secret = [e for e in res.endpoints if e.url.endswith("/secret")]
            self.assertTrue(secret)
            self.assertEqual(secret[0].classification, "auth-required")

    def test_soft404_prevents_false_positive(self):
        with FixtureServer() as s:
            res = DiscoveryEngine(config_for(s), client_for(s)).run()
            # fixture returns 200 soft-404 for unknown wordlist paths
            normals = [e for e in res.endpoints
                       if e.discovered_from == "wordlist" and e.classification == "normal"]
            # /upload, /login, /about exist as real pages; random words should be not-found
            for e in res.endpoints:
                if e.url.endswith(("/old", "/tmp", "/temp", "/private")):
                    self.assertEqual(e.classification, "not-found", e.url)

    def test_missing_security_headers_detected(self):
        with FixtureServer() as s:
            res = DiscoveryEngine(config_for(s), client_for(s)).run()
            self.assertIn("Content-Security-Policy", res.missing_security_headers)


if __name__ == "__main__":
    unittest.main()
