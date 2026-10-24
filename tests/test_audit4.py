"""Audit 4 regression tests: cross-origin header allowlist + redirect
body/header consistency. Written to fail on commit 805ec72's behavior."""

import unittest

from murs.netutil import normalize_url
from murs.httpclient import HttpClient, _redirect_next
from tests.fixtures.appserver import FixtureServer


A = ("https", "a.test", 443)
B = ("https", "b.test", 443)


# ---------------------------------------- 1. cross-origin header allowlist
class TestCrossOriginAllowlist(unittest.TestCase):
    CRED_HEADERS = [
        "X-API-Key", "X-Access-Token", "X-Session-ID", "X-Amz-Security-Token",
        "Authorization", "Cookie", "X-Custom-Secret", "X-Whatever",
    ]

    def test_all_caller_headers_dropped_cross_origin(self):
        for name in self.CRED_HEADERS:
            hdrs = {name: "secret", "Accept": "text/html"}
            _, _, h = _redirect_next(302, "GET", None, hdrs, A, B, set())
            self.assertNotIn(name, h, f"{name} should not cross an origin")

    def test_safe_headers_preserved_cross_origin(self):
        hdrs = {"Accept": "text/html", "User-Agent": "MURS", "Accept-Language": "en"}
        _, _, h = _redirect_next(302, "GET", None, hdrs, A, B, set())
        self.assertIn("Accept", h)
        self.assertIn("User-Agent", h)
        self.assertIn("Accept-Language", h)

    def test_custom_headers_kept_same_origin(self):
        hdrs = {"X-Access-Token": "t", "X-Session-ID": "s"}
        _, _, h = _redirect_next(307, "GET", None, hdrs, A, A, set())
        self.assertIn("X-Access-Token", h)
        self.assertIn("X-Session-ID", h)

    def test_body_preserved_across_origin_keeps_content_type(self):
        # 307 across origin keeps body + Content-Type, but still drops creds
        hdrs = {"Content-Type": "application/json", "X-Access-Token": "t"}
        m, b, h = _redirect_next(307, "POST", b"{}", hdrs, A, B, set())
        self.assertEqual(m, "POST")
        self.assertEqual(b, b"{}")
        self.assertIn("Content-Type", h)
        self.assertNotIn("X-Access-Token", h)


# ---------------------------------------- 2. redirect body/header consistency
class TestBodyHeaderConsistency(unittest.TestCase):
    def test_302_drops_body_headers(self):
        hdrs = {"Content-Type": "text/plain", "Content-Length": "4"}
        m, b, h = _redirect_next(302, "POST", b"data", hdrs, A, A, set())
        self.assertEqual(m, "GET")
        self.assertIsNone(b)
        self.assertNotIn("Content-Type", h)
        self.assertNotIn("Content-Length", h)

    def test_303_drops_body_headers(self):
        hdrs = {"Content-Type": "text/plain", "Content-Length": "4"}
        m, b, h = _redirect_next(303, "POST", b"data", hdrs, A, A, set())
        self.assertEqual(m, "GET")
        self.assertNotIn("Content-Type", h)
        self.assertNotIn("Content-Length", h)

    def test_307_keeps_method_body_and_body_headers(self):
        hdrs = {"Content-Type": "text/plain", "Content-Length": "4"}
        m, b, h = _redirect_next(307, "POST", b"data", hdrs, A, A, set())
        self.assertEqual(m, "POST")
        self.assertEqual(b, b"data")
        self.assertIn("Content-Type", h)
        self.assertIn("Content-Length", h)

    def test_308_keeps_body_headers(self):
        hdrs = {"Content-Type": "text/plain"}
        m, b, h = _redirect_next(308, "POST", b"data", hdrs, A, A, set())
        self.assertEqual(m, "POST")
        self.assertIn("Content-Type", h)


def client_for(server):
    return HttpClient(allowed_hosts={server.host}, allowed_ports={server.port},
                      allowed_schemes={"http"}, allow_private=True,
                      rate_limit_per_sec=1000)


class TestRedirectIntegration(unittest.TestCase):
    def test_302_second_request_has_no_content_type(self):
        with FixtureServer() as s:
            c = client_for(s)
            r = c.request("POST", normalize_url(f"{s.base}/r302"),
                          headers={"Content-Type": "text/plain", "X-API-Key": "k"},
                          body=b"xxxx")
            self.assertIn("METHOD=GET", r.text)
            self.assertIn("BODYLEN=0", r.text)
            self.assertIn("CT=-", r.text)   # Content-Type dropped with the body
            self.assertIn("CL=-", r.text)   # Content-Length dropped with the body
            self.assertIn("XAPI=k", r.text)  # same-origin: custom header kept

    def test_307_second_request_keeps_content_type_and_body(self):
        with FixtureServer() as s:
            c = client_for(s)
            r = c.request("POST", normalize_url(f"{s.base}/r307"),
                          headers={"Content-Type": "text/plain"}, body=b"abc")
            self.assertIn("METHOD=POST", r.text)
            self.assertIn("BODYLEN=3", r.text)
            self.assertIn("CT=text/plain", r.text)

    def test_303_second_request_is_get_without_content_type(self):
        with FixtureServer() as s:
            c = client_for(s)
            r = c.request("POST", normalize_url(f"{s.base}/r303"),
                          headers={"Content-Type": "text/plain"}, body=b"zz")
            self.assertIn("METHOD=GET", r.text)
            self.assertIn("CT=-", r.text)


if __name__ == "__main__":
    unittest.main()
