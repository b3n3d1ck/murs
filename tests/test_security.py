"""Phase 2 regression tests: DNS pinning / rebinding, mixed DNS, redirects."""

import unittest

import murs.netutil as netutil
from murs.netutil import resolve_and_pin, normalize_url, redact_secrets
from murs.httpclient import HttpClient, _redirect_next, _SENSITIVE_HEADERS
from tests.fixtures.appserver import FixtureServer


class TestResolveAndPin(unittest.TestCase):
    def test_public_literal_pins_to_itself(self):
        ip, reason, ips = resolve_and_pin("8.8.8.8")
        self.assertEqual(ip, "8.8.8.8")

    def test_private_literal_blocked(self):
        ip, reason, _ = resolve_and_pin("127.0.0.1")
        self.assertIsNone(ip)

    def test_private_literal_allowed_when_approved(self):
        ip, reason, _ = resolve_and_pin("127.0.0.1", lab_private_ok=True)
        self.assertEqual(ip, "127.0.0.1")

    def test_approved_host_resolving_to_non_loopback_is_blocked(self):
        # finding 3: approval of a hostname must NOT trust whatever DNS returns;
        # the lab exception is loopback-only.
        orig = netutil.resolve_host
        netutil.resolve_host = lambda h: ["169.254.169.254"]  # metadata service
        try:
            ip, reason, _ = resolve_and_pin("approved.lab", lab_private_ok=True)
            self.assertIsNone(ip)
            self.assertIn("loopback-only", reason)
        finally:
            netutil.resolve_host = orig

    def test_approved_host_with_mixed_loopback_and_lan_blocked(self):
        orig = netutil.resolve_host
        netutil.resolve_host = lambda h: ["127.0.0.1", "192.168.1.10"]
        try:
            ip, _, _ = resolve_and_pin("approved.lab", lab_private_ok=True)
            self.assertIsNone(ip, "mixed loopback/LAN under approval must fail closed")
        finally:
            netutil.resolve_host = orig

    def test_approved_loopback_host_allowed(self):
        orig = netutil.resolve_host
        netutil.resolve_host = lambda h: ["127.0.0.1"]
        try:
            ip, _, _ = resolve_and_pin("localhost.lab", lab_private_ok=True)
            self.assertEqual(ip, "127.0.0.1")
        finally:
            netutil.resolve_host = orig

    def test_hostname_pins_to_resolved_public(self):
        orig = netutil.resolve_host
        netutil.resolve_host = lambda h: ["93.184.216.34"]
        try:
            ip, reason, ips = resolve_and_pin("example.test")
            self.assertEqual(ip, "93.184.216.34")
        finally:
            netutil.resolve_host = orig

    def test_rebinding_private_answer_blocked(self):
        orig = netutil.resolve_host
        netutil.resolve_host = lambda h: ["127.0.0.1"]
        try:
            ip, reason, _ = resolve_and_pin("rebind.test")
            self.assertIsNone(ip)
        finally:
            netutil.resolve_host = orig

    def test_mixed_public_private_fails_closed(self):
        orig = netutil.resolve_host
        netutil.resolve_host = lambda h: ["8.8.8.8", "127.0.0.1"]
        try:
            ip, reason, ips = resolve_and_pin("mixed.test")
            self.assertIsNone(ip, "mixed public/private must be refused")
            self.assertIn("non-global", reason)
        finally:
            netutil.resolve_host = orig

    def test_nonresolving_blocked(self):
        orig = netutil.resolve_host
        netutil.resolve_host = lambda h: []
        try:
            ip, _, _ = resolve_and_pin("nope.test")
            self.assertIsNone(ip)
        finally:
            netutil.resolve_host = orig


class TestClientSsrf(unittest.TestCase):
    def test_hostname_rebinding_blocked_at_client(self):
        # a scoped hostname that resolves to a private IP must be refused
        orig = netutil.resolve_host
        netutil.resolve_host = lambda h: ["127.0.0.1"]
        try:
            c = HttpClient(allowed_hosts={"rebind.test"}, allowed_ports={80},
                           allowed_schemes={"http"}, rate_limit_per_sec=1000)
            r = c.get(normalize_url("http://rebind.test/"), follow=False)
            self.assertTrue(r.blocked)
            self.assertIn("ssrf", r.reason)
        finally:
            netutil.resolve_host = orig

    def test_private_bypass_is_scoped_not_global(self):
        # allow_private approves only the scoped host; a different private host
        # (reached by a scope exception) is still SSRF-checked.
        c = HttpClient(allowed_hosts={"127.0.0.1"}, allowed_ports={80, 9999},
                       allowed_schemes={"http"}, allow_private=True,
                       rate_limit_per_sec=1000)
        self.assertEqual(c.private_hosts, {"127.0.0.1"})
        # 169.254.169.254 is not in private_hosts even though allow_private set
        self.assertNotIn("169.254.169.254", c.private_hosts)


class TestRedaction(unittest.TestCase):
    def test_masks_cookie_and_token(self):
        r = redact_secrets("Set-Cookie: session=abc123secretvalue; token=deadbeefcafe1234")
        self.assertNotIn("abc123secretvalue", r)
        self.assertIn("[REDACTED]", r)

    def test_masks_long_base64(self):
        r = redact_secrets("data eyJhbGciOiJIUzI1NiwServerSideLongBase64Token== end")
        self.assertIn("[REDACTED]", r)

    def test_keeps_plain_text(self):
        self.assertEqual(redact_secrets("stored at /uploads/x.png"),
                         "stored at /uploads/x.png")


class TestRedirectSemantics(unittest.TestCase):
    HTTPS_A = ("https", "a.test", 443)
    HTTP_A = ("http", "a.test", 80)
    HTTPS_A_8443 = ("https", "a.test", 8443)
    HTTPS_B = ("https", "b.test", 443)

    def test_301_302_post_becomes_get(self):
        for code in (301, 302):
            m, b, h = _redirect_next(code, "POST", b"data", {}, self.HTTPS_A,
                                     self.HTTPS_A, set())
            self.assertEqual(m, "GET")
            self.assertIsNone(b)

    def test_303_post_becomes_get(self):
        m, b, h = _redirect_next(303, "POST", b"data", {}, self.HTTPS_A,
                                 self.HTTPS_A, set())
        self.assertEqual(m, "GET")
        self.assertIsNone(b)

    def test_307_308_preserve_method_and_body(self):
        for code in (307, 308):
            m, b, h = _redirect_next(code, "POST", b"data", {}, self.HTTPS_A,
                                     self.HTTPS_A, set())
            self.assertEqual(m, "POST")
            self.assertEqual(b, b"data")

    def test_credentials_kept_same_origin(self):
        hdrs = {"Authorization": "Bearer x"}
        _, _, h = _redirect_next(307, "GET", None, hdrs, self.HTTPS_A, self.HTTPS_A,
                                 _SENSITIVE_HEADERS)
        self.assertIn("Authorization", h)

    def test_credentials_dropped_on_hostname_change(self):
        hdrs = {"Authorization": "Bearer x", "Cookie": "s=1", "X-Keep": "1"}
        _, _, h = _redirect_next(302, "GET", None, hdrs, self.HTTPS_A, self.HTTPS_B,
                                 _SENSITIVE_HEADERS)
        self.assertNotIn("Authorization", h)
        self.assertNotIn("Cookie", h)
        self.assertIn("X-Keep", h)

    def test_credentials_dropped_on_port_change(self):
        hdrs = {"Authorization": "Bearer x"}
        _, _, h = _redirect_next(307, "GET", None, hdrs, self.HTTPS_A,
                                 self.HTTPS_A_8443, _SENSITIVE_HEADERS)
        self.assertNotIn("Authorization", h)

    def test_credentials_dropped_on_https_to_http_downgrade(self):
        hdrs = {"Authorization": "Bearer x", "Cookie": "s=1"}
        _, _, h = _redirect_next(307, "GET", None, hdrs, self.HTTPS_A, self.HTTP_A,
                                 _SENSITIVE_HEADERS)
        self.assertNotIn("Authorization", h)
        self.assertNotIn("Cookie", h)


def client_for(server):
    return HttpClient(allowed_hosts={server.host}, allowed_ports={server.port},
                      allowed_schemes={"http"}, allow_private=True,
                      rate_limit_per_sec=1000)


class TestRedirectIntegration(unittest.TestCase):
    def test_post_307_preserves_method_and_body(self):
        with FixtureServer() as s:
            c = client_for(s)
            body = b"x" * 10
            r = c.request("POST", normalize_url(f"{s.base}/r307"),
                          headers={"Content-Type": "text/plain"}, body=body)
            self.assertIn("METHOD=POST", r.text)
            self.assertIn("BODYLEN=10", r.text)

    def test_post_302_becomes_get_without_body(self):
        with FixtureServer() as s:
            c = client_for(s)
            r = c.request("POST", normalize_url(f"{s.base}/r302"),
                          headers={"Content-Type": "text/plain"}, body=b"xxxx")
            self.assertIn("METHOD=GET", r.text)
            self.assertIn("BODYLEN=0", r.text)

    def test_303_becomes_get(self):
        with FixtureServer() as s:
            c = client_for(s)
            r = c.request("POST", normalize_url(f"{s.base}/r303"), body=b"xx")
            self.assertIn("METHOD=GET", r.text)

    def test_308_preserves_post(self):
        with FixtureServer() as s:
            c = client_for(s)
            r = c.request("POST", normalize_url(f"{s.base}/r308"),
                          headers={"Content-Type": "text/plain"}, body=b"abc")
            self.assertIn("METHOD=POST", r.text)
            self.assertIn("BODYLEN=3", r.text)


if __name__ == "__main__":
    unittest.main()
