"""Regression tests for the third audit: redaction, redirect header policy,
and URL port validation. Written to fail on commit ba4dc29's behavior."""

import unittest

from murs.netutil import redact_secrets, normalize_url
from murs.httpclient import HttpClient, _redirect_next, _SENSITIVE_HEADERS
from tests.fixtures.appserver import FixtureServer


# --------------------------------------------------------------- 1. redaction
class TestRedaction(unittest.TestCase):
    def test_bearer_token_fully_masked(self):
        canary = "eyJhbGciOi.PAYLOAD.sigSECRETbearer123"
        out = redact_secrets(f"Authorization: Bearer {canary}")
        self.assertNotIn(canary, out)

    def test_basic_credentials_masked(self):
        canary = "dXNlcm5hbWU6cGFzc3dvcmRCASIC99"
        out = redact_secrets(f"Authorization: Basic {canary}")
        self.assertNotIn(canary, out)

    def test_cookie_value_masked(self):
        canary = "SESSIONCOOKIEsecret123"
        out = redact_secrets(f"Cookie: session={canary}; theme=dark")
        self.assertNotIn(canary, out)

    def test_set_cookie_value_masked(self):
        canary = "SETCOOKIEsecret456"
        out = redact_secrets(f"Set-Cookie: sid={canary}; Path=/; HttpOnly")
        self.assertNotIn(canary, out)

    def test_x_api_key_header_masked(self):
        canary = "XAPIKEYsecret789value"
        out = redact_secrets(f"X-API-Key: {canary}")
        self.assertNotIn(canary, out)

    def test_token_in_query_string_masked(self):
        canary = "QUERYTOKENsecret321"
        out = redact_secrets(f"GET /path?token={canary}&page=2 HTTP/1.1")
        self.assertNotIn(canary, out)

    def test_capitalization_variations_masked(self):
        canary = "CAPSVARYsecret654"
        out = redact_secrets(f"AUTHORIZATION: bearer {canary}")
        self.assertNotIn(canary, out)


# ------------------------------------------------ 2. redirect header policy
class TestRedirectHeaderPolicy(unittest.TestCase):
    A = ("https", "a.test", 443)
    B = ("https", "b.test", 443)

    def test_custom_secret_header_dropped_cross_origin(self):
        # stricter policy: credentials AND custom caller headers are dropped
        # cross-origin; only allowlisted generic headers survive.
        hdrs = {"X-API-Key": "k", "Authorization": "Bearer t", "X-Keep": "1",
                "Accept": "text/html"}
        _, _, h = _redirect_next(302, "GET", None, hdrs, self.A, self.B, _SENSITIVE_HEADERS)
        self.assertNotIn("X-API-Key", h)
        self.assertNotIn("Authorization", h)
        self.assertNotIn("X-Keep", h)   # custom caller header not forwarded
        self.assertIn("Accept", h)      # allowlisted header preserved

    def test_custom_secret_header_kept_same_origin(self):
        hdrs = {"X-API-Key": "k"}
        _, _, h = _redirect_next(307, "GET", None, hdrs, self.A, self.A, _SENSITIVE_HEADERS)
        self.assertIn("X-API-Key", h)

    def test_caller_cannot_override_host_header(self):
        with FixtureServer() as s:
            c = HttpClient(allowed_hosts={s.host}, allowed_ports={s.port},
                           allowed_schemes={"http"}, allow_private=True,
                           rate_limit_per_sec=1000)
            r = c.request("GET", normalize_url(f"{s.base}/echo-host"),
                          headers={"Host": "evil.test"}, follow=False)
            # the validated Host must win, not the caller-supplied one
            self.assertIn(f"HOST=127.0.0.1:{s.port}", r.text)
            self.assertNotIn("evil.test", r.text)


# ---------------------------------------------------- 3. URL port validation
class TestPortValidation(unittest.TestCase):
    def test_default_ports(self):
        self.assertEqual(normalize_url("http://h/").port, 80)
        self.assertEqual(normalize_url("https://h/").port, 443)

    def test_non_default_port(self):
        self.assertEqual(normalize_url("http://h:8080/").port, 8080)

    def test_port_zero_rejected(self):
        with self.assertRaises(ValueError):
            normalize_url("http://h:0/")

    def test_negative_port_rejected(self):
        with self.assertRaises(ValueError):
            normalize_url("http://h:-1/")

    def test_out_of_range_port_rejected(self):
        with self.assertRaises(ValueError):
            normalize_url("http://h:99999/")

    def test_malformed_port_rejected(self):
        with self.assertRaises(ValueError):
            normalize_url("http://h:abc/")

    def test_explicit_default_port_preserved(self):
        self.assertEqual(normalize_url("http://h:80/").port, 80)


if __name__ == "__main__":
    unittest.main()
