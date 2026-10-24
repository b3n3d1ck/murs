import unittest

from murs.httpclient import HttpClient
from murs.netutil import normalize_url
from tests.fixtures.appserver import FixtureServer


def client_for(server, **kw):
    return HttpClient(
        allowed_hosts={server.host},
        allowed_ports={server.port},
        allowed_schemes={"http"},
        allow_private=True,
        rate_limit_per_sec=1000,
        **kw,
    )


class TestHttpClient(unittest.TestCase):
    def test_basic_get(self):
        with FixtureServer() as s:
            c = client_for(s)
            r = c.get(normalize_url(f"{s.base}/about"))
            self.assertTrue(r.ok)
            self.assertEqual(r.status, 200)
            self.assertIn("about page", r.text)

    def test_out_of_scope_blocked(self):
        with FixtureServer() as s:
            c = client_for(s)
            r = c.get(normalize_url("http://external.example/x"), follow=False)
            self.assertTrue(r.blocked)
            self.assertIn("out of scope", r.reason)

    def test_follows_in_scope_redirect(self):
        with FixtureServer() as s:
            c = client_for(s)
            r = c.get(normalize_url(f"{s.base}/redirect-in"))
            self.assertEqual(r.status, 200)
            self.assertIn("about page", r.text)
            self.assertTrue(r.history)

    def test_refuses_out_of_scope_redirect(self):
        with FixtureServer() as s:
            c = client_for(s)
            r = c.get(normalize_url(f"{s.base}/redirect-out"))
            self.assertEqual(r.status, 302)
            self.assertIn("left scope", r.reason)

    def test_body_cap(self):
        with FixtureServer() as s:
            c = client_for(s, max_response_bytes=10)
            r = c.get(normalize_url(f"{s.base}/"))
            self.assertLessEqual(len(r.body), 10)
            self.assertTrue(r.truncated)

    def test_request_budget(self):
        from murs.httpclient import RequestBudgetExceeded

        with FixtureServer() as s:
            c = client_for(s, max_requests=1)
            c.get(normalize_url(f"{s.base}/about"))
            with self.assertRaises(RequestBudgetExceeded):
                c.get(normalize_url(f"{s.base}/login"))

    def test_ssrf_guard_blocks_localhost_without_optin(self):
        # a client WITHOUT allow_private must refuse 127.0.0.1
        c = HttpClient(
            allowed_hosts={"127.0.0.1"},
            allowed_ports={80},
            allowed_schemes={"http"},
            allow_private=False,
            rate_limit_per_sec=1000,
        )
        r = c.get(normalize_url("http://127.0.0.1/"), follow=False)
        self.assertTrue(r.blocked)
        self.assertIn("ssrf", r.reason)


if __name__ == "__main__":
    unittest.main()
