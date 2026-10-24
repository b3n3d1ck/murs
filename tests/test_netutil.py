import unittest

from murs.netutil import (
    normalize_url,
    ip_is_disallowed,
    in_scope,
    join_in_scope,
    check_host_safe,
)


class TestNormalize(unittest.TestCase):
    def test_bare_host_gets_https(self):
        t = normalize_url("example.com")
        self.assertEqual(t.scheme, "https")
        self.assertEqual(t.host, "example.com")
        self.assertEqual(t.port, 443)
        self.assertEqual(t.url, "https://example.com/")

    def test_www_and_path(self):
        t = normalize_url("www.example.com/app/")
        self.assertEqual(t.host, "www.example.com")
        self.assertEqual(t.path, "/app/")

    def test_explicit_scheme_and_port(self):
        t = normalize_url("http://example.com:8080/x")
        self.assertEqual(t.scheme, "http")
        self.assertEqual(t.port, 8080)
        self.assertEqual(t.origin, "http://example.com:8080")

    def test_uppercase_host_lowered(self):
        self.assertEqual(normalize_url("HTTPS://EXAMPLE.COM").host, "example.com")

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            normalize_url("ftp://example.com")

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            normalize_url("   ")


class TestSsrf(unittest.TestCase):
    def test_disallows_loopback_private_metadata(self):
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254",
                   "0.0.0.0", "100.64.0.1", "::1", "fe80::1", "fc00::1"]:
            self.assertTrue(ip_is_disallowed(ip), ip)

    def test_disallows_ipv4_mapped_loopback(self):
        self.assertTrue(ip_is_disallowed("::ffff:127.0.0.1"))

    def test_allows_public(self):
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]:
            self.assertFalse(ip_is_disallowed(ip), ip)

    def test_garbage_fails_closed(self):
        self.assertTrue(ip_is_disallowed("not-an-ip"))

    def test_check_host_literal_private(self):
        c = check_host_safe("127.0.0.1")
        self.assertFalse(c.allowed)


class TestScope(unittest.TestCase):
    def test_in_scope_exact_host(self):
        t = normalize_url("https://a.example.com/x")
        ok, _ = in_scope(t, {"a.example.com"}, {443}, {"https"})
        self.assertTrue(ok)

    def test_out_of_scope_host(self):
        t = normalize_url("https://evil.test/x")
        ok, reason = in_scope(t, {"a.example.com"}, {443}, {"https"})
        self.assertFalse(ok)
        self.assertIn("not in scope", reason)

    def test_out_of_scope_port(self):
        t = normalize_url("https://a.example.com:8443/x")
        ok, _ = in_scope(t, {"a.example.com"}, {443}, {"https"})
        self.assertFalse(ok)

    def test_join_ignores_mailto_and_fragment(self):
        base = normalize_url("https://a.example.com/")
        self.assertIsNone(join_in_scope(base, "mailto:x@y.z"))
        self.assertIsNone(join_in_scope(base, "#top"))

    def test_join_resolves_relative(self):
        base = normalize_url("https://a.example.com/dir/page")
        t = join_in_scope(base, "../other")
        self.assertIsNotNone(t)
        self.assertEqual(t.url, "https://a.example.com/other")


if __name__ == "__main__":
    unittest.main()
