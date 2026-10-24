"""Findings 1, 4, 5: query preservation, IPv6 authority, actual socket pinning."""

import socket
import unittest

import murs.httpclient as hc
import murs.netutil as netutil
from murs.netutil import normalize_url, join_in_scope
from murs.httpclient import HttpClient, _PinnedHTTPSConnection
from tests.fixtures.appserver import FixtureServer


class TestQueryPreservation(unittest.TestCase):
    def test_normalize_keeps_query_not_fragment(self):
        t = normalize_url("https://x.test/p?a=1&b=2#frag")
        self.assertEqual(t.query, "a=1&b=2")
        self.assertEqual(t.request_target, "/p?a=1&b=2")       # query kept
        self.assertNotIn("frag", t.request_target)             # fragment dropped
        self.assertEqual(t.url, "https://x.test/p?a=1&b=2")

    def test_relative_link_preserves_query(self):
        base = normalize_url("https://x.test/dir/page")
        t = join_in_scope(base, "search?q=term")
        self.assertEqual(t.request_target, "/dir/search?q=term")

    def test_empty_query_has_clean_target(self):
        self.assertEqual(normalize_url("https://x.test/p").request_target, "/p")

    def test_query_is_sent_on_the_wire(self):
        with FixtureServer() as s:
            c = HttpClient(allowed_hosts={s.host}, allowed_ports={s.port},
                           allowed_schemes={"http"}, allow_private=True,
                           rate_limit_per_sec=1000)
            r = c.get(normalize_url(f"{s.base}/echo-query?a=1&b=2"))
            self.assertIn("QUERY=a=1&b=2", r.text)


class TestIPv6Authority(unittest.TestCase):
    def test_ipv6_literal_bracketed_with_port(self):
        t = normalize_url("http://[2606:4700:4700::1111]:8080/p?x=1")
        self.assertEqual(t.host, "2606:4700:4700::1111")
        self.assertEqual(t.port, 8080)
        self.assertEqual(t.authority, "[2606:4700:4700::1111]:8080")
        self.assertEqual(t.host_header, "[2606:4700:4700::1111]:8080")
        self.assertEqual(t.origin, "http://[2606:4700:4700::1111]:8080")
        self.assertEqual(t.url, "http://[2606:4700:4700::1111]:8080/p?x=1")

    def test_ipv6_default_port_omitted(self):
        t = normalize_url("https://[::1]/")
        self.assertEqual(t.authority, "[::1]")
        self.assertEqual(t.host_header, "[::1]")

    def test_ipv4_authority_unchanged(self):
        t = normalize_url("http://93.184.216.34:8000/")
        self.assertEqual(t.authority, "93.184.216.34:8000")

    def test_hostname_authority_unchanged(self):
        self.assertEqual(normalize_url("https://a.test/").host_header, "a.test")


class _FakeSock:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _FakeCtx:
    def __init__(self):
        self.sni = None

    def wrap_socket(self, sock, server_hostname=None):
        self.sni = server_hostname
        return sock


class TestActualPinning(unittest.TestCase):
    def test_socket_connects_to_validated_ip_without_reresolution(self):
        captured = {}
        resolve_calls = {"n": 0}

        def fake_resolve(host):
            resolve_calls["n"] += 1
            return ["93.184.216.34"]

        def fake_create_connection(addr, *a, **k):
            captured["addr"] = addr
            raise ConnectionRefusedError("captured")

        orig_resolve = netutil.resolve_host
        orig_cc = hc.socket.create_connection
        netutil.resolve_host = fake_resolve
        hc.socket.create_connection = fake_create_connection
        try:
            c = HttpClient(allowed_hosts={"example.test"}, allowed_ports={80},
                           allowed_schemes={"http"}, rate_limit_per_sec=1000, retries=0)
            r = c.get(normalize_url("http://example.test/path"), follow=False)
            # connected to the validated IP, not the hostname
            self.assertEqual(captured["addr"], ("93.184.216.34", 80))
            # resolution happened once (validation); connect did NOT re-resolve
            self.assertEqual(resolve_calls["n"], 1)
            self.assertIsNotNone(r.error)  # the fake refused, as intended
        finally:
            netutil.resolve_host = orig_resolve
            hc.socket.create_connection = orig_cc

    def test_https_uses_hostname_for_sni_not_pinned_ip(self):
        ctx = _FakeCtx()
        fake = _FakeSock()
        orig_cc = hc.socket.create_connection
        hc.socket.create_connection = lambda addr, *a, **k: fake
        try:
            conn = _PinnedHTTPSConnection("example.test", 443, "93.184.216.34", 5, ctx)
            conn.connect()
            self.assertEqual(ctx.sni, "example.test")  # SNI = hostname, not the IP
        finally:
            hc.socket.create_connection = orig_cc


if __name__ == "__main__":
    unittest.main()
