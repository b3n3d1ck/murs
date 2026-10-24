import unittest

from murs.httpclient import HttpClient
from murs.netutil import normalize_url
from murs.upload import UploadModule, build_probes, _multipart
from tests.fixtures.appserver import FixtureServer


def client_for(server):
    return HttpClient(
        allowed_hosts={server.host}, allowed_ports={server.port},
        allowed_schemes={"http"}, allow_private=True,
        rate_limit_per_sec=1000, max_requests=200,
    )


class TestProbes(unittest.TestCase):
    def test_probes_are_inert(self):
        for p in build_probes(65536):
            text = p.content.decode("latin-1")
            # the code canary must contain NO command execution / input handling
            for bad in ("system(", "exec(", "shell_exec", "passthru",
                        "popen", "eval(", "$_GET", "$_POST", "$_REQUEST",
                        "base64_decode", "include", "require"):
                self.assertNotIn(bad, text, f"{p.kind} contains {bad}")

    def test_canary_source_never_contains_executed_signature(self):
        for p in build_probes(65536):
            if p.executed_signature:
                # the evaluated marker must only appear AFTER execution
                self.assertNotIn(p.executed_signature, p.content.decode("latin-1"))

    def test_multipart_well_formed(self):
        p = build_probes(65536)[0]
        body, ctype = _multipart("file", p)
        self.assertIn("multipart/form-data; boundary=", ctype)
        self.assertIn(b'filename="', body)


class TestUploadAgainstFixture(unittest.TestCase):
    def test_upload_staged_evidence(self):
        with FixtureServer() as s:
            base = normalize_url(s.base)
            mod = UploadModule(client_for(s), base)
            results = mod.assess(f"{s.base}/upload", "file")
            self.assertTrue(results)
            # fixture accepts and serves everything raw (text/plain)
            php = [r for r in results if r.probe_kind == "php_extension"][0]
            self.assertTrue(php.sent)
            self.assertTrue(php.accepted)
            self.assertIsNotNone(php.stored_location)
            self.assertTrue(php.accessible)
            # fixture does NOT run PHP → stored, not executed
            self.assertEqual(php.executed, False)

    def test_out_of_scope_action_blocked(self):
        with FixtureServer() as s:
            base = normalize_url(s.base)
            mod = UploadModule(client_for(s), base)
            results = mod.assess("http://external.example/upload", "file")
            self.assertTrue(all(not r.sent for r in results))


if __name__ == "__main__":
    unittest.main()
