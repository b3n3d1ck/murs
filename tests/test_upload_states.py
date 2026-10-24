"""Integration tests for every upload-execution outcome state.

These exercise the full upload module against a local fixture whose endpoints
deterministically produce each state, so the four outcomes required by the
workflow (acceptance, public accessibility, server-side interpretation, and
confirmed execution) are each covered. Confirmed execution against real PHP is
covered separately in test_lab.py.
"""

import unittest

from murs.httpclient import HttpClient
from murs.netutil import normalize_url
from murs.upload import (
    UploadModule,
    OUT_REJECTED, OUT_ACCESS_CONTROLLED, OUT_PUBLIC_NOT_INTERPRETED,
    OUT_INTERPRETED_UNCONFIRMED, OUT_EXECUTION_UNCONFIRMED,
)
from tests.fixtures.appserver import FixtureServer


def client_for(server):
    return HttpClient(
        allowed_hosts={server.host}, allowed_ports={server.port},
        allowed_schemes={"http"}, allow_private=True,
        rate_limit_per_sec=1000, max_requests=300,
    )


def php_attempt(server, action):
    mod = UploadModule(client_for(server), normalize_url(server.base))
    results = mod.assess(f"{server.base}{action}", "file")
    return [r for r in results if r.probe_kind == "php_extension"][0]


class TestUploadStates(unittest.TestCase):
    def test_rejected(self):
        with FixtureServer() as s:
            at = php_attempt(s, "/upload-reject")
            self.assertTrue(at.sent)
            self.assertFalse(at.accepted)
            self.assertEqual(at.outcome, OUT_REJECTED)
            self.assertIsNone(at.execution_url)

    def test_accepted_public_not_interpreted(self):
        with FixtureServer() as s:
            at = php_attempt(s, "/upload")  # serves raw text/plain
            self.assertTrue(at.accepted)
            self.assertTrue(at.accessible)
            self.assertEqual(at.outcome, OUT_PUBLIC_NOT_INTERPRETED)
            self.assertEqual(at.executed, False)
            self.assertIsNone(at.execution_url)

    def test_access_controlled(self):
        with FixtureServer() as s:
            at = php_attempt(s, "/upload-protected")  # stored location returns 401
            self.assertTrue(at.accepted)
            self.assertFalse(at.accessible)
            self.assertTrue(at.access_controlled)
            self.assertEqual(at.outcome, OUT_ACCESS_CONTROLLED)
            self.assertIsNone(at.execution_url)

    def test_server_side_interpreted_unconfirmed(self):
        with FixtureServer() as s:
            at = php_attempt(s, "/upload-strip")  # php tags stripped, no marker
            self.assertTrue(at.accepted)
            self.assertEqual(at.outcome, OUT_INTERPRETED_UNCONFIRMED)
            self.assertTrue(at.interpreted)
            self.assertIsNone(at.executed)      # not confirmed
            self.assertIsNone(at.execution_url)  # requirement 9

    def test_execution_unconfirmed_when_location_unknown(self):
        with FixtureServer() as s:
            at = php_attempt(s, "/upload-nolocation")
            self.assertTrue(at.accepted)
            self.assertEqual(at.outcome, OUT_EXECUTION_UNCONFIRMED)
            self.assertIsNone(at.execution_url)

    def test_public_stored_url_is_verified_by_marker(self):
        with FixtureServer() as s:
            at = php_attempt(s, "/upload")
            self.assertTrue(at.storage_confirmed)
            self.assertTrue(at.storage_location_observed)
            self.assertIsNotNone(at.stored_location)

    def test_access_controlled_does_not_claim_a_stored_location(self):
        with FixtureServer() as s:
            at = php_attempt(s, "/upload-protected")
            # a 401 candidate must NOT be reported as the confirmed file
            self.assertIsNone(at.stored_location)
            self.assertFalse(at.storage_confirmed)
            self.assertIn("access_controlled_candidate", at.evidence)

    def test_hidden_location_records_candidates_but_confirms_nothing(self):
        with FixtureServer() as s:
            at = php_attempt(s, "/upload-nolocation")
            self.assertTrue(at.candidate_urls, "candidates should be tried")
            self.assertIsNone(at.stored_location)   # none confirmed
            self.assertFalse(at.storage_confirmed)

    def test_no_execution_url_unless_confirmed_across_all_states(self):
        # the invariant: an execution URL is only ever present on a confirmed run
        for action in ("/upload", "/upload-reject", "/upload-protected",
                       "/upload-strip", "/upload-nolocation"):
            with FixtureServer() as s:
                mod = UploadModule(client_for(s), normalize_url(s.base))
                for at in mod.assess(f"{s.base}{action}", "file"):
                    self.assertIsNone(at.execution_url,
                                      f"{action}/{at.probe_kind} leaked an execution URL")


if __name__ == "__main__":
    unittest.main()
