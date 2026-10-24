import unittest

from murs.scheduler import RequestScheduler, parse_retry_after
from murs.httpclient import HttpClient
from murs.netutil import normalize_url
from tests.fixtures.appserver import FixtureServer


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class TestRetryAfterParse(unittest.TestCase):
    def test_delta_seconds(self):
        self.assertEqual(parse_retry_after("5"), 5.0)

    def test_absent(self):
        self.assertIsNone(parse_retry_after(None))
        self.assertIsNone(parse_retry_after(""))

    def test_garbage(self):
        self.assertIsNone(parse_retry_after("not-a-date"))

    def test_http_date_future(self):
        from email.utils import format_datetime
        from datetime import datetime, timezone, timedelta
        when = datetime.now(timezone.utc) + timedelta(seconds=30)
        val = parse_retry_after(format_datetime(when))
        self.assertIsNotNone(val)
        self.assertGreater(val, 10)


class TestScheduler(unittest.TestCase):
    def test_inter_request_delay(self):
        clock = FakeClock()
        slept = []
        s = RequestScheduler(min_delay=2.0, sleeper=lambda d: slept.append(d), clock=clock)
        s.acquire("h")          # first: no wait
        self.assertEqual(slept, [])
        clock.t += 0.5          # 0.5s elapsed
        s.acquire("h")          # should wait ~1.5s
        self.assertAlmostEqual(slept[-1], 1.5, places=5)

    def test_global_budget(self):
        s = RequestScheduler(global_max=2)
        s.acquire("h"); s.acquire("h")
        ok, why = s.check_budget("h")
        self.assertFalse(ok)
        self.assertIn("global", why)

    def test_per_host_budget(self):
        s = RequestScheduler(per_host_max=1)
        s.acquire("a")
        self.assertFalse(s.check_budget("a")[0])
        self.assertTrue(s.check_budget("b")[0])  # a different host is fine

    def test_429_waits_retry_after(self):
        clock = FakeClock()
        slept = []
        s = RequestScheduler(sleeper=lambda d: slept.append(d), clock=clock)
        waited = s.on_response(429, {"retry-after": "7"})
        self.assertEqual(waited, 7.0)
        self.assertEqual(slept, [7.0])

    def test_429_capped(self):
        s = RequestScheduler(retry_after_cap=10.0, sleeper=lambda d: None)
        self.assertEqual(s.on_response(429, {"retry-after": "9999"}), 10.0)

    def test_non_429_does_nothing(self):
        s = RequestScheduler(sleeper=lambda d: None)
        self.assertEqual(s.on_response(200, {}), 0.0)


class TestClientSchedulerIntegration(unittest.TestCase):
    def test_per_host_budget_blocks_request(self):
        with FixtureServer() as s:
            sched = RequestScheduler(per_host_max=1, sleeper=lambda d: None)
            c = HttpClient(allowed_hosts={s.host}, allowed_ports={s.port},
                           allowed_schemes={"http"}, allow_private=True,
                           rate_limit_per_sec=1000, scheduler=sched)
            r1 = c.get(normalize_url(f"{s.base}/about"))
            self.assertTrue(r1.ok)
            r2 = c.get(normalize_url(f"{s.base}/login"))
            self.assertTrue(r2.blocked)
            self.assertIn("per-host", r2.reason)


if __name__ == "__main__":
    unittest.main()
