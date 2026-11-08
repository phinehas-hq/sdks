import unittest
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from phinehas.flask import Phinehas


class MockFlaskRequest:
    def __init__(self, path: str, remote_addr: str = "127.0.0.1", headers: dict = None):
        self.path = path
        self.method = "GET"
        self.remote_addr = remote_addr
        self.headers = headers or {}


class MockFlaskApplication:
    def __init__(self):
        self.before_request_funcs = []

    def before_request(self, func):
        self.before_request_funcs.append(func)


class TestFlaskExtension(unittest.TestCase):
    def test_clean_route_returns_none(self):
        app = MockFlaskApplication()
        phinehas = Phinehas(app)
        self.assertEqual(len(app.before_request_funcs), 1)

        req = MockFlaskRequest("/api/v1/items")
        result = phinehas.intercept_request(req)
        self.assertIsNone(result, "Clean route must return None to allow Flask to proceed")

    def test_strike_on_honeypot(self):
        strike_logged = []
        attacker_ip = "192.0.2.77"

        phinehas = Phinehas(
            allow_list=[],
            proxy_trust=True,
            on_strike=lambda s: strike_logged.append(s),
        )

        req = MockFlaskRequest(
            "/wp-admin",
            headers={"CF-Connecting-IP": attacker_ip},
            remote_addr="10.0.0.1",
        )

        result = phinehas.intercept_request(req)
        self.assertIsNotNone(result, "Attack request must be intercepted")
        self.assertEqual(result[1], 403)
        self.assertEqual(len(strike_logged), 1)
        self.assertEqual(strike_logged[0]["ip"], attacker_ip)
        self.assertEqual(strike_logged[0]["ruleMatched"], "explicit_trap")


if __name__ == "__main__":
    unittest.main()
