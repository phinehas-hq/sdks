import unittest
from pathlib import Path
import sys
from typing import Any, Dict, List

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from phinehas import PhinehasWSGIMiddleware


def dummy_wsgi_app(environ: Dict[str, Any], start_response: Any):
    start_response("200 OK", [("Content-Type", "application/json")])
    return [b'{"status": "ok"}']


class TestWSGIMiddleware(unittest.TestCase):
    def test_clean_route_pass_through(self):
        mw = PhinehasWSGIMiddleware(dummy_wsgi_app)
        captured_status = []
        captured_headers = []

        def mock_start_response(status, headers):
            captured_status.append(status)
            captured_headers.extend(headers)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/api/v1/health",
            "REMOTE_ADDR": "127.0.0.1",
        }
        res = mw(environ, mock_start_response)
        self.assertEqual(captured_status[0], "200 OK")
        self.assertEqual(list(res), [b'{"status": "ok"}'])

    def test_strike_and_severance_on_dotfile(self):
        strike_logged = []
        attacker_ip = "198.51.100.40"

        mw = PhinehasWSGIMiddleware(
            dummy_wsgi_app,
            action="terminate",
            allow_list=[],
            proxy_trust=True,
            on_strike=lambda s: strike_logged.append(s),
        )

        captured_status = []

        def mock_start_response(status, headers):
            captured_status.append(status)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/.env",
            "HTTP_CF_CONNECTING_IP": attacker_ip,
            "REMOTE_ADDR": "10.0.0.1",
        }

        # 1. Attacking request
        res = mw(environ, mock_start_response)
        self.assertEqual(len(strike_logged), 1)
        self.assertEqual(strike_logged[0]["ip"], attacker_ip)
        self.assertEqual(strike_logged[0]["ruleMatched"], "rfc8615_wildcard")
        self.assertEqual(list(res), [b""])

        # 2. Subsequent request from same IP should be blocked
        captured_status.clear()
        environ["PATH_INFO"] = "/api/v1/health"
        res2 = mw(environ, mock_start_response)
        self.assertEqual(captured_status[0], "403 Forbidden")
        self.assertEqual(list(res2), [b""])


if __name__ == "__main__":
    unittest.main()
