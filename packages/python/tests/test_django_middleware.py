import unittest
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from phinehas.django import PhinehasMiddleware


class MockDjangoRequest:
    def __init__(self, path_info: str, meta: dict = None, method: str = "GET"):
        self.path_info = path_info
        self.path = path_info
        self.method = method
        self.META = meta or {"REMOTE_ADDR": "127.0.0.1"}


class MockDjangoResponse:
    def __init__(self, content: bytes = b'{"status": "ok"}', status: int = 200):
        self.content = content
        self.status_code = status
        self.headers = {}

    def __setitem__(self, key, value):
        self.headers[key] = value


def dummy_get_response(request):
    return MockDjangoResponse()


class TestDjangoMiddleware(unittest.TestCase):
    def test_clean_route_pass_through(self):
        mw = PhinehasMiddleware(dummy_get_response)
        req = MockDjangoRequest("/api/v1/users")
        res = mw(req)
        self.assertEqual(res.status_code, 200)

    def test_strike_on_dotfile_and_subsequent_ban(self):
        strike_logged = []
        attacker_ip = "203.0.113.88"

        mw = PhinehasMiddleware(
            dummy_get_response,
            action="terminate",
            allow_list=[],
            proxy_trust=True,
            proxy_header="HTTP_CF_CONNECTING_IP",
            on_strike=lambda s: strike_logged.append(s),
        )

        req = MockDjangoRequest(
            "/.env.production",
            meta={
                "REMOTE_ADDR": "10.0.0.1",
                "HTTP_CF_CONNECTING_IP": attacker_ip,
            },
        )

        # Attack request blocked
        res = mw(req)
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res["X-Phinehas-Verdict"], "blocked")
        self.assertEqual(len(strike_logged), 1)
        self.assertEqual(strike_logged[0]["ip"], attacker_ip)

        # Subsequent clean request from banned IP also blocked
        req_clean = MockDjangoRequest(
            "/api/v1/health",
            meta={
                "REMOTE_ADDR": "10.0.0.1",
                "HTTP_CF_CONNECTING_IP": attacker_ip,
            },
        )
        res2 = mw(req_clean)
        self.assertEqual(res2.status_code, 403)


if __name__ == "__main__":
    unittest.main()
