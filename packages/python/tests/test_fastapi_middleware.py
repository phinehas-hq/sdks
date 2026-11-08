import unittest
from pathlib import Path
import sys
from typing import Any, Dict, List

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from phinehas import PhinehasMiddleware


async def dummy_app(scope: Dict[str, Any], receive: Any, send: Any) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": b'{"status": "ok"}',
            "more_body": False,
        }
    )


async def send_asgi_request(
    middleware: PhinehasMiddleware,
    path: str,
    method: str = "GET",
    headers: Dict[str, str] = None,
    client: tuple = ("127.0.0.1", 12345),
) -> List[Dict[str, Any]]:
    headers_list = [
        (k.encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "path": path,
        "method": method,
        "headers": headers_list,
        "client": client,
    }

    sent_messages: List[Dict[str, Any]] = []

    async def mock_receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def mock_send(msg: Dict[str, Any]):
        sent_messages.append(msg)

    await middleware(scope, mock_receive, mock_send)
    return sent_messages


class TestFastAPIMiddleware(unittest.IsolatedAsyncioTestCase):
    async def test_clean_route_pass_through(self):
        mw = PhinehasMiddleware(dummy_app)
        messages = await send_asgi_request(mw, "/api/v1/health")

        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["type"], "http.response.start")
        self.assertEqual(messages[0]["status"], 200)
        self.assertEqual(messages[1]["body"], b'{"status": "ok"}')

    async def test_immediate_socket_severance_on_attack(self):
        strike_recorded = []
        attacker_ip = "198.51.100.99"

        mw = PhinehasMiddleware(
            dummy_app,
            action="terminate",
            allow_list=[],  # Clear localhost exemption
            proxy_trust=True,
            proxy_header="cf-connecting-ip",
            on_strike=lambda s: strike_recorded.append(s),
        )

        # 1. Attacker probes /.env -> Connection severed (zero messages emitted)
        messages = await send_asgi_request(
            mw, "/.env", headers={"cf-connecting-ip": attacker_ip}
        )
        self.assertEqual(len(messages), 0, "Expected zero ASGI response messages on termination")
        self.assertEqual(len(strike_recorded), 1)
        self.assertEqual(strike_recorded[0]["ip"], attacker_ip)
        self.assertEqual(strike_recorded[0]["ruleMatched"], "rfc8615_wildcard")

        # 2. Subsequent request from same IP to clean route should also be immediately severed
        messages2 = await send_asgi_request(
            mw, "/api/v1/profile", headers={"cf-connecting-ip": attacker_ip}
        )
        self.assertEqual(len(messages2), 0, "Banned IP must be severed on subsequent requests")

    async def test_http_403_rejection_action(self):
        attacker_ip = "203.0.113.55"

        mw = PhinehasMiddleware(
            dummy_app,
            action="reject",
            allow_list=[],
            proxy_trust=True,
            proxy_header="cf-connecting-ip",
            logging_enabled=False,
        )

        messages = await send_asgi_request(
            mw, "/wp-login.php", headers={"cf-connecting-ip": attacker_ip}
        )

        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["type"], "http.response.start")
        self.assertEqual(messages[0]["status"], 403)
        self.assertEqual(messages[1]["body"], b"")

    async def test_allowlist_and_rfc8615_pass_through(self):
        mw = PhinehasMiddleware(
            dummy_app,
            allow_list=["127.0.0.1"],
            logging_enabled=False,
        )

        # RFC 8615 allowed path passes through
        messages = await send_asgi_request(mw, "/.well-known/openid-configuration")
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["status"], 200)

        # Allowlisted IP probing dotfile passes through without ban
        messages2 = await send_asgi_request(mw, "/.env", client=("127.0.0.1", 54321))
        self.assertEqual(len(messages2), 2)
        self.assertEqual(messages2[0]["status"], 200)


if __name__ == "__main__":
    unittest.main()
