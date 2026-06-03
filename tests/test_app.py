from __future__ import annotations

import io
import json
import tempfile
import unittest

from autoedge_licensing.app import create_app
from autoedge_licensing.config import Settings


class AppEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        settings = Settings(
            database_path=f"{self.tmp.name}/app.db",
            bind_host="127.0.0.1",
            bind_port=0,
            public_base_url="https://licenses.example.test",
            whop_webhook_secret=None,
            whop_bearer_token="test-token",
            admin_cookie_secret="x" * 40,
            cookie_secure=False,
            session_hours=12,
            license_check_interval_seconds=3600,
            grace_period_seconds=86400,
            rate_limit_per_minute=60,
        )
        self.app = create_app(settings)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_whop_endpoint_rejects_missing_auth(self) -> None:
        status, _, body = self.call(
            "POST",
            "/api/whop/entitlements",
            {"type": "membership.created", "data": {}},
            {},
        )

        self.assertTrue(status.startswith("401"))
        self.assertEqual("unauthorized", json.loads(body)["status"])

    def test_whop_endpoint_accepts_bearer_token(self) -> None:
        status, _, body = self.call(
            "POST",
            "/api/whop/entitlements",
            {
                "id": "evt_http_001",
                "type": "membership.created",
                "data": {
                    "id": "ent_http_001",
                    "membership_id": "mem_http_001",
                    "status": "active",
                    "email": "http@example.com",
                    "product_id": "prod_http",
                    "product_name": "HTTP Strategy",
                    "product_slug": "http-strategy",
                },
            },
            {"Authorization": "Bearer test-token"},
        )

        self.assertTrue(status.startswith("200"), body)
        payload = json.loads(body)
        self.assertEqual("processed", payload["status"])
        self.assertEqual("active", payload["entitlement_status"])

    def call(self, method: str, path: str, payload: dict, headers: dict[str, str]) -> tuple[str, list[tuple[str, str]], str]:
        body = json.dumps(payload).encode("utf-8")
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/json",
            "wsgi.input": io.BytesIO(body),
            "REMOTE_ADDR": "127.0.0.1",
        }
        for key, value in headers.items():
            environ["HTTP_" + key.upper().replace("-", "_")] = value
        captured: dict[str, object] = {}

        def start_response(status: str, response_headers: list[tuple[str, str]]) -> None:
            captured["status"] = status
            captured["headers"] = response_headers

        chunks = self.app(environ, start_response)
        return captured["status"], captured["headers"], b"".join(chunks).decode("utf-8")  # type: ignore[index,return-value]


if __name__ == "__main__":
    unittest.main()
