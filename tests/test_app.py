from __future__ import annotations

import io
import json
import tempfile
import unittest

from autoedge_licensing.app import create_app, customer_detail_page, packages_page, products_page
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
        product = self.app.service.upsert_product(
            slug="http-strategy",
            name="HTTP Strategy",
            feature_id="strategy.http.runtime",
        )
        self.app.service.upsert_whop_package(
            package_id=None,
            whop_id="prod_http",
            whop_id_type="product",
            name="HTTP Strategy 30 days",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": product["id"], "days": 30}],
        )
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
        self.assertEqual("whop_package", payload["mapping_mode"])

    def test_admin_product_list_hides_internal_slug_and_feature_ids(self) -> None:
        html = products_page(
            [
                {
                    "id": "product-001",
                    "name": "DUO Runtime",
                    "slug": "duo-runtime",
                    "feature_id": "strategy.duo.runtime",
                    "whop_product_id": "",
                    "is_active": 1,
                    "updated_at": "2026-06-04T00:00:00Z",
                }
            ],
            "csrf-token",
        )

        self.assertIn("DUO", html)
        self.assertNotIn("DUO Runtime", html)
        self.assertNotIn("duo-runtime", html)
        self.assertNotIn("strategy.duo.runtime", html)

    def test_packages_page_shows_bundle_without_internal_feature_ids(self) -> None:
        html = packages_page(
            [
                {
                    "id": "package-001",
                    "name": "AutoEdge Bundle 30 days",
                    "whop_id": "plan_bundle",
                    "whop_id_type": "plan",
                    "default_days": 30,
                    "is_active": 1,
                    "is_ignored": 0,
                    "grants": [
                        {
                            "product_id": "product-001",
                            "product_name": "DUO Runtime",
                            "days": 30,
                            }
                    ],
                }
            ],
            [
                {
                    "id": "product-001",
                    "name": "DUO Runtime",
                    "slug": "duo-runtime",
                    "feature_id": "strategy.duo.runtime",
                }
            ],
            "csrf-token",
        )

        self.assertIn("AutoEdge Bundle 30 days", html)
        self.assertIn("plan_bundle", html)
        self.assertIn("DUO 30d", html)
        self.assertNotIn("DUO Runtime", html)
        self.assertNotIn("strategy.duo.runtime", html)

    def test_customer_detail_hides_internal_feature_ids(self) -> None:
        html = customer_detail_page(
            {
                "customer": {
                    "id": "customer-001",
                    "email": "customer@example.com",
                    "name": "Customer",
                    "whop_user_id": "user-001",
                    "whop_member_id": "member-001",
                    "license_key_last4": "ABCD",
                },
                "entitlements": [
                    {
                        "product_name": "DUO Runtime",
                        "feature_id": "strategy.duo.runtime",
                        "status": "active",
                        "source": "manual",
                        "expires_at": None,
                        "manual_reason": None,
                        "updated_at": "2026-06-04T00:00:00Z",
                    }
                ],
                "subscriptions": [],
                "devices": [],
                "checks": [],
                "audit": [],
            },
            [
                {
                    "id": "product-001",
                    "name": "DUO Runtime",
                    "feature_id": "strategy.duo.runtime",
                }
            ],
            "csrf-token",
            "",
        )

        self.assertIn("DUO", html)
        self.assertNotIn("DUO Runtime", html)
        self.assertNotIn("strategy.duo.runtime", html)

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
