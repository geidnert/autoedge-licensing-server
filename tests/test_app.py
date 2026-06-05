from __future__ import annotations

import io
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from autoedge_licensing.app import create_app, customer_detail_page, packages_page, products_page, releases_page
from autoedge_licensing.config import Settings
from autoedge_licensing.service import iso, utc_now


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
            trader_max_devices=1,
            rate_limit_per_minute=60,
            release_artifact_dir=f"{self.tmp.name}/artifacts",
            release_download_token_seconds=600,
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
                "max_devices": None,
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
                "device_limit": {
                    "active_devices": 0,
                    "max_devices": 1,
                    "customer_max_devices": None,
                    "default_max_devices": 1,
                },
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

    def test_releases_page_can_list_trader_desktop_release(self) -> None:
        html = releases_page(
            [
                {
                    "id": "release-001",
                    "scope": "app",
                    "release_type": "trader_desktop",
                    "product_id": None,
                    "product_key": "trader-desktop",
                    "product_name": None,
                    "channel": "stable",
                    "platform": "windows-x64",
                    "version": "0.1.1",
                    "min_supported_version": "0.1.0",
                    "is_required": 0,
                    "is_active": 1,
                    "is_published": 1,
                    "artifact_filename": "Trader-Setup-0.1.1-windows-x64.zip",
                    "size_bytes": 123,
                    "sha256": "abcdef123456",
                    "signature": "sig",
                    "signature_key_id": "key-1",
                    "release_notes": "Desktop update",
                    "published_at": "2026-06-04T13:00:00Z",
                    "created_at": "2026-06-04T13:00:00Z",
                    "updated_at": "2026-06-04T13:05:00Z",
                }
            ],
            [],
            "csrf-token",
            None,
            "/var/lib/autoedge-licensing/artifacts",
        )

        self.assertIn("Trader Desktop", html)
        self.assertIn("trader_desktop", html)
        self.assertIn("trader-desktop", html)
        self.assertIn("<th>Channel</th>", html)
        self.assertNotIn("Channel / Target", html)
        self.assertNotIn("Target Windows x64", html)
        self.assertNotIn("Target platform", html)
        self.assertIn("Published", html)
        self.assertIn("Signature key id", html)
        self.assertIn("Audience", html)
        self.assertIn("Allowed emails", html)
        self.assertIn("Rollback reason", html)
        self.assertIn("Created", html)
        self.assertIn("2026-06-04T13:05:00Z", html)

    def test_release_editor_is_collapsed_for_add_and_open_for_edit(self) -> None:
        add_html = releases_page([], [], "csrf-token", None, "/var/lib/autoedge-licensing/artifacts")
        edit_html = releases_page(
            [],
            [],
            "csrf-token",
            {
                "id": "release-001",
                "scope": "app",
                "release_type": "trader_desktop",
                "product_key": "trader-desktop",
                "channel": "stable",
                "platform": "windows-x64",
                "version": "0.1.1",
                "is_required": 0,
                "is_active": 1,
                "artifact_path": "trader.zip",
                "artifact_filename": "trader.zip",
            },
            "/var/lib/autoedge-licensing/artifacts",
        )

        self.assertIn('<details class="release-editor" >', add_html)
        self.assertNotIn('<details class="release-editor" open>', add_html)
        self.assertIn('<details class="release-editor" open>', edit_html)

    def test_release_manifest_and_download_endpoint(self) -> None:
        product = self.app.service.upsert_product(
            slug="duo-runtime",
            name="DUO Runtime",
            feature_id="strategy.duo.runtime",
        )
        created = self.app.service.create_or_update_customer(email="release-http@example.com")
        self.app.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=product["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="http release",
            actor_id="admin",
            ip_address=None,
        )
        artifact_dir = Path(self.tmp.name) / "artifacts"
        artifact_dir.mkdir()
        artifact = artifact_dir / "duo-http.zip"
        artifact.write_bytes(b"http artifact")
        release = self.app.service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=product["id"],
            channel="stable",
            platform="windows-x64",
            version="2.0.0",
            min_supported_version=None,
            is_required=True,
            is_active=True,
            artifact_path="duo-http.zip",
            artifact_filename=None,
            size_bytes=None,
            sha256_value=None,
            signature=None,
            release_notes=None,
            artifact_dir=str(artifact_dir),
        )

        status, _, manifest_body = self.call(
            "POST",
            "/api/trader/releases/manifest",
            {
                "license_key": created.license_key,
                "machine_fingerprint": "http-release-machine",
                "app_version": "1.0.0",
                "channel": "stable",
                "platform": "windows-x64",
            },
            {},
        )
        token_status, _, token_body = self.call(
            "POST",
            "/api/trader/releases/download-token",
            {
                "license_key": created.license_key,
                "machine_fingerprint": "http-release-machine",
                "app_version": "1.0.0",
                "release_id": release["id"],
            },
            {},
        )
        token_payload = json.loads(token_body)
        download_status, download_headers, download_body = self.call_raw(
            "GET",
            f"/api/trader/releases/download/{token_payload['token']}",
            b"",
            {},
        )

        self.assertTrue(status.startswith("200"), manifest_body)
        manifest = json.loads(manifest_body)
        self.assertEqual("active", manifest["status"])
        self.assertEqual("2.0.0", manifest["releases"][0]["version"])
        self.assertTrue(token_status.startswith("200"), token_body)
        self.assertTrue(download_status.startswith("200"), download_status)
        self.assertIn(("Content-Disposition", 'attachment; filename="duo-http.zip"'), download_headers)
        self.assertEqual("http artifact", download_body)

    def test_release_download_token_requires_license(self) -> None:
        product = self.app.service.upsert_product(
            slug="duo-runtime",
            name="DUO Runtime",
            feature_id="strategy.duo.runtime",
        )
        artifact_dir = Path(self.tmp.name) / "artifacts"
        artifact_dir.mkdir()
        release = self.app.service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=product["id"],
            channel="stable",
            platform="windows-x64",
            version="2.0.0",
            min_supported_version=None,
            is_required=False,
            is_active=True,
            artifact_path="missing.zip",
            artifact_filename=None,
            size_bytes=1,
            sha256_value="abc",
            signature=None,
            release_notes=None,
            artifact_dir=str(artifact_dir),
        )

        status, _, body = self.call(
            "POST",
            "/api/trader/releases/download-token",
            {
                "email": "unknown@example.com",
                "machine_fingerprint": "unknown-machine",
                "release_id": release["id"],
            },
            {},
        )

        self.assertTrue(status.startswith("400"), body)
        self.assertEqual("unknown_customer", json.loads(body)["status"])

    def call(self, method: str, path: str, payload: dict, headers: dict[str, str]) -> tuple[str, list[tuple[str, str]], str]:
        body = json.dumps(payload).encode("utf-8")
        return self.call_raw(method, path, body, {"Content-Type": "application/json", **headers})

    def call_raw(self, method: str, path: str, body: bytes, headers: dict[str, str]) -> tuple[str, list[tuple[str, str]], str]:
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
            "REMOTE_ADDR": "127.0.0.1",
        }
        for key, value in headers.items():
            if key.lower() == "content-type":
                environ["CONTENT_TYPE"] = value
            else:
                environ["HTTP_" + key.upper().replace("-", "_")] = value
        captured: dict[str, object] = {}

        def start_response(status: str, response_headers: list[tuple[str, str]]) -> None:
            captured["status"] = status
            captured["headers"] = response_headers

        chunks = self.app(environ, start_response)
        return captured["status"], captured["headers"], b"".join(chunks).decode("utf-8")  # type: ignore[index,return-value]


if __name__ == "__main__":
    unittest.main()
