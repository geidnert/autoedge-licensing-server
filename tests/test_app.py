from __future__ import annotations

import io
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from autoedge_licensing.app import (
    Request,
    admin_time_input_to_utc,
    create_app,
    customer_detail_page,
    format_admin_time,
    packages_page,
    redact_http_request_line,
    products_page,
    releases_page,
)
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
            license_lease_secret="y" * 40,
            tradovate_oauth_client_id="tradovate-client",
            tradovate_oauth_client_secret="tradovate-secret",
            tradovate_oauth_redirect_uri="https://licenses.example.test/api/trader/tradovate/oauth/callback",
            tradovate_oauth_authorize_url="https://trader.example.test/oauth",
            tradovate_oauth_token_url="https://tradovate.example.test/auth/oauthtoken",
            tradovate_oauth_demo_authorize_url="https://trader-demo.example.test/oauth",
            tradovate_oauth_demo_token_url="https://tradovate-demo.example.test/auth/oauthtoken",
            tradovate_oauth_scopes="trading",
            tradovate_oauth_state_seconds=600,
            tradovate_live_api_base_url="https://live-api.example.test/v1",
            tradovate_demo_api_base_url="https://demo-api.example.test/v1",
            tradovate_oauth_token_secret="z" * 40,
        )
        self.app = create_app(settings)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_admin_times_render_and_parse_as_eastern_time(self) -> None:
        self.assertEqual("2026-06-06 22:30:00 ET", format_admin_time("2026-06-07T02:30:00Z"))
        self.assertEqual("2026-06-07T02:30:00Z", admin_time_input_to_utc("2026-06-06T22:30:00"))

    def test_admin_page_includes_live_eastern_clock(self) -> None:
        html = self.app.page("Admin", "<p>Body</p>", {"username": "admin"})

        self.assertIn("data-admin-clock", html)
        self.assertIn("Current Eastern time", html)
        self.assertIn("America/New_York", html)
        self.assertIn("admin-user", html)

    def test_public_privacy_and_terms_pages(self) -> None:
        privacy_status, privacy_headers, privacy_body = self.call_raw("GET", "/privacy", b"", {})
        terms_status, terms_headers, terms_body = self.call_raw("GET", "/terms", b"", {})

        self.assertTrue(privacy_status.startswith("200"), privacy_body)
        self.assertTrue(terms_status.startswith("200"), terms_body)
        self.assertIn(("Content-Type", "text/html; charset=utf-8"), privacy_headers)
        self.assertIn("AutoEdge TraderPro Privacy Policy", privacy_body)
        self.assertIn("AutoEdge TraderPro Terms &amp; Conditions", terms_body)
        self.assertIn("Last updated: July 10, 2026", privacy_body)
        self.assertIn("Tradovate", privacy_body)
        self.assertIn("Trading Risk", terms_body)

    def test_access_log_request_line_redacts_oauth_query_secrets(self) -> None:
        redacted = redact_http_request_line(
            "GET /api/trader/tradovate/oauth/callback?code=oauth-code-001&state=oauth-state-001&ok=1 HTTP/1.1"
        )

        self.assertEqual(
            "GET /api/trader/tradovate/oauth/callback?code=REDACTED&state=REDACTED&ok=1 HTTP/1.1",
            redacted,
        )
        self.assertNotIn("oauth-code-001", redacted)
        self.assertNotIn("oauth-state-001", redacted)

    def test_admin_customer_create_allows_blank_whop_fields(self) -> None:
        first = self.admin_customer_create_response(
            {
                "email": "stevetorrence@icloud.com",
                "name": "Steve Torrence",
                "whop_user_id": "",
                "whop_member_id": "",
            }
        )
        second = self.admin_customer_create_response(
            {
                "email": "other-manual@example.com",
                "name": "Other Manual",
                "whop_user_id": "",
                "whop_member_id": "",
            }
        )

        self.assertEqual(303, first.status.value)
        self.assertEqual(303, second.status.value)
        self.assertTrue(first.headers[0][1].startswith("/admin/customers/"))
        self.assertTrue(second.headers[0][1].startswith("/admin/customers/"))

    def test_admin_manual_entitlement_can_be_lifetime(self) -> None:
        product = self.app.service.upsert_product(
            slug="lifetime-strategy",
            name="Lifetime Strategy",
            feature_id="strategy.lifetime.runtime",
        )
        created = self.app.service.create_or_update_customer(email="lifetime@example.com")

        response = self.admin_customer_entitlement_response(
            created.customer["id"],
            {
                "product_id": product["id"],
                "status": "active",
                "expires_mode": "lifetime",
                "expires_at": "2026-12-31T23:59",
                "reason": "manual lifetime grant",
            },
        )
        detail = self.app.service.customer_detail(created.customer["id"])

        self.assertEqual(303, response.status.value)
        self.assertEqual("active", detail["entitlements"][0]["status"])
        self.assertIsNone(detail["entitlements"][0]["expires_at"])

    def test_admin_manual_entitlement_can_change_from_lifetime_to_date(self) -> None:
        product = self.app.service.upsert_product(
            slug="lifetime-to-date-strategy",
            name="Lifetime To Date Strategy",
            feature_id="strategy.lifetime-to-date.runtime",
        )
        created = self.app.service.create_or_update_customer(email="lifetime-to-date@example.com")
        self.app.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=product["id"],
            status="active",
            expires_at=None,
            reason="initial lifetime grant",
            actor_id="admin",
            ip_address=None,
        )

        response = self.admin_customer_entitlement_response(
            created.customer["id"],
            {
                "product_id": product["id"],
                "status": "active",
                "expires_mode": "date",
                "expires_at": "2026-07-15T14:19:06",
                "reason": "dated grant",
            },
        )
        detail = self.app.service.customer_detail(created.customer["id"])

        self.assertEqual(303, response.status.value)
        self.assertEqual("2026-07-15T18:19:06Z", detail["entitlements"][0]["expires_at"])

    def test_admin_can_remove_entitlement_from_customer(self) -> None:
        product = self.app.service.upsert_product(
            slug="remove-strategy",
            name="Remove Strategy",
            feature_id="strategy.remove.runtime",
        )
        created = self.app.service.create_or_update_customer(email="remove@example.com")
        entitlement = self.app.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=product["id"],
            status="active",
            expires_at=None,
            reason="remove test",
            actor_id="admin",
            ip_address=None,
        )

        response = self.admin_customer_remove_entitlement_response(created.customer["id"], entitlement["id"])
        detail = self.app.service.customer_detail(created.customer["id"])

        self.assertEqual(303, response.status.value)
        self.assertEqual([], detail["entitlements"])

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

    def test_nt8_license_endpoint_returns_strategy_key_and_lease(self) -> None:
        product = self.app.service.upsert_product(
            slug="duo-runtime",
            name="DUO Runtime",
            feature_id="strategy.duo.runtime",
            nt8_strategy_key="DUO",
        )
        created = self.app.service.create_or_update_customer(email="nt8-http@example.com")
        self.app.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=product["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="nt8 http",
            actor_id="admin",
            ip_address=None,
        )

        status, _, body = self.call(
            "POST",
            "/api/nt8/license/check",
            {
                "license_key": created.license_key,
                "machine_fingerprint": "nt8-http-machine",
                "nt8_version": "8.1.5",
                "strategy": "DUO",
            },
            {},
        )
        payload = json.loads(body)

        self.assertTrue(status.startswith("200"), body)
        self.assertEqual("active", payload["status"])
        self.assertTrue(payload["licensed"])
        self.assertEqual(["DUO"], payload["strategy_keys"])
        self.assertIsNotNone(payload["lease"]["token"])

    def test_nt8_license_endpoint_errors_use_client_json_shape(self) -> None:
        get_status, _, get_body = self.call_raw("GET", "/api/nt8/license/check", b"", {})
        bad_status, _, bad_body = self.call_raw(
            "POST",
            "/api/nt8/license/check",
            b"not-json",
            {"Content-Type": "application/json"},
        )

        get_payload = json.loads(get_body)
        bad_payload = json.loads(bad_body)
        self.assertTrue(get_status.startswith("405"), get_body)
        self.assertEqual("invalid_request", get_payload["status"])
        self.assertFalse(get_payload["licensed"])
        self.assertEqual([], get_payload["strategy_keys"])
        self.assertEqual(300, get_payload["next_check_seconds"])
        self.assertTrue(bad_status.startswith("400"), bad_body)
        self.assertEqual("invalid_request", bad_payload["status"])
        self.assertFalse(bad_payload["licensed"])

    def test_admin_product_list_hides_internal_slug_and_feature_ids(self) -> None:
        html = products_page(
            [
                {
                    "id": "product-001",
                    "name": "DUO Runtime",
                    "slug": "duo-runtime",
                    "feature_id": "strategy.duo.runtime",
                    "whop_product_id": "",
                    "nt8_strategy_key": "DUO",
                    "trader_enabled": 1,
                    "nt8_enabled": 1,
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
        self.assertIn("NT8 key", html)
        self.assertIn("TraderPro", html)
        self.assertIn("DUO", html)
        self.assertIn("2026-06-03 20:00:00 ET", html)

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
        self.assertIn("TraderPro strategy access", html)
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
                        "id": "entitlement-current",
                        "product_name": "DUO Runtime",
                        "feature_id": "strategy.duo.runtime",
                        "status": "active",
                        "source": "manual",
                        "expires_at": None,
                        "manual_reason": None,
                        "updated_at": "2026-06-04T00:00:00Z",
                    }
                ],
                "effective_entitlements": [
                    {
                        "id": "entitlement-current",
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
        self.assertIn('name="expires_mode" type="radio" value="date" checked', html)
        self.assertIn('name="expires_mode" type="radio" value="lifetime"', html)
        self.assertIn('name="expires_at" type="datetime-local" step="1"', html)
        self.assertIn("<td>Lifetime</td>", html)
        self.assertIn("/admin/customers/customer-001/entitlements/entitlement-current/remove", html)
        self.assertIn(">Remove</button>", html)
        self.assertIn("Expiry ET", html)
        self.assertIn("Whop membership", html)
        self.assertIn("2026-06-03 20:00:00 ET", html)
        self.assertIn("/admin/customers/customer-001/license-key", html)
        self.assertIn("Reissue key", html)
        self.assertIn("Shows the new key once.", html)

    def test_customer_detail_shows_current_entitlements_before_history(self) -> None:
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
                "effective_entitlements": [
                    {
                        "product_name": "DUO Runtime",
                        "status": "active",
                        "source": "whop",
                        "whop_membership_id": "mem_current",
                        "expires_at": "2026-09-10T14:33:02Z",
                        "manual_reason": None,
                        "updated_at": "2026-06-12T16:59:34Z",
                    }
                ],
                "entitlements": [
                    {
                        "product_name": "DUO Runtime",
                        "status": "active",
                        "source": "whop",
                        "whop_membership_id": "mem_current",
                        "expires_at": "2026-09-10T14:33:02Z",
                        "manual_reason": None,
                        "updated_at": "2026-06-12T16:59:34Z",
                    },
                    {
                        "product_name": "DUO Runtime",
                        "status": "expired",
                        "source": "whop",
                        "whop_membership_id": "mem_old",
                        "expires_at": "2026-06-10T11:48:17Z",
                        "manual_reason": None,
                        "updated_at": "2026-06-10T11:48:17Z",
                    },
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
            [],
            "csrf-token",
            "",
        )
        current_section = html.split("Entitlement history", 1)[0]
        history_section = html.split("Entitlement history", 1)[1]

        self.assertIn("mem_current", current_section)
        self.assertNotIn("mem_old", current_section)
        self.assertIn("mem_old", history_section)
        self.assertIn("Raw Whop/manual rows", history_section)

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
                    "artifact_filename": "Trader-Desktop-0.1.1-windows-x64.zip",
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

        self.assertIn("TraderPro Desktop", html)
        self.assertIn("<td>TraderPro Desktop<small>trader_desktop · trader-desktop</small></td>", html)
        self.assertIn("Trader-Desktop-0.1.1-windows-x64.zip", html)
        self.assertIn("Extension package", html)
        self.assertIn("trader_desktop", html)
        self.assertIn("trader-desktop", html)
        self.assertIn("Licensed product", html)
        self.assertIn("Product/package id", html)
        self.assertIn("<th>Channel</th>", html)
        self.assertNotIn("Channel / Target", html)
        self.assertNotIn("Target Windows x64", html)
        self.assertNotIn("Target platform", html)
        self.assertIn("Published", html)
        self.assertIn("Signature key id", html)
        self.assertIn("Audience", html)
        self.assertIn("Allowed emails", html)
        self.assertIn("Rollback reason", html)
        self.assertIn("NT8 version", html)
        self.assertIn("TraderPro revision", html)
        self.assertIn("Created ET", html)
        self.assertIn("Updated ET", html)
        self.assertIn("2026-06-04 09:05:00 ET", html)
        self.assertIn("trader-desktop/TraderPro-Desktop-1.0.0-macos-arm64.dmg", html)
        self.assertIn('placeholder="TraderPro Desktop update"', html)

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
                "platform": "custom-os",
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
        self.assertIn('<option value="macos-arm64" selected>macos-arm64</option>', add_html)
        self.assertIn('<option value="windows-x64" >windows-x64</option>', add_html)
        self.assertIn('<option value="linux-x64" >linux-x64</option>', add_html)
        self.assertIn('<details class="release-editor" open>', edit_html)
        self.assertIn('<option value="custom-os" selected>custom-os</option>', edit_html)

    def test_linux_release_manifest_and_download_endpoint(self) -> None:
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
        self.app.service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=product["id"],
            channel="stable",
            platform="linux-x64",
            version="1.9.0",
            min_supported_version=None,
            is_required=False,
            is_active=False,
            artifact_path="duo-http.zip",
            artifact_filename=None,
            size_bytes=None,
            sha256_value=None,
            signature=None,
            release_notes=None,
            artifact_dir=str(artifact_dir),
            nt8_version="2.1.0.7",
            trader_revision=0,
        )
        release = self.app.service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=product["id"],
            channel="stable",
            platform="linux-x64",
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
            nt8_version="2.1.0.8",
            trader_revision=1,
        )

        status, _, manifest_body = self.call(
            "POST",
            "/api/trader/releases/manifest",
            {
                "license_key": created.license_key,
                "machine_fingerprint": "http-release-machine",
                "app_version": "1.0.0",
                "channel": "stable",
                "platform": "linux-x64",
                "installed_packages": [{"package_id": "duo-runtime", "version": "1.9.0"}],
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
                "platform": "linux-x64",
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
        self.assertEqual("linux-x64", manifest["releases"][0]["platform"])
        self.assertEqual("2.1.0.8", manifest["releases"][0]["nt8_version"])
        self.assertEqual(1, manifest["releases"][0]["trader_revision"])
        self.assertEqual("2.1.0.7", manifest["releases"][0]["installed_nt8_version"])
        self.assertEqual(0, manifest["releases"][0]["installed_trader_revision"])
        self.assertTrue(token_status.startswith("200"), token_body)
        self.assertEqual("2.1.0.8", token_payload["release"]["nt8_version"])
        self.assertEqual(1, token_payload["release"]["trader_revision"])
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

    def test_linux_tradovate_oauth_start_returns_authorization_url_without_secret(self) -> None:
        created = self.active_http_customer("tradovate-start@example.com")

        status, _, body = self.call(
            "POST",
            "/api/trader/tradovate/oauth/start",
            {
                "license_key": created.license_key,
                "machine_fingerprint": "tradovate-start-machine",
                "app_version": "1.2.3",
                "platform": "linux-x64",
                "channel": "stable",
                "environment": "demo",
            },
            {},
        )

        payload = json.loads(body)
        parsed = urlparse(payload["authorization_url"])
        query = parse_qs(parsed.query)
        self.assertTrue(status.startswith("200"), body)
        self.assertEqual("ok", payload["status"])
        self.assertEqual("https://trader-demo.example.test/oauth", f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
        self.assertEqual(["code"], query["response_type"])
        self.assertEqual(["tradovate-client"], query["client_id"])
        self.assertEqual(["https://licenses.example.test/api/trader/tradovate/oauth/callback"], query["redirect_uri"])
        self.assertEqual([payload["state"]], query["state"])
        self.assertEqual(["trading"], query["scope"])
        self.assertNotIn("tradovate-secret", payload["authorization_url"])
        with self.app.service.database.session() as connection:
            oauth_state = connection.execute(
                "SELECT platform, channel FROM tradovate_oauth_states ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        self.assertEqual("linux-x64", oauth_state["platform"])
        self.assertEqual("stable", oauth_state["channel"])
        with self.app.service.database.session() as connection:
            devices = connection.execute(
                "SELECT client_type FROM devices WHERE customer_id = ?",
                (created.customer["id"],),
            ).fetchall()
        self.assertEqual(["trader_desktop"], [device["client_type"] for device in devices])

    def test_tradovate_oauth_callback_complete_and_refresh(self) -> None:
        fake = FakeTradovateOAuth()
        self.app.tradovate_oauth = fake
        created = self.active_http_customer("tradovate-flow@example.com")

        start_status, _, start_body = self.call(
            "POST",
            "/api/trader/tradovate/oauth/start",
            {
                "license_key": created.license_key,
                "machine_fingerprint": "tradovate-flow-machine",
                "environment": "live",
            },
            {},
        )
        state = json.loads(start_body)["state"]
        callback_status, _, callback_body = self.call_raw(
            "GET",
            "/api/trader/tradovate/oauth/callback?" + urlencode({"state": state, "code": "oauth-code-001"}),
            b"",
            {},
        )
        complete_status, _, complete_body = self.call(
            "POST",
            "/api/trader/tradovate/oauth/complete",
            {
                "state": state,
                "license_key": created.license_key,
                "machine_fingerprint": "tradovate-flow-machine",
            },
            {},
        )
        complete_payload = json.loads(complete_body)
        self.assertTrue(start_status.startswith("200"), start_body)
        self.assertTrue(callback_status.startswith("200"), callback_body)
        self.assertIn("Tradovate Login Complete", callback_body)
        self.assertIn("You can return to TraderPro Desktop.", callback_body)
        self.assertTrue(complete_status.startswith("200"), complete_body)
        self.assertEqual("authorized", complete_payload["status"])
        self.assertEqual("tv-access-token", complete_payload["access_token"])
        self.assertTrue(complete_payload["oauth_session_id"])
        self.assertNotEqual(state, complete_payload["oauth_session_id"])
        self.assertEqual("12345", complete_payload["user_id"])
        self.assertEqual("https://live-api.example.test/v1", complete_payload["api_base_url"])

        refresh_status, _, refresh_body = self.call(
            "POST",
            "/api/trader/tradovate/oauth/refresh",
            {
                "oauth_session_id": complete_payload["oauth_session_id"],
                "license_key": created.license_key,
                "machine_fingerprint": "tradovate-flow-machine",
            },
            {},
        )
        refresh_payload = json.loads(refresh_body)
        self.assertTrue(refresh_status.startswith("200"), refresh_body)
        self.assertEqual("authorized", refresh_payload["status"])
        self.assertEqual("tv-renewed-token", refresh_payload["access_token"])
        self.assertEqual(complete_payload["oauth_session_id"], refresh_payload["oauth_session_id"])
        self.assertEqual("tv-access-token", fake.renewed_from)
        self.assertEqual("https://tradovate.example.test/auth/oauthtoken", fake.exchange_call["token_url"])
        self.assertEqual("tradovate-secret", fake.exchange_call["client_secret"])
        with self.app.database.session() as connection:
            row = connection.execute("SELECT * FROM tradovate_oauth_states").fetchone()
            self.assertIsNotNone(row)
            self.assertNotIn(state, row["state_hash"])
            self.assertNotIn(complete_payload["oauth_session_id"], row["oauth_session_hash"])
            self.assertNotIn(complete_payload["oauth_session_id"], row["oauth_session_encrypted"])
            self.assertNotIn("tv-access-token", row["access_token_encrypted"])
            self.assertNotIn("tv-renewed-token", row["access_token_encrypted"])

    def test_tradovate_oauth_complete_rejects_different_device(self) -> None:
        fake = FakeTradovateOAuth()
        self.app.tradovate_oauth = fake
        created = self.active_http_customer("tradovate-binding@example.com")
        self.app.service.set_customer_max_devices(
            customer_id=created.customer["id"],
            max_devices=2,
            actor_id="admin",
            ip_address=None,
        )
        _, _, start_body = self.call(
            "POST",
            "/api/trader/tradovate/oauth/start",
            {
                "license_key": created.license_key,
                "machine_fingerprint": "tradovate-bound-machine",
                "environment": "live",
            },
            {},
        )
        state = json.loads(start_body)["state"]
        self.call_raw(
            "GET",
            "/api/trader/tradovate/oauth/callback?" + urlencode({"state": state, "code": "oauth-code-002"}),
            b"",
            {},
        )

        _, _, complete_body = self.call(
            "POST",
            "/api/trader/tradovate/oauth/complete",
            {
                "state": state,
                "license_key": created.license_key,
                "machine_fingerprint": "different-machine",
            },
            {},
        )

        payload = json.loads(complete_body)
        self.assertEqual("failed", payload["status"])
        self.assertNotIn("access_token", payload)
        self.assertNotIn("oauth_session_id", payload)
        self.assertIn("does not match", payload["message"])

    def active_http_customer(self, email: str):
        product = self.app.service.upsert_product(
            slug=f"duo-{email}",
            name="DUO Runtime",
            feature_id=f"strategy.{email.replace('@', '-').replace('.', '-')}.runtime",
        )
        created = self.app.service.create_or_update_customer(email=email)
        self.app.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=product["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="tradovate oauth test",
            actor_id="admin",
            ip_address=None,
        )
        return created

    def call(self, method: str, path: str, payload: dict, headers: dict[str, str]) -> tuple[str, list[tuple[str, str]], str]:
        body = json.dumps(payload).encode("utf-8")
        return self.call_raw(method, path, body, {"Content-Type": "application/json", **headers})

    def admin_customer_create_response(self, fields: dict[str, str]):
        body = urlencode(fields).encode("utf-8")
        request = Request(
            {
                "REQUEST_METHOD": "POST",
                "PATH_INFO": "/admin/customers",
                "QUERY_STRING": "",
                "CONTENT_LENGTH": str(len(body)),
                "CONTENT_TYPE": "application/x-www-form-urlencoded",
                "wsgi.input": io.BytesIO(body),
                "REMOTE_ADDR": "127.0.0.1",
            }
        )
        return self.app.admin_customers(request, {"id": "admin-001", "username": "admin"})

    def admin_customer_entitlement_response(self, customer_id: str, fields: dict[str, str]):
        body = urlencode(fields).encode("utf-8")
        request = Request(
            {
                "REQUEST_METHOD": "POST",
                "PATH_INFO": f"/admin/customers/{customer_id}/entitlements",
                "QUERY_STRING": "",
                "CONTENT_LENGTH": str(len(body)),
                "CONTENT_TYPE": "application/x-www-form-urlencoded",
                "wsgi.input": io.BytesIO(body),
                "REMOTE_ADDR": "127.0.0.1",
            }
        )
        return self.app.admin_customer_detail(request, {"id": "admin-001", "username": "admin"})

    def admin_customer_remove_entitlement_response(self, customer_id: str, entitlement_id: str):
        body = urlencode({"csrf": "csrf-token"}).encode("utf-8")
        request = Request(
            {
                "REQUEST_METHOD": "POST",
                "PATH_INFO": f"/admin/customers/{customer_id}/entitlements/{entitlement_id}/remove",
                "QUERY_STRING": "",
                "CONTENT_LENGTH": str(len(body)),
                "CONTENT_TYPE": "application/x-www-form-urlencoded",
                "wsgi.input": io.BytesIO(body),
                "REMOTE_ADDR": "127.0.0.1",
            }
        )
        return self.app.admin_customer_detail(request, {"id": "admin-001", "username": "admin"})

    def call_raw(self, method: str, path: str, body: bytes, headers: dict[str, str]) -> tuple[str, list[tuple[str, str]], str]:
        path_info, _, query_string = path.partition("?")
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path_info,
            "QUERY_STRING": query_string,
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


class FakeTradovateOAuth:
    def __init__(self) -> None:
        self.exchange_call: dict[str, str] = {}
        self.renewed_from: str | None = None

    def exchange_code(self, **kwargs):
        self.exchange_call = kwargs
        self.assert_secret_not_returned = kwargs["client_secret"]
        return {
            "access_token": "tv-access-token",
            "token_type": "Bearer",
            "expires_in": 5400,
        }

    def me(self, **kwargs):
        return {
            "userId": 12345,
            "fullName": "Tradovate User",
            "email": "tradovate@example.com",
        }

    def renew_access_token(self, **kwargs):
        self.renewed_from = kwargs["access_token"]
        return {
            "accessToken": "tv-renewed-token",
            "expirationTime": iso(utc_now() + timedelta(minutes=90)),
            "userId": 12345,
        }


if __name__ == "__main__":
    unittest.main()
