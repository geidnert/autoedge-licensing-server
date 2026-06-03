from __future__ import annotations

import base64
import hashlib
import hmac
import time
import unittest

from autoedge_licensing.security import verify_standard_webhook


class StandardWebhookTests(unittest.TestCase):
    def test_valid_signature_is_accepted(self) -> None:
        raw_body = b'{"type":"membership.created","data":{"status":"active"}}'
        secret = "test-secret"
        webhook_id = "evt_001"
        timestamp = int(time.time())
        signed_payload = f"{webhook_id}.{timestamp}.".encode("utf-8") + raw_body
        digest = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).digest()
        headers = {
            "webhook-id": webhook_id,
            "webhook-timestamp": str(timestamp),
            "webhook-signature": "v1," + base64.b64encode(digest).decode("utf-8"),
        }

        ok, reason = verify_standard_webhook(raw_body, headers, secret)

        self.assertTrue(ok, reason)

    def test_old_timestamp_is_rejected(self) -> None:
        raw_body = b"{}"
        headers = {
            "webhook-id": "evt_001",
            "webhook-timestamp": "100",
            "webhook-signature": "v1,not-real",
        }

        ok, reason = verify_standard_webhook(raw_body, headers, "test-secret", now_seconds=1_000)

        self.assertFalse(ok)
        self.assertIn("timestamp", reason)


if __name__ == "__main__":
    unittest.main()
