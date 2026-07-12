from __future__ import annotations

import json
import time
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from autoedge_licensing.signing import (
    LICENSE_PAYLOAD_KIND,
    LICENSE_TOKEN_TYPE,
    CompactES256Signer,
    SigningError,
    base64url_decode,
    base64url_encode,
    canonical_json,
    verify_compact_token,
)


class CompactES256Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.signer = CompactES256Signer(self.private_key, "license-test-1")
        self.keys = {"license-test-1": self.private_key.public_key()}
        now = int(time.time())
        self.payload = {
            "v": 1,
            "kind": LICENSE_PAYLOAD_KIND,
            "iss": "solidparts.se",
            "aud": "traderpro",
            "sub": "customer-test",
            "device_id": "device-test",
            "device_fingerprint_sha256": "a" * 64,
            "features": [{"id": "strategy.duo.runtime", "exp": None}],
            "iat": now,
            "nbf": now,
            "exp": now + 600,
            "jti": "random-test-id",
        }

    def verify(self, token: str, **overrides):
        options = {
            "expected_type": LICENSE_TOKEN_TYPE,
            "expected_kind": LICENSE_PAYLOAD_KIND,
            "validate_lease_times": True,
            "expected_issuer": "solidparts.se",
            "expected_audience": "traderpro",
        }
        options.update(overrides)
        return verify_compact_token(token, self.keys, **options)

    def test_es256_round_trip_uses_unpadded_64_byte_signature(self) -> None:
        token = self.signer.sign(self.payload, token_type=LICENSE_TOKEN_TYPE)
        verified = self.verify(token)
        signature_segment = token.split(".")[2]

        self.assertEqual(self.payload, verified.payload)
        self.assertNotIn("=", token)
        self.assertEqual(86, len(signature_segment))

    def test_tampered_header_payload_and_signature_are_rejected(self) -> None:
        token = self.signer.sign(self.payload, token_type=LICENSE_TOKEN_TYPE)
        header, payload, signature = token.split(".")
        tampered_header = base64url_encode(
            canonical_json({"alg": "ES256", "kid": "license-test-1", "typ": "autoedge-license+jwt"})
        )
        tampered_payload_value = dict(self.payload)
        tampered_payload_value["sub"] = "other-customer"
        tampered_payload = base64url_encode(canonical_json(tampered_payload_value))
        tampered_signature = signature[:-1] + ("A" if signature[-1] != "A" else "B")

        for candidate in (
            f"{tampered_header}.{payload}.{signature}",
            f"{header}.{tampered_payload}.{signature}",
            f"{header}.{payload}.{tampered_signature}",
        ):
            with self.subTest(candidate=candidate[-12:]), self.assertRaises(SigningError):
                self.verify(candidate)

    def test_unknown_key_wrong_algorithm_type_and_kind_are_rejected(self) -> None:
        unknown = CompactES256Signer(self.private_key, "unknown-key").sign(self.payload, token_type=LICENSE_TOKEN_TYPE)
        wrong_algorithm_header = base64url_encode(
            canonical_json({"alg": "HS256", "kid": "license-test-1", "typ": LICENSE_TOKEN_TYPE})
        )
        valid = self.signer.sign(self.payload, token_type=LICENSE_TOKEN_TYPE)
        _, payload_segment, signature_segment = valid.split(".")
        wrong_algorithm = f"{wrong_algorithm_header}.{payload_segment}.{signature_segment}"
        wrong_type = self.signer.sign(self.payload, token_type="wrong-type")
        wrong_kind_payload = dict(self.payload)
        wrong_kind_payload["kind"] = "autoedge.release"
        wrong_kind = self.signer.sign(wrong_kind_payload, token_type=LICENSE_TOKEN_TYPE)

        for candidate in (unknown, wrong_algorithm, wrong_type, wrong_kind):
            with self.subTest(candidate=candidate[:16]), self.assertRaises(SigningError):
                self.verify(candidate)

    def test_malformed_base64url_and_non_64_byte_signature_are_rejected(self) -> None:
        token = self.signer.sign(self.payload, token_type=LICENSE_TOKEN_TYPE)
        header, payload, _ = token.split(".")
        malformed = f"{header}.{payload}.not+padded="
        short_signature = f"{header}.{payload}.{base64url_encode(b'short')}"

        for candidate in (malformed, short_signature):
            with self.assertRaises(SigningError):
                self.verify(candidate)
        with self.assertRaises(SigningError):
            base64url_decode("AB")  # Decodes like canonical "AA" unless unused tail bits are checked.

    def test_expired_and_not_yet_valid_leases_are_rejected(self) -> None:
        now = int(time.time())
        expired = dict(self.payload, iat=now - 20, nbf=now - 20, exp=now - 1)
        future = dict(self.payload, iat=now + 10, nbf=now + 10, exp=now + 100)

        for payload in (expired, future):
            with self.assertRaises(SigningError):
                self.verify(self.signer.sign(payload, token_type=LICENSE_TOKEN_TYPE), now_seconds=now)


if __name__ == "__main__":
    unittest.main()
