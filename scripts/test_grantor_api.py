import json
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.request
import uuid

import grantor_api


class ClientSecurityTests(unittest.TestCase):
    def test_origin_and_transport_cannot_leak_token(self):
        for url in ("http://example.com", "https://u:p@example.com", "https://example.com/?token=x"):
            with self.subTest(url=url), self.assertRaises(grantor_api.APIError):
                grantor_api.Client(url, "unit-credential")
        client = grantor_api.Client("https://grantor.example", "unit-credential")
        for path in ("https://attacker.example/api/v1/connections", "//attacker.example/api/v1/me", "/api/v1/me?token=x"):
            with self.subTest(path=path), self.assertRaises(grantor_api.APIError):
                client.request("GET", path)
        self.assertIsNone(grantor_api.NoRedirect().redirect_request(None, None, 302, None, {}, "https://attacker.example"))

    def test_bearer_and_json_are_sent_without_cookie(self):
        client = grantor_api.Client("https://grantor.example", "unit-credential")
        response = Mock()
        response.read.return_value = b'{"operation_id":"op"}'
        client.opener = Mock()
        client.opener.open.return_value.__enter__ = Mock(return_value=response)
        client.opener.open.return_value.__exit__ = Mock(return_value=False)
        client.request("POST", "/api/v1/accounts", {"engine_identity": "login"})
        req = client.opener.open.call_args.args[0]
        self.assertEqual(req.get_header("Authorization"), "Bearer unit-credential")
        self.assertIsNone(req.get_header("Cookie"))
        self.assertEqual(json.loads(req.data), {"engine_identity": "login"})

    def test_failed_mutation_is_not_retried_or_echoed(self):
        client = grantor_api.Client("https://grantor.example", "unit-credential")
        client.opener = Mock()
        client.opener.open.side_effect = urllib.error.URLError("private transport details")
        with self.assertRaisesRegex(grantor_api.APIError, "outcome may be unknown") as caught:
            client.request("POST", "/api/v1/connection-registrations", {})
        self.assertNotIn("private transport details", str(caught.exception))
        self.assertEqual(client.opener.open.call_count, 1)

    def test_idempotent_favorite_put_supports_empty_response(self):
        client = grantor_api.Client("https://grantor.example", "unit-credential")
        response = Mock()
        response.read.return_value = b''
        client.opener = Mock()
        client.opener.open.return_value.__enter__ = Mock(return_value=response)
        client.opener.open.return_value.__exit__ = Mock(return_value=False)
        result = client.request("PUT", "/api/v1/me/favorite-connections/" + str(uuid.uuid4()))
        self.assertEqual(result, {})
        self.assertEqual(client.opener.open.call_args.args[0].method, "PUT")

    def test_redaction_preserves_identity_metadata_and_hides_one_time_secrets(self):
        value = {"api_key": {"id": "public-id", "role": "viewer"}, "token": "one-time",
                 "children": [{"password": "credential", "share_url": "https://one-time-link"}]}
        output = json.dumps(grantor_api.redact(value))
        self.assertIn("public-id", output)
        self.assertNotIn("one-time", output)
        self.assertNotIn("credential", output)

    def test_wait_requires_actual_success_and_never_retries_mutations(self):
        client = grantor_api.Client("https://grantor.example", "unit-credential")
        client.request = Mock(side_effect=[{"status": "running"}, {"status": "success"}])
        with patch("grantor_api.time.sleep"):
            result = client.wait(str(uuid.uuid4()), interval=0)
        self.assertEqual(result["status"], "success")
        self.assertTrue(all(call.args[0] == "GET" for call in client.request.call_args_list))
        client.request = Mock(return_value={"status": "partial"})
        with self.assertRaisesRegex(grantor_api.APIError, "partial"):
            client.wait(str(uuid.uuid4()))


if __name__ == "__main__":
    unittest.main()
