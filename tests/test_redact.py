import copy
import unittest

from harshield.redact import InvalidHAR, redact_har, sensitive_name


def sample():
    return {"log": {"version": "1.2", "entries": [{
        "request": {
            "url": "https://user:pw@example.test/login?access_token=abc&search=hello#private",
            "headers": [{"name": "Authorization", "value": "Bearer abc"},
                        {"name": "Accept", "value": "application/json"}],
            "cookies": [{"name": "sid", "value": "secret-cookie"}],
            "queryString": [{"name": "api_key", "value": "123"},
                            {"name": "page", "value": "1"}],
            "postData": {"mimeType": "application/json", "text": '{"password":"secret"}',
                         "params": [{"name": "name", "value": "private", "fileName": "secret.txt"}]},
        },
        "response": {
            "status": 302,
            "headers": [{"name": "Set-Cookie", "value": "sid=secret"}],
            "cookies": [{"name": "sid", "value": "value"}],
            "redirectURL": "https://example.test/?token=redirect",
            "content": {"mimeType": "text/plain", "encoding": "base64", "text": "c2VjcmV0"},
        },
        "_private": {"token": "secret"}, "comment": "private note",
    }]}}


class RedactionTests(unittest.TestCase):
    def test_secrets_are_redacted(self):
        original = sample()
        clean, count = redact_har(original)
        self.assertGreaterEqual(count, 12)
        entry = clean["log"]["entries"][0]
        req, res = entry["request"], entry["response"]
        self.assertIn("access_token=%5BREDACTED%5D", req["url"])
        self.assertIn("search=hello", req["url"])
        self.assertNotIn("user:pw", req["url"])
        self.assertNotIn("#private", req["url"])
        self.assertEqual(req["headers"][0]["value"], "[REDACTED]")
        self.assertEqual(req["headers"][1]["value"], "application/json")
        self.assertEqual(req["cookies"][0]["value"], "[REDACTED]")
        self.assertEqual(req["queryString"][0]["value"], "[REDACTED]")
        self.assertEqual(req["queryString"][1]["value"], "1")
        self.assertEqual(req["postData"]["text"], "[REDACTED]")
        self.assertEqual(req["postData"]["params"][0]["value"], "[REDACTED]")
        self.assertEqual(res["headers"][0]["value"], "[REDACTED]")
        self.assertEqual(res["content"]["text"], "[REDACTED]")
        self.assertNotIn("encoding", res["content"])
        self.assertNotIn("_private", entry)
        self.assertNotIn("comment", entry)

    def test_does_not_mutate_input(self):
        source = sample()
        before = copy.deepcopy(source)
        redact_har(source)
        self.assertEqual(source, before)

    def test_idempotent(self):
        clean, _ = redact_har(sample())
        again, count = redact_har(clean)
        self.assertEqual(count, 0)
        self.assertEqual(clean, again)

    def test_empty_document(self):
        clean, count = redact_har({"log": {"entries": []}})
        self.assertEqual(count, 0)
        self.assertEqual(clean, {"log": {"entries": []}})

    def test_sensitive_names(self):
        for name in ("apiKey", "X-API-Key", "access_token", "clientSecret", "password", "auth", "csrf_token"):
            self.assertTrue(sensitive_name(name), name)
        for name in ("page", "monkey", "Accept", "content-type"):
            self.assertFalse(sensitive_name(name), name)

    def test_bearer_in_custom_header(self):
        obj = sample()
        obj["log"]["entries"][0]["request"]["headers"] = [{"name": "X-Custom", "value": "Bearer abc"}]
        clean, _ = redact_har(obj)
        self.assertEqual(clean["log"]["entries"][0]["request"]["headers"][0]["value"], "[REDACTED]")

    def test_invalid_root(self):
        for value in ([], {}, {"log": []}, {"log": {}}, {"log": {"entries": {}}}):
            with self.subTest(value=value), self.assertRaises(InvalidHAR):
                redact_har(value)

    def test_invalid_items(self):
        for field in ("headers", "cookies", "queryString"):
            obj = sample()
            obj["log"]["entries"][0]["request"][field] = [{"value": "unlabeled"}]
            with self.subTest(field=field), self.assertRaises(InvalidHAR):
                redact_har(obj)

    def test_existing_redacted_body_drops_encoding(self):
        obj = sample()
        obj["log"]["entries"][0]["response"]["content"]["text"] = "[REDACTED]"
        clean, _ = redact_har(obj)
        self.assertNotIn("encoding", clean["log"]["entries"][0]["response"]["content"])

    def test_encoded_query_key(self):
        obj = sample()
        obj["log"]["entries"][0]["request"]["url"] = "https://example.test/?access%5Ftoken=secret"
        clean, _ = redact_har(obj)
        self.assertNotIn("secret", clean["log"]["entries"][0]["request"]["url"])

    def test_location_and_referer_headers(self):
        obj = sample()
        obj["log"]["entries"][0]["response"]["headers"] = [
            {"name": "Location", "value": "https://example.test/?token=secret&lang=en"},
            {"name": "Referer", "value": "https://example.test/?api_key=secret"},
        ]
        clean, _ = redact_har(obj)
        headers = clean["log"]["entries"][0]["response"]["headers"]
        self.assertNotIn("secret", str(headers))
        self.assertIn("lang=en", headers[0]["value"])

    def test_invalid_url(self):
        obj = sample()
        obj["log"]["entries"][0]["request"]["url"] = "http://[invalid/"
        with self.assertRaises(InvalidHAR):
            redact_har(obj)


if __name__ == "__main__":
    unittest.main()
