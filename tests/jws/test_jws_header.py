import unittest

from shiro.exceptions import InvalidJWSHeader, UnsupportedAlgorithm
from shiro.jws import JsonWebSignatureHeader


class TestJsonWebSignatureHeader(unittest.TestCase):
    def test_instantiate(self):
        self.assertRaises(InvalidJWSHeader, JsonWebSignatureHeader, "")

    def test_validate_alg(self):
        self.assertRaises(InvalidJWSHeader, JsonWebSignatureHeader, {})
        self.assertRaises(
            UnsupportedAlgorithm,
            JsonWebSignatureHeader,
            {"alg": "whatkindofalgorithmisthisagain"},
        )

    def test_validate_crit(self):
        header = JsonWebSignatureHeader({"alg": "HS256", "typ": "JWT", "crit": ["typ"]})

        self.assertEqual(header.get("typ"), "JWT")
        self.assertEqual(header.get("crit"), ["typ"])

        self.assertRaises(
            InvalidJWSHeader, JsonWebSignatureHeader, {"alg": "HS256", "crit": []}
        )
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "crit": ["b64", 14, "typ"]},
        )
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "crit": ["b64", "", "typ"]},
        )
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "crit": ["b64"]},  # Missing parameter "b64".
        )

    def test_validate_cty(self):
        header = JsonWebSignatureHeader({"alg": "HS256", "cty": "at+json"})

        self.assertEqual(header.get("cty"), "at+json")
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "cty": ["foo", "bar"]},
        )

    def test_validate_kid(self):
        header = JsonWebSignatureHeader({"alg": "HS256", "kid": "key0"})

        self.assertEqual(header.get("kid"), "key0")
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "kid": 0x1237742},
        )

    def test_validate_typ(self):
        header = JsonWebSignatureHeader({"alg": "HS256", "typ": "JWT"})

        self.assertEqual(header.get("typ"), "JWT")
        self.assertRaises(
            InvalidJWSHeader,
            JsonWebSignatureHeader,
            {"alg": "HS256", "typ": False},
        )
