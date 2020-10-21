import unittest

from shiro.exceptions import InvalidKey, UnsupportedAlgorithm, UnsupportedParsingMethod
from shiro.jwk import JsonWebKey

from tests.utils import load_json, load_pem


class TestJsonWebKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ec_private_json, cls.ec_public_json = load_json("ec")
        cls.oct_secret_json = load_json("oct")
        cls.rsa_private_json, cls.rsa_public_json = load_json("rsa")

        cls.ec_private_pem, cls.ec_public_pem = load_pem("ec")
        cls.oct_secret_pem = load_pem("oct")
        cls.rsa_private_pem, cls.rsa_public_pem = load_pem("rsa")

    def test_dump(self):
        data = dict(**self.ec_public_json, use="sig", kid="some_id")
        key = JsonWebKey(data)

        self.assertDictEqual(key, data)

    def test_generate(self):
        key = JsonWebKey.generate("RSA", 2048, use="sig", kid="key_id")

        self.assertEqual(key.get("kty"), "RSA")
        self.assertEqual(key.get("use"), "sig")
        self.assertEqual(key.get("kid"), "key_id")

    def test_instantiate(self):
        key = JsonWebKey(self.oct_secret_json)

        self.assertDictEqual(key.algorithm.dump(), self.oct_secret_json)
        self.assertRaises(InvalidKey, JsonWebKey, {"kty": ""})
        self.assertRaises(UnsupportedAlgorithm, JsonWebKey, {"kty": "tutstuts"})

    def test_parse(self):
        private_key = JsonWebKey.parse(self.ec_private_pem, "EC", False, use="sig")
        public_key = JsonWebKey.parse(
            self.ec_public_pem, "EC", True, use="sig", kid="key_id"
        )

        self.assertDictEqual(private_key, dict(**self.ec_private_json, use="sig"))

        self.assertDictEqual(
            public_key, dict(**self.ec_public_json, use="sig", kid="key_id")
        )

        self.assertRaises(
            UnsupportedAlgorithm,
            JsonWebKey.parse,
            self.rsa_private_pem,
            "tutstuts",
            False,
        )

        self.assertRaises(
            UnsupportedParsingMethod,
            JsonWebKey.parse,
            self.rsa_public_pem,
            "RSA",
            True,
            format="BaP(QUiEi'X",
        )

        self.assertRaises(InvalidKey, JsonWebKey.parse, self.ec_public_pem, "RSA", True)
