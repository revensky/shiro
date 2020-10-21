import unittest

from shiro.exceptions import InvalidKeySet
from shiro.jwk import JsonWebKey, JsonWebKeySet

from tests.utils import load_pem


class TestJsonWebKeySet(unittest.TestCase):
    def test_dump(self):
        k0 = JsonWebKey.parse(load_pem("rsa")[1], "RSA", True, use="sig", kid="key0")
        k1 = JsonWebKey.parse(load_pem("ec")[1], "EC", True, use="sig", kid="key1")

        jwks = JsonWebKeySet([k0, k1])

        self.assertDictEqual(jwks.dump(), {"keys": [k0, k1]})

    def test_get_key(self):
        k0 = JsonWebKey.parse(load_pem("ec")[0], "EC", False, use="sig", kid="key0")
        k1 = JsonWebKey.parse(load_pem("rsa")[0], "RSA", False, use="sig", kid="key1")

        jwks = JsonWebKeySet([k0, k1])

        self.assertEqual(jwks.get_key("key0"), k0)
        self.assertIsNone(jwks.get_key("idontknow"))

    def test_instantiate(self):
        k0 = JsonWebKey.parse(load_pem("ec")[1], "EC", True, use="sig", kid="key0")
        k1 = JsonWebKey.parse(load_pem("rsa")[1], "RSA", True, use="sig", kid="key1")
        k2 = JsonWebKey.generate("RSA", 2048)

        jwks0 = JsonWebKeySet([k0, k1])

        self.assertListEqual(jwks0.keys, [k0, k1])
        self.assertRaises(InvalidKeySet, JsonWebKeySet, [k0, k1, k2])

        k30 = JsonWebKey.generate("EC", "P-256", kid="key2")
        k31 = JsonWebKey.generate("RSA", 2048, kid="key2")

        self.assertRaises(InvalidKeySet, JsonWebKeySet, [k30, k31])
