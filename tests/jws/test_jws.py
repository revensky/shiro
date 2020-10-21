import unittest

from shiro.exceptions import InvalidJWSHeader
from shiro.jwk import JsonWebKey
from shiro.jws import JsonWebSignature

from tests.utils import load_json


# TODO: Add test_deserialize()
class TestJsonWebSignature(unittest.TestCase):
    def test_instantiate(self):
        jws = JsonWebSignature(b"Super important message.", {"alg": "HS256"})

        self.assertEqual(jws.header.get("alg"), "HS256")
        self.assertRaises(InvalidJWSHeader, JsonWebSignature, b"Lorem ipsum...", {})

    def test_serialize(self):
        key = JsonWebKey(load_json("oct"))
        jws = JsonWebSignature(b"Super important message.", {"alg": "HS256"})
        token = (
            b"eyJhbGciOiAiSFMyNTYifQ."
            b"U3VwZXIgaW1wb3J0YW50IG1lc3NhZ2Uu."
            b"hcKC9ON7r55CL1bekT5KlYN37Dwx_3yGNlhexf89-1Y"
        )

        # TODO: Add tests that fail.
        self.assertEqual(jws.serialize(key), token)
