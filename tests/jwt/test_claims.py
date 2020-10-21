import unittest
from datetime import datetime

from shiro.exceptions import ExpiredToken, InvalidJWTClaim, NotYetValidToken
from shiro.jwt import JsonWebTokenClaims


def now() -> int:
    return int(datetime.utcnow().timestamp())


def future() -> int:
    return now() + 3600


def past() -> int:
    return now() - 3600


class TestJWTClaims(unittest.TestCase):
    def test_instantiate(self):
        self.assertIsInstance(JsonWebTokenClaims({"sub": "someid"}), JsonWebTokenClaims)
        self.assertRaises(InvalidJWTClaim, JsonWebTokenClaims, "")

    def test_validate_aud(self):
        claims = JsonWebTokenClaims({"aud": "Valid Audience"})
        self.assertIsNone(claims.validate())

        claims = JsonWebTokenClaims({"aud": ["Valid Audience 1", "Valid Audience 2"]})
        self.assertIsNone(claims.validate())

        claims = JsonWebTokenClaims({"aud": 123})
        self.assertRaises(InvalidJWTClaim, claims.validate)

        claims = JsonWebTokenClaims({"aud": [1, 2, 3]})
        self.assertRaises(InvalidJWTClaim, claims.validate)

    def test_validate_exp(self):
        claims = JsonWebTokenClaims({"exp": future()})
        self.assertIsNone(claims.validate(now=now))

        claims = JsonWebTokenClaims({"exp": past()})
        self.assertRaises(ExpiredToken, claims.validate, now=now)

        claims = JsonWebTokenClaims({"exp": True})
        self.assertRaises(InvalidJWTClaim, claims.validate, now=now)

    def test_validate_iat(self):
        claims = JsonWebTokenClaims({"iat": past()})
        self.assertIsNone(claims.validate(now=now))

        claims = JsonWebTokenClaims({"iat": True})
        self.assertRaises(InvalidJWTClaim, claims.validate, now=now)

    def test_validate_iss(self):
        claims = JsonWebTokenClaims({"iss": "http://localhost:8000"})
        self.assertIsNone(claims.validate())

        claims = JsonWebTokenClaims({"iss": {}})
        self.assertRaises(InvalidJWTClaim, claims.validate)

    def test_validate_jti(self):
        claims = JsonWebTokenClaims({"jti": "T5CbNGVDcILMuqpb"})
        self.assertIsNone(claims.validate())

        claims = JsonWebTokenClaims({"jti": {}})
        self.assertRaises(InvalidJWTClaim, claims.validate)

    def test_validate_nbf(self):
        claims = JsonWebTokenClaims({"nbf": past()})
        self.assertIsNone(claims.validate(now=now))

        claims = JsonWebTokenClaims({"nbf": future()})
        self.assertRaises(NotYetValidToken, claims.validate, now=now)

        claims = JsonWebTokenClaims({"nbf": True})
        self.assertRaises(InvalidJWTClaim, claims.validate, now=now)

    def test_validate_sub(self):
        claims = JsonWebTokenClaims({"sub": "7zODKKvaU-PJETxIcm03gOk63S8rYCag"})
        self.assertIsNone(claims.validate())

        claims = JsonWebTokenClaims({"sub": object()})
        self.assertRaises(InvalidJWTClaim, claims.validate)
