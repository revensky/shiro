import unittest

from shiro.exceptions import InvalidKey, InvalidSignature, UnsupportedParsingMethod
from shiro.jwa.jwk import ECKey, OCTKey, RSAKey

from tests.utils import load_json, load_pem


class TestECKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv_json, cls.pub_json = load_json("ec")
        cls.priv_pem, cls.pub_pem = load_pem("ec")

    def test_dump(self):
        private_key = ECKey(**self.priv_json)
        public_key = ECKey(**self.pub_json)

        self.assertDictEqual(
            dict(
                kty=private_key.kty,
                crv=private_key.crv,
                x=private_key.x,
                y=private_key.y,
                d=private_key.d,
            ),
            private_key.dump(public=False),
        )

        self.assertDictEqual(
            dict(
                kty=public_key.kty,
                crv=public_key.crv,
                x=public_key.x,
                y=public_key.y,
            ),
            public_key.dump(),
        )

    def test_export(self):
        private_key = ECKey(**self.priv_json)
        public_key = ECKey(**self.pub_json)

        self.assertEqual(private_key.export(), self.priv_pem)
        self.assertEqual(public_key.export(public=True), self.pub_pem)

    def test_generate(self):
        key = ECKey.generate("P-256")

        self.assertEqual(key.kty, "EC")
        self.assertIsInstance(key.x, str)

    def test_instantiate(self):
        private_key = ECKey(**self.priv_json)
        public_key = ECKey(**self.pub_json)

        self.assertDictEqual(
            dict(
                kty=private_key.kty,
                crv=private_key.crv,
                x=private_key.x,
                y=private_key.y,
                d=private_key.d,
            ),
            self.priv_json,
        )

        self.assertDictEqual(
            dict(
                kty=public_key.kty,
                crv=public_key.crv,
                x=public_key.x,
                y=public_key.y,
            ),
            self.pub_json,
        )

    def test_parse(self):
        private_key = ECKey.parse(self.priv_pem)
        public_key = ECKey.parse(self.pub_pem)

        self.assertDictEqual(private_key.dump(public=False), self.priv_json)
        self.assertDictEqual(public_key.dump(), self.pub_json)

        # Invalid format case.
        self.assertRaises(
            UnsupportedParsingMethod,
            ECKey.parse,
            self.pub_pem,
            format="BaP(QUiEi'X",
        )

        # Unmatching algorithm and raw key case.
        self.assertRaises(InvalidKey, ECKey.parse, load_pem("rsa")[0])

    def test_sign_and_verify(self):
        private_key = ECKey(**self.priv_json)
        public_key = ECKey(**self.pub_json)

        data = b"This is a super secret message."
        signature = private_key.sign(data, "SHA-256")

        self.assertIsInstance(signature, bytes)
        self.assertIsNone(public_key.verify(signature, data, "SHA-256"))
        self.assertRaises(
            InvalidSignature,
            public_key.verify,
            signature,
            b"",
            "SHA-256",
        )


class TestOCTKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.oct_json = load_json("oct")
        cls.oct_pem = load_pem("oct")

    def test_dump(self):
        key = OCTKey(**self.oct_json)

        self.assertDictEqual(dict(kty=key.kty, k=key.k), key.dump(public=False))

    def test_export(self):
        key = OCTKey(**self.oct_json)

        self.assertIsInstance(key.export(), bytes)

    def test_generate(self):
        key = OCTKey.generate()

        self.assertEqual(key.kty, "oct")
        self.assertIsInstance(key.k, str)

    def test_instantiate(self):
        key = OCTKey(**self.oct_json)

        self.assertDictEqual(dict(kty=key.kty, k=key.k), self.oct_json)

    def test_parse(self):
        key = OCTKey.parse(self.oct_pem)

        self.assertDictEqual(key.dump(), self.oct_json)

        # Invalid format case.
        self.assertRaises(
            UnsupportedParsingMethod,
            OCTKey.parse,
            self.oct_pem,
            format="BaP(QUiEi'X",
        )

        # Unmatching algorithm and raw key case.
        self.assertRaises(InvalidKey, OCTKey.parse, load_pem("rsa")[0])

    def test_sign_and_verify(self):
        key = OCTKey(**self.oct_json)

        data = b"This is a super secret message."
        signature = key.sign(data, "SHA-256")

        self.assertIsInstance(signature, bytes)
        self.assertIsNone(key.verify(signature, data, "SHA-256"))
        self.assertRaises(InvalidSignature, key.verify, signature, b"", "SHA-256")


class TestRSAKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv_json, cls.pub_json = load_json("rsa")
        cls.priv_pem, cls.pub_pem = load_pem("rsa")

    def test_dump(self):
        private_key = RSAKey(**self.priv_json)
        public_key = RSAKey(**self.pub_json)

        self.assertDictEqual(
            dict(
                kty=private_key.kty,
                n=private_key.n,
                e=private_key.e,
                d=private_key.d,
                p=private_key.p,
                q=private_key.q,
                dp=private_key.dp,
                dq=private_key.dq,
                qi=private_key.qi,
            ),
            private_key.dump(public=False),
        )

        self.assertDictEqual(
            dict(kty=public_key.kty, n=public_key.n, e=public_key.e),
            public_key.dump(),
        )

    def test_export(self):
        private_key = RSAKey(**self.priv_json)
        public_key = RSAKey(**self.pub_json)

        self.assertEqual(private_key.export(), self.priv_pem)
        self.assertEqual(public_key.export(public=True), self.pub_pem)

    def test_generate(self):
        key = RSAKey.generate()

        self.assertEqual(key.kty, "RSA")
        self.assertIsInstance(key.p, str)

    def test_instantiate(self):
        private_key = RSAKey(**self.priv_json)
        public_key = RSAKey(**self.pub_json)

        self.assertDictEqual(
            dict(
                kty=private_key.kty,
                n=private_key.n,
                e=private_key.e,
                d=private_key.d,
                p=private_key.p,
                q=private_key.q,
                dp=private_key.dp,
                dq=private_key.dq,
                qi=private_key.qi,
            ),
            self.priv_json,
        )

        self.assertDictEqual(
            dict(kty=public_key.kty, n=public_key.n, e=public_key.e),
            self.pub_json,
        )

    def test_parse(self):
        private_key = RSAKey.parse(self.priv_pem)
        public_key = RSAKey.parse(self.pub_pem)

        self.assertDictEqual(private_key.dump(public=False), self.priv_json)
        self.assertDictEqual(public_key.dump(), self.pub_json)

        # Invalid format case.
        self.assertRaises(
            UnsupportedParsingMethod,
            RSAKey.parse,
            self.pub_pem,
            format="BaP(QUiEi'X",
        )

        # Unmatching algorithm and raw key case.
        self.assertRaises(InvalidKey, RSAKey.parse, load_pem("ec")[0])

    def test_sign_and_verify(self):
        private_key = RSAKey(**self.priv_json)
        public_key = RSAKey(**self.pub_json)

        data = b"This is a super secret message."
        signature = private_key.sign(data, "SHA-256", "PKCS1v15")

        self.assertIsInstance(signature, bytes)
        self.assertIsNone(public_key.verify(signature, data, "SHA-256", "PKCS1v15"))
        self.assertRaises(
            InvalidSignature,
            public_key.verify,
            signature,
            b"",
            "SHA-256",
            "PKCS1v15",
        )
