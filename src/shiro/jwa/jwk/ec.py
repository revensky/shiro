from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature as BaseInvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fulldict import FullDict
from webtools import b64_to_int, int_to_b64, to_string

from shiro.exceptions import InvalidKey, InvalidSignature, UnsupportedParsingMethod
from shiro.jwa.jwk.base import JWKAlgorithm


@dataclass
class ECKey(JWKAlgorithm):
    """
    Implementation of the Elliptic Curve Key Algorithm.

    The standard curves are: "P-256", "P-384", "P-521".
    It is possible to add different curves, but they should be implemented
    by the application for a good support.

    :param kty: Key type. MUST be "EC".
    :type kty: str

    :param crv: Elliptic Curve.
    :type crv: str

    :param x: X coordinate of the curve.
    :type x: str

    :param y: Y coordinate of the curve.
    :type y: str

    :param d: Private value. MANDATORY if it is a private key.
    :type d: str, optional
    """

    __allowed_attributes__ = frozenset(("kty", "crv", "x", "y", "d"))

    _curves = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
    }

    _curves_names = {
        ec.SECP256R1.name: "P-256",
        ec.SECP384R1.name: "P-384",
        ec.SECP521R1.name: "P-521",
    }

    crv: str
    x: str
    y: str
    d: Optional[str] = None

    def __post_init__(self):
        if self.kty != "EC":
            raise InvalidKey(f'Invalid type "{self.kty}". Expected "EC".')

        if self.crv not in self._curves.keys():
            raise InvalidKey(f'Unknown curve "{self.crv}".')

        self._private = None
        self._public = None

        crv = self._curves.get(self.crv)
        x = b64_to_int(self.x)
        y = b64_to_int(self.y)
        d = b64_to_int(self.d)

        public = ec.EllipticCurvePublicNumbers(x, y, crv)
        self._public = public.public_key(default_backend())

        if d:
            private = ec.EllipticCurvePrivateNumbers(d, public)
            self._private = private.private_key(default_backend())

    @classmethod
    def generate(cls, curve: str) -> ECKey:
        """
        Generates a key on the fly based on the provided curve name.

        :param curve: Curve used to generate the key.
        :type curve: str

        :raises InvalidKey: Invalid parameters for the key.

        :return: Generated key as ECKey.
        :rtype: ECKey
        """

        if not (crv := cls._curves.get(curve)):
            raise InvalidKey(f'Unknown curve "{curve}".')

        key = ec.generate_private_key(crv, default_backend())

        private = key.private_numbers()
        public = key.public_key().public_numbers()

        return cls(
            kty="EC",
            crv=curve,
            x=to_string(int_to_b64(public.x)),
            y=to_string(int_to_b64(public.y)),
            d=to_string(int_to_b64(private.private_value)),
        )

    def dump(self, public: bool = True) -> dict:
        """
        Returns a JSON-ready dictionary representation of the key.

        :param public: Dumps the public info of the key, defaults to True.
        :type public: bool, optional

        :return: Key in dict format.
        :rtype: dict
        """

        if public:
            return FullDict(kty=self.kty, crv=self.crv, x=self.x, y=self.y)

        return FullDict(kty=self.kty, crv=self.crv, x=self.x, y=self.y, d=self.d)

    @classmethod
    def parse(cls, raw: bytes, password: bytes = None, format: str = "pem") -> ECKey:
        """
        Parses a raw key into an ECKey.

        :param raw: Raw representation of the data.
        :type raw: bytes

        :param password: Password used to decrypt the raw key, defaults to None.
        :type password: bytes, optional

        :param format: The format of the raw key, defaults to pem.
            If `pem`, assumes it is PEM Encoded.
            If `der`, assumes it is a regular sequence of bytes.
        :type format: str, optional

        :raises UnsupportedParsingMethod: Method not supported.
        :raises InvalidKey: The raw key type is different from the class.

        :return: Parsed key as ECKey.
        :rtype: ECKey
        """

        if format == "der":
            raise UnsupportedParsingMethod

        if format == "pem":
            if b"PRIVATE" in raw:
                key = serialization.load_pem_private_key(
                    raw, password, default_backend()
                )

                if not isinstance(key, ec.EllipticCurvePrivateKey):
                    raise InvalidKey(
                        "The raw key is not an Elliptic Curve Private Key."
                    )

                private = key.private_numbers()
                public = key.public_key().public_numbers()

                return cls(
                    kty="EC",
                    crv=cls._curves_names.get(public.curve.name),
                    x=to_string(int_to_b64(public.x)),
                    y=to_string(int_to_b64(public.y)),
                    d=to_string(int_to_b64(private.private_value)),
                )

            if b"PUBLIC" in raw:
                key = serialization.load_pem_public_key(raw, default_backend())

                if not isinstance(key, ec.EllipticCurvePublicKey):
                    raise InvalidKey("The raw key is not an Elliptic Curve Public Key.")

                public = key.public_numbers()

                return cls(
                    kty="EC",
                    crv=cls._curves_names.get(public.curve.name),
                    x=to_string(int_to_b64(public.x)),
                    y=to_string(int_to_b64(public.y)),
                )

            raise InvalidKey("Unknown raw key format for Elliptic Curve.")

        raise UnsupportedParsingMethod

    def export(self, public: bool = False) -> bytes:
        """
        Exports the key in PEM format.

        :param public: Exports the public key, defaults to False.
        :type public: bool, optional

        :return: PEM encoded key data.
        :rtype: bytes
        """

        if not public:
            if self._private:
                return self._private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )

            raise InvalidKey("No private key found.")

        return self._public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, data: bytes, hash_method: str) -> bytes:
        """
        Creates a digital signature of the provided data.

        :param data: Data to be signed.
        :type data: bytes

        :param hash_method: Hash method used to sign the data.
        :param hash_method: str

        :return: Signature of the provided data.
        :rtype: bytes
        """

        if not self._private:
            raise InvalidKey("Cannot sign with a public key.")

        hashfn = self._hashes.get(hash_method)

        return self._private.sign(data, ec.ECDSA(hashfn))

    def verify(self, signature: bytes, data: bytes, hash_method: str):
        """
        Verifies the provided digital signature against the provided data.

        :param signature: Digital signature to be verified.
        :type signature: bytes

        :param data: Data used to verify the signature.
        :type data: bytes

        :param hash_method: Hash used to verify the signature.
        :type hash_method: str

        :raises InvalidSignature: The signature does not match the data.
        """

        try:
            if not self._public:
                raise InvalidKey("Cannot verify with a private key.")

            hashfn = self._hashes.get(hash_method)

            self._public.verify(signature, data, ec.ECDSA(hashfn))
        except BaseInvalidSignature:
            raise InvalidSignature

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts the provided plaintext.

        :param plaintext: Plaintext to be encrypted.
        :type plaintext: bytes

        :return: Encrypted plaintext.
        :rtype: bytes
        """

        raise NotImplementedError

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypts the provided ciphertext.

        :param ciphertext: Ciphertext to be decrypted.
        :type ciphertext: bytes

        :return: Decrypted data.
        :rtype: bytes
        """

        raise NotImplementedError
