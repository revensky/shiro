from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature as BaseInvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fulldict import FullDict
from webtools import b64_to_int, int_to_b64, to_string

from shiro.exceptions import InvalidKey, InvalidSignature, UnsupportedParsingMethod
from shiro.jwa.jwk.base import JWKAlgorithm


@dataclass
class RSAKey(JWKAlgorithm):
    """
    Implementation of a RSA asymmetric key.

    The private key **MUST** be used to sign and decrypt information.
    The public key **MUST** be used to verify and encrypt information.

    The **RECOMMENDED** size of the key is 2048 bits.

    :param kty: Key type. MUST be "RSA".
    :type kty: str

    :param n: Modulus of the key.
    :type n: str

    :param e: Public exponent.
    :type e: str

    :param d: Private exponent. MANDATORY if it is a private key.
    :type d: str, optional

    :param p: First prime coefficient.
    :type p: str, optional

    :param q: Second prime coefficient.
    :type q: str, optional

    :param dp: First prime CRT exponent.
    :type dp: str, optional

    :param dq: Second prime CRT exponent.
    :type dq: str, optional

    :param qi: First CRT coefficient.
    :type qi: str, optional
    """

    __allowed_attributes__ = frozenset(
        ("kty", "n", "e", "d", "p", "q", "dp", "dq", "qi")
    )

    n: str
    e: str
    d: Optional[str] = None
    p: Optional[str] = None
    q: Optional[str] = None
    dp: Optional[str] = None
    dq: Optional[str] = None
    qi: Optional[str] = None

    def __post_init__(self):
        if self.kty != "RSA":
            raise InvalidKey(f'Invalid type "{self.kty}". Expected "RSA".')

        self._private = None
        self._public = None

        n = b64_to_int(self.n)
        e = b64_to_int(self.e)

        public = rsa.RSAPublicNumbers(e, n)
        self._public = public.public_key(default_backend())

        if self.d:
            d = b64_to_int(self.d)
            p = b64_to_int(self.p)
            q = b64_to_int(self.q)
            dp = b64_to_int(self.dp)
            dq = b64_to_int(self.dq)
            qi = b64_to_int(self.qi)

            if not p or not q:
                p, q = rsa.rsa_recover_prime_factors(n, e, d)

            if not dp:
                dp = rsa.rsa_crt_dmp1(d, p)

            if not dq:
                dq = rsa.rsa_crt_dmq1(d, q)

            if not qi:
                qi = rsa.rsa_crt_iqmp(p, q)

            private = rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, public)
            self._private = private.private_key(default_backend())

    @classmethod
    def generate(cls, size: int = 2048) -> RSAKey:
        """
        Generates a key on the fly based on the provided module size.

        :param size: Size of the modulus in bits, defaults to 2048.
        :type size: int, optional

        :raises InvalidKey: Invalid parameters for the key.

        :return: Generated key as RSAKey.
        :rtype: RSAKey
        """

        if size < 512:
            raise InvalidKey("Size is too short. Must be AT LEAST 512 bits.")

        key = rsa.generate_private_key(65537, size, default_backend())

        private = key.private_numbers()
        public = key.public_key().public_numbers()

        return cls(
            kty="RSA",
            n=to_string(int_to_b64(public.n)),
            e=to_string(int_to_b64(public.e)),
            d=to_string(int_to_b64(private.d)),
            p=to_string(int_to_b64(private.p)),
            q=to_string(int_to_b64(private.q)),
            dp=to_string(int_to_b64(private.dmp1)),
            dq=to_string(int_to_b64(private.dmq1)),
            qi=to_string(int_to_b64(private.iqmp)),
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
            return FullDict(kty=self.kty, n=self.n, e=self.e)

        return FullDict(
            kty=self.kty,
            n=self.n,
            e=self.e,
            d=self.d,
            p=self.p,
            q=self.q,
            dp=self.dp,
            dq=self.dq,
            qi=self.qi,
        )

    @classmethod
    def parse(cls, raw: bytes, password: bytes = None, format: str = "pem") -> RSAKey:
        """
        Parses a raw key into an RSAKey.

        :param raw: Raw representation of the data.
        :type raw: bytes

        :param password: Password used to decrypt the raw key, defaults to None.
        :type password: bytes, optional

        :param format: The format of the raw key, defaults to `pem`.
            If `pem`, assumes it is PEM Encoded.
            If `der`, assumes it is a regular sequence of bytes.
        :type format: str, optional

        :raises UnsupportedParsingMethod: Method not supported.
        :raises InvalidKey: The raw key type is different from the class.

        :return: Parsed key as RSAKey.
        :rtype: RSAKey
        """

        if format == "der":
            raise UnsupportedParsingMethod

        if format == "pem":
            if b"PRIVATE" in raw:
                key = serialization.load_pem_private_key(
                    raw,
                    password,
                    default_backend(),
                )

                if not isinstance(key, rsa.RSAPrivateKey):
                    raise InvalidKey("The raw key is not a RSA Private Key.")

                private = key.private_numbers()
                public = key.public_key().public_numbers()

                return cls(
                    kty="RSA",
                    n=to_string(int_to_b64(public.n)),
                    e=to_string(int_to_b64(public.e)),
                    d=to_string(int_to_b64(private.d)),
                    p=to_string(int_to_b64(private.p)),
                    q=to_string(int_to_b64(private.q)),
                    dp=to_string(int_to_b64(private.dmp1)),
                    dq=to_string(int_to_b64(private.dmq1)),
                    qi=to_string(int_to_b64(private.iqmp)),
                )

            if b"PUBLIC" in raw:
                key = serialization.load_pem_public_key(raw, default_backend())

                if not isinstance(key, rsa.RSAPublicKey):
                    raise InvalidKey("The raw key is not a RSA Public Key.")

                public = key.public_numbers()

                return cls(
                    kty="RSA",
                    n=to_string(int_to_b64(public.n)),
                    e=to_string(int_to_b64(public.e)),
                )

            raise InvalidKey("Unknown raw key format for RSA.")

        raise UnsupportedParsingMethod

    def export(self, public: bool = False) -> bytes:
        """
        Exports the key in PEM format.

        :param public: Defines which key will be exported, defaults to False.
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

    def sign(self, data: bytes, hash_method: str, padd: str) -> bytes:
        """
        Creates a digital signature of the provided data.

        :param data: Data to be signed.
        :type data: bytes

        :param hash_method: Hash method used to sign the data.
        :param hash_method: str

        :param padd: Padding used to sign the data.
        :type padd: str

        :return: Signature of the provided data.
        :rtype: bytes
        """

        if not self._private:
            raise InvalidKey("Cannot sign with a public key.")

        hashfn = self._hashes.get(hash_method)

        if padd == "PKCS1v15":
            return self._private.sign(data, padding.PKCS1v15(), hashfn)

        if padd == "PSS":
            return self._private.sign(
                data,
                padding.PSS(padding.MGF1(hashfn), padding.PSS.MAX_LENGTH),
                hashfn,
            )

        raise InvalidKey("Unsupported padding.")

    def verify(self, signature: bytes, data: bytes, hash_method: str, padd: str):
        """
        Verifies the provided digital signature against the provided data.

        :param signature: Digital signature to be verified.
        :type signature: bytes

        :param data: Data used to verify the signature.
        :type data: bytes

        :param hash_method: Hash used to verify the signature.
        :type hash_method: str

        :param padd: Padding used to sign the data.
        :type padd: str

        :raises InvalidSignature: The signature does not match the data.
        """

        try:
            if not self._public:
                raise InvalidKey("Cannot verify with a private key.")

            hashfn = self._hashes.get(hash_method)

            if padd == "PKCS1v15":
                return self._public.verify(signature, data, padding.PKCS1v15(), hashfn)

            if padd == "PSS":
                return self._public.verify(
                    signature,
                    data,
                    padding.PSS(padding.MGF1(hashfn), padding.PSS.MAX_LENGTH),
                    hashfn,
                )

            raise InvalidKey("Unsupported padding.")
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
