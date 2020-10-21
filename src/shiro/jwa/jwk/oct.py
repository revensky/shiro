from __future__ import annotations

import base64
import secrets
import warnings
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature as BaseInvalidSignature
from cryptography.hazmat.primitives import hmac
from fulldict import FullDict
from webtools import base64url_decode, base64url_encode, to_bytes, to_string

from shiro.exceptions import InvalidKey, InvalidSignature, UnsupportedParsingMethod
from shiro.jwa.jwk.base import JWKAlgorithm


@dataclass
class OCTKey(JWKAlgorithm):
    """
    Implementation of a symmetric key.

    The same key is used in all operations. This key **SHOULD NOT** be used
    in a public JWKSet, since this **COULD** leaboold to security issues.

    :param kty: Key type. MUST be "oct".
    :type kty: str

    :param k: Secret key. MUST be a urlsafe base64 string.
    :type k: str
    """

    __allowed_attributes__ = frozenset(("kty", "k"))

    k: str

    def __post_init__(self):
        if self.kty != "oct":
            raise InvalidKey(f'Invalid type "{self.kty}". Expected "oct".')

        if len(raw := base64url_decode(to_bytes(self.k))) < 32:
            raise InvalidKey("Secret is too short. MUST be AT LEAST 32 bytes.")

        self._secret = raw

    @classmethod
    def generate(cls, size: int = 32) -> OCTKey:
        """
        Generates a secure random bytes sequence based on the provided size.

        :param size: Size of the secret in bytes, defaults to 32.
        :type size: int, optional

        :raises InvalidKey: Invalid parameters for the key.

        :return: Instance of an OCTKey.
        :rtype: OCTKey
        """

        if size < 32:
            raise InvalidKey("Size is too short. MUST be AT LEAST 32 bytes.")

        secret = base64url_encode(secrets.token_bytes(size))

        return cls(kty="oct", k=to_string(secret))

    def dump(self, public: bool = True) -> dict:
        """
        Returns a JSON-ready dictionary representation of the key.

        :param public: Dumps the public info of the key, defaults to True.
        :type public: bool, optional

        :return: Key in dict format.
        :rtype: dict
        """

        if public:
            warnings.warn("Secret keys fo not have public info.", RuntimeWarning)

        return FullDict({"kty": self.kty, "k": self.k})

    @classmethod
    def parse(cls, raw: bytes, password: bytes = None, format: str = "pem") -> OCTKey:
        """
        Parses a raw secret into an OCTKey.

        :param raw: Raw representation of the data.
        :type raw: bytes

        :param password: Password used to decrypt the raw key, defaults to None.
        :type password: bytes, optional

        :param format: The format of the raw key, defaults to pem.
            If `pem`, assumes it is Base64 Encoded.
            If `der`, assumes it is a regular sequence of bytes.
        :type format: str, optional

        :raises UnsupportedParsingMethod: Method not supported.
        :raises InvalidKey: The raw key type is different from the class.

        :return: Parsed key as OCTKey.
        :rtype: OCTKey
        """

        if format not in ("pem", "der"):
            raise UnsupportedParsingMethod

        if format == "pem":
            invalid_strings = [
                b"-----BEGIN CERTIFICATE-----",
                b"-----BEGIN PRIVATE KEY-----",
                b"-----BEGIN RSA PRIVATE KEY-----",
                b"-----BEGIN EC PRIVATE KEY-----",
                b"-----BEGIN PUBLIC KEY-----",
                b"-----BEGIN RSA PUBLIC KEY-----",
                b"-----BEGIN EC PUBLIC KEY-----",
                b"ssh-rsa",
            ]

            if any(string in raw for string in invalid_strings):
                raise InvalidKey(
                    "The raw key is an asymmetric key or X.509 Certificate "
                    "and CANNOT be used as a symmetric key."
                )

            data = to_string(base64url_encode(base64.b64decode(raw)))

        if format == "der":
            data = to_string(base64url_encode(raw))

        return cls(kty="oct", k=data)

    def export(self, public: bool = False) -> bytes:
        """
        Exports the key in Base64 format.

        :param public: Exports the public info, defaults to False.
        :type public: bool, optional

        :return: Base64 encoded key data.
        :rtype: bytes
        """

        if public:
            warnings.warn("Secret keys do not have public info.", RuntimeWarning)

        return base64.b64encode(base64url_decode(to_bytes(self.k)))

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

        hashfn = self._hashes.get(hash_method)
        signature = hmac.HMAC(self._secret, hashfn, default_backend())
        signature.update(data)
        return signature.finalize()

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
            hashfn = self._hashes.get(hash_method)
            message = hmac.HMAC(self._secret, hashfn, default_backend())
            message.update(data)
            message.verify(signature)
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
