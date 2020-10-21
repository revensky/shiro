from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes


@dataclass
class JWKAlgorithm(abc.ABC):
    """
    Implementation of the Section 6 of RFC 7518.

    This class provides the expected method signatures
    that will be used throughout the package.

    All JWK Algorithms **MUST** inherit from this class and
    implement its methods.

    All parameters passed in the constructor that denote the key's data
    **MUST** be passed **STRICTLY** as urlsafe base64 encoded strings.

    :cvar ``__allowed_attributes__``: Denotes the attributes that compose the JWK.
        Attributes not in this collection are ignored. Used when parsing a JWK.
    """

    __allowed_attributes__ = None

    _hashes = {
        "SHA-256": hashes.SHA256(),
        "SHA-384": hashes.SHA384(),
        "SHA-512": hashes.SHA512(),
    }

    kty: str

    @classmethod
    def load(cls, key: dict) -> JWKAlgorithm:
        """
        Loads the data from a JWK object.

        Use this method instead of instantiating the class directly
        if you are loading data from a full JWK, since the constructor
        only accepts the algorithm's parameters.

        :param key: JWK with possibly more parameters
            than the ones allowed by the algorithm.
        :type key: dict

        :raises InvalidKey: Invalid parameters for the key.

        :return: Instance of a JWKAlgorithm.
        :rtype: JWKAlgorithm
        """

        data = {k: v for k, v in key.items() if k in cls.__allowed_attributes__}
        return cls(**data)

    @classmethod
    @abc.abstractmethod
    def generate(cls, **kwargs) -> JWKAlgorithm:
        """
        Generates a key on the fly based on the provided arguments.

        :return: Generated key as JWKAlgorithm.
        :rtype: JWKAlgorithm
        """

    @abc.abstractmethod
    def dump(self, public: bool = True) -> dict:
        """
        Returns a JSON-ready dictionary representation of the key.

        :param public: Dumps the public info of the key, defaults to True.
        :type public: bool, optional

        :return: Key in dict format.
        :rtype: dict
        """

    @classmethod
    @abc.abstractmethod
    def parse(
        cls,
        raw: bytes,
        password: bytes = None,
        format: str = "pem",
    ) -> JWKAlgorithm:
        """
        Parses a raw key into a JWKAlgorithm.

        A raw symmetric key is simply its bytes string.
        A raw asymmetric key would be a PEM encoded key data.

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

        :return: Parsed key as a JWKAlgorithm.
        :rtype: JWKAlgorithm
        """

    @abc.abstractmethod
    def export(self, public: bool = False) -> bytes:
        """
        Exports the key in PEM format if asymmetric, or Base64 if symmetric.

        :param public: Exports the public key, defaults to False.
        :type public: bool, optional

        :return: Base64/PEM encoded key data.
        :rtype: bytes
        """

    @abc.abstractmethod
    def sign(self, data: bytes, hash_method: str, **kwargs: Any) -> bytes:
        """
        Creates a digital signature of the provided data.

        :param data: Data to be signed.
        :type data: bytes

        :param hash_method: Hash method used to sign the data.
        :param hash_method: str

        :return: Signature of the provided data.
        :rtype: bytes
        """

    @abc.abstractmethod
    def verify(self, signature: bytes, data: bytes, hash_method: str, **kwargs: Any):
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

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts the provided plaintext.

        :param plaintext: Plaintext to be encrypted.
        :type plaintext: bytes

        :return: Encrypted plaintext.
        :rtype: bytes
        """

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypts the provided ciphertext.

        :param ciphertext: Ciphertext to be decrypted.
        :type ciphertext: bytes

        :return: Decrypted data.
        :rtype: bytes
        """
