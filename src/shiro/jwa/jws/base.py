import abc

from shiro.exceptions import InvalidKey
from shiro.jwk import JsonWebKey


class JWSAlgorithm(abc.ABC):
    """
    Implementation of the Section 3 of RFC 7518.

    This class provides the expected method signatures
    that will be used throughout the package.

    All JWS Algorithms **MUST** inherit from this class and
    implement its methods.

    :cvar ``__algorithm__``: Name of the algorithm.
    :cvar ``__hash_name__``: Name of the hash function used by the algorithm.
    :cvar ``__key_type__``: Type of the key that the algorithm accepts.
    """

    __algorithm__: str = None
    __hash_name__: str = None
    __key_type__: str = None

    @classmethod
    def validate_key(cls, key: JsonWebKey):
        """
        Validates the provided key against the algorithm's
        specifications and restrictions.

        :param key: JWK to be validated.
        :type key: JsonWebKey

        :raises InvalidKey: The provided key is invalid.
        """

        if not isinstance(key, JsonWebKey):
            raise InvalidKey

        # pylint: disable=used-before-assignment
        if (alg := key.get("alg")) and alg != cls.__algorithm__:
            raise InvalidKey(
                f'This key is intended to be used by the algorithm "{alg}".'
            )

        if key.get("kty") != cls.__key_type__:
            raise InvalidKey(f'This algorithm only accepts "{cls.__key_type__}" keys.')

    @classmethod
    @abc.abstractmethod
    def sign(cls, data: bytes, key: JsonWebKey) -> bytes:
        """
        Signs the provided data using the provided key.

        :param data: Data to be signed.
        :type data: bytes

        :param key: JWK used to sign the data.
        :type key: JsonWebKey

        :return: URL Safe Base64 encoded signature of the data.
        :rtype: bytes
        """

    @classmethod
    @abc.abstractmethod
    def verify(cls, signature: bytes, data: bytes, key: JsonWebKey):
        """
        Verifies if the data and signature provided match
        based on the provided Json Web Key.

        :param signature: Signature used in the verification.
            **MUST** be a URL Safe Base64 encoded bytes string.
        :type signature: bytes

        :param data: Data to be verified.
        :type data: bytes

        :param key: JWK used to verify the data.
        :type key: JsonWebKey

        :raises InvalidSignature: The signature and data do not match.
        """
