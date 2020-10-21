import binascii

from shiro.exceptions import InvalidKey, InvalidSignature
from shiro.jwa.jws.base import JWSAlgorithm
from shiro.jwk import JsonWebKey
from shiro.utils import base64url_decode, base64url_encode


class _EC(JWSAlgorithm):
    __curve__: str = None
    __key_type__: str = "EC"

    @classmethod
    def sign(cls, data: bytes, key: JsonWebKey) -> bytes:
        cls.validate_key(key)
        signature = key.algorithm.sign(data, cls.__hash_name__)
        return base64url_encode(signature)

    @classmethod
    def verify(cls, signature: bytes, data: bytes, key: JsonWebKey):
        cls.validate_key(key)

        try:
            # Incorrect padding of the encoded signature.
            raw_signature = base64url_decode(signature)
        except binascii.Error:
            raise InvalidSignature

        key.algorithm.verify(raw_signature, data, cls.__hash_name__)

    @classmethod
    def validate_key(cls, key: JsonWebKey):
        super(_EC, cls).validate_key(key)

        if key.algorithm.crv != cls.__curve__:
            raise InvalidKey(
                f'This algorithm only accepts the curve "{cls.__curve__}".'
            )


class ES256(_EC):
    __algorithm__: str = "ES256"
    __curve__: str = "P-256"
    __hash_name__: str = "SHA-256"


class ES384(_EC):
    __algorithm__: str = "ES384"
    __curve__: str = "P-384"
    __hash_name__: str = "SHA-384"


class ES512(_EC):
    __algorithm__: str = "ES512"
    __curve__: str = "P-521"
    __hash_name__: str = "SHA-512"
