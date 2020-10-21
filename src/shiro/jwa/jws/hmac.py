import binascii

from shiro.exceptions import InvalidSignature
from shiro.jwa.jws.base import JWSAlgorithm
from shiro.jwk import JsonWebKey
from shiro.utils import base64url_decode, base64url_encode


class _HMAC(JWSAlgorithm):
    __key_type__: str = "oct"

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


class HS256(_HMAC):
    __algorithm__: str = "HS256"
    __hash_name__: str = "SHA-256"


class HS384(_HMAC):
    __algorithm__: str = "HS384"
    __hash_name__: str = "SHA-384"


class HS512(_HMAC):
    __algorithm__: str = "HS512"
    __hash_name__: str = "SHA-512"
