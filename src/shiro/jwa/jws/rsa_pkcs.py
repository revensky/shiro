import binascii

from shiro.exceptions import InvalidSignature
from shiro.jwa.jws.base import JWSAlgorithm
from shiro.jwk import JsonWebKey
from shiro.utils import base64url_decode, base64url_encode


class _RSA_PKCS1v15(JWSAlgorithm):
    __key_type__: str = "RSA"
    __padding__: str = "PKCS1v15"

    @classmethod
    def sign(cls, data: bytes, key: JsonWebKey) -> bytes:
        cls.validate_key(key)
        signature = key.algorithm.sign(data, cls.__hash_name__, cls.__padding__)
        return base64url_encode(signature)

    @classmethod
    def verify(cls, signature: bytes, data: bytes, key: JsonWebKey):
        cls.validate_key(key)

        try:
            # Incorrect padding of the encoded signature.
            raw_signature = base64url_decode(signature)
        except binascii.Error:
            raise InvalidSignature

        key.algorithm.verify(raw_signature, data, cls.__hash_name__, cls.__padding__)


class RS256(_RSA_PKCS1v15):
    __algorithm__: str = "RS256"
    __hash_name__: str = "SHA-256"


class RS384(_RSA_PKCS1v15):
    __algorithm__: str = "RS384"
    __hash_name__: str = "SHA-384"


class RS512(_RSA_PKCS1v15):
    __algorithm__: str = "RS512"
    __hash_name__: str = "SHA-512"
