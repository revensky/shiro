from shiro.jwa.jws.base import JWSAlgorithm
from shiro.jwk import JsonWebKey


class none(JWSAlgorithm):
    __algorithm__: str = "none"

    @classmethod
    def sign(cls, data: bytes, key: JsonWebKey = None) -> bytes:
        return b""

    @classmethod
    def verify(cls, signature: bytes, data: bytes, key: JsonWebKey = None):
        pass
