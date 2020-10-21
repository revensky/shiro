from __future__ import annotations

from shiro.exceptions import InvalidJWSSerialization, InvalidKey
from shiro.jwk import JsonWebKey
from shiro.jws.header import JsonWebSignatureHeader
from shiro.utils import base64url_decode, base64url_encode, json_dumps, json_loads


class JsonWebSignature:
    """
    Implementation of RFC 7515.

    The JWS is used for transporting data on the network, providing a signature
    that guarantees the integrity of the information received.

    This implementation provides a set of attributes (described below) to represent
    the state of the information, as well as segregating the header from the payload,
    which in turn facilitates the use of any of them.

    It provides an algorithm attribute as well. The algorithm is used to sign
    and verify the data of the JWS.

    TODO: Add JSON Serialization.

    :ivar header: The header of the JWS.
    :ivar payload: The data that is being handled.

    :param payload: Data to be used by the JWS. MUST be a bytes sequence.
    :type payload: bytes

    :param header: Dictionary that comprise the JWS Header.
    :type header: JsonWebSignatureHeader
    """

    def __init__(self, payload: bytes, header: JsonWebSignatureHeader):
        if not isinstance(header, JsonWebSignatureHeader):
            header = JsonWebSignatureHeader(header)

        self.header = header
        self.payload = payload

    def serialize(self, key: JsonWebKey) -> bytes:
        """
        Serializes the content of the current JsonWebSignature.

        It serializes the header into a Base64Url version of its JSON representation,
        and serializes the payload into a Base64Url format, allowing the compatibility
        of the payload in different systems.

        It creates a byte string message of the following format::

            Base64Url(UTF-8(header)).Base64Url(payload)

        It then signs the message using the provided key, and imbues the signature
        into the message, resulting in the following token::

            Base64Url(UTF-8(header)).Base64Url(payload).Base64Url(signature)

        The above token is then returned to the application.

        :param key: Key used to sign the message.
        :type key: JsonWebKey

        :raises InvalidKey: The provided key is invalid.

        :return: Signed token representing the content of the JWS.
        :rtype: bytes
        """

        self.validate_key(key, self.header)

        message = b".".join(
            [base64url_encode(json_dumps(self.header)), base64url_encode(self.payload)]
        )

        signature = self.header.algorithm.sign(message, key)

        return b".".join([message, signature])

    @classmethod
    def deserialize(
        cls,
        token: bytes,
        key: JsonWebKey,
        algorithm: str = None,
        validate: bool = True,
    ) -> JsonWebSignature:
        """
        Deserializes a token checking if its signature matches its content.

        Despite being optional, it is recommended to provide an algorithm
        to prevent the "none attack" and the misuse of a public key
        as secret key.

        The algorithm specified at the header of the token
        MUST match the provided algorithm, if any.

        :param token: Token to be deserialized.
        :type token: bytes

        :param key: Key used to validate the token's signature.
        :type key: JsonWebKey

        :param algorithm: Expected algorithm of the token.
        :type algorithm: str

        :param validate: Defines if the deserialization should validate the signature.
            Defaults to True.
        :type validate: bool, optional

        :raises InvalidJWSSerialization: The provided JWS token is invalid.
        :raises InvalidKey: The provided key is invalid.
        :raises InvalidSignature: Unmatching token signature and content.

        :return: Instance of a JsonWebSignature.
        :rtype: JsonWebSignature
        """

        try:
            header, payload, signature = token.split(b".")
        except (AttributeError, ValueError):
            raise InvalidJWSSerialization

        jws_header = JsonWebSignatureHeader(json_loads(base64url_decode(header)))

        if algorithm:
            if jws_header.get("alg") != algorithm:
                raise InvalidJWSSerialization(
                    "The provided algorithm does not match the one on the header of the token."
                )

        if validate:
            cls.validate_key(key, jws_header)
            jws_header.algorithm.verify(signature, b".".join([header, payload]), key)

        return cls(base64url_decode(payload), jws_header)

    @classmethod
    def validate_key(cls, key: JsonWebKey, header: JsonWebSignatureHeader):
        """
        Validates the provided key against the header
        algorithm's specifications and restrictions.

        :param key: JWK to be validated.
        :type key: JsonWebKey

        :param header: JWS Header used to validate the key against.
        :type header: JsonWebSignatureHeader

        :raises InvalidKey: The provided key is invalid.
        """

        if not isinstance(key, JsonWebKey):
            raise InvalidKey

        if key.get("alg"):
            if key.get("alg") != header.get("alg"):
                raise InvalidKey(
                    f'This key cannot be used by the algorithm "{header.get("alg")}".'
                )

        if header.get("kid"):
            if key.get("kid") != header.get("kid"):
                raise InvalidKey(
                    "The key ID does not match the specified on the header."
                )

        if key.get("use"):
            if key.get("use") != "sig":
                raise InvalidKey("This key cannot be used to sign a JWS.")

        if key.get("key_ops"):
            if any(op not in ("sign", "verify") for op in key.get("key_ops")):
                raise InvalidKey("This key cannot be used to sign a JWS.")
