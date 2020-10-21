from __future__ import annotations

from typing import Any, Union

from shiro.jwk import JsonWebKey
from shiro.jws import JsonWebSignature, JsonWebSignatureHeader
from shiro.jwt.claims import JsonWebTokenClaims
from shiro.utils import json_dumps, json_loads, to_bytes, to_string


class JsonWebToken:
    """
    Implementation of RFC 7519.

    The JWT is used for transporting claims over the network,
    providing a signature that guarantees the integrity of the information received.

    This implementation provides a set of attributes (described below) to represent
    the state of the information, as well as segregating the header from the payload,
    which in turn facilitates the use of any of them.

    It can be used with either a JWS or a JWE. The most common way of representing
    a JWT is through the JWS Compact Serialization, which gives a small token
    that is digitally signed.

    The claims are represented via a JSON object that contains information about
    an application, system or user. Since this information is digitally signed,
    the receiver can then use the respective key to validate the token and can
    trust that the information is legit.

    TODO: Add support for JWE headers.

    :param claims: Claims about the entity represented by the token.
    :type claims: dict

    :param header: Dictionary that comprise the header of the token.
    :type header: dict

    :param options: Optional validation options for the claims of the token.
    :type options: dict[str, dict]
    """

    def __init__(self, claims: JsonWebTokenClaims, header: dict):
        self.header = JsonWebSignatureHeader(header)
        self.claims = claims
        self._jws = JsonWebSignature(to_bytes(json_dumps(self.claims)), self.header)

    def __repr__(self):
        return f"<Header: {self.header}, Claims: {self.claims}>"

    def validate(self, **kwargs: Any):
        """
        Validates the claims of the current JWT using the validators
        declared in JWTClaims.

        For more info about the validation,
        please refer to the documentation of JWTClaims.
        """

        self.claims.validate(**kwargs)

    def encode(self, key: JsonWebKey) -> str:
        """
        Encodes the internal representation of the current JWT object,
        signs it with the provided key and returns the respective token.

        :param key: Key used to sign and encode the token.
        :type key: JsonWebKey

        :return: Encoded Json Web Token header, payload and signature.
        :rtype: bytes
        """

        return to_string(self._jws.serialize(key))

    @classmethod
    def decode(
        cls,
        token: Union[bytes, str],
        key: JsonWebKey,
        algorithm: str = None,
        validate: bool = True,
        options: dict[str, dict] = None,
    ) -> JsonWebToken:
        """
        Decodes a token checking if its signature matches its content.

        Despite being optional, it is recommended to provide an algorithm
        to prevent the "none attack" and the misuse of a public key
        as secret key.

        The algorithm specified at the header of the token **MUST** match
        the provided algorithm, if any.

        If the token has an Issued At (`iat`) parameter, it will verify the
        validity of the token against the provided `expiration` argument.

        :param token: Token to be verified.
        :type token: Union[bytes, str]

        :param key: Key used to validate the token's signature.
        :type key: JsonWebKey

        :param algorithm: Expected algorithm of the token, defaults to None.
        :type algorithm: str, optional

        :param validate: Defines if the decoding should validate the signature.
            Defaults to True.
        :type validate: bool, optional

        :param options: Optional validation options for the claims of the token.
        :type options: dict[str, dict]

        :return: Instance of a JsonWebToken.
        :rtype: JsonWebToken
        """

        jws = JsonWebSignature.deserialize(to_bytes(token), key, algorithm, validate)
        claims = JsonWebTokenClaims(
            json_loads(jws.payload), options if validate else None
        )

        return cls(claims, jws.header)
