from __future__ import annotations

import inspect

from fulldict import FullDict

from shiro.exceptions import InvalidJWSHeader, UnsupportedAlgorithm
from shiro.jwa.jws import (
    JWSAlgorithm,
    none,
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512,
)


class JsonWebSignatureHeader(dict):
    """
    Implementation of RFC 7515.

    This is the implementation of the Header of the Json Web Signature.
    It provides validation for the default parameters of the JWS header.

    The JWS Header is a JSON object that provides information on how to
    manipulate the payload of the message, such as permitted algorithms
    and the keys to be used in signing and verifying the payload.

    TODO: Add support for RFC 7797.

    :cvar ``__algorithms__``: Algorithms supported by the JWS.

    :param header: Dictionary containing the parameters of the JWS header.
    :type header: dict
    """

    __algorithms__: dict[str, JWSAlgorithm] = {
        none.__algorithm__: none,
        HS256.__algorithm__: HS256,
        HS384.__algorithm__: HS384,
        HS512.__algorithm__: HS512,
        RS256.__algorithm__: RS256,
        RS384.__algorithm__: RS384,
        RS512.__algorithm__: RS512,
        ES256.__algorithm__: ES256,
        ES384.__algorithm__: ES384,
        ES512.__algorithm__: ES512,
        PS256.__algorithm__: PS256,
        PS384.__algorithm__: PS384,
        PS512.__algorithm__: PS512,
    }

    def __init__(self, header: dict):
        if not header or not isinstance(header, dict):
            raise InvalidJWSHeader

        validators = [
            method
            for name, method in inspect.getmembers(self, predicate=inspect.ismethod)
            if name.startswith("validate_")
        ]

        for validator in validators:
            validator(header)

        self.algorithm = self.__algorithms__[header.get("alg")]

        super().__init__(FullDict(header))

    def validate_alg(self, header: dict):
        """
        The alg parameter is mandatory, and MUST be a registered algorithm.

        :param header: Dictionary with the JWS Header parameters.
        :type header: dict

        :raises InvalidJWSHeader: Did not find "alg".
        :raises UnsupportedAlgorithm: The algorithm is not supported.
        """

        if "alg" not in header.keys():
            raise InvalidJWSHeader('Missing parameter "alg".')

        if header.get("alg") not in self.__algorithms__.keys():
            raise UnsupportedAlgorithm

    def validate_jku(self, header: dict):
        pass

    def validate_jwk(self, header: dict):
        pass

    def validate_kid(self, header: dict):
        """
        ID of the JWK used by this JWS. If present, MUST be a string.

        :param header: Dictionary with the JWS Header parameters.
        :type header: dict

        :raises InvalidJWSHeader: Key ID is invalid.
        """

        if "kid" in header.keys():
            # pylint: disable=used-before-assignment
            if not (kid := header.get("kid")) or not isinstance(kid, str):
                raise InvalidJWSHeader('Invalid parameter "kid".')

    def validate_x5u(self, header: dict):
        pass

    def validate_x5c(self, header: dict):
        pass

    def validate_x5t(self, header: dict):
        pass

    def validate_x5tS256(self, header: dict):
        pass

    def validate_typ(self, header: dict):
        """
        Type of the JWS. If present, MUST be a string.

        :param header: Dictionary with the JWS Header parameters.
        :type header: dict

        :raises InvalidJWSHeader: The type is not a string.
        """

        if "typ" in header.keys():
            # pylint: disable=used-before-assignment
            if not (typ := header.get("typ")) or not isinstance(typ, str):
                raise InvalidJWSHeader('Invalid parameter "typ".')

    def validate_cty(self, header: dict):
        """
        Type of the payload. If present, MUST be a string.

        :param header: Dictionary with the JWS Header parameters.
        :type header: dict

        :raises InvalidJWSHeader: Content Type is not a string.
        """

        if "cty" in header.keys():
            # pylint: disable=used-before-assignment
            if not (cty := header.get("cty")) or not isinstance(cty, str):
                raise InvalidJWSHeader('Invalid parameter "cty".')

    def validate_crit(self, header: dict):
        """
        Critical parameters of the JWS header. If present, MUST be a list of strings.

        :param header: Dictionary with the JWS Header parameters.
        :type header: dict

        :raises InvalidJWSHeader: Not a list of strings,
            or the critical parameter was not found in the JWS header.
        """

        if "crit" in header.keys():
            # Ensures the type safety of the parameter.
            # pylint: disable=used-before-assignment
            if not (crit := header.get("crit")) or not isinstance(crit, list):
                raise InvalidJWSHeader('Invalid parameter "crit".')

            # Ensures that each critical parameter is a VALID string.
            if any(not item or not isinstance(item, str) for item in crit):
                raise InvalidJWSHeader('Invalid parameter "crit".')

            for item in crit:
                if not header.get(item):
                    raise InvalidJWSHeader(f'The parameter "{item}" is required.')
