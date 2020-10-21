from __future__ import annotations

import inspect
from typing import Any

from fulldict import FullDict

from shiro.exceptions import InvalidKey, InvalidUseKeyOps, UnsupportedAlgorithm
from shiro.jwa.jwk import JWKAlgorithm, OCTKey, RSAKey, ECKey


class JsonWebKey(dict):
    """
    Implementation of RFC 7517.

    It represents the keys used by the application via the algorithms
    defined at RFC 7518 and implemented as :class:`JWKAlgorithm` in this package.

    The usage of this representation instead of directly using the key is
    so that there is a well defined granularity regarding the usage of
    each key, as well as the allowed operations.

    It is possible to define an ID for each key as well, which helps identifying
    the key used at any point in the application.

    Validation of the standard parameters of the JWK is already provided.
    To validate any custom parameters, simply create your own :meth:`validate_*`.

    Example::

        from guarani.jose import JsonWebKey

        class CustomKey(JsonWebKey):
            # Assuming that "attr" is a string.
            def validate_attr(self, key: dict) -> None:
                if attr := key.get("attr"):
                    if not isinstance(attr, str):
                        raise InvalidKey("The provided attr is invalid.")

    The usage of any functionality pertaining to the key's algorithm, such as
    signing or verifying data, **MUST** be called via the key's `algorithm` attribute.

    Example::

        data = b"This is a super important message."
        signature = key.algorithm.sign(data, "SHA-256")

    :cvar ``__algorithms__``: Dictionary of the supported algorithms and their names.

    :param key: Dictionary containing the data of the key.
    :type key: dict

    :param kwargs: Overrides the provided parameter in the original JWK.
    """

    __algorithms__: dict[str, JWKAlgorithm] = {
        "oct": OCTKey,
        "RSA": RSAKey,
        "EC": ECKey,
    }

    def __init__(self, key: dict, /, **kwargs: Any) -> None:
        if not key or not isinstance(key, dict):
            raise InvalidKey

        key = FullDict(key, **kwargs)

        validators = [
            method
            for name, method in inspect.getmembers(self, predicate=inspect.ismethod)
            if name.startswith("validate_")
        ]

        for validator in validators:
            validator(key)

        self.algorithm = self.__algorithms__[key["kty"]].load(key)

        super().__init__(key)

    @classmethod
    def generate(cls, algorithm: str, option: Any = None, **params) -> JsonWebKey:
        """
        Generates a Json Web Key based on the provided algorithm.

        :param algorithm: Name of the JWK Algorithm used to generate the JWK.
        :type algorithm: str

        :param option: Option used to customize the key generation.
            MUST be supported by the :meth:`JWKAlgorithm.generate` of the algorithm.
            Defaults to None.
        :type option: Any

        :param params: Parameters that will compose the final JsonWebKey.
            **MUST** be supported by the JsonWebKey definition.

        :raises UnsupportedAlgorithm: Unsupported algorithm. 😒

        :return: Instance of a JsonWebKey.
        :rtype: JsonWebKey
        """

        if algorithm not in cls.__algorithms__.keys():
            raise UnsupportedAlgorithm

        alg: JWKAlgorithm = (
            cls.__algorithms__.get(algorithm).generate(option)
            if option
            else cls.__algorithms__.get(algorithm).generate()
        )

        attrs = FullDict(alg.dump(public=False), **params)

        return cls(attrs)

    def dump(self, public: bool = True) -> dict:
        """
        Returns a JSON-ready dictionary representation of the key.

        :param public: Dumps the public info of the key, defaults to True.
        :type public: bool, optional

        :return: Key in dict format.
        :rtype: dict
        """

        data = {
            key: value
            for key, value in self.items()
            if key not in self.algorithm.__allowed_attributes__
        }
        data.update(self.algorithm.dump(public))

        return data

    @classmethod
    def parse(
        cls,
        raw: bytes,
        algorithm: str,
        public: bool,
        password: bytes = None,
        format: str = "pem",
        **options,
    ) -> JsonWebKey:
        """
        Parses a raw key into a JWKAlgorithm.

        A raw symmetric key is simply its bytes string.
        A raw asymmetric key would be a PEM encoded key data.

        :param raw: Raw representation of the data.
        :type raw: bytes

        :param algorithm: JWK Algorithm used to parse the raw key.
        :type algorithm: str

        :param public: Defines if the key will be parsed as public or as private/secret.
        :type public: bool

        :param password: Password used to decrypt the raw key, defaults to None.
        :type password: bytes, optional

        :param format: The format of the raw key, defaults to pem.
            If `pem`, assumes it is Base64 Encoded.
            If `der`, assumes it is a regular sequence of bytes.
        :type format: str, optional

        :raises UnsupportedAlgorithm: Algorithm not supported.
        :raises UnsupportedParsingMethod: Method not supported (alg).
        :raises InvalidKey: The raw key type is different from the class' (alg).

        :return: Parsed key as JsonWebKey.
        :rtype: JsonWebKey
        """

        if not (method := cls.__algorithms__.get(algorithm)):
            raise UnsupportedAlgorithm

        jwk = method.parse(raw, password, format)
        key = jwk.dump(public)

        key.update(options)

        return cls(key)

    def export(self, public: bool = False) -> bytes:
        """
        Exports the key in PEM format if asymmetric, or Base64 if symmetric.

        :param public: Exports the public key, defaults to False.
        :type public: bool, optional

        :return: Base64/PEM encoded key data.
        :rtype: bytes
        """

        return self.algorithm.export(public)

    def validate_kty(self, key: dict) -> None:
        """
        Validates the provided key type.

        :param key: Json Web Key being loaded.
        :type key: dict

        :raises InvalidKey: No key type was provided.
        :raises UnsupportedAlgorithm: The provided key type is unsupported.
        """

        if not (kty := key.get("kty")):
            raise InvalidKey('Missing parameter "kty".')

        if kty not in self.__algorithms__.keys():
            raise UnsupportedAlgorithm

    def validate_use_and_key_ops(self, key: dict) -> None:
        """
        Validates the `use` and `key_ops` parameters, both individually and combined.

        :param key: Json Web Key being loaded.
        :type key: dict

        :raises InvalidKey: Not a valid key use or operations.
        :raises InvalidUseKeyOps: The `use` and `key_ops` do not match.
        """

        if use := key.get("use"):
            if not isinstance(use, str):
                raise InvalidKey("The provided use is invalid.")

        if key_ops := key.get("key_ops"):
            if not isinstance(key_ops, list):
                raise InvalidKey("The provided key_ops is invalid.")

            if any(not isinstance(op, str) for op in key_ops):
                raise InvalidKey("The provided key_ops is invalid.")

        if use and key_ops:
            if use == "sig" and any(op not in ("sign", "verify") for op in key_ops):
                raise InvalidUseKeyOps(
                    'When the use is "sig", the key_ops MUST '
                    'be a combination of ("sign", "verify").'
                )

            if use == "enc" and any(
                op
                not in (
                    "encrypt",
                    "decrypt",
                    "wrapKey",
                    "unwrapKey",
                    "deriveKey",
                    "deriveBits",
                )
                for op in key_ops
            ):
                raise InvalidUseKeyOps(
                    'When the use is "enc", the key_ops MUST be a combination of '
                    '("encrypt", "decrypt", "wrapKey", '
                    '"unwrapKey", "deriveKey", "deriveBits").'
                )

    def validate_alg(self, key: dict) -> None:
        """
        Validates the JWS or JWE algorithm that can use this key.

        :param key: Json Web Key being loaded.
        :type key: dict

        :raises InvalidKey: The provided JWS or JWE algorithm is invalid.
        """

        if alg := key.get("alg"):
            if not alg or not isinstance(alg, str):
                raise InvalidKey('Invalid parameter "alg".')

    def validate_kid(self, key: dict) -> None:
        """
        Validates the key ID.

        :param key: Json Web Key being loaded.
        :type key: dict

        :raises InvalidKey: The provided key ID is invalid.
        """

        if kid := key.get("kid"):
            if not kid or not isinstance(kid, str):
                raise InvalidKey('Invalid parameter "kid".')
