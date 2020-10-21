from __future__ import annotations

from shiro.jwk.jwk import JsonWebKey
from shiro.exceptions import InvalidKeySet


class JsonWebKeySet:
    """
    Implementation of RFC 7517.

    The Json Web Key Set is a collection of Json Web Keys, providing a pool of
    keys accepted by the application. It is useful when there are multiple keys,
    each one having a specific usage.

    In order to be added into a key set, the key **MUST** have an ID,
    via the `kid` parameter, since there **SHOULD NOT** be
    any repeated keys within the set.

    The method :meth:`get_key` provides an easy way of retrieving a key via the ID.

    :param keys: A collection of the keys to be used by the application.
        Note that **ALL** the keys **MUST** have a valid unique ID assigned to itself.
    :type keys: list[JsonWebKey]

    :ivar keys: A collection of the keys accepted by the JWKS.
    """

    def __init__(self, keys: list[JsonWebKey]):
        if not keys or not isinstance(keys, list):
            raise InvalidKeySet

        if any(not isinstance(key, JsonWebKey) for key in keys):
            raise InvalidKeySet

        # Verifies if there are any repeated IDs.
        ids = [key.get("kid") for key in keys]

        if None in ids:
            raise InvalidKeySet("One or more keys do not have an ID.")

        if len(ids) != len(set(ids)):
            raise InvalidKeySet(
                "The usage of the same ID for multiple keys in a JWKS is forbidden."
            )

        self.keys = keys

    def load(self, keyset: dict[str, list[dict]]) -> JsonWebKeySet:
        """
        Loads a raw Key Set into a JsonWebKeySet object.

        :param keyset: Key Set to be loaded.
        :type keyset: List[dict]
        """

        if not keyset or not isinstance(keyset, dict):
            raise InvalidKeySet("Invalid JWKS format.")

        if list(keyset.keys()) != ["keys"]:
            raise InvalidKeySet("Invalid JWKS format.")

        return JsonWebKeySet([JsonWebKey(key) for key in keyset["keys"]])

    def dump(self) -> dict:
        """
        Returns the public data of the keys of the JWKS.

        :return: Public data of the JWK Set and its JWKs.
        :rtype: dict
        """

        return {"keys": [key.dump() for key in self.keys]}

    def get_key(self, kid: str) -> JsonWebKey:
        """
        Returns the key identified by the provided ID.

        :param kid: ID of the key to be retrieved.
        :type kid: str

        :return: Instance of a Json Web Key.
        :rtype: JsonWebKey
        """

        return next((key for key in self.keys if key["kid"] == kid), None)
