from __future__ import annotations

import copy
import inspect
from typing import Any

from fulldict import FullDict

from shiro.exceptions import ExpiredToken, InvalidJWTClaim, NotYetValidToken


class JsonWebTokenClaims(dict):
    """
    Implementation of RFC 7519.

    It provides validation for the default parameters of the JWT claims.

    The JWT Claims is a JSON object that contains information about
    an application, system or user.

    :param claims: Dictionary containing the parameters
        of the payload of the JWT.
    :type claims: dict

    :param options: Options used to validate the claims.
    :type options: dict[str, dict]
    """

    def __init__(self, claims: dict, options: dict[str, dict] = None):
        if not claims or not isinstance(claims, dict):
            raise InvalidJWTClaim("The claims object MUST be a valid dict.")

        super().__init__(FullDict(claims))

        if isinstance(options, dict):
            self._validate_claims(options)

        self.options = options

    def _validate_claims(self, options: dict[str, dict]):
        """
        Validates the provided claims using the declared options.

        :param options: Options used to validate the JWT claims.
        :type options: dict
        """

        for claim, option in options.items():
            if not isinstance(option, dict):
                continue

            value = self.get(claim)

            if option.get("essential") and value is None:
                raise InvalidJWTClaim(f'Missing required claim "{claim}".')

            if option.get("value") and value != option.get("value"):
                raise InvalidJWTClaim(
                    f'Mismatching expected value "{option.get("value")}". Got "{value}".'
                )

            if option.get("values"):
                if not isinstance(option["values"], list):
                    raise InvalidJWTClaim('Expected a list for the attribute "values".')

                if isinstance(value, list) and any(
                    item in option["values"] for item in value
                ):
                    break

                for expected_value in option["values"]:
                    if value == expected_value:
                        break
                else:
                    raise InvalidJWTClaim(
                        f'Mismatching any of expected values {option["values"]}. Got "{value}".'
                    )

    def validate(self, **kwargs: Any):
        """
        Validates the provided claims using the declared validators.
        If a claim does not have a validator, it will be accepted as is.

        All the defaults for all the validators have to be passed as
        keyword arguments to this function, whether scalar or callable.
        """

        validators = {
            name: method
            for name, method in inspect.getmembers(self, predicate=inspect.ismethod)
            if name.startswith("validate_")
        }

        # Gets the values from kwargs.
        values = {k: v for k, v in kwargs.items()}

        # Solves the problem of callable defaults.
        for k, v in values.items():
            if callable(v):
                values[k] = v()

        for name, method in validators.items():
            # Name of the claim.
            claim = name.replace("validate_", "")

            # If the claim was not provided, we skip.
            if claim not in self.keys():
                continue

            # Gets the signature arguments of the validator.
            signature = inspect.signature(method)
            args = dict(signature.parameters.items())

            # Runs the validator without any proof-value.
            if len(args) == 0:
                method()
                continue

            if len(args) > 0:
                # We use a copy of the defaults of validate because
                # the same values will be used on ALL validators.
                default = copy.deepcopy(values)

                # Uses the default value of the signature when no value is provided.
                for k, v in list(args.items())[1:]:
                    if v.default is not v.empty and k not in default.keys():
                        default[k] = v.default
                        continue

                    # If the signature expect a default parameter other than the claim
                    # and it was not provided, it fails instantly.
                    if k not in default.keys() and v.default is v.empty:
                        raise RuntimeError(f'Missing argument "{k}" for "{name}".')

                # Runs the validator with the required claim and values.
                method(**default)

    def validate_aud(self):
        if self.get("aud") is not None and not isinstance(self.get("aud"), (str, list)):
            raise InvalidJWTClaim('Invalid claim "aud".')

        if isinstance(self["aud"], list):
            if any(not isinstance(item, str) for item in self["aud"]):
                raise InvalidJWTClaim('Invalid claim "aud".')

    def validate_exp(self, now: int):
        if self.get("exp") is not None and type(self.get("exp")) is not int:
            raise InvalidJWTClaim('Invalid claim "exp".')

        if now >= self["exp"]:
            raise ExpiredToken

    def validate_iat(self, now: int):
        if self.get("iat") is not None and type(self.get("iat")) is not int:
            raise InvalidJWTClaim('Invalid claim "iat".')

        if now < self["iat"]:
            raise InvalidJWTClaim('Invalid claim "iat".')

    def validate_iss(self):
        if self.get("iss") is not None and not isinstance(self.get("iss"), str):
            raise InvalidJWTClaim('Invalid claim "iss".')

    def validate_jti(self):
        if self.get("jti") is not None and not isinstance(self.get("jti"), str):
            raise InvalidJWTClaim('Invalid claim "jti".')

    def validate_nbf(self, now: int):
        if self.get("nbf") is not None and type(self.get("nbf")) is not int:
            raise InvalidJWTClaim('Invalid claim "nbf".')

        if now < self["nbf"]:
            raise NotYetValidToken

    def validate_sub(self):
        if self.get("sub") is not None and not isinstance(self.get("sub"), str):
            raise InvalidJWTClaim('Invalid claim "sub".')
