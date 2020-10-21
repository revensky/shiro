class JoseError(Exception):
    """ Base class for the exceptions of the package. """

    error: str = None

    def __init__(self, error: str = None):
        super().__init__(error or self.error)


class ExpiredToken(JoseError):
    error = "The provided Json Web Token is expired."


class InvalidJWSHeader(JoseError):
    error = "The provided Json Web Signature Header is invalid."


class InvalidJWSSerialization(JoseError):
    error = "The provided JWS Serialization is invalid."


class InvalidJWTClaim(JoseError):
    error = "The provided Json Web Key Token contains an invalid claim."


class InvalidKey(JoseError):
    error = "The provided key is invalid or contain invalid parameters."


class InvalidKeySet(JoseError):
    error = "The provided key set is invalid or contain invalid keys."


class InvalidSignature(JoseError):
    error = "The provided signature does not match the provided data."


class InvalidUseKeyOps(JoseError):
    error = "The provided use and key_ops do not match."


class NotYetValidToken(JoseError):
    error = "The provided Json Web Token is not yet valid."


class UnsupportedAlgorithm(JoseError):
    error = "The provided algorithm is not supported."


class UnsupportedParsingMethod(JoseError):
    error = "The provided parsing method is not supported."
