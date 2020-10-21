Json Web Token (JWT)
====================

The JWT is used for transporting claims over the network, providing a signature
that guarantees the integrity of the information received. These claims provide
information about the entity represented in the token, as well as information
about the validity of the data.

.. note:: The JWT **DOES NOT** encrypt the message. Therefore, the inclusion
   of sensitive data such as passwords or credit card information,
   for example, is highly discouraged.

Creating and Using a JWT
########################

In order to create and use a JWT, you use the class
:class:`shiro.jwt.JsonWebToken`.

Its use is demonstrated by the following example::

   from shiro.jwk import JsonWebKey
   from shiro.jwt import JsonWebToken

   key = JsonWebKey({"kty": "oct", "k": "supersafepassword"})
   payload = {"sub": "client", "iss": "https://mywebsite.com", "iat": 1598523107}

   message = JsonWebToken(payload, {"alg": "HS256", "typ": "JWT"})
   token = message.encode(key)

Validating a JWT
################

In order to validate a JWT, you must use the method
:meth:`shiro.jwt.JsonWebToken.decode`,
which validates the token and returns
an instance of :class:`shiro.jwt.JsonWebToken`.

Its use is demonstrated by the following example
(the line breaks are for display purposes)::

   from shiro.jwk import JsonWebKey
   from shiro.jwt import JsonWebToken

   token = (
      b'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJIUzI1NiJ9.'
      b'eyJzdWIiOiAiY2xpZW50IiwgImlzcyI6ICJodHRwczovL2xvY2FsaG9zdC5jb20iLCAiaWF0IjogMTU5ODUyMzEwN30.'
      b'6_9Ujvf4S-5R5tBL_RmaoPgmYOFVFzIp2pOdgyJFs9A'
   )

   key = JsonWebKey({"kty": "oct", "k": "supersafepassword"})

   message = JsonWebToken.decode(token, key, "HS256")

.. note:: When decoding a token, it is highly recommended to provide the desired
   algorithm to be used, since it prevents the "none algorithm" attack, as well
   as the misuse of the public key as a secret key.

Source Code
###########

.. automodule:: shiro.jwt

.. autoclass:: JsonWebTokenClaims
   :members:

.. autoclass:: JsonWebToken
   :members:
