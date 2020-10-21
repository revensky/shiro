Json Web Signature (JWS)
========================

The JWS is used to transport data on the network in a safe way, thanks to the
signature of the header and the payload. It is important to notice that the JWS
**DOES NOT** encrypt the message. Therefore, the inclusion of sensitive data
such as passwords or credit card information, for example, is highly discouraged.

Creating and Using a JWS
########################

In order to create and use a JWS, you use the class
:class:`shiro.jws.JsonWebSignature`.

Its use is demonstrated by the following example::

   from shiro.jwk import JsonWebKey
   from shiro.jws import JsonWebSignature

   key = JsonWebKey({"kty": "oct", "k": "supersafepassword"})
   payload = b'{"sub": "client", "iss": "https://mywebsite.com", "iat": 1598523107}'

   message = JsonWebSignature(payload, {"alg": "HS256", "typ": "JWT"})
   token = message.encode(key)

Validating a JWS
################

In order to validate a JWS, you must use the method
:meth:`shiro.jws.JsonWebSignature.decode`,
which validates the token and returns
an instance of :class:`shiro.jws.JsonWebSignature`.

Its use is demonstrated by the following example
(the line breaks are for display purposes)::

   from shiro.jwk import JsonWebKey
   from shiro.jws import JsonWebSignature

   token = (
      b'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJIUzI1NiJ9.'
      b'eyJzdWIiOiAiY2xpZW50IiwgImlzcyI6ICJodHRwczovL2xvY2FsaG9zdC5jb20iLCAiaWF0IjogMTU5ODUyMzEwN30.'
      b'6_9Ujvf4S-5R5tBL_RmaoPgmYOFVFzIp2pOdgyJFs9A'
   )

   key = JsonWebKey({"kty": "oct", "k": "supersafepassword"})

   message = JsonWebSignature.decode(token, key, "HS256")

.. note:: When decoding a token, it is highly recommended to provide the desired
   algorithm to be used, since it prevents the "none algorithm" attack, as well
   as the misuse of the public key as a secret key.

Source Code
###########

.. automodule:: shiro.jws

.. autoclass:: JsonWebSignatureHeader
   :members:

.. autoclass:: JsonWebSignature
   :members:
