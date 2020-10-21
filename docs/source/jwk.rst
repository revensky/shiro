Json Web Key (JWK) and Json Web Key Set (JWKS)
==============================================

The JWK is used to represent a secret key or a private/public key pair.
It represents the key's essential data in a JSON format, as well as ensuring
the correct usage of the key.

Json Web Key
############

In order to create and use a JWK, you use the class :class:`shiro.jwk.JsonWebKey`.

.. note:: The Json Web Key can be generated on the fly, can be loaded from
   a raw format, such as PEM for asymmetric keys, and can be instantiated
   from a raw dict using the constructor.

Its use is demonstrated by the following example: ::

   from shiro.jwk import JsonWebKey

   key = JsonWebKey({"kty": "oct", "k": "totallysafesupersecurepassword"})

   print(key)

Json Web Key Set
################

You can add multiple JWKs into a **key set**, using the class
:class:`shiro.jwk.JsonWebKeySet`. This set is generally used to create a
well defined pool of keys to be used by the application.

It is important to notice that a key can only be added if it has a **unique ID**
assigned to it via the **kid** parameter. Failure to meet this criteria **WILL**
result in an error, since it creates ambiguity when retrieving a key.

Its use is demonstrated by the following example
(with ellipsis for display purposes only): ::

   from shiro.jwk import JsonWebKey, JsonWebKeySet

   rsa_key = JsonWebKey.parse(b"-----BEGIN PUBLIC KEY-----...", kid="rsa")
   ec_key = JsonWebKey.parse(b"-----BEGIN PUBLIC KEY-----...", kid="ec")

   key_set = JsonWebKeySet([rsa_key, ece_key])

   print(key_set.get_key("rsa"))

Source Code
###########

.. automodule:: shiro.jwk

.. autoclass:: JsonWebKey
   :members:

.. autoclass:: JsonWebKeySet
   :members:
