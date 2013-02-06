==========================
EncryptedPickle for Python
==========================

EncryptedPickle is Python class for encrypting and signing data with support
for versions, serialization, compression, and passphrase generations (rotation).

It's partly inspired by `iron`_ but isn't compatible with.


Example Usage
=============

.. code-block:: python

    from encryptedpickle import encryptedpickle

    passphrases = {
        0: 'Change me! CHange me! CHAnge me! CHANge me!'
           'CHANGe me! CHANGE ME! CHANGE Me! CHANGE ME!'
    }

    data = {'example': 123, 'test': 'testing'}

    encoder = encryptedpickle.EncryptedPickle(signature_passphrases=passphrases,
                                              encryption_passphrases=passphrases)

    print("* data: %s" % data)

    sealed = encoder.seal(data)
    print("* sealed: %s" % sealed)

    unsealed = encoder.unseal(sealed)
    print("* unsealed: %s" % unsealed)


Customization Example
=====================

.. code-block:: python

    from encryptedpickle import encryptedpickle

    # You can use different passphrases for signature and encryption
    signature_passphrases = {
        0: 'change me! change me! change me! change me!'
           'change me! change me! change me! change me!'
    }

    encryption_passphrases = {
        0: 'Change me! CHange me! CHAnge me! CHANge me!'
           'CHANGe me! CHANGE ME! CHANGE Me! CHANGE ME!'
    }

    data = {'example': 123, 'test': 'testing'}

    encoder = encryptedpickle.EncryptedPickle(signature_passphrases,
                                              encryption_passphrases)

    encryption = {
        # Add new encryption algorithm specification with id = 255.
        # Default algorithms can not be overridden so we must use some other
        # id, maybe best starting with 255 (maximum id) and decreasing by one
        # for next added algorithm.
        255: {
            # Algorithm name defined in EncryptedPickle.ALGORITHMS.
            'algorithm': 'aes-256-cbc',

            # Salt size for PBKDF2 key.
            'salt_size': 32,

            # Digest mode for PBKDF2 key.
            'pbkdf2_algorithm': 'sha256',

            # Use 10 iterations in PBKDF2 key generation.
            'pbkdf2_iterations': 10,
        },
    }
    encoder.set_algorithms(encryption=encryption)

    options = {
        # Use above defined encryption algorithm (id = 255).
        'encryption_algorithm_id': 255,

        # Use "gzip-deflate" (id = 1) algorithm for compression.
        #
        # Be carefull with this option, because compression is applied before
        # encryption and "Crime" attack is possible if third party can modify
        # data that is encrypted. For more info see:
        #
        # https://www.isecpartners.com/news-events/news/2012/september/details-on-the-crime-attack.aspx
        #
        'compression_algorithm_id': 1,

        # Add timestamp to header (unencrypted).
        'flags': {
            'timestamp': True,
        },
    }
    encoder.set_options(options)

    sealed = encoder.seal(data)
    print("* sealed: %s" % sealed)

    unsealed, unsealed_options = encoder.unseal(sealed, return_options=True)
    print("* unsealed: %s" % unsealed)
    if unsealed_options['info']['timestamp']:
        print("* timestamp: %d" % unsealed_options['info']['timestamp'])


Copyright and License
=====================

EncryptedPickle for Python is Copyright (c) 2013 Vingd, Inc. and licensed under
the MIT License.


.. _`iron`: https://github.com/hueniverse/iron
