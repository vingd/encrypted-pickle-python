# -*- coding: utf-8 -*-

'''
Class for encrypting and signing data with support for versions, serialization,
compression, and passphrase generations (rotation)
'''

from __future__ import absolute_import

import zlib
from time import time
from struct import pack, unpack
from collections import namedtuple

import simplejson as json
from pbkdf2 import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA, SHA256, SHA384, SHA512

from .utils import (
    const_equal,
    urlsafe_nopadding_b64encode,
    urlsafe_nopadding_b64decode
)


class EncryptedPickle(object):
    '''EncryptedPickle class'''

    DEFAULT_MAGIC = 'EP'

    VERSIONS = {
        1: {
            'header_size': 9,
            'header_format': '>BBBBBBBBB',
            'header': namedtuple('header', [
                'version',
                'signature_algorithm_id',
                'signature_passphrase_id',
                'encryption_algorithm_id',
                'encryption_passphrase_id',
                'serialization_algorithm_id',
                'compression_algorithm_id',
                'custom_id',
                'flags',
            ]),
            'flags': namedtuple('flags', [
                'timestamp',
                'unused_1',
                'unused_2',
                'unused_3',
                'unused_4',
                'unused_5',
                'unused_6',
                'unused_7',
            ]),
            'timestamp_size': 8,
            'timestamp_format': '>Q',
        },
    }

    DEFAULT_OPTIONS = {
        'version': 1,
        'signature_algorithm_id': 0,
        'signature_passphrase_id': 0,
        'encryption_algorithm_id': 0,
        'encryption_passphrase_id': 0,
        'serialization_algorithm_id': 1,

        # Be carefull with compression option, because compression is applied
        # before encryption and "Crime" attack is possible if third party can
        # modify data that is encrypted. For more info see:
        #
        # https://www.isecpartners.com/news-events/news/2012/september/details-on-the-crime-attack.aspx

        'compression_algorithm_id': 0,

        'custom_id': 0,
        'flags': {
            'timestamp': False,
            'unused_1': False,
            'unused_2': False,
            'unused_3': False,
            'unused_4': False,
            'unused_5': False,
            'unused_6': False,
            'unused_7': False,
        },
    }

    DEFAULT_SIGNATURE = {
        0: {
            'algorithm': 'hmac-sha256',
            'salt_size': 32,
            'pbkdf2_iterations': 1,
            'pbkdf2_algorithm': 'sha256',
        },
    }

    DEFAULT_ENCRYPTION = {
        0: {
            'algorithm': 'aes-256-cbc',
            'salt_size': 32,
            'pbkdf2_iterations': 1,
            'pbkdf2_algorithm': 'sha256',
        },
    }

    DEFAULT_SERIALIZATION = {
        0: {
            'algorithm': 'no-serialization',
        },
        1: {
            'algorithm': 'json',
        },
    }

    DEFAULT_COMPRESSION = {
        0: {
            'algorithm': 'no-compression',
        },
        1: {
            'algorithm': 'gzip-deflate',
            'level': 9,
        },
    }

    ALGORITHMS = {
        'hmac-sha256': {
            'type': 'hmac',
            'subtype': 'sha256',
            'key_size': 32,
            'hash_size': 32,
        },
        'hmac-sha384': {
            'type': 'hmac',
            'subtype': 'sha384',
            'key_size': 32,
            'hash_size': 48,
        },
        'hmac-sha512': {
            'type': 'hmac',
            'subtype': 'sha512',
            'key_size': 32,
            'hash_size': 64,
        },

        'aes-256-cbc': {
            'type': 'aes',
            'subtype': 'cbc',
            'key_size': 32,
            'iv_size': 16,
        },

        'no-serialization': {
            'type': 'no-serialization',
        },
        'json': {
            'type': 'json',
        },

        'no-compression': {
            'type': 'no-compression',
        },
        'gzip-deflate': {
            'type': 'gzip',
            'subtype': 'deflate',
        },
    }

    def __init__(self,
                 signature_passphrases=None,
                 encryption_passphrases=None,
                 options=None):

        self.signature_algorithms = self.DEFAULT_SIGNATURE.copy()
        self.encryption_algorithms = self.DEFAULT_ENCRYPTION.copy()
        self.serialization_algorithms = self.DEFAULT_SERIALIZATION.copy()
        self.compression_algorithms = self.DEFAULT_COMPRESSION.copy()
        self.signature_passphrases = self._update_dict(signature_passphrases,
                                                       {}, replace_data=True)
        self.encryption_passphrases = self._update_dict(encryption_passphrases,
                                                        {}, replace_data=True)
        self.magic = self.DEFAULT_MAGIC
        self.options = self.DEFAULT_OPTIONS.copy()
        if options:
            self.set_options(options)

    def set_signature_passphrases(self, signature_passphrases):
        '''Set signature passphrases'''
        self.signature_passphrases = self._update_dict(signature_passphrases,
                                                       {}, replace_data=True)

    def get_signature_passphrases(self):
        '''Get signature passphrases'''
        return self.signature_passphrases

    def set_encryption_passphrases(self, encryption_passphrases):
        '''Set encryption passphrases'''
        self.encryption_passphrases = self._update_dict(encryption_passphrases,
                                                        {}, replace_data=True)

    def get_encryption_passphrases(self):
        '''Get encryption passphrases'''
        return self.encryption_passphrases

    def set_algorithms(self, signature=None, encryption=None,
                       serialization=None, compression=None):
        '''Set algorithms used for sealing. Defaults can not be overridden.'''

        self.signature_algorithms = \
            self._update_dict(signature, self.DEFAULT_SIGNATURE)

        self.encryption_algorithms = \
            self._update_dict(encryption, self.DEFAULT_ENCRYPTION)

        self.serialization_algorithms = \
            self._update_dict(serialization, self.DEFAULT_SERIALIZATION)

        self.compression_algorithms = \
            self._update_dict(compression, self.DEFAULT_COMPRESSION)

    def get_algorithms(self):
        '''Get algorithms used for sealing'''

        return {
            'signature': self.signature_algorithms,
            'encryption': self.encryption_algorithms,
            'serialization': self.serialization_algorithms,
            'compression': self.compression_algorithms,
        }

    def set_options(self, options):
        '''Set options used for sealing'''
        self.options = self._set_options(options)

    def _set_options(self, options):
        '''Private function for setting options used for sealing'''
        if not options:
            return self.options.copy()

        options = options.copy()

        if 'magic' in options:
            self.set_magic(options['magic'])
            del(options['magic'])

        if 'flags' in options:
            flags = options['flags']
            del(options['flags'])
            for key, value in flags.iteritems():
                if not isinstance(value, bool):
                    raise TypeError('Invalid flag type for: %s' % key)
        else:
            flags = self.options['flags']

        if 'info' in options:
            del(options['info'])

        for key, value in options.iteritems():
            if not isinstance(value, int):
                raise TypeError('Invalid option type for: %s' % key)
            if value < 0 or value > 255:
                raise ValueError('Option value out of range for: %s' % key)

        new_options = self.options.copy()
        new_options.update(options)
        new_options['flags'].update(flags)

        return new_options

    def get_options(self):
        '''Get options used for sealing'''
        return self.options

    def set_magic(self, magic):
        '''Set magic (prefix)'''
        if magic is None or isinstance(magic, str):
            self.magic = magic
        else:
            raise TypeError('Invalid value for magic')

    def get_magic(self):
        '''Get magic (prefix)'''
        return self.magic

    def seal(self, data, options=None):
        '''Seal data'''

        options = self._set_options(options)

        data = self._serialize_data(data, options)
        data = self._compress_data(data, options)
        data = self._encrypt_data(data, options)
        data = self._add_header(data, options)
        data = self._add_magic(data)
        data = self._sign_data(data, options)
        data = self._remove_magic(data)
        data = urlsafe_nopadding_b64encode(data)
        data = self._add_magic(data)

        return data

    def unseal(self, data, return_options=False):
        '''Unseal data'''

        data = self._remove_magic(data)
        data = urlsafe_nopadding_b64decode(data)
        options = self._read_header(data)
        data = self._add_magic(data)
        data = self._unsign_data(data, options)
        data = self._remove_magic(data)
        data = self._remove_header(data, options)
        data = self._decrypt_data(data, options)
        data = self._decompress_data(data, options)
        data = self._unserialize_data(data, options)

        if return_options:
            return data, options
        else:
            return data

    def verify_signature(self, data):
        '''Verify sealed data signature'''

        data = self._remove_magic(data)
        data = urlsafe_nopadding_b64decode(data)
        options = self._read_header(data)
        data = self._add_magic(data)
        self._unsign_data(data, options)

    def get_data_options(self, data, verify_signature=True):
        '''Get sealed data options'''

        data = self._remove_magic(data)
        data = urlsafe_nopadding_b64decode(data)
        options = self._read_header(data)
        data = self._add_magic(data)
        if verify_signature:
            data = self._unsign_data(data, options)
        return options

    def _encode(self, data, algorithm, key=None):
        '''Encode data with specific algorithm'''

        if algorithm['type'] == 'hmac':
            return data + self._hmac_generate(data, algorithm, key)
        elif algorithm['type'] == 'aes':
            return self._aes_encrypt(data, algorithm, key)
        elif algorithm['type'] == 'no-serialization':
            return data
        elif algorithm['type'] == 'json':
            return json.dumps(data)
        elif algorithm['type'] == 'no-compression':
            return data
        elif algorithm['type'] == 'gzip':
            return self._zlib_compress(data, algorithm)
        else:
            raise Exception('Algorithm not supported: %s' % algorithm['type'])

    def _decode(self, data, algorithm, key=None):
        '''Decode data with specific algorithm'''

        if algorithm['type'] == 'hmac':
            verify_signature = data[-algorithm['hash_size']:]
            data = data[:-algorithm['hash_size']]
            signature = self._hmac_generate(data, algorithm, key)
            if not const_equal(verify_signature, signature):
                raise Exception('Invalid signature')
            return data
        elif algorithm['type'] == 'aes':
            return self._aes_decrypt(data, algorithm, key)
        elif algorithm['type'] == 'no-serialization':
            return data
        elif algorithm['type'] == 'json':
            return json.loads(data)
        elif algorithm['type'] == 'no-compression':
            return data
        elif algorithm['type'] == 'gzip':
            return self._zlib_decompress(data, algorithm)
        else:
            raise Exception('Algorithm not supported: %s' % algorithm['type'])

    def _sign_data(self, data, options):
        '''Add signature to data'''

        if options['signature_algorithm_id'] not in self.signature_algorithms:
            raise Exception('Unknown signature algorithm id: %d'
                            % options['signature_algorithm_id'])

        signature_algorithm = \
            self.signature_algorithms[options['signature_algorithm_id']]

        algorithm = self._get_algorithm_info(signature_algorithm)

        key_salt = get_random_bytes(algorithm['salt_size'])
        key = self._generate_key(options['signature_passphrase_id'],
                            self.signature_passphrases, key_salt, algorithm)

        data = self._encode(data, algorithm, key)

        return data + key_salt

    def _unsign_data(self, data, options):
        '''Verify and remove signature'''

        if options['signature_algorithm_id'] not in self.signature_algorithms:
            raise Exception('Unknown signature algorithm id: %d'
                            % options['signature_algorithm_id'])

        signature_algorithm = \
            self.signature_algorithms[options['signature_algorithm_id']]

        algorithm = self._get_algorithm_info(signature_algorithm)

        key_salt = ''
        if algorithm['salt_size']:
            key_salt = data[-algorithm['salt_size']:]
            data = data[:-algorithm['salt_size']]

        key = self._generate_key(options['signature_passphrase_id'],
                            self.signature_passphrases, key_salt, algorithm)

        data = self._decode(data, algorithm, key)

        return data

    def _encrypt_data(self, data, options):
        '''Encrypt data'''

        if options['encryption_algorithm_id'] not in self.encryption_algorithms:
            raise Exception('Unknown encryption algorithm id: %d'
                            % options['encryption_algorithm_id'])

        encryption_algorithm = \
            self.encryption_algorithms[options['encryption_algorithm_id']]

        algorithm = self._get_algorithm_info(encryption_algorithm)

        key_salt = get_random_bytes(algorithm['salt_size'])
        key = self._generate_key(options['encryption_passphrase_id'],
                            self.encryption_passphrases, key_salt, algorithm)

        data = self._encode(data, algorithm, key)

        return data + key_salt

    def _decrypt_data(self, data, options):
        '''Decrypt data'''

        if options['encryption_algorithm_id'] not in self.encryption_algorithms:
            raise Exception('Unknown encryption algorithm id: %d'
                            % options['encryption_algorithm_id'])

        encryption_algorithm = \
            self.encryption_algorithms[options['encryption_algorithm_id']]

        algorithm = self._get_algorithm_info(encryption_algorithm)

        key_salt = ''
        if algorithm['salt_size']:
            key_salt = data[-algorithm['salt_size']:]
            data = data[:-algorithm['salt_size']]

        key = self._generate_key(options['encryption_passphrase_id'],
                            self.encryption_passphrases, key_salt, algorithm)

        data = self._decode(data, algorithm, key)

        return data

    def _serialize_data(self, data, options):
        '''Serialize data'''

        serialization_algorithm_id = options['serialization_algorithm_id']
        if serialization_algorithm_id not in self.serialization_algorithms:
            raise Exception('Unknown serialization algorithm id: %d'
                            % serialization_algorithm_id)

        serialization_algorithm = \
            self.serialization_algorithms[serialization_algorithm_id]

        algorithm = self._get_algorithm_info(serialization_algorithm)

        data = self._encode(data, algorithm)

        return data

    def _unserialize_data(self, data, options):
        '''Unserialize data'''

        serialization_algorithm_id = options['serialization_algorithm_id']
        if serialization_algorithm_id not in self.serialization_algorithms:
            raise Exception('Unknown serialization algorithm id: %d'
                            % serialization_algorithm_id)

        serialization_algorithm = \
            self.serialization_algorithms[serialization_algorithm_id]

        algorithm = self._get_algorithm_info(serialization_algorithm)

        data = self._decode(data, algorithm)

        return data

    def _compress_data(self, data, options):
        '''Compress data'''

        compression_algorithm_id = options['compression_algorithm_id']
        if compression_algorithm_id not in self.compression_algorithms:
            raise Exception('Unknown compression algorithm id: %d'
                            % compression_algorithm_id)

        compression_algorithm = \
            self.compression_algorithms[compression_algorithm_id]

        algorithm = self._get_algorithm_info(compression_algorithm)

        compressed = self._encode(data, algorithm)

        if len(compressed) < len(data):
            data = compressed
        else:
            options['compression_algorithm_id'] = 0

        return data

    def _decompress_data(self, data, options):
        '''Decompress data'''

        compression_algorithm_id = options['compression_algorithm_id']
        if compression_algorithm_id not in self.compression_algorithms:
            raise Exception('Unknown compression algorithm id: %d'
                            % compression_algorithm_id)

        compression_algorithm = \
            self.compression_algorithms[compression_algorithm_id]

        algorithm = self._get_algorithm_info(compression_algorithm)

        data = self._decode(data, algorithm)

        return data

    def _remove_magic(self, data):
        '''Verify and remove magic'''

        if not self.magic:
            return data

        magic_size = len(self.magic)
        magic = data[:magic_size]
        if magic != self.magic:
            raise Exception('Invalid magic')
        data = data[magic_size:]

        return data

    def _add_magic(self, data):
        '''Add magic'''

        if self.magic:
            return self.magic + data

        return data

    def _add_header(self, data, options):
        '''Add header to data'''

        # pylint: disable=W0142

        version_info = self._get_version_info(options['version'])

        flags = options['flags']

        header_flags = dict(
            (i, str(int(j))) for i, j in options['flags'].iteritems())
        header_flags = ''.join(version_info['flags'](**header_flags))
        header_flags = int(header_flags, 2)
        options['flags'] = header_flags

        header = version_info['header']
        header = header(**options)
        header = pack(version_info['header_format'], *header)

        if 'timestamp' in flags and flags['timestamp']:
            timestamp = long(time())
            timestamp = pack(version_info['timestamp_format'], timestamp)
            header = header + timestamp

        return header + data

    def _read_header(self, data):
        '''Read header from data'''

        # pylint: disable=W0212

        version = self._read_version(data)
        version_info = self._get_version_info(version)
        header_data = data[:version_info['header_size']]
        header = version_info['header']
        header = header._make(
            unpack(version_info['header_format'], header_data))
        header = dict(header._asdict())

        flags = list("{0:0>8b}".format(header['flags']))
        flags = dict(version_info['flags']._make(flags)._asdict())
        flags = dict((i, bool(int(j))) for i, j in flags.iteritems())
        header['flags'] = flags

        timestamp = None
        if flags['timestamp']:
            ts_start = version_info['header_size']
            ts_end = ts_start + version_info['timestamp_size']
            timestamp_data = data[ts_start:ts_end]
            timestamp = unpack(
                version_info['timestamp_format'], timestamp_data)[0]
        header['info'] = {'timestamp': timestamp}

        return header

    def _remove_header(self, data, options):
        '''Remove header from data'''

        version_info = self._get_version_info(options['version'])
        header_size = version_info['header_size']

        if options['flags']['timestamp']:
            header_size += version_info['timestamp_size']

        data = data[header_size:]

        return data

    def _read_version(self, data):
        '''Read header version from data'''

        version = ord(data[0])
        if version not in self.VERSIONS:
            raise Exception('Version not defined: %d' % version)
        return version

    def _get_version_info(self, version):
        '''Get version info'''

        return self.VERSIONS[version]

    def _get_algorithm_info(self, algorithm_info):
        '''Get algorithm info'''

        if algorithm_info['algorithm'] not in self.ALGORITHMS:
            raise Exception('Algorithm not supported: %s'
                            % algorithm_info['algorithm'])

        algorithm = self.ALGORITHMS[algorithm_info['algorithm']]
        algorithm_info.update(algorithm)

        return algorithm_info

    @staticmethod
    def _generate_key(pass_id, passphrases, salt, algorithm):
        '''Generate and return PBKDF2 key'''

        if pass_id not in passphrases:
            raise Exception('Passphrase not defined for id: %d' % pass_id)

        passphrase = passphrases[pass_id]

        if len(passphrase) < 32:
            raise Exception('Passphrase less than 32 characters long')

        digestmod = EncryptedPickle._get_hashlib(algorithm['pbkdf2_algorithm'])

        encoder = PBKDF2(passphrase, salt,
                         iterations=algorithm['pbkdf2_iterations'],
                         digestmodule=digestmod)

        return encoder.read(algorithm['key_size'])

    @staticmethod
    def _update_dict(data, default_data, replace_data=False):
        '''Update algorithm definition type dictionaries'''

        if not data:
            data = default_data.copy()
            return data

        if not isinstance(data, dict):
            raise TypeError('Value not dict type')
        if len(data) > 255:
            raise ValueError('More than 255 values defined')
        for i in data.keys():
            if not isinstance(i, int):
                raise TypeError('Index not int type')
            if i < 0 or i > 255:
                raise ValueError('Index value out of range')

        if not replace_data:
            data.update(default_data)

        return data

    @staticmethod
    def _get_hashlib(digestmode):
        '''Generate HMAC hash'''
        if digestmode == 'sha1':
            return SHA
        if digestmode == 'sha256':
            return SHA256
        elif digestmode  == 'sha384':
            return SHA384
        elif digestmode == 'sha512':
            return SHA512
        else:
            raise Exception('digestmode not supported: %s'
                            % digestmode)

    @staticmethod
    def _hmac_generate(data, algorithm, key):
        '''Generate HMAC hash'''

        digestmod = EncryptedPickle._get_hashlib(algorithm['subtype'])

        return HMAC.new(key, data, digestmod).digest()

    @staticmethod
    def _aes_encrypt(data, algorithm, key):
        '''AES encrypt'''

        if algorithm['subtype'] == 'cbc':
            mode = AES.MODE_CBC
        else:
            raise Exception('AES subtype not supported: %s'
                            % algorithm['subtype'])

        iv_size = algorithm['iv_size']
        block_size = iv_size
        include_iv = True

        if 'iv'in algorithm and algorithm['iv']:
            if len(algorithm['iv']) != algorithm['iv_size']:
                raise Exception('Invalid IV size')
            iv_value = algorithm['iv']
            include_iv = False
        else:
            iv_value = get_random_bytes(iv_size)

        numpad = block_size - (len(data) % block_size)
        data = data + numpad * chr(numpad)

        enc = AES.new(key, mode, iv_value).encrypt(data)

        if include_iv:
            enc = iv_value + enc

        return enc

    @staticmethod
    def _aes_decrypt(data, algorithm, key):
        '''AES decrypt'''

        if algorithm['subtype'] == 'cbc':
            mode = AES.MODE_CBC
        else:
            raise Exception('AES subtype not supported: %s'
                            % algorithm['subtype'])

        iv_size = algorithm['iv_size']

        if 'iv' in algorithm and algorithm['iv']:
            if len(algorithm['iv']) != algorithm['iv_size']:
                raise Exception('Invalid IV size')
            iv_value = algorithm['iv']
            enc = data
        else:
            iv_value = data[:iv_size]
            enc = data[iv_size:]

        dec = AES.new(key, mode, iv_value).decrypt(enc)

        numpad = ord(dec[-1])
        dec = dec[0:-numpad]

        return dec

    @staticmethod
    def _zlib_compress(data, algorithm):
        '''GZIP compress'''

        if algorithm['subtype'] == 'deflate':
            encoder = zlib.compressobj(algorithm['level'], zlib.DEFLATED, -15)
            compressed = encoder.compress(data)
            compressed += encoder.flush()

            return compressed
        else:
            raise Exception('Compression subtype not supported: %s'
                            % algorithm['subtype'])


    @staticmethod
    def _zlib_decompress(data, algorithm):
        '''GZIP decompress'''

        if algorithm['subtype'] == 'deflate':
            return zlib.decompress(data, -15)
        else:
            raise Exception('Compression subtype not supported: %s'
                            % algorithm['subtype'])
