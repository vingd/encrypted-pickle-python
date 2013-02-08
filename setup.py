#!/usr/bin/env python

'''EncryptedPickle Setup'''

from distutils.core import setup

import encryptedpickle

setup(
    name=encryptedpickle.__title__,
    version=encryptedpickle.__version__,
    author=encryptedpickle.__author__,
    author_email=encryptedpickle.__author_email__,
    url=encryptedpickle.__url__,
    license=encryptedpickle.__license__,
    description=encryptedpickle.__doc__,
    long_description=open('README.rst').read(),
    packages=['encryptedpickle'],
    install_requires=[i.strip() for i in open('requirements.txt').readlines()],
    platforms=['OS Independent'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
