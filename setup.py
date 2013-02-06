#!/usr/bin/env python

from distutils.core import setup

setup(
    name='EncryptedPickle',
    version='0.1.1',
    description='Class for pickling and encrypting data',
    long_description=open('README.rst').read(),
    author='Andjelko Horvat',
    author_email='comel@vingd.com',
    url='https://github.com/vingd/encrypted-pickle-python',
    packages=['encryptedpickle'],
    install_requires=[i.strip() for i in open('requirements.txt').readlines()],
    platforms=['OS Independent'],
    license='MIT License',
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
    )
)
