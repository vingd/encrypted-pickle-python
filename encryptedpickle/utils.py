# -*- coding: utf-8 -*-

'''
Some common, generic utilities
'''

from __future__ import absolute_import

from base64 import urlsafe_b64encode, urlsafe_b64decode


def urlsafe_nopadding_b64encode(data):
    '''URL safe Base64 encode without padding (=)'''

    return urlsafe_b64encode(data).rstrip('=')

def urlsafe_nopadding_b64decode(data):
    '''URL safe Base64 decode without padding (=)'''

    padding = len(data) % 4
    if padding != 0:
        padding = 4 - padding
    padding = '=' * padding
    data = data + padding
    return urlsafe_b64decode(data)

def const_equal(str_a, str_b):
    '''Constant time string comparison'''

    if len(str_a) != len(str_b):
        return False

    result = True
    for i in range(len(str_a)):
        result &= (str_a[i] == str_b[i])

    return result
