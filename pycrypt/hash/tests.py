#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko


import random
import unittest as ut

from Crypto.Hash import SHA256 as SHA_PCD, HMAC

from hash.sha2 import BinOps, SHA256
from hash.py_hmac import hmac


class BinOpsTester(ut.TestCase):

    def test_rotr(self):
        s = '00000000000000000000000000010001'
        s_int = int(s, 2)
        n = 3
        t = '00100000000000000000000000000010'
        t_int = int(t, 2)
        self.assertEqual(t_int, BinOps.rotr(s_int, n))

    def test_rotr2(self):
        s = '10000000000000000000000000010001'
        s_int = int(s, 2)
        n = 5
        t = '10001100000000000000000000000000'
        t_int = int(t, 2)
        self.assertEqual(t_int, BinOps.rotr(s_int, n))

    def test_shr(self):
        s = 1251343
        n = 5
        self.assertEqual(s >> n, BinOps.shr(s, n))

    def test_slices(self):
        s = 0x12345678
        n = 8
        reference = [0x12, 0x34, 0x56, 0x78]
        reference2 = [0x1234, 0x5678]
        res = list(BinOps.slices_n(s, n))
        res2 = list(BinOps.slices_n(s, 2*n))
        self.assertListEqual(res, reference)
        self.assertListEqual(res2, reference2)


def rand(n):
    b = random._urandom(n)
    return b


class SHATester(ut.TestCase):

    s = [b'', b'123', rand(16), rand(32),
         rand(64), rand(128)]

    def test_sha(self):
        for c in self.s:
            h1 = SHA256(c).hex_digest()
            h2 = SHA_PCD.new(c).hexdigest()
            self.assertEqual(h1, h2)

    def test_hmac(self):
        for i in range(len(self.s)):
            m = k = self.s[i]
            custom = hmac(m, k)
            h = HMAC.new(k, digestmod=SHA_PCD).update(m)
            reference = h.hexdigest()
            self.assertEqual(custom, reference)




if __name__ == '__main__':
    ut.main(verbosity=2)