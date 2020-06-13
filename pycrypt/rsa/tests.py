#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko

import random
import unittest as ut
from itertools import chain

import rsa.utils as rsa_u
import rsa.rsa_init as rsa_init
import rsa.rsa_main as rsa_main
import rsa.data_types as dt


class IsPrimeTester(ut.TestCase):

    n = [24, 42, 91, 327, 1991, 2341]

    # results calculated at sage math cell
    xgcd_vals = [(767, 445, 1, 123, -212),
                 (998, 718, 2, -100, 139),
                 (972, 124, 4, 6, -47),
                 (237, 621, 3, 76, -29),
                 (744, 892, 4, 6, -5),
                 (382, 729, 1, 250, -131),
                 (58, 399, 1, 172, -25),
                 (260, 344, 4, -41, 31),
                 (564, 562, 2, 1, -1),
                 (529, 485, 1, -11, 12),
                 (289, 714, 17, 5, -2),
                 (486, 289, 1, -22, 37),
                 (190, 316, 2, 5, -3), (114, 907, 1, 183, -23),
                 (849, 274, 1, -71, 220), (111, 636, 3, -63, 11),
                 (879, 223, 1, -103, 406), (733, 300, 1, 97, -237),
                 (721, 564, 1, 97, -124), (793, 903, 1, -353, 310)]
    # from wiki
    small_primes = [1997, 1999, 2003, 2011, 2017, 2027,
                    2029, 2039, 2053, 2063, 2069, 2081]

    big_primes = [682649553190601022597121418831,
                  129972717819428150240655055081,
                  356974327440368388599427608881]

    carmichael_nums = [561, 1105, 1729, 2465]

    not_primes = [340282366920938463463374607431768211456,
                  30630425128319,
                  186984870778483581528599905107]

    def test_factorizer(self):
        for cur_n in self.n:
            s, d = rsa_u._miller_rabin_exponent_factorizer(cur_n)
            self.assertEqual((2 ** s) * d, cur_n, msg='Incorrect value')
            self.assertTrue(s >= 0, msg='s < 0')
            self.assertTrue(d > 0, msg='d <= 0')

    def test_xgcd(self):
        for a, b, g, x, y in self.xgcd_vals:
            g_test, x_test, y_test = rsa_u.xgcd(a, b)
            self.assertEqual(g_test, g, msg=f'GCD inconsistency: Expected {g}, Got {g_test}')
            self.assertEqual(x_test, x, msg=f'X inconsistency: Expected {x}, Got {x_test}')
            self.assertEqual(y_test, y, msg=f'Y inconsistency: Expected {y}, Got {y_test}')

    def test_binpowmod(self):
        max_a = 1024
        max_n = 1024
        max_m = 1024
        for i in range(20):
            a = random.randrange(1, max_a)
            n = random.randrange(1, max_n)
            m = random.randrange(1, max_m)
            expected = (a ** n) % m
            received = rsa_u.bin_pow_mod(a, n, m)
            self.assertEqual(expected, received, msg=f'bin_pow_mod inconsistensy: Expected {expected}, Received {received}')

    def test_primality_test(self):
        for n in chain(self.small_primes, self.big_primes):
            self.assertTrue(rsa_u.is_prime(n), msg=f"Not recognized as prime: {n}")
        for n in chain(self.carmichael_nums, self.not_primes):
            self.assertFalse(rsa_u.is_prime(n), msg=f"Not recognized as composite: {n}")

    def test_rsa_invertability(self):
        pub, priv = rsa_init.init_rsa(2048)
        m = 123

        m_prime = rsa_main.rsa_decode(rsa_main.rsa_encode(m, pub), priv)
        self.assertEqual(m_prime, m, msg=f'RSA Dec(Enc(m)) != m')


if __name__ == '__main__':
    # print(rsa_u.is_prime(1997))
    ut.main(verbosity=2)