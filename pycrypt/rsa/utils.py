#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko


import random

from rsa.const import RSA_SMALL_PRIMES
from hash.sha2 import SHA256


def xor(a: str, b: str):
    assert len(a) == len(b)
    res = ''
    for i in range(len(a)):
        ai = a[i]
        bi = b[i]
        res += i2osp(int(ai, 16) ^ int(bi, 16), 1)
    return res


def i2osp(x: int, size: int) -> str:
    if x > 256 ** size:
        raise ValueError('Value too large')
    c = hex(x)[2:].rjust(size, '0')
    return c


def osp2i(s: str) -> int:
    return int(s, 16)


def mgf1(input_str: str, length: int, h=lambda s: SHA256(s).hex_digest()):
    counter = 0
    output = ''
    while len(output) < length:
        C = i2osp(counter, 4)
        output += h(input_str + C)
        counter += 1
    return output[:length]



def _miller_rabin_exponent_factorizer(n):
    s = 0
    while n % 2 == 0:
        n //= 2
        s += 1
    return s, n


def _miller_step(a: int, d: int, p: int, s: int):
    # x = bin_pow_mod(a, d, p)
    x = bin_pow_mod(a, d, p)
    if x == 1 or x == p-1:
        return True

    for i in range(s):
        x = (x ** 2) % p
        if x == 1:
            return False
        if x == p - 1:
            return True
    return False


def miller_rabin(p: int, rounds: int = 20) -> bool:
    s, d = _miller_rabin_exponent_factorizer(p - 1)

    for i in range(rounds):
        a = random.randrange(1, p - 1)
        if _miller_step(a, d, p, s) is False:
            return False
    return True


def is_prime(p: int) -> bool:
    if p in RSA_SMALL_PRIMES:
        return True

    for a in RSA_SMALL_PRIMES:
        if p % a == 0:
            return False

    return miller_rabin(p)


def xgcd(a: int, b: int):
    """Extended Euqlidean algorithm"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = xgcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def inv_mod(c: int, m: int) -> int:
    """Inverse for `c` modulo `m`"""
    g, a, b = xgcd(c, m)
    assert g == 1, f"{c} and {m} must be co-prime. Common divisor: {g}"
    return a % m


def euler_phi(p: int, q: int) -> int:
    return (p - 1) * (q -  1)


def bin_pow_mod(a: int, n: int, m: int) -> int:
    res = 1
    while n > 0:
        if n & 1:
            res = (res * a) % m
        a = (a * a) % m
        n >>= 1
    return res % m


if __name__ == '__main__':
    a = 12333
    b = 12733
    m = 83293
    import math
    print(f'Expected ops: {math.log2(b)}')
    print(bin_pow_mod(a, b, m))
    print(pow(a, b, m))
