#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko

# crypto-safe random
import secrets

from rsa.utils import is_prime


class RandomPrimeError(Exception): pass


def rand_prime(n: int) -> int:
    threshold = 10_000
    i = 0
    # ensure leading 1 to preserve length
    s = 1 << (n - 1)
    # fill other bits randomly
    t = secrets.randbits(n - 1)
    x = s | t
    # ensure odd
    x |= 1

    while i < threshold:
        x += 2
        if is_prime(x):
            return x
        i += 1
    raise RandomPrimeError(f'Unable to find random value after '
                           f'{threshold} attempts.')


if __name__ == '__main__':
    print(rand_prime(2048))