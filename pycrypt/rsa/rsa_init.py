#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko

import os
import typing as tp

from rsa.rand_prime import rand_prime
from rsa.data_types import PublicKey, PrivateKey
from rsa.utils import inv_mod, euler_phi

from rsa.const import RSA_DEFAULT_PUBLIC_EXPONENT, RSA_MODULO_BIT_SIZES


def init_rsa(n: int) -> tp.Tuple[PublicKey, PrivateKey]:
    assert n in RSA_MODULO_BIT_SIZES, f"Unsupported RSA modulo bit size: {n}"
    factors_size = n // 2

    p = rand_prime(factors_size)
    q = rand_prime(factors_size)
    e = RSA_DEFAULT_PUBLIC_EXPONENT
    d = inv_mod(e, euler_phi(p, q))

    N = p*q
    return PublicKey(e, N), PrivateKey(d, N)


def init_rsa_and_dump(n: int, out_dir: str):
    if not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    pub, priv = init_rsa(n)
    pub.serialize(os.path.join(out_dir, 'py_rsa_key.pub'))
    priv.serialize(os.path.join(out_dir, 'py_rsa_key'))


if __name__ == '__main__':
    init_rsa_and_dump(2048, '.')