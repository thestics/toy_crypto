#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko

from math import log, ceil

from rsa.data_types import PublicKey, PrivateKey
from rsa.utils import bin_pow_mod, i2osp, osp2i, mgf1, xor
from rsa.const import RSA_MODULO_OCTETS

import secrets

from hash.sha2 import SHA256

k = 128     # length of rsa modulus in octets
hLen = 32   # sha256 hash length in octets


def rsa_encode(m: int, pub_key: PublicKey):
    assert m < pub_key.n, \
        f"Message too long. Max bit length: {pub_key.modulus_bin_size}"
    return bin_pow_mod(m, pub_key.e, pub_key.n)


def rsa_decode(c: int, priv_key: PrivateKey):
    assert c < priv_key.n, \
        f"Ciphertext too long. Max bit length: {priv_key.modulus_bin_size}"
    return bin_pow_mod(c, priv_key.d, priv_key.n)


def rsa_oaep_encode(m: int, pub_key: PublicKey, l: str = ''):
    mLen = ceil(len(hex(m)[2:]) / 2)
    m_str = i2osp(m, mLen)
    assert mLen <= k - 2 * hLen - 2, "Encryption error: too long message"
    lHash = SHA256(l).hex_digest()
    PS = '0' * (k - mLen - 2 * hLen - 2)
    DB = lHash + PS + '01' + m_str

    seed = i2osp(secrets.randbits(hLen * 8), hLen)
    dbMask = mgf1(seed, k - hLen - 1)
    maskedDB = xor(DB, dbMask)
    seedMask = mgf1(maskedDB, hLen)
    maskedSeed = xor(seed, seedMask)
    EM = '00' + maskedSeed + maskedDB

    repr_m = osp2i(EM)
    c = rsa_encode(repr_m, pub_key)
    C = i2osp(c, RSA_MODULO_OCTETS)
    return C


def rsa_oaep_decode(C: str, priv_key: PrivateKey, l: str = ''):
    assert len(C) == k, 'Decryption error: Inconsistent ciphertext length'
    assert k < 2 * hLen + 2, 'Dectyprion error: Too large RSA modulus. Expected < 2 hLen + 2'
    c = osp2i(C)
    m = rsa_decode(c, priv_key)
    EM = i2osp(m, k)
    lHash = SHA256(l).hex_digest()

    maskedDB = EM[-(k - hLen - 1):]
    maskedSeed = EM[-(k - hLen - 1) - hLen: -(k - hLen - 1)]
    Y = EM[:-(k - hLen - 1) - hLen]
    assert all(Y[i] == '0' for i in
               range(len(Y))), "Decryption error: corrupted message"

    seedMask = mgf1(maskedDB, hLen)
    seed = xor(maskedSeed, seedMask)

    dbMask = mgf1(seed, k - hLen - 1)
    DB = xor(maskedDB, dbMask)
    lHash2 = DB[:hLen]
    assert lHash == lHash2, "Decryption error: corrupted message"

    M = DB[hLen:].lstrip('0')
    assert M[0] == '1', "Decryption error: corrupted message."
    M = M[1:]
    return osp2i(M)


if __name__ == '__main__':
    ...