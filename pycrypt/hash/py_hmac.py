#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko


from Crypto.Hash import HMAC, SHA256 as SHA_PCD

from hash.sha2 import SHA256


BLOCK_SIZE_BYTES = 512 // 8


def xor_bytes(s, t):
    assert len(s) == len(t)
    res = b''
    for i in range(len(s)):
        x = s[i]
        y = t[i]
        res += (x ^ y).to_bytes(1, 'big')
    return res


def hmac(data: bytes, key: bytes):
    ipad = b'\x36' * BLOCK_SIZE_BYTES
    opad = b'\x5c' * BLOCK_SIZE_BYTES

    if len(key) > BLOCK_SIZE_BYTES:
        key = SHA256(key).digest()
    if len(key) < BLOCK_SIZE_BYTES:
        key = key.ljust(BLOCK_SIZE_BYTES, b'\x00')

    x = xor_bytes(key, ipad) + data
    x = SHA256(x).digest()
    x = xor_bytes(key, opad) + x
    return SHA256(x).hex_digest()


if __name__ == '__main__':
    secret = b'Swordfish1'

    h = HMAC.new(secret, digestmod=SHA_PCD)
    h.update(b'hello')
    print(h.hexdigest())

    print(hmac(b'hello', secret))