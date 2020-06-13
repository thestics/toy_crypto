#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko


from itertools import chain
from random import getrandbits

import matplotlib.pyplot as plt

from aes.ops import (schedule_keys, add_round_key,
                 shift_rows, mix_columns, sub_bytes,
                 inv_shift_rows, inv_mix_columns, inv_sub_bytes, INT_MATRIX)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    size = max(len(a), len(b))
    a = int.from_bytes(a, 'big')
    b = int.from_bytes(b, 'big')
    res = a ^ b
    return int.to_bytes(res, size, 'big')


def cast_to_matrix(values: bytes) -> INT_MATRIX:
    assert len(values) == 16
    plain = list(values)
    res = [
        plain[:4],
        plain[4: 8],
        plain[8: 12],
        plain[12: 16]
    ]
    return list(list(c) for c in zip(*res))


def cast_from_matrix(state: INT_MATRIX) -> bytes:
    state = list(zip(*state))
    state = [int(c).to_bytes(1, 'big') for c in chain(*state)]
    res = b''.join(state)
    return res


def print_state(state):
    for row in state:
        for char in row:
            print('{: <4}'.format(hex(char)), end='\t')
        print()
    print()


def _aes128_encrypt(state: bytes, key: bytes) -> bytes:
    assert len(state) == len(key) == 16, \
           "Chunk and key must be of 16 bytes size"
    state = cast_to_matrix(state)
    key = cast_to_matrix(key)
    keys = schedule_keys(key)

    state = add_round_key(state, key)
    for i in range(9):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, keys[i])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, keys[9])
    return cast_from_matrix(state)


def _aes128_decrypt(state: bytes, key: bytes) -> bytes:
    assert len(state) == len(key) == 16, \
        "Chunk and key must be of 16 bytes size"
    state = cast_to_matrix(state)
    key = cast_to_matrix(key)
    keys = schedule_keys(key)

    state = add_round_key(state, keys[-1])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)

    for i in range(8, -1, -1):
        state = add_round_key(state, keys[i])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)

    state = add_round_key(state, key)
    return cast_from_matrix(state)


def aes_encrypt(data: bytes, key: bytes, mode='CBC', iv=None, ctr_val=None) -> bytes:
    assert len(key) == 16

    if mode not in ("CBC", "CTR"):
        raise AttributeError(f'Unknown mode: {mode}')

    if len(data) % 16 != 0:
        extra = 16 - (len(data) % 16)
        data += b'0' * extra

    if mode == 'CBC':
        if not iv:
            iv = int.to_bytes(getrandbits(128), 16, 'big')
        res = iv
        prev = iv
        for i in range(0, len(data), 16):
            cur = data[i: i + 16]
            to_encrypt = xor_bytes(prev, cur)
            encrypt = _aes128_encrypt(to_encrypt, key)
            res += encrypt
            prev = encrypt
        return res

    if mode == 'CTR':
        if not ctr_val:
            iv = getrandbits(128)
            # iv = int.to_bytes(iv, 16, 'big')
        else:
            iv = ctr_val
        res = int.to_bytes(iv, 16, 'big')
        prev = iv
        for i in range(0, len(data), 16):
            cur = prev + 1
            to_encrypt = int.to_bytes(cur, 16, 'big')
            encrypted_ctr = _aes128_encrypt(to_encrypt, key)
            encrypted_msg = xor_bytes(encrypted_ctr, data[i: i + 16])
            res += encrypted_msg
            prev = cur
        return res


def aes_decrypt(data: bytes, key: bytes, mode='CBC'):
    assert len(key) == 16
    assert len(data) % 16 == 0

    if mode not in ("CBC", "CTR"):
        raise AttributeError(f'Unknown mode: {mode}')

    if mode == 'CBC':
        iv = data[:16]
        prev = iv
        res = b''
        for i in range(16, len(data), 16):
            cur = data[i: i + 16]
            decrypted = _aes128_decrypt(cur, key)
            msg_i = xor_bytes(prev, decrypted)
            prev = cur
            res += msg_i
        return res

    if mode == 'CTR':
        ctr_val = int.from_bytes(data[:16], 'big')
        raw_decrypted = aes_encrypt(data[16:], key, 'CTR', ctr_val)
        decrypted = raw_decrypted[16:]
        return decrypted



if __name__ == '__main__':
    data = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
    key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    _aes128_encrypt(data, key)
    keys = schedule_keys(cast_to_matrix(key))
    print()
    # key = int.to_bytes(0x54202020454b464d53454f455459522e, 16, 'big')
    # iv = int.to_bytes(0x4571d5668a487715ede2cfb78cd4323f, 16, ''
    #                                                           'big')
    # ct = int.to_bytes(0x70aa913e7495a7cab820c3304c939c5d6b53963f88274744e9eeb4bd31c327d9, 32, 'big')
    # print(ct)
    # from Crypto.Cipher import AES
    #
    # iv = int.to_bytes(getrandbits(128), 16, 'big')
    # key = b'qwertyuiasdfghjk'
    # cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    # msg = b'aaaaaaaabbbbbbbb'
    # ciphertext = cipher.encrypt(msg).hex()
    #
    # ct = aes_encrypt(msg, key, 'CBC', iv=iv)
    # print(ciphertext)
    # print(ct.hex()[16:])
    # print(len(msg))
    # print(len(ct))
    # print(msg)
    # print(ct)
    # pt = aes_decrypt(ct, key, 'CBC')
    # print(pt.hex())
    # print(pt)
    # ct = _aes128_encrypt(msg, key)
    # print(ct)
    # pt = _aes128_decrypt(ct, key)
    # print(pt)
    # text = b'9%\x84\x1d\x02\xdc\t\xfb\xdc\x11\x85\x97\x19j\x0b2'
    # pkey = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
    # plain_text = _aes128_decrypt(text, pkey).hex()
    # print(plain_text)
