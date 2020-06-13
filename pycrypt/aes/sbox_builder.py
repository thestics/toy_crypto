#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko


from __future__ import annotations


byte_max = 8


def mul_by_x_n(a, n, base=0x11b):
    """Multiply polynomial by x^n (polynomial represented as byte)"""
    res = a
    for i in range(n):
        res = res << 1
        if res > 0xff:
            res = res ^ base
    return res


def mul_in_gf2_8(a, b):
    """Multiply two polynomials in GF(2^8)"""
    base = 0x11b                    # x^8 + x^4 + x^3 + x + 1
    res = 0
    le = bin(b)[2:][::-1]           # lower bits first
    for i, bin_repr in enumerate(le):
        if bin_repr == '1':         # if i-th bit == 1
            cur = mul_by_x_n(a, i)
            if cur > 0xff:
                cur ^= base
            res ^= cur
    return res


def get_inv_in_gf2_8(a):
    """Find inverse for a in GF(2^8)"""
    if a == 0:
        return 0
    assert a <= 0xff, "Element must be from GF2^8 (in range of byte values)"
    res = a
    while True:
        cur = mul_in_gf2_8(res, a)
        if cur == 0x01:
            return res
        res = cur


def left_rotate(n, d):
    """Left circular rotate"""
    d = d % 8
    return ((n << d) | (n >> (byte_max - d))) % 256


def find_sub_for_byte(a):
    inv = get_inv_in_gf2_8(a)
    res = inv ^ \
          left_rotate(inv, 1) ^ \
          left_rotate(inv, 2) ^ \
          left_rotate(inv, 3) ^ \
          left_rotate(inv, 4) ^ \
          0x63
    return res


def find_inv_sub_for_byte(a):
    res = left_rotate(a, 1) ^ left_rotate(a, 3) ^ left_rotate(a, 6) ^ 0x5
    return get_inv_in_gf2_8(res)


def build_s_box():
    s_box = [find_sub_for_byte(i) for i in range(256)]
    return s_box


def build_inv_s_box():
    inv_s_box = [find_inv_sub_for_byte(i) for i in range(256)]
    return inv_s_box


if __name__ == '__main__':
    s = build_s_box()
    t = build_inv_s_box()
    print([hex(c) for c in s])
    print([hex(c) for c in t])