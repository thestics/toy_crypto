#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko

from typing import List, Iterable
from itertools import chain

from aes.sbox_builder import build_s_box, build_inv_s_box, mul_in_gf2_8

INT_MATRIX = List[List[int]]

s_box = build_s_box()
inv_s_box = build_inv_s_box()


def xor_sum(data: Iterable[int]):
    first = True
    res = None
    for value in data:
        if first:
            res = value
            first = False
        else:
            res ^= value
    return res


def shift_rows(state: INT_MATRIX) -> INT_MATRIX:
    res = []
    for i in range(4):
        res.append(state[i][i:] + state[i][:i])
    return res


def inv_shift_rows(state: INT_MATRIX) -> INT_MATRIX:
    res = []
    for i in range(4):
        res.append(state[i][-i:] + state[i][:-i])
    return res


def _mix_columns_common(state: INT_MATRIX, mul_matrix: INT_MATRIX) -> INT_MATRIX:
    """Common routine for `mix_columns` and `inv_mix_columns`"""
    columns = list(zip(*state))
    res_columns = []
    for col in columns:
        cur_col = []
        for row in mul_matrix:
            values = [mul_in_gf2_8(col[i], row[i]) for i in range(4)]
            cur_col.append(xor_sum(values))
        res_columns.append(cur_col)
    res = list(list(c) for c in zip(*res_columns))
    return res


def mix_columns(state: INT_MATRIX) -> INT_MATRIX:
    mul_matrix = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]
    return _mix_columns_common(state, mul_matrix)


def inv_mix_columns(state: INT_MATRIX) -> INT_MATRIX:
    mul_matrix = [
        [0x0E, 0x0B, 0x0D, 0x09],
        [0x09, 0x0E, 0x0B, 0x0D],
        [0x0D, 0x09, 0x0E, 0x0B],
        [0x0B, 0x0D, 0x09, 0x0E],
    ]
    return _mix_columns_common(state, mul_matrix)


def _sub_bytes_common(state: INT_MATRIX, sub: List[int]) -> INT_MATRIX:
    """Common routine for `sub_bytes` and `inv_sub_bytes`"""
    res = [[0 for i in range(4)] for j in range(4)]
    for i in range(4):
        for j in range(4):
            val = state[i][j]
            res[i][j] = sub[val]
    return res


def sub_bytes(state: INT_MATRIX) -> INT_MATRIX:
    return _sub_bytes_common(state, s_box)


def inv_sub_bytes(state: INT_MATRIX) -> INT_MATRIX:
    return _sub_bytes_common(state, inv_s_box)


def add_round_key(state: INT_MATRIX, key: INT_MATRIX) -> INT_MATRIX:
    state_columns = list(zip(*state))
    key_columns = list(zip(*key))
    res_columns = []

    for i in range(4):
        cur_state = state_columns[i]
        cur_key = key_columns[i]
        cur_column = [cur_state[j] ^ cur_key[j] for j in range(4)]
        res_columns.append(cur_column)

    res = list(list(c) for c in zip(*res_columns))
    return res


def _derive_next_key(prev_key: INT_MATRIX,
                     round_constant: List[int]) -> INT_MATRIX:
    res_columns = []
    transposed = list(zip(*prev_key))
    last = list(transposed[-1])
    rotated = last[1:] + [last[0]]
    subbed = [s_box[c] for c in rotated]
    final = [subbed[i] ^ round_constant[i] ^ transposed[0][i] for i in range(4)]
    res_columns.append(final)

    prev = final
    for i in range(1, 4):
        col = transposed[i]
        new_col = [prev[i] ^ col[i] for i in range(4)]
        res_columns.append(new_col)
        prev = new_col

    return list(list(c) for c in zip(*res_columns))


def schedule_keys(key: INT_MATRIX):
    r_cons = [[0x01, 0, 0, 0],
              [0x02, 0, 0, 0],
              [0x04, 0, 0, 0],
              [0x08, 0, 0, 0],
              [0x10, 0, 0, 0],
              [0x20, 0, 0, 0],
              [0x40, 0, 0, 0],
              [0x80, 0, 0, 0],
              [0x1b, 0, 0, 0],
              [0x36, 0, 0, 0]]
    keys = []

    prev_key = key
    for i in range(len(r_cons)):
        next_key = _derive_next_key(prev_key, r_cons[i])
        keys.append(next_key)
        prev_key = next_key
    return keys


if __name__ == '__main__':
    cur_key = [[0x2b, 0x28, 0xab, 0x9],
               [0x7e, 0xae, 0xf7, 0xcf],
               [0x15, 0xd2, 0x15, 0x4f],
               [0x16, 0xa6, 0x88, 0x3c]]
    keys = schedule_keys(cur_key)
    # from pprint import pprint
    # pprint(next_key)
    for key in keys:
        for line in key:
            for c in line:
                print("{0: >4}".format(hex(c)), end='\t')
            print()
        print()
