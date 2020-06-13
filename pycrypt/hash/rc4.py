#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko


def rc4_init(k):
    s = list(range(256))

    j = 0
    for i in range(256):
        j = (j + s[i] + k[i % len(k)]) % 256
        s[i], s[j] = s[j], s[i]
    return s


if __name__ == '__main__':
    k_ = [0 for i in range(256)]
    k1 = k_.copy()

    k2 = k_.copy()
    k2[-1] = 1

    s1 = rc4_init(k1)
    s2 = rc4_init(k2)
    print(s1)
    print(s2)

    unchanged_bytes = [i for i in range(256) if s1[i] == s2[i]]
    print(len(unchanged_bytes))

    # output:
    # [0, 35, 3, 43, 9, 11, 65, 229, 32, 36, 134, 98, 59, ...
    # [0, 35, 3, 43, 9, 11, 65, 229, 32, 36, 134, 98, 59, ...
    # 253
