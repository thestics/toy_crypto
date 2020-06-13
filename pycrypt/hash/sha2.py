#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko

INT_BIN_SIZE = 32
MAX_INT = 1 << INT_BIN_SIZE


def message_to_int(msg):
    assert isinstance(msg, (str, bytes, int))
    res = 0
    for c in msg:
        if isinstance(msg, str):
            code = ord(c)
        elif isinstance(msg, bytes):
            code = c
        res <<= 8
        res |= code
    return res


class BinOps:
    """Extra binary operations"""

    @staticmethod
    def slices_n(target: int, n: int):
        """Slices `target` in chunks of size `n`"""
        res = []
        message = target
        cur = (1 << n) - 1
        while message > 0:
            res.append(cur & message)
            message >>= n
        return reversed(res)

    @staticmethod
    def rotr(target: int, n: int):
        """Rotate to right"""
        if target == 0: return 0
        s = 32
        n = n % s
        return ((target >> n) | (target << (s - n))) % (1 << s)

    @staticmethod
    def rotl(target: int, n: int):
        """Rotate to left"""
        if target == 0: return 0
        s = 32
        n = n % s
        return ((target << n) | (target >> (s - n))) % (1 << s)

    @staticmethod
    def shr(target: int, n: int):
        """Shift to right"""
        return target >> n


class SHA256(BinOps):

    h = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
         0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

    k = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
         0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
         0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
         0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
         0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
         0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
         0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
         0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
         0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
         0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
         0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
         0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
         0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
         0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
         0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
         0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2]

    DIGEST_SIZE = 512
    MSG_MAX_BIT_LEN = 64

    _input_raw: str
    _input_int: int

    def __init__(self, message):
        self._input_raw = message
        self._input_int = message_to_int(message)
        self._digest = 0
        self._padded = False

    @classmethod
    def from_int(cls, val):
        """From explicit desired internal value"""
        obj = cls.__new__(cls)
        obj._input_int = val
        h = hex(val)[2:]
        if len(h) % 2 != 0:
            h = '0' + h
        obj._input_raw = bytes.fromhex(h)
        return obj

    @property
    def msg_bin_size(self):
        return self._input_int.bit_length()

    def _pad(self):
        L = len(self._input_raw) * 8
        K = (448 - L - 1) % self.DIGEST_SIZE
        self._input_int <<= 1
        self._input_int |= 0x1

        self._input_int <<= (K + 64)
        self._input_int |= L
        self._padded = True

    def update(self, new_message):
        self._padded = False
        self._input_raw += new_message
        self._input_int = int(self._input_raw, 16)
        self._digest = 0

    def _build_words(self, piece):
        w = list(self.slices_n(piece, INT_BIN_SIZE))
        assert len(w) == 16

        for i in range(16, 64):
            x = w[i - 15]
            y = w[i - 2]
            s0 = self.rotr(x, 7) ^ self.rotr(x, 18) ^ self.shr(x, 3)
            s1 = self.rotr(y, 17) ^ self.rotr(y, 19) ^ self.shr(y, 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) % MAX_INT)
        assert len(w) == 64
        return w

    def _sha_step(self, variables, w, i):
        """Performs one step of SHA mainloop"""
        a, b, c, d, e, f, g, h = variables
        S0 = self.rotr(a, 2) ^ self.rotr(a, 13) ^ self.rotr(a, 22)
        Ma = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + Ma) % MAX_INT

        S1 = self.rotr(e, 6) ^ self.rotr(e, 11) ^ self.rotr(e, 25)
        Ch = (e & f) ^ ((~e) & g)
        t1 = (h + S1 + Ch + self.k[i] + w[i]) % MAX_INT

        h = g
        g = f
        f = e
        e = (d + t1) % MAX_INT
        d = c
        c = b
        b = a
        a = (t1 + t2) % MAX_INT
        return a, b, c, d, e, f, g, h

    def digest(self) -> bytes:
        self._pad()
        hash_words = self.h.copy()

        for piece in self.slices_n(self._input_int, self.DIGEST_SIZE):
            w = self._build_words(piece)
            variables = self.h.copy()

            for i in range(64):
                variables = self._sha_step(variables, w, i)
                assert all(c.bit_length() <= 32 for c in variables), \
                    "Overgrowth at iter: " + str(i)

            hash_words = [(hash_words[i] + variables[i]) % MAX_INT
                          for i in range(8)]
            self.h = hash_words

        digest = 0
        for w in hash_words:
            digest <<= 32
            digest = digest | w
        self._digest = digest
        return int.to_bytes(digest, 32, 'big')

    def hex_digest(self) -> str:
        self.digest()
        return hex(self._digest)[2:]


def cli_main():
    import sys
    s = sys.stdin.read()
    print(len(s))
    print(SHA256(s).hex_digest())


if __name__ == '__main__':
    cli_main()