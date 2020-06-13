#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko

from dataclasses import dataclass

from serialization import Serializable


@dataclass
class PublicKey(Serializable):
    """Struct for holding RSA public key"""
    e: int
    n: int

    @property
    def modulus_bin_size(self):
        return len(bin(self.n[2:]))


@dataclass
class PrivateKey(Serializable):
    """Struct for holding RSA private key"""
    d: int
    n: int

    @property
    def modulus_bin_size(self):
        return len(bin(self.n[2:]))
