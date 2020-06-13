#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko

from serialization.common import EncoderDecoderBase


class IntFieldEncoder(EncoderDecoderBase, endpoint=True):

    def encode_int(self, value: int) -> dict:
        return {'type': 'int',
                'value': hex(value)[2:]}


class FieldEncoder(IntFieldEncoder):
    """
    Class for all field encoders.

    Has to inherit from all field encoders
    Implements main method `encode` which encodes value to json
    """

    def encode(self, value: object) -> dict:
        err_msg = f'Unsupported value type: {type(value).__name__}'
        if type(value).__name__ in self.supported_types:
            encoder_name = f'encode_{type(value).__name__}'
            encoder = getattr(self, encoder_name, NotImplementedError)
            if encoder is NotImplemented:
                raise NotImplementedError(err_msg)
            return encoder(value)
        else:
            raise NotImplementedError(err_msg)
