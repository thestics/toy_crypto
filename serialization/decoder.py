#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko

from serialization.common import EncoderDecoderBase


class IntFieldDecoder(EncoderDecoderBase, endpoint=True):

    def decode_int(self, value: dict) -> int:
        hex_val = value.get('value')
        real_val = int(hex_val, 16)
        return real_val


class FieldDecoder(IntFieldDecoder):
    """
    Base class for all field decoders

    Has to inherit from all field decoders
    Implements main method `decode` which decodes json value to python object
    """

    def decode(self, value: dict) -> object:
        assert 'type' in value and 'value' in value, \
            "Encoded value has to comply with: {'type': A, 'value': B} schema"

        val_type = value.get('type')
        err_msg = f'Unsupported value type: {val_type}'
        if val_type in self.supported_types:
            decoder_name = f'decode_{val_type}'
            decoder = getattr(self, decoder_name, NotImplementedError)
            if decoder is NotImplemented:
                raise NotImplementedError(err_msg)
            return decoder(value)
        else:
            raise NotImplementedError(err_msg)