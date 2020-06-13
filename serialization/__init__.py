#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko

"""
Package which implements dataclasses serialization to JSON

Implements the following structure:

- Serializable contains two objects: encoder and decoder
- For each supported value type there has to be `<TYPE>FieldEncoder(Decoder)`
    -- class  which is responsible for encoding one specific type <TYPE>
- FieldEncoder(Decoder) -- class which aggregates all implemented
    Encoders(Decoders) and provides general API to access them

More specifically


BaseEncoderDecoder
    +---------------------+
    |supported_types: set |
    +---------------------+
    |__init_subclass__    |
    |assert_consistency   |
    +---------------------+
    Defines all supported types. Ensures that there is a class, which implements
    encoding and decoding routine for each type


IntFieldEncoder(BaseEncoderDecoder)     IntFieldDecoder(BaseEncoderDecoder)
    +---------------------+                 +---------------------+
    +---------------------+                 +---------------------+
    |encode_int()         |                 |decode_int()         |
    +---------------------+                 +---------------------+
    Classes specifically responsible for encoding integer values.
    For each supported type such classes have to be implemented



FieldEncoder(IntFieldEncoder)           FieldDecoder(IntFieldDecoder)
    +---------------------+                 +---------------------+
    +---------------------+                 +---------------------+
    |encode()             |                 |decode()             |
    +---------------------+                 +---------------------+
    Aggregator classes. Have to inherit all encoders and decoder respectively


Serializable:
    +---------------------+
    |encoder: FieldEncoder|
    |decoder: FieldDecoder|
    +---------------------+
    |serialize()          |
    |deserialize()        |
    +---------------------+
    Main class to inherit to make user class serializable. Exposes
    serialization API.

This approach is flexible enough to support any desired data types, dump types.
Good in terms of factoring-out repetative code, as one may implement "proxy"
class and insert it in inheritance tree to store common code for several
encoders/decoders.

To extend supported types one may implement a following pattern:
```
class FooFieldEncoder:
    ...

class FooFieldDecoder:
    ...

class MyFieldEncoder(FieldEncoder, FooFieldEncoder):
    ...

class MyFieldDecoder(FieldDecoder, FooFieldDecoder):
    ...

class MySerializable(Serializable):
    encoder = MyFieldEncoder()
    decoder = MyFieldDecoder()
```

TBD: implement serializable factory, allow user to specify
encoders-decoders only

"""

import json
import typing as tp

from serialization.common import EncoderDecoderBase
from serialization.encoder import FieldEncoder
from serialization.decoder import FieldDecoder


encoder_func = tp.Callable[[object], tp.Dict[str, str]]
encoders = tp.Dict[str, encoder]


class Serializable:
    """
    Base class for any serializable object

    Has to be inherited to support serialization/deserialization
    """

    encoder = FieldEncoder()
    decoder = FieldDecoder()

    def encode_attrs(self):
        attrs = {k: self.encoder.encode(v) for k, v in self.__dict__.items()
                 if not callable(v)}
        return attrs

    def serialize(self, out_filename):
        attrs = self.encode_attrs()
        attrs['type'] = type(self).__name__

        with open(out_filename, 'w') as f:
            json.dump(attrs, f, indent=4)

    @classmethod
    def deserialize(cls, input_filename):
        with open(input_filename, 'r') as f:
            attrs = json.load(f)
            assert cls.__name__ == attrs['type'], \
                f"Cannot deserialize class {cls.__name__} " \
                f"from serialization built for {attrs['type']}"

            attrs.pop('type')
            decoded_attrs = {k: cls.decoder.decode(v) for k, v in attrs.items()}
            return cls(**decoded_attrs)


def serializable_factory(encoders_dict: encoders,
                         decoders_dict: encoders
                         ) -> tp.Type[Serializable]:
    """Builds `Serializable` subclass from provided custom encoders-decoders"""
    raise NotImplementedError('TBD')


__all__ = ['FieldEncoder', 'FieldDecoder', 'Serializable', 'EncoderDecoderBase']
