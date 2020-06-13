#!/usr/bin/env python3
# -*-encoding: utf-8-*-
# Author: Danil Kovalenko


class EncoderDecoderBase:
    """
    Base class for fields encoders/decoders

    Defines set of supported types. For each supported type one must
    implement encoder and decoder classes. Latter has to implement
    `encode_<TYPENAME>` and `decode_<TYPENAME>` respectively.
    Collects all subclasses, which specify `endpoint=True` in inheritance.
    For each type defined in `supported_types` tests that one have implemented
    class <TYPENAME>Field<Encoder|Decoder>, which in turn implements
    methods `encode_<TYPENAME>` and `decode_<TYPENAME>`
    """

    supported_types = {'int' }
    endpoint_subclasses = []

    def __init_subclass__(cls, **kwargs):
        if kwargs.get('endpoint', False) is True:
            EncoderDecoderBase.endpoint_subclasses.append(cls)
        # cls.assert_consistency_with_supported_types()
    #
    # @classmethod
    # def assert_consistency_with_supported_types(cls):
    #     ...
