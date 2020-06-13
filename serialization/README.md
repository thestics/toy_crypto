"""
Package which implements dataclasses serialization to JSON

Implements the following structure:

- Serializable contains two objects: encoder and decoder
- For each supported value type there has to be `<TYPE>FieldEncoder(Decoder)`
    -- class  which is responsible for encoding one specific type <TYPE>
- FieldEncoder(Decoder) -- class which aggregates all implemented
    Encoders(Decoders) and provides general API to access them

More specifically


|BaseEncoderDecoder    
|:----------------------------:
|fields
|`supported_types`: set
|methods
|`__init_subclass__()`  
|`assert_consistency()`   

- Defines all supported types. Ensures that there is a class, which implements
encoding and decoding routine for each type


|IntFieldEncoder(BaseEncoderDecoder)     
|:---------------------:                 
|methods
|`encode_int()`                 

|IntFieldDecoder(BaseEncoderDecoder)     
|:---------------------:                 
|methods
|`decode_int()`                 

- Classes specifically responsible for encoding integer values.
For each supported type such classes have to be implemented



|FieldEncoder(IntFieldEncoder) 
|:---------------------: 
|methods 
|`encode()`


|FieldDecoder(IntFieldDecoder)
|:---------------------:
|methods
|`decode()`
- Aggregator classes. Have to inherit all encoders and decoder respectively


|Serializable:
|:--------------------:
|fields
|`encoder`: FieldEncoder|
|`decoder`: FieldDecoder|
|`serialize()`          |
|`deserialize()`        |
- Main class to inherit to make user class serializable. Exposes
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
