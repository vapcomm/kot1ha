# kot1ha

Pure Kotlin t1ha2 hash function implementation translated from original C sources.

`t1ha2` 64-bit hash function is one of the fastest non-cryptographic hash functions. It's suitable for hash maps, caches and
similar data structures where speed is more important than security and collision resistance.

This `t1ha2` variant is very portable in Kotlin world, was made with "speed in mind" and very close to original C sources.

## Usage

Simplest way to use `kot1ha` in your project is to put `koT1haAtOnce.kt` file and unit tests in your source tree
and call `koT1ha2AtOnce(data, seed)` function. For KMM project it may be `commonMain` and `commonTest`, for Kotlin Native - 
`nativeMain` and `nativeTest` directories respectively.

Result of koT1ha2AtOnce() function is 8 bytes of the hash value packed in ByteArray in big endian bytes order,
it's very useful for comparison, encoding to Hex or Base64 strings. See `KoT1ha2AtOnceTest` for usage examples. 

## License

We use MIT License to keep this project really free. See LICENCE file for details.
