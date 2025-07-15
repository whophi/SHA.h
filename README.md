# SHA Implementation

Single-header-library that provides all sha functions (1,2,3) in a single library.

## Header only library

SHA implementation as a header only library, based on the format introduced by [nothings/stb](https://github.com/nothings/stb)

For declarations:

```C
#include "sha.h"
```

For declarations & definitions:

```C
#define SHA_IMPLEMENTATION
#include "sha.h"
```

## Specification

- SHA 1/2: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
- SHA 3: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

## Tests

### Test Files/Cases

TEST Cases: [NIST](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)\
DEBUG Examples: [NIST (intermediate values)](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values)

### Run Tests

NOTE: Will build a executable, that allows running every sha, via command line arguments

```batch
cd ./test
make
```

## SIMD Support

Currently, only x86/x64 is supported.

Uses normal compiler flags (SSE/AVX/SHA), to figure out what to use.\
Can be disabled with:

```C
// TODO: Create separate flag for sha1, sha2_256, sha2_512, sha3?
#define SHA_NO_SIMD
```

Extensions used are:
SHA | x86_64 | arm
----|------------------------------------|-------------
sha1| SSE2, SSE3, SSE4.1, SHA | not implemented
sha2_224/256| SSE2, SSE3, SSE4.1, SHA | not implemented
sha2_384/512| SSE3, AVX2, AVX, SHA512 | not implemented
sha3| SSE2 or AVX, AVX2 | not implemented

## Other Options

Other compile time options are listed in the sha.h file.
