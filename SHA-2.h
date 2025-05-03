/*
  SHA.h - v0.1 - Phil Wihler 2025

  Single-header-library that provides all sha functions (1,2,3) in a single library.

  SPECIFICATION:
    - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

  COMPILE-TIME OPTIONS

    #define SHA_2_IMPLEMENTATION
      Includes the implementation of the library.

    #define SHA_LIB_STATIC
      Sets all functions to be static.
      Default is extern.

    #define SHA_DEF
      Allows putting anything before each function (eg. static, extern).
      If set, #define SHA_LIB_STATIC does nothing.

    #define SHA2_ASSERT
      Set the assert function used.
      Has to be an expression.
      WARNING: The default implementation uses <stdio.h> and <stdlib.h>.

    #define SHA2_NO_STRING_INCLUDE
      Prevents the import of <string.h>.
      If this is defined, SHA2_MEMSET and SHA_MEMCPY have to also be defined

    #define SHA2_MEMSET
    #define SHA_MEMCPY
      Allows setting own functions for memory operations.

    #define SHA_NO_SIMD
      Prevents the use of <immintrin.h> and thereby the use of any intrinsics
      This makes it slower, as it will use a normal c implementation instead of the sha intrinsics.
      Used extensions are:
        x86: __SSE2__, __SSE3__, __SSE4_1__, __SSE4_2__ and __SHA__
        arm: NOT IMPLEMENTED

    #define SHA_NO_RUNTIME_INTRINSICS (NOT IMPLEMENTED)
      Prevents the test for available intrinsics at runtime
      // TODO: Implement testing for intrinsics at runtime

    #define SHA_IS_X86
      Sets the architecture to be x86 32 or 64 bit.
      The defaults is checking for compiler defined macros like __i386__.

    #define SHA_WORD_TYPE_32
    #define SHA_WORD_TYPE_64
      Allows setting the used type for a 32 and 64 bit word.
      Default is uint32_t and uint64_t;

    #define SHA_IS_BIG_ENDIAN
      Allows to specify a check for the endianess of the system.
      Can be an expression, evaluated at run time, or a constant.

    #define SHA2_ROTR
    #define SHA2_ROTL
      Allows defining custom rotation operations.
      The signature is (WS, x, n), where WS is the word size (32,64), x is the value and n is the shift amount.
      The defaults are implemented using shifts and ORs.

*/

#ifndef _SHA_2_
#define _SHA_2_

// --------------------
// Includes
// --------------------

// TODO: something for static_assert
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

// --------------------------
// Defines
// --------------------------

#ifndef SHA_DEF
#ifdef SHA_LIB_STATIC
#define SHA_DEF static
#else  // SHA_LIB_STATIC
#define SHA_DEF extern
#endif // SHA_LIB_STATIC
#endif // SHA_DEF

// Assert
#ifndef SHA2_ASSERT
#include <stdio.h>
#include <stdlib.h>
int sha_assert_empty();
#ifdef SHA_2_IMPLEMENTATION
int sha_assert_empty() { return 0; }
#endif // SHA_2_IMPLEMENTATION
#define SHA2_ASSERT(cond, message) \
  (!!(cond) ? sha_assert_empty()   \
            : (printf("%s:%d:ASSERT FAILED: %s\n", __FILE__, __LINE__, message), exit(1), sha_assert_empty()))
#endif // SHA2_ASSERT

// Memory Functions
#ifndef SHA2_NO_STRING_INCLUDE
#include <string.h>
#ifndef SHA2_MEMSET
#define SHA2_MEMSET(dest, value, size) memset(dest, value, size)
#endif // SHA2_MEMSET
#ifndef SHA_MEMCPY
#define SHA_MEMCPY(dest, src, size) memcpy(dest, src, size)
#endif // SHA_MEMCPY
#else  // SHA2_NO_STRING_INCLUDE
#ifndef SHA2_MEMSET
static_assert("SHA2_MEMSET not defined without string.h");
#endif // SHA2_MEMSET
#ifndef SHA_MEMCPY
static_assert("SHA_MEMCPY not defined without string.h");
#endif // SHA_MEMCPY
#endif // SHA2_NO_STRING_INCLUDE

#ifndef SHA_NO_SIMD
#include <immintrin.h>
#define SHA_IS_X86_32 defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
#define SHA_IS_X86_64 defined(__x86_64__) || defined(_M_X64)
#ifndef SHA_IS_X86
#define SHA_IS_X86 (SHA_IS_X86_32 || SHA_IS_X86_64)
#endif // SHA_IS_X86
#endif // SHA_NO_SIMD

// -------------------
// Values
// -------------------

// SHA VALUES
#define SHA1                          1
#define SHA2_224                      224
#define SHA2_256                      256
#define SHA2_384                      384
#define SHA2_512                      512
#define SHA2_512_224                  512224
#define SHA2_512_256                  512256

#define SHA2_HASH_SIZE_1              160
#define SHA2_HASH_SIZE_224            224
#define SHA2_HASH_SIZE_256            256
#define SHA2_HASH_SIZE_384            384
#define SHA2_HASH_SIZE_512            512
#define SHA2_HASH_SIZE_512224         SHA2_HASH_SIZE_224
#define SHA2_HASH_SIZE_512256         SHA2_HASH_SIZE_256
#define _SHA2_HASH_SIZE(SHA_SIZE)     SHA2_HASH_SIZE_##SHA_SIZE
#define SHA2_HASH_SIZE(SHA_SIZE)      _SHA2_HASH_SIZE(SHA_SIZE)

#define SHA2_BLOCK_SIZE_1             512
#define SHA2_BLOCK_SIZE_224           512
#define SHA2_BLOCK_SIZE_256           512
#define SHA2_BLOCK_SIZE_384           1024
#define SHA2_BLOCK_SIZE_512           1024
#define SHA2_BLOCK_SIZE_512224        1024
#define SHA2_BLOCK_SIZE_512256        1024
#define _SHA2_BLOCK_SIZE(SHA_SIZE)    SHA2_BLOCK_SIZE_##SHA_SIZE
#define SHA2_BLOCK_SIZE(SHA_SIZE)     _SHA2_BLOCK_SIZE(SHA_SIZE)

#define SHA2_WORD_SIZE_SHA_1          32
#define SHA2_WORD_SIZE_SHA_224        32
#define SHA2_WORD_SIZE_SHA_256        32
#define SHA2_WORD_SIZE_SHA_384        64
#define SHA2_WORD_SIZE_SHA_512        64
#define SHA2_WORD_SIZE_SHA_512224     64
#define SHA2_WORD_SIZE_SHA_512256     64
#define _SHA2_WORD_SIZE(SHA_SIZE)     SHA2_WORD_SIZE_SHA_##SHA_SIZE
#define SHA2_WORD_SIZE(SHA_SIZE)      _SHA2_WORD_SIZE(SHA_SIZE)

#define SHA2_WORDS_IN_BLOCK(SHA_SIZE) (SHA2_BLOCK_SIZE(SHA_SIZE) / SHA2_WORD_SIZE(SHA_SIZE))
#define SHA2_WORDS_IN_HASH(SHA_SIZE)  (SHA2_HASH_SIZE(SHA_SIZE) / SHA2_WORD_SIZE(SHA_SIZE))

#define SHA_WORD_TYPE_32              uint32_t
#define SHA_WORD_TYPE_64              uint64_t
#define __SHA2_WORD_TYPE(WS)          SHA_WORD_TYPE_##WS
#define _SHA2_WORD_TYPE(WS)           __SHA2_WORD_TYPE(WS)
#define SHA_WORD_TYPE(SHA)            _SHA2_WORD_TYPE(SHA2_WORD_SIZE(SHA))

// --------------------------
// Basic Operations
// --------------------------
#define SHA2_NOT(WS, a)    (~((_SHA2_WORD_TYPE(WS))(a)))
#define SHA2_OR(WS, a, b)  (((_SHA2_WORD_TYPE(WS))(a)) | ((_SHA2_WORD_TYPE(WS))(b)))
#define SHA2_AND(WS, a, b) (((_SHA2_WORD_TYPE(WS))(a)) & ((_SHA2_WORD_TYPE(WS))(b)))
#define SHA2_XOR(WS, a, b) (((_SHA2_WORD_TYPE(WS))(a)) ^ ((_SHA2_WORD_TYPE(WS))(b)))
#define SHA2_SHR(WS, x, n) (((_SHA2_WORD_TYPE(WS))(x)) >> (n))
#define SHA2_SHL(WS, x, n) (((_SHA2_WORD_TYPE(WS))(x)) << (n))

#ifndef SHA2_ROTR
#define SHA2_ROTR(WS, x, n) SHA2_OR(WS, SHA2_SHR(WS, x, n), SHA2_SHL(WS, x, (WS) - (n)))
#endif // SHA2_ROTR
#ifndef SHA2_ROTL
#define SHA2_ROTL(WS, x, n) SHA2_OR(WS, SHA2_SHL(WS, x, n), SHA2_SHR(WS, x, (WS) - (n)))
#endif // SHA2_ROTL

// -------------------------
// Intrinsics
// -------------------------
#ifndef SHA_NO_SIMD
#define SHA2_ROTL_MM_32(x, n)   _mm_or_epi32(_mm_sll_epi32(x, _mm_set1_epi32(n)), _mm_srl_epi32(x, _mm_set1_epi32(32 - n)))
#define SHA2_ROTL_MM_64(x, n)   _mm_or_epi64(_mm_sll_epi64(x, _mm_set1_epi64(n)), _mm_srl_epi64(x, _mm_set1_epi64(64 - n)))
#define _SHA2_ROTL_MM(WS, x, n) SHA2_ROTL_MM_##WS(x, n)
#define SHA2_ROTL_MM(WS, x, n)  _SHA2_ROTL_MM(WS, x, n)

#define SHA2_ROTR_MM_32(x, n)   _mm_or_epi32(_mm_srl_epi32(x, _mm_set1_epi32(n)), _mm_sll_epi32(x, _mm_set1_epi32(32 - n)))
#define SHA2_ROTR_MM_64(x, n)   _mm_or_epi64(_mm_srl_epi64(x, _mm_set1_epi64(n)), _mm_sll_epi64(x, _mm_set1_epi64(64 - n)))
#define _SHA2_ROTR_MM(WS, x, n) SHA2_ROTR_MM_##WS(x, n)
#define SHA2_ROTR_MM(WS, x, n)  _SHA2_ROTR_MM(WS, x, n)
#endif // SHA_NO_SIMD

// --------------------------
// Byte Swap (little/big endian)
// --------------------------

// Little- or Bigendian
#ifndef SHA_IS_BIG_ENDIAN
#define SHA_IS_BIG_ENDIAN \
  (!(union {              \
      uint16_t      u16;  \
      unsigned char c;    \
    }) { .u16 = 1 }       \
        .c)
#endif // SHA_IS_BIG_ENDIAN

// (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))
#define _SHA2_BYTE_SWAP_32(x)                                                             \
  SHA2_OR(                                                                                \
      32, SHA2_OR(32, SHA2_SHR(32, x, 24), SHA2_SHR(32, SHA2_AND(32, x, 0x00FF0000), 8)), \
      SHA2_OR(32, SHA2_SHL(32, SHA2_AND(32, x, 0x0000FF00), 8), SHA2_SHL(32, x, 24)))

// ((((x) >> 56) & 0x00000000000000FF) | (((x) >> 40) & 0x000000000000FF00) | (((x) >> 24) & 0x0000000000FF0000) |
//   (((x) >> 8) & 0x00000000FF000000) | (((x) << 8) & 0x000000FF00000000) | (((x) << 24) & 0x0000FF0000000000) |
//   (((x) << 40) & 0x00FF000000000000) | (((x) << 56) & 0xFF00000000000000))
#define _SHA2_BYTE_SWAP_64_R(x)                                                                                                  \
  SHA2_OR(                                                                                                                       \
      64,                                                                                                                        \
      SHA2_OR(64, SHA2_AND(64, SHA2_SHR(64, x, 56), 0x00000000000000FF), SHA2_AND(64, SHA2_SHR(64, x, 40), 0x000000000000FF00)), \
      SHA2_OR(64, SHA2_AND(64, SHA2_SHR(64, x, 24), 0x0000000000FF0000), SHA2_AND(64, SHA2_SHR(64, x, 8), 0x00000000FF000000)))
#define _SHA2_BYTE_SWAP_64_L(x)                                                                                                 \
  SHA2_OR(                                                                                                                      \
      64,                                                                                                                       \
      SHA2_OR(64, SHA2_AND(64, SHA2_SHL(64, x, 8), 0x000000FF00000000), SHA2_AND(64, SHA2_SHL(64, x, 24), 0x0000FF0000000000)), \
      SHA2_OR(64, SHA2_AND(64, SHA2_SHL(64, x, 40), 0x00FF000000000000), SHA2_AND(64, SHA2_SHL(64, x, 56), 0xFF00000000000000)))
#define _SHA2_BYTE_SWAP_64(x)                 SHA2_OR(64, _SHA2_BYTE_SWAP_64_R(x), _SHA2_BYTE_SWAP_64_L(x))
#define _SHA2_BYTE_SWAP(WS, x)                _SHA2_BYTE_SWAP_##WS(x)
#define SHA2_BYTE_SWAP_WS(WS, x)              _SHA2_BYTE_SWAP(WS, x)
#define SHA_BYTE_SWAP(SHA_SIZE, x)            SHA2_BYTE_SWAP_WS(SHA2_WORD_SIZE(SHA_SIZE), x)

#define SHA2_BYTE_SWAP_IF_LITTLE(SHA_SIZE, x) (SHA_IS_BIG_ENDIAN ? (x) : SHA_BYTE_SWAP(SHA_SIZE, x))
#define SHA2_BYTE_SWAP_IF_LITTLE_WS(WS, x)    (SHA_IS_BIG_ENDIAN ? (x) : SHA2_BYTE_SWAP_WS(WS, x))

// ---------------
// Min/Max
// ---------------
#define SHA2_MIN(x, y) ((x) < (y) ? (x) : (y))
#define SHA2_MAX(x, y) ((x) > (y) ? (x) : (y))

// --------------------------
// SHA Specific Operations
// --------------------------
#define SHA2_CH(WS, x, y, z)  SHA2_XOR(WS, SHA2_AND(WS, x, y), SHA2_AND(WS, SHA2_NOT(WS, x), z))
#define SHA2_MAJ(WS, x, y, z) SHA2_XOR(WS, SHA2_XOR(WS, SHA2_AND(WS, x, y), SHA2_AND(WS, x, z)), SHA2_AND(WS, y, z))

// SHA1
#define _SHA1_PARITY(WS, x, y, z) SHA2_XOR(WS, x, SHA2_XOR(WS, y, z))
#define _SHA1_40_59(x, y, z)      SHA2_MAJ(SHA2_WORD_SIZE(SHA1), x, y, z)
#define _SHA1_20_39_60_79(t, x, y, z) \
  (t < 40 || (60 <= t && t < 80) ? _SHA1_PARITY(SHA2_WORD_SIZE(SHA1), x, y, z) : _SHA1_40_59(x, y, z))
#define _SHA1_0_19(t, x, y, z) (0 <= t && t < 20 ? SHA2_CH(SHA2_WORD_SIZE(SHA1), x, y, z) : _SHA1_20_39_60_79(t, x, y, z))
#define SHA1_F(t, x, y, z)     _SHA1_0_19(t, x, y, z)

// SHA2
#define SHA2_SIGMA_LARGE(WS, x, n0, n1, n2) \
  SHA2_XOR(WS, SHA2_XOR(WS, SHA2_ROTR(WS, x, n0), SHA2_ROTR(WS, x, n1)), SHA2_ROTR(WS, x, n2))
#define SHA2_SIGMA_SMALL(WS, x, n0, n1, n2) \
  SHA2_XOR(WS, SHA2_XOR(WS, SHA2_ROTR(WS, x, n0), SHA2_ROTR(WS, x, n1)), SHA2_SHR(WS, x, n2))

// --------------------------
// API
// --------------------------
#ifdef __cplusplus
extern "C" {
#endif

  // TODO: Add function, that prints infos, such as if simd is used

  // Block Types
  typedef struct {
    union {
      uint8_t bytes[SHA2_BLOCK_SIZE(SHA2_256) / 8];
      SHA_WORD_TYPE(SHA2_256) words[SHA2_WORDS_IN_BLOCK(SHA2_256)];
      uint64_t sizes[SHA2_BLOCK_SIZE(SHA2_256) / 64];
    };
  } sha2_block_256_t;

  typedef struct {
    union {
      uint8_t bytes[SHA2_BLOCK_SIZE(SHA2_512) / 8];
      SHA_WORD_TYPE(SHA2_512) words[SHA2_WORDS_IN_BLOCK(SHA2_512)];
    };
  } sha2_block_512_t;

  // Hash Types
#define _SHA2_HASH_TYPE_NAME(SHA_SIZE) sha_##SHA_SIZE##_t
#define _SHA2_HASH_TYPE(SHA_SIZE)                                \
  typedef struct {                                               \
    SHA_WORD_TYPE(SHA_SIZE) words[SHA2_WORDS_IN_HASH(SHA_SIZE)]; \
  } _SHA2_HASH_TYPE_NAME(SHA_SIZE)

  // SHA 1
  typedef struct {
    SHA_WORD_TYPE(SHA1) words[SHA2_WORDS_IN_HASH(SHA1)];
  } sha1_t;
  // SHA 2/3
  _SHA2_HASH_TYPE(SHA2_224);
  _SHA2_HASH_TYPE(SHA2_256);
  _SHA2_HASH_TYPE(SHA2_384);
  _SHA2_HASH_TYPE(SHA2_512);

  // Byte Types
  // SHA 1
  typedef struct {
    uint8_t bytes[SHA2_HASH_SIZE(SHA1) / 8];
  } sha1_bytes_t;
  // SHA 2/3
  typedef struct {
    uint8_t bytes[SHA2_HASH_SIZE(SHA2_224) / 8];
  } sha_224_bytes_t;
  typedef struct {
    uint8_t bytes[SHA2_HASH_SIZE(SHA2_256) / 8];
  } sha_256_bytes_t;
  typedef struct {
    uint8_t bytes[SHA2_HASH_SIZE(SHA2_384) / 8];
  } sha_384_bytes_t;
  typedef struct {
    uint8_t bytes[SHA2_HASH_SIZE(SHA2_512) / 8];
  } sha_512_bytes_t;

  // Contexts
  typedef struct {
    sha2_block_256_t block;
    uint64_t         block_count;
    uint16_t         bit_count;
    sha1_t           hash;
  } sha1_ctx;

  typedef struct {
    sha2_block_256_t block;
    uint64_t         block_count;
    uint16_t         bit_count;
    sha_256_t        hash;
  } sha2_256_ctx;

  typedef struct {
    sha2_block_512_t block;
    uint64_t         block_count_low;
    uint64_t         block_count_high;
    uint16_t         bit_count;
    sha_512_t        hash;
  } sha2_512_ctx;

  typedef struct {
    union {
      uint8_t  bytes[5 * 5 * sizeof(uint64_t)];
      uint64_t words[5 * 5];
    };
  } sha3_state_t;
  typedef struct {
    uint8_t bytes[1600 / 8];
  } sha3_block_t;

  typedef struct {
    uint16_t     d;
    sha3_state_t state;
    sha3_block_t pi;
    uint16_t     r;
    uint16_t     bit_count;
  } sha3_ctx;

  // ---------------------
  // Reset Context
  // ---------------------
  // SHA 1
  SHA_DEF void sha1_reset(sha1_ctx* ctx);
  // SHA2
  SHA_DEF void sha2_224_reset(sha2_256_ctx* ctx);
  SHA_DEF void sha2_256_reset(sha2_256_ctx* ctx);
  SHA_DEF void sha2_384_reset(sha2_512_ctx* ctx);
  SHA_DEF void sha2_512_reset(sha2_512_ctx* ctx);
  SHA_DEF void sha2_512_224_reset(sha2_512_ctx* ctx);
  SHA_DEF void sha2_512_256_reset(sha2_512_ctx* ctx);
  // SHA 3
  SHA_DEF void sha3_224_reset(sha3_ctx* ctx);
  SHA_DEF void sha3_256_reset(sha3_ctx* ctx);
  SHA_DEF void sha3_384_reset(sha3_ctx* ctx);
  SHA_DEF void sha3_512_reset(sha3_ctx* ctx);

  // -------------------------
  // Append
  // -------------------------
  // SHA 1
  SHA_DEF void sha1_append_bytes(sha1_ctx* ctx, const uint8_t* data, uint64_t byte_count);
  SHA_DEF void sha1_append_bits(sha1_ctx* ctx, const uint8_t* data, uint64_t bit_count);
  SHA_DEF void sha1_append(sha1_ctx* ctx, const uint8_t* data, uint64_t bit_count);
  // SHA 2
  SHA_DEF void sha2_256_append_bytes(sha2_256_ctx* ctx, const uint8_t* data, uint64_t byte_count);
  SHA_DEF void sha2_256_append_bits(sha2_256_ctx* ctx, const uint8_t* data, uint64_t bit_count);
  SHA_DEF void sha2_256_append(sha2_256_ctx* ctx, const uint8_t* data, uint64_t bit_count);
  SHA_DEF void sha2_512_append_bytes(sha2_512_ctx* ctx, const uint8_t* data, uint64_t byte_count);
  SHA_DEF void sha2_512_append_bits(sha2_512_ctx* ctx, const uint8_t* data, uint64_t bit_count);
  SHA_DEF void sha2_512_append(sha2_512_ctx* ctx, const uint8_t* data, uint64_t bit_count);
  // SHA 3
  SHA_DEF void sha3_append_bytes(sha3_ctx* ctx, const uint8_t* data, uint64_t byte_count);
  SHA_DEF void sha3_append_bits(sha3_ctx* ctx, const uint8_t* data, uint64_t bit_count);
  SHA_DEF void sha3_append(sha3_ctx* ctx, const uint8_t* data, uint64_t bit_count);

  // -----------------------
  // Get Hash (and reset)
  // -----------------------
  // SHA 1
  SHA_DEF sha1_t sha1_get_hash(sha1_ctx* ctx);
  // SHA 2
  SHA_DEF sha_224_t sha2_224_get_hash(sha2_256_ctx* ctx);
  SHA_DEF sha_256_t sha2_256_get_hash(sha2_256_ctx* ctx);
  SHA_DEF sha_384_t sha2_384_get_hash(sha2_512_ctx* ctx);
  SHA_DEF sha_512_t sha2_512_get_hash(sha2_512_ctx* ctx);
  SHA_DEF sha_224_t sha2_512_224_get_hash(sha2_512_ctx* ctx);
  SHA_DEF sha_256_t sha2_512_256_get_hash(sha2_512_ctx* ctx);

  // --------------------
  // Words to bytes
  // Convert the normal sha2_xxx_t containing words, to sha2_xxx_bytes_t containing bytes
  // --------------------
  // SHA 1
  SHA_DEF void sha1_to_bytes(sha1_t h, uint8_t* bytes_out);
  // SHA 2/3
  SHA_DEF void sha_224_to_bytes(sha_224_t h, uint8_t* bytes_out);
  SHA_DEF void sha_256_to_bytes(sha_256_t h, uint8_t* bytes_out);
  SHA_DEF void sha_384_to_bytes(sha_384_t h, uint8_t* bytes_out);
  SHA_DEF void sha_512_to_bytes(sha_512_t h, uint8_t* bytes_out);

  // ----------------
  // Bytes to words
  // ----------------
  // SHA 1
  SHA_DEF void sha1_from_bytes(uint8_t* bytes, sha1_t* hash_out);
  // SHA 2/3
  SHA_DEF void sha_224_from_bytes(uint8_t* bytes, sha_224_t* hash_out);
  SHA_DEF void sha_256_from_bytes(uint8_t* bytes, sha_256_t* hash_out);
  SHA_DEF void sha_384_from_bytes(uint8_t* bytes, sha_384_t* hash_out);
  SHA_DEF void sha_512_from_bytes(uint8_t* bytes, sha_512_t* hash_out);

  // --------------------
  // Compare
  // --------------------
  // SHA 1
  SHA_DEF bool sha1_is_equal(const sha1_t* a, const sha1_t* b);
  // SHA 2
  SHA_DEF bool sha_224_is_equal(const sha_224_t* a, const sha_224_t* b);
  SHA_DEF bool sha_256_is_equal(const sha_256_t* a, const sha_256_t* b);
  SHA_DEF bool sha_384_is_equal(const sha_384_t* a, const sha_384_t* b);
  SHA_DEF bool sha_512_is_equal(const sha_512_t* a, const sha_512_t* b);

  // ----------------------
  // To String
  // Note: Not thread save (static buffer in fn)
  // ----------------------
  // SHA 1
  SHA_DEF const char* sha1_to_string(const sha1_t* h, bool upper_case);
  // SHA 2
  SHA_DEF const char* sha_224_to_string(const sha_224_t* h, bool upper_case);
  SHA_DEF const char* sha_256_to_string(const sha_256_t* h, bool upper_case);
  SHA_DEF const char* sha_384_to_string(const sha_384_t* h, bool upper_case);
  SHA_DEF const char* sha_512_to_string(const sha_512_t* h, bool upper_case);

  // ---------------------
  // Constants
  // ---------------------
#ifdef SHA_2_IMPLEMENTATION
  static SHA_WORD_TYPE(SHA1) sha1_K(size_t t)
  {
    if (t < 20) return 0x5a827999;
    else if (t < 40) return 0x6ed9eba1;
    else if (t < 60) return 0x8f1bbcdc;
    else if (t < 80) return 0xca62c1d6;
    else SHA2_ASSERT(false, "t out of range 0-79");
  }
#endif // SHA_2_IMPLEMENTATION

#ifdef SHA_2_IMPLEMENTATION
  static _SHA2_WORD_TYPE(32) SHA2_CONST_224_256[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  };
#endif // SHA_2_IMPLEMENTATION

#ifdef SHA_2_IMPLEMENTATION
  static _SHA2_WORD_TYPE(64) SHA2_CONST_384_512[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
  };
#endif // SHA_2_IMPLEMENTATION

  // Initial Hash Value
#ifdef SHA_2_IMPLEMENTATION
  static SHA_WORD_TYPE(SHA1) SHA2_CONST_INITIAL_1[] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
#endif

#ifdef SHA_2_IMPLEMENTATION
  static SHA_WORD_TYPE(SHA2_224) SHA2_CONST_INITIAL_224[] = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
  };
#endif

#ifdef SHA_2_IMPLEMENTATION
  static SHA_WORD_TYPE(SHA2_256) SHA2_CONST_INITIAL_256[] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  };
#endif

#ifdef SHA_2_IMPLEMENTATION
  static SHA_WORD_TYPE(SHA2_384) SHA2_CONST_INITIAL_384[] = {
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
  };
#endif

#ifdef SHA_2_IMPLEMENTATION
  static SHA_WORD_TYPE(SHA2_512) SHA2_CONST_INITIAL_512[] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
  };
#endif

#ifdef SHA_2_IMPLEMENTATION
  static SHA_WORD_TYPE(SHA2_512_224) SHA2_CONST_INITIAL_512_224[] = {
    0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
  };
#endif

#ifdef SHA_2_IMPLEMENTATION
  static SHA_WORD_TYPE(SHA2_512_256) SHA2_CONST_INITIAL_512_256[] = {
    0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
    0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
  };
#endif

// ----------------------
// Implementation
// ----------------------

// ------------------
// Context reset
// ------------------
#ifdef SHA_2_IMPLEMENTATION
  // SHA 1
  SHA_DEF void sha1_reset(sha1_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_1[i];
    }
    ctx->block_count = 0;
    ctx->bit_count   = 0;
    // TODO: When removing this set, have to change |= in append_bits
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_224) / 8);
  }
  // SHA 2
  SHA_DEF void sha2_224_reset(sha2_256_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_224[i];
    }
    ctx->block_count = 0;
    ctx->bit_count   = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_224) / 8);
  }
  SHA_DEF void sha2_256_reset(sha2_256_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_256[i];
    }
    ctx->block_count = 0;
    ctx->bit_count   = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_256) / 8);
  }
  SHA_DEF void sha2_384_reset(sha2_512_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_384[i];
    }
    ctx->block_count_low  = 0;
    ctx->block_count_high = 0;
    ctx->bit_count        = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_384) / 8);
  }
  SHA_DEF void sha2_512_reset(sha2_512_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_512[i];
    }
    ctx->block_count_low  = 0;
    ctx->block_count_high = 0;
    ctx->bit_count        = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_512) / 8);
  }
  SHA_DEF void sha2_512_224_reset(sha2_512_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_512_224[i];
    }
    ctx->block_count_low  = 0;
    ctx->block_count_high = 0;
    ctx->bit_count        = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_512) / 8);
  }
  SHA_DEF void sha2_512_256_reset(sha2_512_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_512_256[i];
    }
    ctx->block_count_low  = 0;
    ctx->block_count_high = 0;
    ctx->bit_count        = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_512) / 8);
  }
  // SHA 3
  SHA_DEF void sha3_224_reset(sha3_ctx* ctx)
  {
    SHA2_MEMSET(ctx->state.bytes, 0, sizeof(ctx->state.bytes));
    SHA2_MEMSET(ctx->pi.bytes, 0, sizeof(ctx->pi.bytes));
    ctx->bit_count = 0;
    ctx->d         = 224;
    ctx->r         = 1600 - 448;
  }
  SHA_DEF void sha3_256_reset(sha3_ctx* ctx)
  {
    SHA2_MEMSET(ctx->state.bytes, 0, sizeof(ctx->state.bytes));
    SHA2_MEMSET(ctx->pi.bytes, 0, sizeof(ctx->pi.bytes));
    ctx->bit_count = 0;
    ctx->d         = 256;
    ctx->r         = 1600 - 512;
  }
  SHA_DEF void sha3_384_reset(sha3_ctx* ctx)
  {
    SHA2_MEMSET(ctx->state.bytes, 0, sizeof(ctx->state.bytes));
    SHA2_MEMSET(ctx->pi.bytes, 0, sizeof(ctx->pi.bytes));
    ctx->bit_count = 0;
    ctx->d         = 384;
    ctx->r         = 1600 - 768;
  }
  SHA_DEF void sha3_512_reset(sha3_ctx* ctx)
  {
    SHA2_MEMSET(ctx->state.bytes, 0, sizeof(ctx->state.bytes));
    SHA2_MEMSET(ctx->pi.bytes, 0, sizeof(ctx->pi.bytes));
    ctx->bit_count = 0;
    ctx->d         = 512;
    ctx->r         = 1600 - 1024;
  }
  SHA_DEF void sha3_shake128_reset(sha3_ctx* ctx, unsigned int hash_bit_count)
  {
    SHA2_MEMSET(ctx->state.bytes, 0, sizeof(ctx->state.bytes));
    SHA2_MEMSET(ctx->pi.bytes, 0, sizeof(ctx->pi.bytes));
    ctx->bit_count = 0;
    ctx->d         = hash_bit_count;
    ctx->r         = 1600 - 256;
  }
  SHA_DEF void sha3_shake256_reset(sha3_ctx* ctx, unsigned int hash_bit_count)
  {
    SHA2_MEMSET(ctx->state.bytes, 0, sizeof(ctx->state.bytes));
    SHA2_MEMSET(ctx->pi.bytes, 0, sizeof(ctx->pi.bytes));
    ctx->bit_count = 0;
    ctx->d         = hash_bit_count;
    ctx->r         = 1600 - 512;
  }
#endif // SHA_2_IMPLEMENTATION

// ---------------------
// Append
// ---------------------
#ifdef SHA_2_IMPLEMENTATION
  // SHA 1
  static void _sha1_hash_block_base(sha1_ctx* ctx, sha2_block_256_t* block_optional)
  {
    static SHA_WORD_TYPE(SHA1) W[80];
    sha2_block_256_t* block = block_optional == NULL ? &ctx->block : block_optional;

    {
      // Init W state
      for (size_t t = 0; t < 16; t++) { W[t] = SHA2_BYTE_SWAP_IF_LITTLE(SHA1, block->words[t]); }
      for (size_t t = 16; t < 80; t++) {
        SHA_WORD_TYPE(SHA1) xor1 = SHA2_XOR(SHA2_WORD_SIZE(SHA1), W[t - 3], W[t - 8]);
        SHA_WORD_TYPE(SHA1) xor2 = SHA2_XOR(SHA2_WORD_SIZE(SHA1), W[t - 14], W[t - 16]);
        xor1                     = SHA2_XOR(SHA2_WORD_SIZE(SHA1), xor1, xor2);
        W[t]                     = SHA2_ROTL(SHA2_WORD_SIZE(SHA1), xor1, 1);
      }
    }

    SHA_WORD_TYPE(SHA1) a, b, c, d, e;
    {
      (a = ctx->hash.words[0], b = ctx->hash.words[1], c = ctx->hash.words[2]);
      (d = ctx->hash.words[3], e = ctx->hash.words[4]);
    }

    for (size_t t = 0; t < 80; t++) {
      const SHA_WORD_TYPE(SHA1) T = SHA2_ROTL(SHA2_WORD_SIZE(SHA1), a, 5) + SHA1_F(t, b, c, d) + e + sha1_K(t) + W[t];
      (e = d, d = c, c = SHA2_ROTL(SHA2_WORD_SIZE(SHA1), b, 30), b = a, a = T);
    }

    {
      // Hash i from i - 1
      (ctx->hash.words[0] = a + ctx->hash.words[0], ctx->hash.words[1] = b + ctx->hash.words[1]);
      (ctx->hash.words[2] = c + ctx->hash.words[2], ctx->hash.words[3] = d + ctx->hash.words[3]);
      (ctx->hash.words[4] = e + ctx->hash.words[4]);
    }
  }
  static void _sha1_hash_block_x86_mm(sha1_ctx* ctx, sha2_block_256_t* block_optional)
  {
    sha2_block_256_t* block = block_optional == NULL ? &ctx->block : block_optional;
    sha1_t            hash  = ctx->hash;

    __m128i           ABCD, ABCD_SAVE, E0, E0_SAVE, E1;
    __m128i           MASK, MSG0, MSG1, MSG2, MSG3;

    // Load initial values
    ABCD = _mm_set_epi32(hash.words[0], hash.words[1], hash.words[2], hash.words[3]);
    E0   = _mm_set_epi32(hash.words[4], 0, 0, 0); // 4 3 2 1 -> 1 2 3 4
    MASK = _mm_set_epi64x(0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);
    if (SHA_IS_BIG_ENDIAN) MASK = _mm_set_epi64x(0x0f0e0d0c0b0a0908ULL, 0x0706050403020100ULL);

    // Save current hash
    ABCD_SAVE = ABCD;
    E0_SAVE   = E0;

    // Rounds 0-3
    MSG0 = _mm_loadu_si128((__m128i_u*)block->words + 0);
    MSG0 = _mm_shuffle_epi8(MSG0, MASK);
    E0   = _mm_add_epi32(E0, MSG0);
    E1   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);

    // Rounds 4-7
    MSG1 = _mm_loadu_si128((__m128i_u*)(block->words + 4));
    MSG1 = _mm_shuffle_epi8(MSG1, MASK);
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);

    // Rounds 8-11
    MSG2 = _mm_loadu_si128((__m128i_u*)(block->words + 8));
    MSG2 = _mm_shuffle_epi8(MSG2, MASK);
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    // Rounds 12-15
    MSG3 = _mm_loadu_si128((__m128i_u*)(block->words + 12));
    MSG3 = _mm_shuffle_epi8(MSG3, MASK);
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    // Rounds 16-19
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    // Rounds 20-23
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    // Rounds 24-27
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    // Rounds 28-31
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    // Rounds 32-35
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    // Rounds 36-39
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    // Rounds 40-43
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    // Rounds 44-47
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    // Rounds 48-51
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    // Rounds 52-55
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    // Rounds 56-59
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    // Rounds 60-63
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    // Rounds 64-67
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    // Rounds 68-71
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    // Rounds 72-75
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);

    // Rounds 76-79
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

    // Add values back to state
    E0   = _mm_sha1nexte_epu32(E0, E0_SAVE);
    ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);

    // Save state
    ABCD = _mm_shuffle_epi32(ABCD, 0b00011011);
    _mm_storeu_si128((__m128i_u*)ctx->hash.words, ABCD);
    *(ctx->hash.words + 4) = _mm_extract_epi32(E0, 3);
  }
  static void _sha1_hash_block(sha1_ctx* ctx, sha2_block_256_t* block_optional)
  {
#ifdef SHA_NO_SIMD
    _sha1_hash_block_base(ctx, block_optional);
#else  // SHA_NO_SIMD
#if SHA_IS_X86 && defined(__SSE2__) && defined(__SSE3__) && defined(__SSE4_1__) && defined(__SHA__)
    _sha1_hash_block_x86_mm(ctx, block_optional);
#else  // IS_X86 // TODO: ARM
    // TODO: Runtime Check for intrinsics
    _sha1_hash_block_base(ctx, block_optional);
#endif // IS_X86
#endif // SHA_NO_SIMD

    {
      // Reset state
      ctx->block_count += 1;
      ctx->bit_count    = 0;
    }
  }
  static void _sha1_pad_block(sha1_ctx* ctx, size_t bits_in_block, uint64_t bits_total)
  {
    const size_t byte_index     = bits_in_block / 8;
    const size_t byte_bit_index = bits_in_block - (byte_index * 8);
    uint8_t*     bytes          = ctx->block.bytes;
    if (SHA_IS_BIG_ENDIAN) {
      const uint8_t null_mask = 0xFF >> (8 - byte_bit_index);
      const uint8_t set_mask  = 0b00000001 << byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    } else {
      const uint8_t null_mask = 0xFF << (8 - byte_bit_index);
      const uint8_t set_mask  = 0b10000000 >> byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    }
    // Null leftover
    if (byte_index < (SHA2_BLOCK_SIZE(SHA1) / 8) - 1) {
      SHA2_MEMSET(bytes + byte_index + 1, 0, (SHA2_BLOCK_SIZE(SHA1) / 8) - (byte_index + 1));
    }
    // Check if len fits in rest of block
    if (byte_index >= (SHA2_BLOCK_SIZE(SHA1) - 64) / 8) {
      ctx->bit_count = SHA2_BLOCK_SIZE(SHA1);
      _sha1_hash_block(ctx, NULL);
      SHA2_MEMSET(bytes, 0, (SHA2_BLOCK_SIZE(SHA2_256) - 64) / 8);
    }
    // Set length
    ctx->block.sizes[7] = SHA2_BYTE_SWAP_IF_LITTLE_WS(64, bits_total);
    ctx->bit_count      = SHA2_BLOCK_SIZE(SHA1);
  }
  SHA_DEF void sha1_append_bytes(sha1_ctx* ctx, const uint8_t* data, uint64_t byte_count)
  {
    if (ctx->bit_count % 8 != 0) { return sha1_append_bits(ctx, data, byte_count * 8); }

    // Fill started block
    if (ctx->bit_count > 0) {
      const size_t missing_byte_count = (SHA2_BLOCK_SIZE(SHA1) - ctx->bit_count) / 8;
      const size_t copy_byte_count    = SHA2_MIN(missing_byte_count, byte_count);
      SHA_MEMCPY(ctx->block.bytes + (ctx->bit_count / 8), data, copy_byte_count);
      data           += copy_byte_count;
      byte_count     -= copy_byte_count;
      ctx->bit_count += copy_byte_count * 8;
      if (ctx->bit_count == SHA2_BLOCK_SIZE(SHA1)) _sha1_hash_block(ctx, NULL);
    }

    // Do full blocks
    const uint8_t bytes_in_block = SHA2_BLOCK_SIZE(SHA1) / 8;
    while (byte_count >= bytes_in_block) {
      ctx->bit_count = SHA2_BLOCK_SIZE(SHA1);
      _sha1_hash_block(ctx, (sha2_block_256_t*)data);
      data       += bytes_in_block;
      byte_count -= bytes_in_block;
    }

    // Set rest
    if (byte_count > 0) {
      SHA_MEMCPY(ctx->block.bytes, data, byte_count);
      ctx->bit_count += byte_count * 8;
    }
  }
  SHA_DEF void sha1_append_bits(sha1_ctx* ctx, const uint8_t* data, uint64_t bit_count)
  {
    if (ctx->bit_count % 8 == 0 && bit_count > 8) {
      const uint64_t byte_count = bit_count / 8;
      sha1_append_bytes(ctx, data, byte_count);
      bit_count = bit_count - (byte_count * 8);
      if (bit_count == 0) return;
      data += byte_count;
    }

    while (bit_count > 0) {
      const uint8_t byte              = *(data++);
      const size_t  byte_index        = ctx->bit_count / 8;
      const uint8_t bits_in_byte      = ctx->bit_count - (byte_index * 8);
      const uint8_t missing_bit_count = 8 - bits_in_byte;

      // Set rest of current byte
      const uint8_t bits_in_data_byte  = bit_count >= 8 ? 8 : bit_count;
      ctx->block.bytes[byte_index]    |= (byte & ~(0xFF >> bits_in_data_byte)) >> bits_in_byte;
      const uint8_t added_bit_count    = SHA2_MIN(missing_bit_count, bits_in_data_byte);
      ctx->bit_count                  += added_bit_count;

      // Set start of next byte
      size_t byte_index_next = byte_index + 1;
      if (ctx->bit_count >= SHA2_BLOCK_SIZE(SHA1)) {
        _sha1_hash_block(ctx, NULL);
        byte_index_next = 0;
      }

      if (added_bit_count < bits_in_data_byte) {
        ctx->block.bytes[byte_index_next]  = (byte & ~(0xFF >> bits_in_data_byte)) << missing_bit_count;
        ctx->bit_count                    += bits_in_data_byte - added_bit_count;
      }
      bit_count -= bits_in_data_byte;
    }
  }
  SHA_DEF void sha1_append(sha1_ctx* ctx, const uint8_t* data, uint64_t bit_count) { sha1_append_bits(ctx, data, bit_count); }

  // SHA 2
  static void _sha2_print_m128i(__m128i v)
  {
    printf("%02x ", _mm_extract_epi8(v, 0));
    printf("%02x ", _mm_extract_epi8(v, 1));
    printf("%02x ", _mm_extract_epi8(v, 2));
    printf("%02x ", _mm_extract_epi8(v, 3));
    printf("%02x ", _mm_extract_epi8(v, 4));
    printf("%02x ", _mm_extract_epi8(v, 5));
    printf("%02x ", _mm_extract_epi8(v, 6));
    printf("%02x ", _mm_extract_epi8(v, 7));
    printf("%02x ", _mm_extract_epi8(v, 8));
    printf("%02x ", _mm_extract_epi8(v, 9));
    printf("%02x ", _mm_extract_epi8(v, 10));
    printf("%02x ", _mm_extract_epi8(v, 11));
    printf("%02x ", _mm_extract_epi8(v, 12));
    printf("%02x ", _mm_extract_epi8(v, 13));
    printf("%02x ", _mm_extract_epi8(v, 14));
    printf("%02x ", _mm_extract_epi8(v, 15));
    printf("\n");
  }
  static void _sha2_256_hash_block_base(sha2_256_ctx* ctx, sha2_block_256_t* block_optional)
  {
    static SHA_WORD_TYPE(SHA2_256) W[64];
    sha2_block_256_t* block = block_optional == NULL ? &ctx->block : block_optional;

    {
      // Init W state
      for (size_t t = 0; t < 16; t++) { W[t] = SHA2_BYTE_SWAP_IF_LITTLE(SHA2_256, block->words[t]); }
      for (size_t t = 16; t < 64; t++) {
        const SHA_WORD_TYPE(SHA2_256) sigma_1 = SHA2_SIGMA_SMALL(SHA2_WORD_SIZE(SHA2_256), W[t - 2], 17, 19, 10);
        const SHA_WORD_TYPE(SHA2_256) sigma_0 = SHA2_SIGMA_SMALL(SHA2_WORD_SIZE(SHA2_256), W[t - 15], 7, 18, 3);
        W[t]                                  = sigma_1 + W[t - 7] + sigma_0 + W[t - 16];
      }
    }

    SHA_WORD_TYPE(SHA2_256) a, b, c, d, e, f, g, h;
    {
      (a = ctx->hash.words[0], b = ctx->hash.words[1], c = ctx->hash.words[2], d = ctx->hash.words[3]);
      (e = ctx->hash.words[4], f = ctx->hash.words[5], g = ctx->hash.words[6], h = ctx->hash.words[7]);
    }

    for (size_t t = 0; t < 64; t++) {
      const SHA_WORD_TYPE(SHA2_256) sigma_1 = SHA2_SIGMA_LARGE(SHA2_WORD_SIZE(SHA2_256), e, 6, 11, 25);
      const SHA_WORD_TYPE(SHA2_256) sigma_0 = SHA2_SIGMA_LARGE(SHA2_WORD_SIZE(SHA2_256), a, 2, 13, 22);
      const SHA_WORD_TYPE(SHA2_256) ch      = SHA2_CH(SHA2_WORD_SIZE(SHA2_256), e, f, g);
      const SHA_WORD_TYPE(SHA2_256) maj     = SHA2_MAJ(SHA2_WORD_SIZE(SHA2_256), a, b, c);
      const SHA_WORD_TYPE(SHA2_256) T1      = h + sigma_1 + ch + SHA2_CONST_224_256[t] + W[t];
      const SHA_WORD_TYPE(SHA2_256) T2      = sigma_0 + maj;
      (h = g, g = f, f = e, e = d + T1, d = c, c = b, b = a, a = T1 + T2);
    }

    {
      // Hash i from i - 1
      (ctx->hash.words[0] = a + ctx->hash.words[0], ctx->hash.words[1] = b + ctx->hash.words[1]);
      (ctx->hash.words[2] = c + ctx->hash.words[2], ctx->hash.words[3] = d + ctx->hash.words[3]);
      (ctx->hash.words[4] = e + ctx->hash.words[4], ctx->hash.words[5] = f + ctx->hash.words[5]);
      (ctx->hash.words[6] = g + ctx->hash.words[6], ctx->hash.words[7] = h + ctx->hash.words[7]);
    }
  }
  static void _sha2_256_hash_block_x86_mm(sha2_256_ctx* ctx, sha2_block_256_t* block_optional)
  {
    sha2_block_256_t* block = block_optional == NULL ? &ctx->block : block_optional;

    __m128i           ABEF, CDGH, ABEF_SAVE, CDGH_SAVE;
    __m128i           MSG, MSGTMP0, MSGTMP1, MSGTMP2, MSGTMP3;
    __m128i           MASK, TMP;

    // Load initial values
    // ABEF = _mm_set_epi32(ctx->hash.words[0], ctx->hash.words[1], ctx->hash.words[4], ctx->hash.words[5]);
    // CDGH = _mm_set_epi32(ctx->hash.words[2], ctx->hash.words[3], ctx->hash.words[6], ctx->hash.words[7]);
    TMP  = _mm_loadu_si128((const __m128i*)&ctx->hash.words[0]);
    CDGH = _mm_loadu_si128((const __m128i*)&ctx->hash.words[4]);

    TMP  = _mm_shuffle_epi32(TMP, 0xB1);     /* CDAB */
    CDGH = _mm_shuffle_epi32(CDGH, 0x1B);    /* EFGH */
    ABEF = _mm_alignr_epi8(TMP, CDGH, 8);    /* ABEF */
    CDGH = _mm_blend_epi16(CDGH, TMP, 0xF0); /* CDGH */

    // MASK = _mm_set_epi64x(0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);
    MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
    if (SHA_IS_BIG_ENDIAN) MASK = _mm_set_epi64x(0x0f0e0d0c0b0a0908ULL, 0x0706050403020100ULL);

    // Save current hash
    ABEF_SAVE = ABEF;
    CDGH_SAVE = CDGH;

#define SHA_LOAD_MSG(i)   (_mm_loadu_si128((__m128i*)(block->words + i)))
#define SHA_LOAD_CONST(i) (_mm_loadu_si128((__m128i*)(SHA2_CONST_224_256 + i)))

    // Rounds 0-3
    MSG     = SHA_LOAD_MSG(0);
    MSGTMP0 = _mm_shuffle_epi8(MSG, MASK);
    MSG     = _mm_add_epi32(MSGTMP0, SHA_LOAD_CONST(0));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);

    // Round 4-7
    MSG     = SHA_LOAD_MSG(1 * 4);
    MSGTMP1 = _mm_shuffle_epi8(MSG, MASK);
    MSG     = _mm_add_epi32(MSGTMP1, SHA_LOAD_CONST(4));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP0 = _mm_sha256msg1_epu32(MSGTMP0, MSGTMP1);

    // Round 8-11
    MSG     = SHA_LOAD_MSG(2 * 4);
    MSGTMP2 = _mm_shuffle_epi8(MSG, MASK);
    MSG     = _mm_add_epi32(MSGTMP2, SHA_LOAD_CONST(8));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP1 = _mm_sha256msg1_epu32(MSGTMP1, MSGTMP2);

    // Round 12-15
    MSG     = SHA_LOAD_MSG(3 * 4);
    MSGTMP3 = _mm_shuffle_epi8(MSG, MASK);
    MSG     = _mm_add_epi32(MSGTMP3, SHA_LOAD_CONST(12));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP3, MSGTMP2, 4);
    MSGTMP0 = _mm_add_epi32(MSGTMP0, TMP);
    MSGTMP0 = _mm_sha256msg2_epu32(MSGTMP0, MSGTMP3);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP2 = _mm_sha256msg1_epu32(MSGTMP2, MSGTMP3);

    // Round 16-19
    MSG     = _mm_add_epi32(MSGTMP0, SHA_LOAD_CONST(16));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP0, MSGTMP3, 4);
    MSGTMP1 = _mm_add_epi32(MSGTMP1, TMP);
    MSGTMP1 = _mm_sha256msg2_epu32(MSGTMP1, MSGTMP0);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP3 = _mm_sha256msg1_epu32(MSGTMP3, MSGTMP0);

    // Round 20-23
    MSG     = _mm_add_epi32(MSGTMP1, SHA_LOAD_CONST(20));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP1, MSGTMP0, 4);
    MSGTMP2 = _mm_add_epi32(MSGTMP2, TMP);
    MSGTMP2 = _mm_sha256msg2_epu32(MSGTMP2, MSGTMP1);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP0 = _mm_sha256msg1_epu32(MSGTMP0, MSGTMP1);

    // Round 24-27
    MSG     = _mm_add_epi32(MSGTMP2, SHA_LOAD_CONST(24));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP2, MSGTMP1, 4);
    MSGTMP3 = _mm_add_epi32(MSGTMP3, TMP);
    MSGTMP3 = _mm_sha256msg2_epu32(MSGTMP3, MSGTMP2);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP1 = _mm_sha256msg1_epu32(MSGTMP1, MSGTMP2);

    // Round 28-31
    MSG     = _mm_add_epi32(MSGTMP3, SHA_LOAD_CONST(28));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP3, MSGTMP2, 4);
    MSGTMP0 = _mm_add_epi32(MSGTMP0, TMP);
    MSGTMP0 = _mm_sha256msg2_epu32(MSGTMP0, MSGTMP3);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP2 = _mm_sha256msg1_epu32(MSGTMP2, MSGTMP3);

    // Round 32-35
    MSG     = _mm_add_epi32(MSGTMP0, SHA_LOAD_CONST(32));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP0, MSGTMP3, 4);
    MSGTMP1 = _mm_add_epi32(MSGTMP1, TMP);
    MSGTMP1 = _mm_sha256msg2_epu32(MSGTMP1, MSGTMP0);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP3 = _mm_sha256msg1_epu32(MSGTMP3, MSGTMP0);

    // Round 36-39
    MSG     = _mm_add_epi32(MSGTMP1, SHA_LOAD_CONST(36));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP1, MSGTMP0, 4);
    MSGTMP2 = _mm_add_epi32(MSGTMP2, TMP);
    MSGTMP2 = _mm_sha256msg2_epu32(MSGTMP2, MSGTMP1);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP0 = _mm_sha256msg1_epu32(MSGTMP0, MSGTMP1);

    // Round 40-43
    MSG     = _mm_add_epi32(MSGTMP2, SHA_LOAD_CONST(40));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP2, MSGTMP1, 4);
    MSGTMP3 = _mm_add_epi32(MSGTMP3, TMP);
    MSGTMP3 = _mm_sha256msg2_epu32(MSGTMP3, MSGTMP2);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP1 = _mm_sha256msg1_epu32(MSGTMP1, MSGTMP2);

    // Round 44-47
    MSG     = _mm_add_epi32(MSGTMP3, SHA_LOAD_CONST(44));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP3, MSGTMP2, 4);
    MSGTMP0 = _mm_add_epi32(MSGTMP0, TMP);
    MSGTMP0 = _mm_sha256msg2_epu32(MSGTMP0, MSGTMP3);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP2 = _mm_sha256msg1_epu32(MSGTMP2, MSGTMP3);

    // Round 48-51
    MSG     = _mm_add_epi32(MSGTMP0, SHA_LOAD_CONST(48));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP0, MSGTMP3, 4);
    MSGTMP1 = _mm_add_epi32(MSGTMP1, TMP);
    MSGTMP1 = _mm_sha256msg2_epu32(MSGTMP1, MSGTMP0);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);
    MSGTMP3 = _mm_sha256msg1_epu32(MSGTMP3, MSGTMP0);

    // Round 52-55
    MSG     = _mm_add_epi32(MSGTMP1, SHA_LOAD_CONST(52));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP1, MSGTMP0, 4);
    MSGTMP2 = _mm_add_epi32(MSGTMP2, TMP);
    MSGTMP2 = _mm_sha256msg2_epu32(MSGTMP2, MSGTMP1);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);

    // Round 56-59
    MSG     = _mm_add_epi32(MSGTMP2, SHA_LOAD_CONST(56));
    CDGH    = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    TMP     = _mm_alignr_epi8(MSGTMP2, MSGTMP1, 4);
    MSGTMP3 = _mm_add_epi32(MSGTMP3, TMP);
    MSGTMP3 = _mm_sha256msg2_epu32(MSGTMP3, MSGTMP2);
    MSG     = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF    = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);

    // Round 60-63
    MSG  = _mm_add_epi32(MSGTMP3, SHA_LOAD_CONST(60));
    CDGH = _mm_sha256rnds2_epu32(CDGH, ABEF, MSG);
    MSG  = _mm_shuffle_epi32(MSG, 0b00001110);
    ABEF = _mm_sha256rnds2_epu32(ABEF, CDGH, MSG);

    // Add values back to state
    ABEF = _mm_add_epi32(ABEF, ABEF_SAVE);
    CDGH = _mm_add_epi32(CDGH, CDGH_SAVE);

    // Save state
    TMP  = _mm_shuffle_epi32(ABEF, 0b00011011);
    CDGH = _mm_shuffle_epi32(CDGH, 0b10110001);
    ABEF = _mm_blend_epi16(TMP, CDGH, 0b11110000);
    CDGH = _mm_alignr_epi8(CDGH, TMP, 8);

    _mm_storeu_si128((__m128i*)ctx->hash.words, ABEF);
    _mm_storeu_si128((__m128i*)ctx->hash.words + 1, CDGH);
  }
  static void _sha2_256_hash_block(sha2_256_ctx* ctx, sha2_block_256_t* block_optional)
  {
#ifdef SHA_NO_SIMD
    _sha2_256_hash_block_base(ctx, block_optional);
#else  // SHA_NO_SIMD
#if SHA_IS_X86 && defined(__SSE2__) && defined(__SSE3__) && defined(__SSE4_1__) && defined(__SHA__)
    _sha2_256_hash_block_x86_mm(ctx, block_optional);
#else  // IS_X86 // TODO: ARM
    // TODO: Runtime Check for intrinsics
    _sha2_256_hash_block_base(ctx, block_optional);
#endif // IS_X86
#endif // SHA_NO_SIMD

    {
      // Reset state
      ctx->block_count += 1;
      ctx->bit_count    = 0;
    }
  }
  static void _sha2_256_pad_block(sha2_256_ctx* ctx, size_t bits_in_block, uint64_t bits_total)
  {
    const size_t byte_index     = bits_in_block / 8;
    const size_t byte_bit_index = bits_in_block - (byte_index * 8);
    uint8_t*     bytes          = ctx->block.bytes;
    if (SHA_IS_BIG_ENDIAN) {
      const uint8_t null_mask = 0xFF >> (8 - byte_bit_index);
      const uint8_t set_mask  = 0b00000001 << byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    } else {
      const uint8_t null_mask = 0xFF << (8 - byte_bit_index);
      const uint8_t set_mask  = 0b10000000 >> byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    }
    // Null leftover
    if (byte_index < (SHA2_BLOCK_SIZE(SHA2_256) / 8) - 1) {
      SHA2_MEMSET(bytes + byte_index + 1, 0, (SHA2_BLOCK_SIZE(SHA2_256) / 8) - (byte_index + 1));
    }
    // Check if len fits in rest of block
    if (byte_index >= (SHA2_BLOCK_SIZE(SHA2_256) - 64) / 8) {
      ctx->bit_count = SHA2_BLOCK_SIZE(SHA2_256);
      _sha2_256_hash_block(ctx, NULL);
      SHA2_MEMSET(bytes, 0, (SHA2_BLOCK_SIZE(SHA2_256) - 64) / 8);
    }
    // Set length
    ctx->block.sizes[7] = SHA2_BYTE_SWAP_IF_LITTLE_WS(64, bits_total);
    ctx->bit_count      = SHA2_BLOCK_SIZE(SHA2_256);
  }
  SHA_DEF void sha2_256_append_bytes(sha2_256_ctx* ctx, const uint8_t* data, uint64_t byte_count)
  {
    if (ctx->bit_count % 8 != 0) { return sha2_256_append_bits(ctx, data, byte_count * 8); }

    // Fill started block
    if (ctx->bit_count > 0) {
      const size_t missing_byte_count = (SHA2_BLOCK_SIZE(SHA2_256) - ctx->bit_count) / 8;
      const size_t copy_byte_count    = SHA2_MIN(missing_byte_count, byte_count);
      SHA_MEMCPY(ctx->block.bytes + (ctx->bit_count / 8), data, copy_byte_count);
      data           += copy_byte_count;
      byte_count     -= copy_byte_count;
      ctx->bit_count += copy_byte_count * 8;
      if (ctx->bit_count == SHA2_BLOCK_SIZE(SHA2_256)) _sha2_256_hash_block(ctx, NULL);
    }

    // Do full blocks
    const uint8_t bytes_in_block = SHA2_BLOCK_SIZE(SHA2_256) / 8;
    while (byte_count >= bytes_in_block) {
      // SHA_MEMCPY(ctx->block.bytes, data, bytes_in_block);
      ctx->bit_count = SHA2_BLOCK_SIZE(SHA2_256);
      _sha2_256_hash_block(ctx, (sha2_block_256_t*)data);
      data       += bytes_in_block;
      byte_count -= bytes_in_block;
    }

    // Set rest
    if (byte_count > 0) {
      SHA_MEMCPY(ctx->block.bytes, data, byte_count);
      ctx->bit_count += byte_count * 8;
    }
  }
  SHA_DEF void sha2_256_append_bits(sha2_256_ctx* ctx, const uint8_t* data, uint64_t bit_count)
  {
    if (ctx->bit_count % 8 == 0 && bit_count > 8) {
      const uint64_t byte_count = bit_count / 8;
      sha2_256_append_bytes(ctx, data, byte_count);
      bit_count = bit_count - (byte_count * 8);
      if (bit_count == 0) return;
      data += byte_count;
    }

    while (bit_count > 0) {
      const uint8_t byte              = *(data++);
      const size_t  byte_index        = ctx->bit_count / 8;
      const uint8_t bits_in_byte      = ctx->bit_count - (byte_index * 8);
      const uint8_t missing_bit_count = 8 - bits_in_byte;

      // Set rest of current byte
      const uint8_t bits_in_data_byte  = bit_count >= 8 ? 8 : bit_count;
      ctx->block.bytes[byte_index]    |= (byte & ~(0xFF >> bits_in_data_byte)) >> bits_in_byte;
      const uint8_t added_bit_count    = SHA2_MIN(missing_bit_count, bits_in_data_byte);
      ctx->bit_count                  += added_bit_count;

      // Set start of next byte
      size_t byte_index_next = byte_index + 1;
      if (ctx->bit_count >= SHA2_BLOCK_SIZE(SHA2_256)) {
        _sha2_256_hash_block(ctx, NULL);
        byte_index_next = 0;
      }

      if (added_bit_count < bits_in_data_byte) {
        ctx->block.bytes[byte_index_next]  = (byte & ~(0xFF >> bits_in_data_byte)) << missing_bit_count;
        ctx->bit_count                    += bits_in_data_byte - added_bit_count;
      }
      bit_count -= bits_in_data_byte;
    }
  }
  SHA_DEF void sha2_256_append(sha2_256_ctx* ctx, const uint8_t* data, uint64_t bit_count)
  {
    sha2_256_append_bits(ctx, data, bit_count);
  }

  static void _sha2_512_hash_block(sha2_512_ctx* ctx, sha2_block_512_t* block_optional)
  {
    static SHA_WORD_TYPE(SHA2_512) W[80];
    sha2_block_512_t* block = block_optional == NULL ? &ctx->block : block_optional;

    {
      // Init W state
      for (size_t t = 0; t < 16; t++) { W[t] = SHA2_BYTE_SWAP_IF_LITTLE(SHA2_512, block->words[t]); }
      for (size_t t = 16; t < 80; t++) {
        const SHA_WORD_TYPE(SHA2_512) sigma_1 = SHA2_SIGMA_SMALL(SHA2_WORD_SIZE(SHA2_512), W[t - 2], 19, 61, 6);
        const SHA_WORD_TYPE(SHA2_512) sigma_0 = SHA2_SIGMA_SMALL(SHA2_WORD_SIZE(SHA2_512), W[t - 15], 1, 8, 7);
        W[t]                                  = sigma_1 + W[t - 7] + sigma_0 + W[t - 16];
      }
    }

    SHA_WORD_TYPE(SHA2_512) a, b, c, d, e, f, g, h;
    {
      (a = ctx->hash.words[0], b = ctx->hash.words[1], c = ctx->hash.words[2], d = ctx->hash.words[3]);
      (e = ctx->hash.words[4], f = ctx->hash.words[5], g = ctx->hash.words[6], h = ctx->hash.words[7]);
    }

    for (size_t t = 0; t < 80; t++) {
      const SHA_WORD_TYPE(SHA2_512) sigma_1 = SHA2_SIGMA_LARGE(SHA2_WORD_SIZE(SHA2_512), e, 14, 18, 41);
      const SHA_WORD_TYPE(SHA2_512) sigma_0 = SHA2_SIGMA_LARGE(SHA2_WORD_SIZE(SHA2_512), a, 28, 34, 39);
      const SHA_WORD_TYPE(SHA2_512) ch      = SHA2_CH(SHA2_WORD_SIZE(SHA2_512), e, f, g);
      const SHA_WORD_TYPE(SHA2_512) maj     = SHA2_MAJ(SHA2_WORD_SIZE(SHA2_512), a, b, c);
      const SHA_WORD_TYPE(SHA2_512) T1      = h + sigma_1 + ch + SHA2_CONST_384_512[t] + W[t];
      const SHA_WORD_TYPE(SHA2_512) T2      = sigma_0 + maj;
      (h = g, g = f, f = e, e = d + T1, d = c, c = b, b = a, a = T1 + T2);
    }

    {
      // Hash i from i - 1
      (ctx->hash.words[0] = a + ctx->hash.words[0], ctx->hash.words[1] = b + ctx->hash.words[1]);
      (ctx->hash.words[2] = c + ctx->hash.words[2], ctx->hash.words[3] = d + ctx->hash.words[3]);
      (ctx->hash.words[4] = e + ctx->hash.words[4], ctx->hash.words[5] = f + ctx->hash.words[5]);
      (ctx->hash.words[6] = g + ctx->hash.words[6], ctx->hash.words[7] = h + ctx->hash.words[7]);
    }

    {
      // Reset
      if (ctx->block_count_low == UINT64_MAX) {
        ctx->block_count_low   = 0;
        ctx->block_count_high += 1;
      }
      ctx->block_count_low += 1;
      ctx->bit_count        = 0;
    }
  }
  static void _sha2_512_pad_block(sha2_512_ctx* ctx, size_t bits_in_block, uint64_t bits_total_h, uint64_t bits_total_l)
  {
    const size_t byte_index     = bits_in_block / 8;
    const size_t byte_bit_index = bits_in_block - (byte_index * 8);
    uint8_t*     bytes          = ctx->block.bytes;
    if (SHA_IS_BIG_ENDIAN) {
      const uint8_t null_mask = 0xFF >> (8 - byte_bit_index);
      const uint8_t set_mask  = 0b00000001 << byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    } else {
      const uint8_t null_mask = 0xFF << (8 - byte_bit_index);
      const uint8_t set_mask  = 0b10000000 >> byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    }
    // Null leftover
    if (byte_index < (SHA2_BLOCK_SIZE(SHA2_512) / 8) - 1) {
      SHA2_MEMSET(bytes + byte_index + 1, 0, (SHA2_BLOCK_SIZE(SHA2_512) / 8) - (byte_index + 1));
    }
    // Check if len fits in rest of block
    if (byte_index >= (SHA2_BLOCK_SIZE(SHA2_512) - 128) / 8) {
      ctx->bit_count = SHA2_BLOCK_SIZE(SHA2_512);
      _sha2_512_hash_block(ctx, NULL);
      SHA2_MEMSET(bytes, 0, (SHA2_BLOCK_SIZE(SHA2_512) - 128) / 8);
    }
    // Set Length
    ctx->block.words[SHA2_WORDS_IN_BLOCK(SHA2_512) - 1] = SHA2_BYTE_SWAP_IF_LITTLE_WS(64, bits_total_l);
    ctx->block.words[SHA2_WORDS_IN_BLOCK(SHA2_512) - 2] = SHA2_BYTE_SWAP_IF_LITTLE_WS(64, bits_total_h);
    ctx->bit_count                                      = SHA2_BLOCK_SIZE(SHA2_512);
  }
  SHA_DEF void sha2_512_append_bytes(sha2_512_ctx* ctx, const uint8_t* data, uint64_t byte_count)
  {
    if (ctx->bit_count % 8 != 0) { sha2_512_append_bits(ctx, data, byte_count * 8); }

    // Fill started block
    if (ctx->bit_count > 0) {
      const size_t missing_byte_count = (SHA2_BLOCK_SIZE(SHA2_512) - ctx->bit_count) / 8;
      const size_t copy_byte_count    = SHA2_MIN(missing_byte_count, byte_count);
      SHA_MEMCPY(ctx->block.bytes + (ctx->bit_count / 8), data, copy_byte_count);
      data           += copy_byte_count;
      byte_count     -= copy_byte_count;
      ctx->bit_count += copy_byte_count * 8;
      if (ctx->bit_count == SHA2_BLOCK_SIZE(SHA2_512)) _sha2_512_hash_block(ctx, NULL);
    }

    // Do full blocks
    const size_t bytes_in_block = SHA2_BLOCK_SIZE(SHA2_512) / 8;
    while (byte_count >= bytes_in_block) {
      ctx->bit_count = SHA2_BLOCK_SIZE(SHA2_512);
      _sha2_512_hash_block(ctx, (sha2_block_512_t*)data);
      data       += bytes_in_block;
      byte_count -= bytes_in_block;
    }

    // Set rest
    if (byte_count > 0) {
      SHA_MEMCPY(ctx->block.bytes, data, byte_count);
      ctx->bit_count += byte_count * 8;
    }
  }
  SHA_DEF void sha2_512_append_bits(sha2_512_ctx* ctx, const uint8_t* data, uint64_t bit_count)
  {
    // Use append bytes for as many bytes as possible
    if (ctx->bit_count % 8 == 0 && bit_count > 8) {
      const uint64_t byte_count = bit_count / 8;
      sha2_512_append_bytes(ctx, data, byte_count);
      bit_count = bit_count - (byte_count * 8);
      if (bit_count == 0) return;
      data += byte_count;
    }

    while (bit_count > 0) {
      const uint8_t byte              = *(data++);
      const size_t  byte_index        = ctx->bit_count / 8;
      const uint8_t bits_in_byte      = ctx->bit_count - (byte_index * 8);
      const uint8_t missing_bit_count = 8 - bits_in_byte;

      // Set rest of current byte
      const uint8_t bits_in_data_byte  = bit_count >= 8 ? 8 : bit_count;
      ctx->block.bytes[byte_index]    |= (byte & ~(0xFF >> bits_in_data_byte)) >> bits_in_byte;
      const uint8_t added_bit_count    = SHA2_MIN(missing_bit_count, bits_in_data_byte);
      ctx->bit_count                  += added_bit_count;

      // Hash if was last byte in block
      size_t byte_index_next = byte_index + 1;
      if (ctx->bit_count >= SHA2_BLOCK_SIZE(SHA2_512)) {
        _sha2_512_hash_block(ctx, NULL);
        byte_index_next = 0;
      }

      // Set start of next byte
      if (added_bit_count < bits_in_data_byte) {
        ctx->block.bytes[byte_index_next]  = (byte & ~(0xFF >> bits_in_data_byte)) << missing_bit_count;
        ctx->bit_count                    += bits_in_data_byte - added_bit_count;
      }
      bit_count -= bits_in_data_byte;
    }
  }
  SHA_DEF void sha2_512_append(sha2_512_ctx* ctx, const uint8_t* data, uint64_t bit_count)
  {
    sha2_512_append_bits(ctx, data, bit_count);
  }

// SHA3
#define SHA3_BLOCK_SIZE             1600
#define SHA3_b1600_W                64
#define SHA3_b1600_L                6
#define SHA3_STATE_TO_SA(str, x, y) (((uint64_t*)str)[(5 * y + x)]) // S[w(5y+x)+z]

#define _SHA_MOD_32(x, n)           (((SHA_WORD_TYPE_32)(x) % (n) + (n)) % (n))
#define _SHA_MOD_64(x, n)           (((SHA_WORD_TYPE_64)(x) % (n) + (n)) % (n))
#define _SHA_MOD(WS, x, n)          _SHA_MOD_##WS(x, n)
#define SHA_MOD(WS, x, n)           _SHA_MOD(WS, x, n)

  static void sha3_print_state(sha3_ctx* ctx, int round_index, const char* str)
  {
    printf("After round %u: %s\n", round_index, str);
    for (unsigned int i = 0; i < sizeof(ctx->state); i++) { printf("%02x ", ctx->state.bytes[i]); }
    printf("\n");
  }

  static void sha3_b1600_theta(sha3_ctx* ctx)
  {
    uint8_t* s = ctx->state.bytes;
    uint64_t C[5];
    for (unsigned int x = 0; x < 5; x++) {
      C[x] = SHA2_XOR(64, SHA3_STATE_TO_SA(s, x, 0), SHA3_STATE_TO_SA(s, x, 1));
      C[x] = SHA2_XOR(64, C[x], SHA3_STATE_TO_SA(s, x, 2));
      C[x] = SHA2_XOR(64, C[x], SHA3_STATE_TO_SA(s, x, 3));
      C[x] = SHA2_XOR(64, C[x], SHA3_STATE_TO_SA(s, x, 4));
    }

    // uint64_t D[5];
    for (unsigned int x = 0; x < 5; x++) {
      uint64_t d_x = SHA2_ROTL(64, C[(x + 1) % 5], 1);
      d_x          = SHA2_XOR(64, C[(x + 4) % 5], d_x); // (x + 4) % 5 = (x - 1) mod 5

      for (unsigned int y = 0; y < 5; y++) { SHA3_STATE_TO_SA(s, x, y) = SHA2_XOR(64, SHA3_STATE_TO_SA(s, x, y), d_x); }
      // sha3_print_state(ctx, 0, "Theta:C");
    }
  }
  static void sha3_b1600_rho(sha3_ctx* ctx)
  {
    uint8_t*     bytes = ctx->state.bytes;
    unsigned int x, y, ty;
    x = 1;
    y = 0;
    for (unsigned int t = 0; t < 24; t++) {
      unsigned int n = (((t + 1) * (t + 2)) / 2) % 64;
      // printf("n=%u, x=%u, y=%u\n", n, x, y);
      SHA3_STATE_TO_SA(bytes, x, y) = SHA2_ROTL(64, SHA3_STATE_TO_SA(bytes, x, y), n);
      //
      ty = y;
      y  = (2 * x + 3 * y) % 5;
      x  = ty;
    }
  }
  static void sha3_b1600_pi(sha3_ctx* ctx)
  {
    sha3_state_t s_copy = ctx->state; // TODO: Swapping buffer
    uint8_t*     bytes  = ctx->state.bytes;
    for (unsigned int x = 0; x < 5; x++) {
      for (unsigned int y = 0; y < 5; y++) {
        unsigned int xn               = (x + 3 * y) % 5;
        SHA3_STATE_TO_SA(bytes, x, y) = SHA3_STATE_TO_SA(s_copy.bytes, xn, x);
      }
    }
  }
  static void sha3_b1600_chi(sha3_ctx* ctx)
  {
    sha3_state_t s_copy = ctx->state;
    uint8_t*     bytes  = ctx->state.bytes;
    for (unsigned int y = 0; y < 5; y++) {
      for (unsigned int x = 0; x < 5; x++) {
        uint64_t res                  = SHA2_NOT(64, SHA3_STATE_TO_SA(s_copy.bytes, (x + 1) % 5, y)); // XOR with 1 equals not
        res                           = SHA2_AND(64, res, SHA3_STATE_TO_SA(s_copy.bytes, (x + 2) % 5, y));
        SHA3_STATE_TO_SA(bytes, x, y) = SHA2_XOR(64, SHA3_STATE_TO_SA(s_copy.bytes, x, y), res);
      }
    }
  }
  static void sha3_b1600_iota(sha3_ctx* ctx, uint64_t round_index)
  {
    /* Round constants */
    static const uint64_t RC[24] = {
      0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
      0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
      0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
      0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    };
    SHA3_STATE_TO_SA(ctx->state.bytes, 0, 0) = SHA2_XOR(64, SHA3_STATE_TO_SA(ctx->state.bytes, 0, 0), RC[round_index]);
  }
  static void sha3_rnd(sha3_ctx* ctx, uint64_t round_index)
  {
    sha3_b1600_theta(ctx);
    // sha3_print_state(ctx, round_index, "Theta");
    sha3_b1600_rho(ctx);
    // sha3_print_state(ctx, round_index, "Rho");
    sha3_b1600_pi(ctx);
    // sha3_print_state(ctx, round_index, "Pi");
    sha3_b1600_chi(ctx);
    // sha3_print_state(ctx, round_index, "Chi");
    sha3_b1600_iota(ctx, round_index);
    // sha3_print_state(ctx, round_index, "Iota");
  }
  static void sha3_keccak_p(sha3_ctx* ctx)
  {
    // sha3_rnd(ctx, 0);
    for (unsigned int i = 12 + 2 * SHA3_b1600_L - 24; i < 12 + 2 * SHA3_b1600_L; i++) { sha3_rnd(ctx, i); }
  }
  static uint8_t sha3_reverse_bits_in_byte(uint8_t b)
  {
    b = (b & 0b11110000) >> 4 | (b & 0b00001111) << 4;
    b = (b & 0b11001100) >> 2 | (b & 0b00110011) << 2;
    b = (b & 0b10101010) >> 1 | (b & 0b01010101) << 1;
    return b;
  }
  static uint64_t sha3_reverse_64(uint64_t value)
  {
    for (unsigned short j = 0; j < sizeof(value); j++) {
      uint8_t* byte_ptr = (uint8_t*)&value;
      byte_ptr[j]       = sha3_reverse_bits_in_byte(byte_ptr[j]);
    }
    return SHA_IS_BIG_ENDIAN ? SHA2_BYTE_SWAP_WS(64, value) : value;
  }
  static void sha3_print_data(const uint8_t* data, unsigned int count, const char* str)
  {
    printf("%s:\n", str);
    for (unsigned int i = 0; i < count; i++) {
      // const uint64_t v = data[i];
      const uint64_t v = sha3_reverse_bits_in_byte(data[i]);
      printf("%02x ", v);
    }
    // #define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
    // #define BYTE_TO_BINARY(byte)                                                                                          \
//   ((byte) & 0x80 ? '1' : '0'), ((byte) & 0x40 ? '1' : '0'), ((byte) & 0x20 ? '1' : '0'), ((byte) & 0x10 ? '1' : '0'), \
//       ((byte) & 0x08 ? '1' : '0'), ((byte) & 0x04 ? '1' : '0'), ((byte) & 0x02 ? '1' : '0'), ((byte) & 0x01 ? '1' : '0')
    //     for (unsigned int i = 0; i < count; i++) {
    //       // const uint8_t rev = sha3_reverse_bits_in_byte(data[i]);
    //       const uint8_t rev = data[i];
    //       printf(BYTE_TO_BINARY_PATTERN " ", BYTE_TO_BINARY(rev));
    //     }
    printf("\n");
  }
  static void sha3_sponge(sha3_ctx* ctx, const uint8_t* opt_data)
  {
    const uint8_t* data = opt_data != NULL ? opt_data : ctx->pi.bytes;
    // TODO: Have to Check if r is always 64bit aligned.
    // TODO: Have to mask with 0 if not
    // sha3_print_data(data, ctx->r / 8, "Data");
    for (unsigned int i = 0; i < (ctx->r + 63) / 64; i++) {
      const uint64_t rev = sha3_reverse_64(((uint64_t*)data)[i]);
      // const uint64_t rev               = ((uint64_t*)data)[i];
      ((uint64_t*)ctx->state.bytes)[i] = SHA2_XOR(64, ((uint64_t*)ctx->state.bytes)[i], rev);
    }
    // sha3_print_state(ctx, 0, "XOR'd state");
    sha3_keccak_p(ctx);
    ctx->bit_count = 0;
  }

  SHA_DEF void sha3_append_bytes(sha3_ctx* ctx, const uint8_t* data, uint64_t byte_count)
  {
    if (ctx->bit_count % 8 != 0) sha3_append_bits(ctx, data, byte_count * 8);

    // Fill started block
    if (ctx->bit_count > 0) {
      const unsigned int missing_byte_count = (ctx->r - ctx->bit_count) / 8;
      const unsigned int copy_byte_count    = SHA2_MIN(missing_byte_count, byte_count);
      SHA_MEMCPY(ctx->pi.bytes + (ctx->bit_count / 8), data, copy_byte_count);
      data           += copy_byte_count;
      byte_count     -= copy_byte_count;
      ctx->bit_count += copy_byte_count * 8;
      if (ctx->bit_count == ctx->r) sha3_sponge(ctx, NULL);
    }

    // Do full blocks
    const size_t bytes_in_block = ctx->r / 8;
    while (byte_count >= bytes_in_block) {
      ctx->bit_count = ctx->r; // ?
      sha3_sponge(ctx, data);
      data       += bytes_in_block;
      byte_count -= bytes_in_block;
    }

    // Set rest
    if (byte_count > 0) {
      SHA_MEMCPY(ctx->pi.bytes, data, byte_count);
      ctx->bit_count += byte_count * 8;
    }
  }
  SHA_DEF void sha3_append_bits(sha3_ctx* ctx, const uint8_t* data, uint64_t bit_count)
  {
    // Use append bytes for as many bytes as possible
    if (ctx->bit_count % 8 == 0 && bit_count > 8) {
      const uint64_t byte_count = bit_count / 8;
      sha3_append_bytes(ctx, data, byte_count);
      bit_count = bit_count - (byte_count * 8);
      if (bit_count == 0) return;
      data += byte_count;
    }

    while (bit_count > 0) {
      const uint8_t byte              = *(data++); // sha3_reverse_bits_in_byte
      const size_t  byte_index        = ctx->bit_count / 8;
      const uint8_t bits_in_byte      = ctx->bit_count - (byte_index * 8);
      const uint8_t missing_bit_count = 8 - bits_in_byte;

      // Set rest of current byte
      const uint8_t bits_in_data_byte  = bit_count >= 8 ? 8 : bit_count;
      const uint8_t zeroed_pi_byte     = ctx->pi.bytes[byte_index] & ~((1 << missing_bit_count) - 1);
      ctx->pi.bytes[byte_index]        = zeroed_pi_byte | ((byte & ~(0xFF >> bits_in_data_byte)) >> bits_in_byte);
      const uint8_t added_bit_count    = SHA2_MIN(missing_bit_count, bits_in_data_byte);
      ctx->bit_count                  += added_bit_count;

      // Sponge block if was last byte
      size_t byte_index_next = byte_index + 1;
      if (ctx->bit_count >= ctx->r) {
        sha3_sponge(ctx, NULL);
        byte_index_next = 0;
      }

      // Set start of next byte
      if (added_bit_count < bits_in_data_byte) {
        ctx->pi.bytes[byte_index_next]  = (byte & ~(0xFF >> bits_in_data_byte)) << missing_bit_count;
        ctx->bit_count                 += bits_in_data_byte - added_bit_count;
      }
      bit_count -= bits_in_data_byte;
    }
  }
  SHA_DEF void sha3_append(sha3_ctx* ctx, const uint8_t* data, uint64_t bit_count) { sha3_append_bits(ctx, data, bit_count); }

#endif // SHA_2_IMPLEMENTATION

  // -------------------
  // Get Hash
  // -------------------
#ifdef SHA_2_IMPLEMENTATION
  // SHA 1
  SHA_DEF sha1_t sha1_get_hash(sha1_ctx* ctx)
  {
    const uint64_t total_bits = ctx->block_count * SHA2_BLOCK_SIZE(SHA1) + ctx->bit_count;
    _sha1_pad_block(ctx, ctx->bit_count, total_bits);
    _sha1_hash_block(ctx, NULL);
    sha1_t hash;
    for (uint32_t i = 0; i < sizeof(hash.words) / sizeof(*hash.words); i++) { hash.words[i] = ctx->hash.words[i]; }
    sha1_reset(ctx);
    return hash;
  }
  // SHA 2
  SHA_DEF sha_224_t sha2_224_get_hash(sha2_256_ctx* ctx)
  {
    const uint64_t total_bits = ctx->block_count * SHA2_BLOCK_SIZE(SHA2_256) + ctx->bit_count;
    _sha2_256_pad_block(ctx, ctx->bit_count, total_bits);
    _sha2_256_hash_block(ctx, NULL);
    sha_224_t hash;
    for (uint32_t i = 0; i < sizeof(hash.words) / sizeof(*hash.words); i++) { hash.words[i] = ctx->hash.words[i]; }
    sha2_224_reset(ctx);
    return hash;
  }
  SHA_DEF sha_256_t sha2_256_get_hash(sha2_256_ctx* ctx)
  {
    const uint64_t total_bits = ctx->block_count * SHA2_BLOCK_SIZE(SHA2_256) + ctx->bit_count;
    _sha2_256_pad_block(ctx, ctx->bit_count, total_bits);
    _sha2_256_hash_block(ctx, NULL);
    const sha_256_t hash = ctx->hash;
    sha2_256_reset(ctx);
    return hash;
  }
  SHA_DEF sha_384_t sha2_384_get_hash(sha2_512_ctx* ctx)
  {
    static_assert(SHA2_BLOCK_SIZE(SHA2_384) == 1024, "Block size for SHA2_384 is expected to be 1024");
    const uint64_t total_bits_low   = ctx->block_count_low * SHA2_BLOCK_SIZE(SHA2_384) + ctx->bit_count;
    uint64_t       total_bits_high  = ctx->block_count_high * SHA2_BLOCK_SIZE(SHA2_384);
    total_bits_high                |= ctx->block_count_low >> (64 - 10); // 2^10 = 1024
    _sha2_512_pad_block(ctx, ctx->bit_count, total_bits_high, total_bits_low);
    _sha2_512_hash_block(ctx, NULL);
    sha_384_t hash;
    for (uint32_t i = 0; i < sizeof(hash.words) / sizeof(*hash.words); i++) { hash.words[i] = ctx->hash.words[i]; }
    sha2_384_reset(ctx);
    return hash;
  }
  SHA_DEF sha_512_t sha2_512_get_hash(sha2_512_ctx* ctx)
  {
    static_assert(SHA2_BLOCK_SIZE(SHA2_512) == 1024, "Block size for SHA2_512 is expected to be 1024");
    const uint64_t total_bits_low   = ctx->block_count_low * SHA2_BLOCK_SIZE(SHA2_512) + ctx->bit_count;
    uint64_t       total_bits_high  = ctx->block_count_high * SHA2_BLOCK_SIZE(SHA2_512);
    total_bits_high                |= ctx->block_count_low >> (64 - 10); // 2^10 = 1024
    _sha2_512_pad_block(ctx, ctx->bit_count, total_bits_high, total_bits_low);
    _sha2_512_hash_block(ctx, NULL);
    const sha_512_t hash = ctx->hash;
    sha2_384_reset(ctx);
    return hash;
  }
  SHA_DEF sha_224_t sha2_512_224_get_hash(sha2_512_ctx* ctx)
  {
    static_assert(SHA2_BLOCK_SIZE(SHA2_512) == 1024, "Block size for SHA2_512 is expected to be 1024");
    const uint64_t total_bits_low   = ctx->block_count_low * SHA2_BLOCK_SIZE(SHA2_512) + ctx->bit_count;
    uint64_t       total_bits_high  = ctx->block_count_high * SHA2_BLOCK_SIZE(SHA2_512);
    total_bits_high                |= ctx->block_count_low >> (64 - 10); // 2^10 = 1024
    _sha2_512_pad_block(ctx, ctx->bit_count, total_bits_high, total_bits_low);
    _sha2_512_hash_block(ctx, NULL);
    sha_224_t hash;
    for (uint32_t i = 0; i < sizeof(hash.words) / sizeof(*hash.words);) {
      const uint64_t v   = ctx->hash.words[i / 2];
      hash.words[i]      = v >> 32;
      hash.words[i + 1]  = v & 0xFFFFFFFF;
      i                 += 2;
    }
    sha2_512_224_reset(ctx);
    return hash;
  }
  SHA_DEF sha_256_t sha2_512_256_get_hash(sha2_512_ctx* ctx)
  {
    static_assert(SHA2_BLOCK_SIZE(SHA2_512) == 1024, "Block size for SHA2_512 is expected to be 1024");
    const uint64_t total_bits_low   = ctx->block_count_low * SHA2_BLOCK_SIZE(SHA2_512) + ctx->bit_count;
    uint64_t       total_bits_high  = ctx->block_count_high * SHA2_BLOCK_SIZE(SHA2_512);
    total_bits_high                |= ctx->block_count_low >> (64 - 10); // 2^10 = 1024
    _sha2_512_pad_block(ctx, ctx->bit_count, total_bits_high, total_bits_low);
    _sha2_512_hash_block(ctx, NULL);
    sha_256_t hash;
    for (uint32_t i = 0; i < sizeof(hash.words) / sizeof(*hash.words);) {
      const uint64_t v   = ctx->hash.words[i / 2];
      hash.words[i]      = v >> 32;
      hash.words[i + 1]  = v & 0xFFFFFFFF;
      i                 += 2;
    }
    sha2_512_256_reset(ctx);
    return hash;
  }
  // SHA 3
  static const uint8_t ZERO_READ_ONLY[1600 / 8] = { 0 };
  static void          sha3_pad10_star_1(sha3_ctx* ctx, uint16_t leftover_bits)
  {
    static const uint8_t ONE_READ_ONLY = 0b10000000;
    sha3_append_bits(ctx, &ONE_READ_ONLY, 1);
    int v   = -leftover_bits - 2;
    int mod = (v % ctx->r + ctx->r) % ctx->r;   // Actual modulo, not remainder %
    sha3_append_bits(ctx, ZERO_READ_ONLY, mod); // (-m - 2) mod ctx->r
    sha3_append_bits(ctx, &ONE_READ_ONLY, 1);
    // TODO: Assert ctx->bit_count == 1600?
  }
  static unsigned short sha3_copy_state_reversed(sha3_ctx* ctx, uint8_t* src, uint8_t* dest, unsigned short cpy_byte_count)
  {
    unsigned short src_byte_count = ctx->r / 8;

    unsigned short cpy_word_count = cpy_byte_count / 8;
    unsigned short src_word_count = src_byte_count / 8;
    unsigned short word_count     = SHA2_MIN(cpy_word_count, src_word_count);
    for (unsigned short i = 0; i < word_count; i++) {
      // ((uint64_t*)dest)[i] = sha3_reverse_64(((uint64_t*)src)[i]);
      ((uint64_t*)dest)[i] = ((uint64_t*)src)[i];
    }
    if (cpy_byte_count >= src_byte_count) return src_byte_count;
    dest += word_count * 8;
    src  += word_count * 8;

    uint8_t buf_rev[8];
    for (unsigned short i = 0; i < 8; i++) {
      // buf_rev[i] = sha3_reverse_bits_in_byte(src[7 - i]);
      buf_rev[i] = src[i];
    }
    unsigned short bytes_leftover = cpy_byte_count - (word_count * 8);
    SHA_MEMCPY(dest, buf_rev, bytes_leftover);
    return cpy_byte_count;
  }
  static void sha3_get_hash(sha3_ctx* ctx, uint8_t* hash_bytes_out)
  {
    // Pad Message ending
    static const uint8_t PAD_STR_READ_ONLY = 0b01000000;
    sha3_append_bits(ctx, &PAD_STR_READ_ONLY, 2);
    // Pad Block
    // ASSERT (ctx->block_count * ctx->r) <= UINT64_MAX
    sha3_pad10_star_1(ctx, ctx->bit_count);
    //
    // sha3_sponge(ctx, NULL);

    // Init Values
    unsigned int missing_byte_count  = ctx->d / 8;
    unsigned int added_count         = sha3_copy_state_reversed(ctx, ctx->state.bytes, hash_bytes_out, missing_byte_count);
    missing_byte_count              -= added_count;
    hash_bytes_out                  += added_count;

    while (missing_byte_count > 0) {
      sha3_keccak_p(ctx);
      added_count         = sha3_copy_state_reversed(ctx, ctx->state.bytes, hash_bytes_out, missing_byte_count);
      missing_byte_count -= added_count;
      hash_bytes_out     += added_count;
    }
  }
  SHA_DEF void sha3_224_get_hash(sha3_ctx* ctx, sha_224_t* hash_out)
  {
    sha_224_bytes_t bytes;
    sha3_get_hash(ctx, bytes.bytes);
    sha_224_from_bytes(bytes.bytes, hash_out);
  }
  SHA_DEF void sha3_256_get_hash(sha3_ctx* ctx, sha_256_t* hash_out)
  {
    sha_256_bytes_t bytes;
    sha3_get_hash(ctx, bytes.bytes);
    sha_256_from_bytes(bytes.bytes, hash_out);
  }
  SHA_DEF void sha3_384_get_hash(sha3_ctx* ctx, sha_384_t* hash_out)
  {
    sha_384_bytes_t bytes;
    sha3_get_hash(ctx, bytes.bytes);
    sha_384_from_bytes(bytes.bytes, hash_out);
  }
  SHA_DEF void sha3_512_get_hash(sha3_ctx* ctx, sha_512_t* hash_out)
  {
    sha_512_bytes_t bytes;
    sha3_get_hash(ctx, bytes.bytes);
    sha_512_from_bytes(bytes.bytes, hash_out);
  }
  SHA_DEF void sha3_shake128_get_hash(sha3_ctx* ctx, uint8_t* hash_out) { sha3_get_hash(ctx, hash_out); }
  SHA_DEF void sha3_shake256_get_hash(sha3_ctx* ctx, uint8_t* hash_out) { sha3_get_hash(ctx, hash_out); }

#endif // SHA_2_IMPLEMENTATION

// --------------------
// Words to bytes
// Convert the normal sha2_xxx_t containing words, to sha2_xxx_bytes_t containing bytes
// --------------------
#ifdef SHA_2_IMPLEMENTATION
  // SHA 1
  SHA_DEF void sha1_to_bytes(sha1_t h, uint8_t* bytes_out)
  {
    if (bytes_out == NULL) return;
    if (!SHA_IS_BIG_ENDIAN) {
      for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
        SHA_WORD_TYPE(SHA1) word_swapped = SHA_BYTE_SWAP(SHA1, h.words[i]);
        SHA_MEMCPY(bytes_out + i * 4, &word_swapped, 4);
      }
    }
  }
  // SHA 2/3
  SHA_DEF void sha_224_to_bytes(sha_224_t h, uint8_t* bytes_out)
  {
    if (bytes_out == NULL) return;
    if (!SHA_IS_BIG_ENDIAN) {
      for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
        SHA_WORD_TYPE(SHA2_224) word_swapped = SHA_BYTE_SWAP(SHA2_224, h.words[i]);
        SHA_MEMCPY(bytes_out + i * 4, &word_swapped, 4);
      }
    }
  }
  SHA_DEF void sha_256_to_bytes(sha_256_t h, uint8_t* bytes_out)
  {
    if (bytes_out == NULL) return;
    if (!SHA_IS_BIG_ENDIAN) {
      for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
        SHA_WORD_TYPE(SHA2_256) word_swapped = SHA_BYTE_SWAP(SHA2_256, h.words[i]);
        SHA_MEMCPY(bytes_out + i * 4, &word_swapped, 4);
      }
    }
  }
  SHA_DEF void sha_384_to_bytes(sha_384_t h, uint8_t* bytes_out)
  {
    if (bytes_out == NULL) return;
    if (!SHA_IS_BIG_ENDIAN) {
      for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
        SHA_WORD_TYPE(SHA2_384) word_swapped = SHA_BYTE_SWAP(SHA2_384, h.words[i]);
        SHA_MEMCPY(bytes_out + i * 8, &word_swapped, 8);
      }
    }
  }
  SHA_DEF void sha_512_to_bytes(sha_512_t h, uint8_t* bytes_out)
  {
    if (bytes_out == NULL) return;
    if (!SHA_IS_BIG_ENDIAN) {
      for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
        SHA_WORD_TYPE(SHA2_512) word_swapped = SHA_BYTE_SWAP(SHA2_512, h.words[i]);
        SHA_MEMCPY(bytes_out + i * 8, &word_swapped, 8);
      }
    }
  }
#endif // SHA_2_IMPLEMENTATION

// ------------------
// Bytes to words
// ------------------
#ifdef SHA_2_IMPLEMENTATION
  // SHA 1
  SHA_DEF void sha1_from_bytes(uint8_t* bytes, sha1_t* hash_out)
  {
    if (hash_out == NULL) return;
    if (!SHA_IS_BIG_ENDIAN) {
      for (size_t i = 0; i < sizeof(hash_out->words) / sizeof(*hash_out->words); i++) {
        SHA_MEMCPY(&hash_out->words[i], bytes + i * 4, 4);
        hash_out->words[i] = SHA_BYTE_SWAP(SHA1, hash_out->words[i]);
      }
    }
  }
  // SHA 2/3
  SHA_DEF void sha_224_from_bytes(uint8_t* bytes, sha_224_t* hash_out)
  {
    if (hash_out == NULL) return;
    if (!SHA_IS_BIG_ENDIAN) {
      for (size_t i = 0; i < sizeof(hash_out->words) / sizeof(*hash_out->words); i++) {
        SHA_MEMCPY(&hash_out->words[i], bytes + i * 4, 4);
        hash_out->words[i] = SHA_BYTE_SWAP(SHA2_224, hash_out->words[i]);
      }
    }
  }
  SHA_DEF void sha_256_from_bytes(uint8_t* bytes, sha_256_t* hash_out)
  {
    if (hash_out == NULL) return;
    if (!SHA_IS_BIG_ENDIAN) {
      for (size_t i = 0; i < sizeof(hash_out->words) / sizeof(*hash_out->words); i++) {
        SHA_MEMCPY(&hash_out->words[i], bytes + i * 4, 4);
        hash_out->words[i] = SHA_BYTE_SWAP(SHA2_256, hash_out->words[i]);
      }
    }
  }
  SHA_DEF void sha_384_from_bytes(uint8_t* bytes, sha_384_t* hash_out)
  {
    if (hash_out == NULL) return;
    if (!SHA_IS_BIG_ENDIAN) {
      for (size_t i = 0; i < sizeof(hash_out->words) / sizeof(*hash_out->words); i++) {
        SHA_MEMCPY(&hash_out->words[i], bytes + i * 8, 8);
        hash_out->words[i] = SHA_BYTE_SWAP(SHA2_384, hash_out->words[i]);
      }
    }
  }
  SHA_DEF void sha_512_from_bytes(uint8_t* bytes, sha_512_t* hash_out)
  {
    if (hash_out == NULL) return;
    if (!SHA_IS_BIG_ENDIAN) {
      for (size_t i = 0; i < sizeof(hash_out->words) / sizeof(*hash_out->words); i++) {
        SHA_MEMCPY(&hash_out->words[i], bytes + i * 8, 8);
        hash_out->words[i] = SHA_BYTE_SWAP(SHA2_512, hash_out->words[i]);
      }
    }
  }
#endif // SHA_2_IMPLEMENTATION

  // ------------------------
  // Compare
  // ------------------------
#ifdef SHA_2_IMPLEMENTATION
  // SHA 1
  SHA_DEF bool sha1_is_equal(const sha1_t* a, const sha1_t* b)
  {
    for (int i = 0; i < sizeof(a->words) / sizeof(*a->words); i++) {
      if (a->words[i] != b->words[i]) return false;
    }
    return true;
  }
  // SHA 2
  SHA_DEF bool sha_224_is_equal(const sha_224_t* a, const sha_224_t* b)
  {
    for (int i = 0; i < sizeof(a->words) / sizeof(*a->words); i++) {
      if (a->words[i] != b->words[i]) return false;
    }
    return true;
  }
  SHA_DEF bool sha_256_is_equal(const sha_256_t* a, const sha_256_t* b)
  {
    for (int i = 0; i < sizeof(a->words) / sizeof(*a->words); i++) {
      if (a->words[i] != b->words[i]) return false;
    }
    return true;
  }
  SHA_DEF bool sha_384_is_equal(const sha_384_t* a, const sha_384_t* b)
  {
    for (int i = 0; i < sizeof(a->words) / sizeof(*a->words); i++) {
      if (a->words[i] != b->words[i]) return false;
    }
    return true;
  }
  SHA_DEF bool sha_512_is_equal(const sha_512_t* a, const sha_512_t* b)
  {
    for (int i = 0; i < sizeof(a->words) / sizeof(*a->words); i++) {
      if (a->words[i] != b->words[i]) return false;
    }
    return true;
  }
#endif // SHA_2_IMPLEMENTATION

  // -------------------------
  // To String
  // -------------------------
#ifdef SHA_2_IMPLEMENTATION
  static void sha_byte_to_hex_string(char* buf, bool upper_case, uint8_t v)
  {
    const char bits_low  = v & 0x0F;
    const char bits_high = (v & 0xF0) >> 4;
    {
      // Low
      if (bits_low < 10) buf[1] = bits_low + '0';
      else buf[1] = (bits_low - 10) + (upper_case ? 'A' : 'a');
    }
    {
      // High
      if (bits_high < 10) buf[0] = bits_high + '0';
      else buf[0] = (bits_high - 10) + (upper_case ? 'A' : 'a');
    }
  }
  static void sha_word_32_to_hex_string(char* buf, bool upper_case, _SHA2_WORD_TYPE(32) v)
  {
    for (int i = (32 / 8) - 1; i >= 0; i--) {
      unsigned int  shift_amount = (i * 8);
      const uint8_t byte         = SHA2_AND(32, v, 0xFF);
      sha_byte_to_hex_string(buf + i * 2, upper_case, byte);
      v = SHA2_SHR(32, v, 8);
    }
  }
  static void sha_word_64_to_hex_string(char* buf, bool upper_case, _SHA2_WORD_TYPE(64) v)
  {
    for (int i = (64 / 8) - 1; i >= 0; i--) {
      unsigned int  shift_amount = (i * 8);
      const uint8_t byte         = SHA2_AND(64, v, 0xFF);
      sha_byte_to_hex_string(buf + i * 2, upper_case, byte);
      v = SHA2_SHR(64, v, 8);
    }
  }

  // SHA 1
  SHA_DEF const char* sha1_to_string(const sha1_t* h, bool upper_case)
  {
    static char buf[(SHA2_HASH_SIZE(SHA1) / 4) + 1]; // 4bits per char
    for (size_t i = 0; i < sizeof(h->words) / sizeof(*h->words); i++) {
      sha_word_32_to_hex_string(buf + i * 8, upper_case, h->words[i]);
    }
    buf[SHA2_HASH_SIZE(SHA1) / 4] = '\0';
    return buf;
  }
  // SHA 2
  SHA_DEF const char* sha_224_to_string(const sha_224_t* h, bool upper_case)
  {
    static char buf[(SHA2_HASH_SIZE(SHA2_224) / 4) + 1]; // 4bits per char
    for (size_t i = 0; i < sizeof(h->words) / sizeof(*h->words); i++) {
      sha_word_32_to_hex_string(buf + i * 8, upper_case, h->words[i]);
    }
    buf[SHA2_HASH_SIZE(SHA2_224) / 4] = '\0';
    return buf;
  }
  SHA_DEF const char* sha_256_to_string(const sha_256_t* h, bool upper_case)
  {
    static char buf[(SHA2_HASH_SIZE(SHA2_256) / 4) + 1]; // 4bits per char
    for (size_t i = 0; i < sizeof(h->words) / sizeof(*h->words); i++) {
      sha_word_32_to_hex_string(buf + i * 8, upper_case, h->words[i]);
    }
    buf[SHA2_HASH_SIZE(SHA2_256) / 4] = '\0';
    return buf;
  }
  SHA_DEF const char* sha_384_to_string(const sha_384_t* h, bool upper_case)
  {
    static char buf[(SHA2_HASH_SIZE(SHA2_384) / 4) + 1]; // 4bits per char
    for (size_t i = 0; i < sizeof(h->words) / sizeof(*h->words); i++) {
      sha_word_64_to_hex_string(buf + i * 16, upper_case, h->words[i]);
    }
    buf[SHA2_HASH_SIZE(SHA2_384) / 4] = '\0';
    return buf;
  }
  SHA_DEF const char* sha_512_to_string(const sha_512_t* h, bool upper_case)
  {
    static char buf[(SHA2_HASH_SIZE(SHA2_512) / 4) + 1]; // 4bits per char
    for (size_t i = 0; i < sizeof(h->words) / sizeof(*h->words); i++) {
      sha_word_64_to_hex_string(buf + i * 16, upper_case, h->words[i]);
    }
    buf[SHA2_HASH_SIZE(SHA2_512) / 4] = '\0';
    return buf;
  }
  // TODO: Bytes to string?
#endif // SHA_2_IMPLEMENTATION

#ifdef __cplusplus
}
#endif

#endif // _SHA_2_