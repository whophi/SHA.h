#ifndef _SHA_2_
#define _SHA_2_

// --------------------
// Includes
// --------------------

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

// TODO if available
#include <immintrin.h> // for #include "sha512intrin.h"
// #include "sha512intrin.h"
// #if __has_builtin()

// ---------------------------
// Infos
// ---------------------------

// Specification
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

// Implementation
// To include the implementation, define SHA_2_IMPLEMENTATION:
// #define SHA_2_IMPLEMENTATION

// Assert
// The assert function can be set by #defining SHA2_ASSERT. But it has to be an expression.
// The default assert implementation needs <stdio.h> and <stdlib.h>
// TODO: Find way to static_assert it is an expression
// TODO: Find a way to check if static_assert is available/make it definable

// Memory Functions
// Can use own memory functions (memset, memcpy), by #defining SHA2_MEMSET and SHA2_MEMCPY
// If no <string.h> is available, can also prevents its import with #define SHA2_NO_STRING_INCLUDE

// Word to Hex
// A
// Can disable the import of <inttypes.h> with #define SHA2_NO_INTTYPES_INCLUDE

// Word types
// Can #define SHA2_WORD_TYPE_32, SHA2_WORD_TYPE_64 to change the types used for the underlying words in hash and block
// The default is uint32_t and uint64_t

// Is big endian
// Can replace the test for big endian, by #defining SHA2_IS_BIG_ENDIAN as an expr,
// that is true if the current system is big endian

// Rotation Ops
// Existing rotation operations defined based on basic ops
// But if you want to use a native impl, can replace them with #define SHA2_NO_ROT_OPS
// Rotation Ops are: SHA2_ROTR(WS, x, n), SHA2_ROTL
// Arguments are: WS:WordSize, x:value, n:shift

// --------------------------
// Defines
// --------------------------

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
#ifndef SHA2_MEMCPY
#define SHA2_MEMCPY(dest, src, size) memcpy(dest, src, size)
#endif // SHA2_MEMCPY
#else  // SHA2_NO_STRING_INCLUDE
#ifndef SHA2_MEMSET
static_assert("SHA2_MEMSET not defined without string.h");
#endif // SHA2_MEMSET
#ifndef SHA2_MEMCPY
static_assert("SHA2_MEMCPY not defined without string.h");
#endif // SHA2_MEMCPY
#endif // SHA2_NO_STRING_INCLUDE

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
#define SHA2_WORD_TYPE(SHA)           _SHA2_WORD_TYPE(SHA2_WORD_SIZE(SHA))

// --------------------------
// Basic Operations
// --------------------------
#define SHA2_NOT(WS, a)    (~((_SHA2_WORD_TYPE(WS))(a)))
#define SHA2_OR(WS, a, b)  (((_SHA2_WORD_TYPE(WS))(a)) | ((_SHA2_WORD_TYPE(WS))(b)))
#define SHA2_AND(WS, a, b) (((_SHA2_WORD_TYPE(WS))(a)) & ((_SHA2_WORD_TYPE(WS))(b)))
#define SHA2_XOR(WS, a, b) (((_SHA2_WORD_TYPE(WS))(a)) ^ ((_SHA2_WORD_TYPE(WS))(b)))
#define SHA2_SHR(WS, x, n) (((_SHA2_WORD_TYPE(WS))(x)) >> (n))
#define SHA2_SHL(WS, x, n) (((_SHA2_WORD_TYPE(WS))(x)) << (n))

#ifndef SHA2_NO_ROT_OPS
#define SHA2_ROTR(WS, x, n) SHA2_OR(WS, SHA2_SHR(WS, x, n), SHA2_SHL(WS, x, (WS) - (n)))
#define SHA2_ROTL(WS, x, n) SHA2_OR(WS, SHA2_SHL(WS, x, n), SHA2_SHR(WS, x, (WS) - (n)))
#else  // SHA2_NO_ROT_OPS
#ifndef SHA2_ROTR
static_assert(false, "Missing definition for SHA2_ROTR(WS, x, n)");
#endif // SHA2_ROTR
#ifndef SHA2_ROTL
static_assert(false, "Missing definition for SHA2_ROTL(WS, x, n)");
#endif // SHA2_ROTL
#endif // SHA2_NO_ROT_OPS

// --------------------------
// Byte Swap (little/big endian)
// --------------------------

// Little- or Bigendian
#ifndef SHA2_IS_BIG_ENDIAN
#define SHA2_IS_BIG_ENDIAN \
  (!(union {               \
      uint16_t      u16;   \
      unsigned char c;     \
    }) { .u16 = 1 }        \
        .c)
#endif // SHA2_IS_BIG_ENDIAN

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
#define SHA2_BYTE_SWAP(SHA_SIZE, x)           SHA2_BYTE_SWAP_WS(SHA2_WORD_SIZE(SHA_SIZE), x)

#define SHA2_BYTE_SWAP_IF_LITTLE(SHA_SIZE, x) (SHA2_IS_BIG_ENDIAN ? (x) : SHA2_BYTE_SWAP(SHA_SIZE, x))
#define SHA2_BYTE_SWAP_IF_LITTLE_WS(WS, x)    (SHA2_IS_BIG_ENDIAN ? (x) : SHA2_BYTE_SWAP_WS(WS, x))

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

#ifdef __cplusplus
extern "C" {
#endif

  // --------------------------
  // API
  // --------------------------

  // Block Types
  typedef struct {
    union {
      uint8_t bytes[SHA2_BLOCK_SIZE(SHA2_256) / 8];
      SHA2_WORD_TYPE(SHA2_256) words[SHA2_WORDS_IN_BLOCK(SHA2_256)];
      uint64_t sizes[SHA2_BLOCK_SIZE(SHA2_256) / 64];
    };
  } sha2_block_256_t;

  typedef struct {
    union {
      uint8_t bytes[SHA2_BLOCK_SIZE(SHA2_512) / 8];
      SHA2_WORD_TYPE(SHA2_512) words[SHA2_WORDS_IN_BLOCK(SHA2_512)];
    };
  } sha2_block_512_t;

  // Hash Types
#define _SHA2_HASH_TYPE_NAME(SHA_SIZE) sha2_##SHA_SIZE##_t
#define _SHA2_HASH_TYPE(SHA_SIZE)                                 \
  typedef struct {                                                \
    SHA2_WORD_TYPE(SHA_SIZE) words[SHA2_WORDS_IN_HASH(SHA_SIZE)]; \
  } _SHA2_HASH_TYPE_NAME(SHA_SIZE)

  typedef struct {
    SHA2_WORD_TYPE(SHA1) words[SHA2_WORDS_IN_HASH(SHA1)];
  } sha1_t;

  _SHA2_HASH_TYPE(SHA2_224);
  _SHA2_HASH_TYPE(SHA2_256);
  _SHA2_HASH_TYPE(SHA2_384);
  _SHA2_HASH_TYPE(SHA2_512);

  // Byte Types
#define _SHA2_HASH_BYTE_TYPE_NAME(SHA_SIZE) sha2_##SHA_SIZE##_bytes_t
#define _SHA2_HASH_BYTE_TYPE(SHA_SIZE)                            \
  typedef struct {                                                \
    SHA2_WORD_TYPE(SHA_SIZE) bytes[SHA2_WORDS_IN_HASH(SHA_SIZE)]; \
  } _SHA2_HASH_BYTE_TYPE_NAME(SHA_SIZE)

  typedef struct {
    SHA2_WORD_TYPE(SHA1) bytes[SHA2_WORDS_IN_HASH(SHA1)];
  } sha1_bytes_t;

  _SHA2_HASH_BYTE_TYPE(SHA2_224);
  _SHA2_HASH_BYTE_TYPE(SHA2_256);
  _SHA2_HASH_BYTE_TYPE(SHA2_384);
  _SHA2_HASH_BYTE_TYPE(SHA2_512);

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
    sha2_256_t       hash;
  } sha2_256_ctx;

  typedef struct {
    sha2_block_512_t block;
    uint64_t         block_count_low;
    uint64_t         block_count_high;
    uint16_t         bit_count;
    sha2_512_t       hash;
  } sha2_512_ctx;

  // ---------------------
  // Reset Context
  // ---------------------
  void sha1_reset(sha1_ctx* ctx);
  void sha2_224_reset(sha2_256_ctx* ctx);
  void sha2_256_reset(sha2_256_ctx* ctx);
  void sha2_384_reset(sha2_512_ctx* ctx);
  void sha2_512_reset(sha2_512_ctx* ctx);
  void sha2_512_224_reset(sha2_512_ctx* ctx);
  void sha2_512_256_reset(sha2_512_ctx* ctx);

  // -------------------------
  // Append
  // -------------------------
  // 1
  void sha1_append_bytes(sha1_ctx* ctx, uint8_t* data, uint64_t byte_count);
  void sha1_append_bits(sha1_ctx* ctx, uint8_t* data, uint64_t bit_count);
  void sha1_append(sha1_ctx* ctx, uint8_t* data, uint64_t bit_count);
  // 224/256
  void sha2_256_append_bytes(sha2_256_ctx* ctx, uint8_t* data, uint64_t byte_count);
  void sha2_256_append_bits(sha2_256_ctx* ctx, uint8_t* data, uint64_t bit_count);
  void sha2_256_append(sha2_256_ctx* ctx, uint8_t* data, uint64_t bit_count);
  // 384/512
  void sha2_512_append_bytes(sha2_512_ctx* ctx, uint8_t* data, uint64_t byte_count);
  void sha2_512_append_bits(sha2_512_ctx* ctx, uint8_t* data, uint64_t bit_count);
  void sha2_512_append(sha2_512_ctx* ctx, uint8_t* data, uint64_t bit_count);

  // -----------------------
  // Get Hash (and reset)
  // -----------------------
  sha1_t     sha1_get_hash(sha1_ctx* ctx);
  sha2_224_t sha2_224_get_hash(sha2_256_ctx* ctx);
  sha2_256_t sha2_256_get_hash(sha2_256_ctx* ctx);
  sha2_384_t sha2_384_get_hash(sha2_512_ctx* ctx);
  sha2_512_t sha2_512_get_hash(sha2_512_ctx* ctx);
  sha2_224_t sha2_512_224_get_hash(sha2_512_ctx* ctx);
  sha2_256_t sha2_512_256_get_hash(sha2_512_ctx* ctx);

  // --------------------
  // Words to bytes
  // Convert the normal sha2_xxx_t containing words, to sha2_xxx_bytes_t containing bytes
  // --------------------
  sha2_224_bytes_t sha2_224_to_bytes(sha2_224_t h);
  sha2_256_bytes_t sha2_256_to_bytes(sha2_256_t h);
  sha2_384_bytes_t sha2_384_to_bytes(sha2_384_t h);
  sha2_512_bytes_t sha2_512_to_bytes(sha2_512_t h);

  // --------------------
  // Compare
  // --------------------
  bool sha1_is_equal(sha1_t a, sha1_t b);
  bool sha2_224_is_equal(sha2_224_t a, sha2_224_t b);
  bool sha2_256_is_equal(sha2_256_t a, sha2_256_t b);
  bool sha2_384_is_equal(sha2_384_t a, sha2_384_t b);
  bool sha2_512_is_equal(sha2_512_t a, sha2_512_t b);

  // ----------------------
  // To String
  // Note: Not thread save (static buffer in fn)
  // ----------------------
  const char* sha1_to_string(sha1_t h, bool upper_case);
  const char* sha2_224_to_string(sha2_224_t h, bool upper_case);
  const char* sha2_256_to_string(sha2_256_t h, bool upper_case);
  const char* sha2_384_to_string(sha2_384_t h, bool upper_case);
  const char* sha2_512_to_string(sha2_512_t h, bool upper_case);

  // ---------------------
  // Constants
  // ---------------------
  SHA2_WORD_TYPE(SHA1) sha1_K(size_t t);
#ifdef SHA_2_IMPLEMENTATION
  SHA2_WORD_TYPE(SHA1) sha1_K(size_t t)
  {
    if (t < 20) return 0x5a827999;
    else if (t < 40) return 0x6ed9eba1;
    else if (t < 60) return 0x8f1bbcdc;
    else if (t < 80) return 0xca62c1d6;
    else SHA2_ASSERT(false, "t out of range 0-79");
  }
#endif // SHA_2_IMPLEMENTATION

  extern _SHA2_WORD_TYPE(32) SHA2_CONST_224_256[];
#ifdef SHA_2_IMPLEMENTATION
  _SHA2_WORD_TYPE(32)
  SHA2_CONST_224_256[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  };
#endif // SHA_2_IMPLEMENTATION

  extern _SHA2_WORD_TYPE(64) SHA2_CONST_384_512[];
#ifdef SHA_2_IMPLEMENTATION
  _SHA2_WORD_TYPE(64)
  SHA2_CONST_384_512[] = {
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
  extern SHA2_WORD_TYPE(SHA1) SHA2_CONST_INITIAL_1[];
#ifdef SHA_2_IMPLEMENTATION
  SHA2_WORD_TYPE(SHA1) SHA2_CONST_INITIAL_1[] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
#endif

  extern SHA2_WORD_TYPE(SHA2_224) SHA2_CONST_INITIAL_224[];
#ifdef SHA_2_IMPLEMENTATION
  SHA2_WORD_TYPE(SHA2_224)
  SHA2_CONST_INITIAL_224[] = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
  };
#endif

  extern SHA2_WORD_TYPE(SHA2_256) SHA2_CONST_INITIAL_256[];
#ifdef SHA_2_IMPLEMENTATION
  SHA2_WORD_TYPE(SHA2_256)
  SHA2_CONST_INITIAL_256[] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  };
#endif

  extern SHA2_WORD_TYPE(SHA2_384) SHA2_CONST_INITIAL_384[];
#ifdef SHA_2_IMPLEMENTATION
  SHA2_WORD_TYPE(SHA2_384)
  SHA2_CONST_INITIAL_384[] = {
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
  };
#endif

  extern SHA2_WORD_TYPE(SHA2_512) SHA2_CONST_INITIAL_512[];
#ifdef SHA_2_IMPLEMENTATION
  SHA2_WORD_TYPE(SHA2_512)
  SHA2_CONST_INITIAL_512[] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
  };
#endif

  extern SHA2_WORD_TYPE(SHA2_512_224) SHA2_CONST_INITIAL_512_224[];
#ifdef SHA_2_IMPLEMENTATION
  SHA2_WORD_TYPE(SHA2_512_224)
  SHA2_CONST_INITIAL_512_224[] = {
    0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
  };
#endif

  extern SHA2_WORD_TYPE(SHA2_512_256) SHA2_CONST_INITIAL_512_256[];
#ifdef SHA_2_IMPLEMENTATION
  SHA2_WORD_TYPE(SHA2_512_256)
  SHA2_CONST_INITIAL_512_256[] = {
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
  void sha1_reset(sha1_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_1[i];
    }
    ctx->block_count = 0;
    ctx->bit_count   = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_224) / 8);
  }
  void sha2_224_reset(sha2_256_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_224[i];
    }
    ctx->block_count = 0;
    ctx->bit_count   = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_224) / 8);
  }
  void sha2_256_reset(sha2_256_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_256[i];
    }
    ctx->block_count = 0;
    ctx->bit_count   = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_256) / 8);
  }
  void sha2_384_reset(sha2_512_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_384[i];
    }
    ctx->block_count_low  = 0;
    ctx->block_count_high = 0;
    ctx->bit_count        = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_384) / 8);
  }
  void sha2_512_reset(sha2_512_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_512[i];
    }
    ctx->block_count_low  = 0;
    ctx->block_count_high = 0;
    ctx->bit_count        = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_512) / 8);
  }
  void sha2_512_224_reset(sha2_512_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_512_224[i];
    }
    ctx->block_count_low  = 0;
    ctx->block_count_high = 0;
    ctx->bit_count        = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_512) / 8);
  }
  void sha2_512_256_reset(sha2_512_ctx* ctx)
  {
    for (size_t i = 0; i < sizeof(ctx->hash.words) / sizeof(*ctx->hash.words); i++) {
      ctx->hash.words[i] = SHA2_CONST_INITIAL_512_256[i];
    }
    ctx->block_count_low  = 0;
    ctx->block_count_high = 0;
    ctx->bit_count        = 0;
    SHA2_MEMSET(ctx->block.bytes, 0, SHA2_BLOCK_SIZE(SHA2_512) / 8);
  }
#endif // SHA_2_IMPLEMENTATION

// ---------------------
// Append
// ---------------------
#ifdef SHA_2_IMPLEMENTATION
  // 1
  static void _sha1_hash_block(sha1_ctx* ctx)
  {
    static uint32_t  W[80];
    sha2_block_256_t block = ctx->block;

    {
      // Init W state
      for (size_t t = 0; t < 16; t++) { W[t] = SHA2_BYTE_SWAP_IF_LITTLE(SHA1, block.words[t]); }
      for (size_t t = 16; t < 80; t++) {
        SHA2_WORD_TYPE(SHA1) xor = SHA2_XOR(SHA2_WORD_SIZE(SHA1), W[t - 3], W[t - 8]);
        xor                      = SHA2_XOR(SHA2_WORD_SIZE(SHA1), xor, W[t - 14]);
        xor                      = SHA2_XOR(SHA2_WORD_SIZE(SHA1), xor, W[t - 16]);
        W[t]                     = SHA2_ROTL(SHA2_WORD_SIZE(SHA1), xor, 1);
      }
    }

    SHA2_WORD_TYPE(SHA1) a, b, c, d, e;
    {
      (a = ctx->hash.words[0], b = ctx->hash.words[1], c = ctx->hash.words[2]);
      (d = ctx->hash.words[3], e = ctx->hash.words[4]);
    }

    for (size_t t = 0; t < 80; t++) {
      const SHA2_WORD_TYPE(SHA1) T = SHA2_ROTL(SHA2_WORD_SIZE(SHA1), a, 5) + SHA1_F(t, b, c, d) + e + sha1_K(t) + W[t];
      (e = d, d = c, c = SHA2_ROTL(SHA2_WORD_SIZE(SHA1), b, 30), b = a, a = T);
    }

    {
      // Hash i from i - 1
      (ctx->hash.words[0] = a + ctx->hash.words[0], ctx->hash.words[1] = b + ctx->hash.words[1]);
      (ctx->hash.words[2] = c + ctx->hash.words[2], ctx->hash.words[3] = d + ctx->hash.words[3]);
      (ctx->hash.words[4] = e + ctx->hash.words[4]);
    }

    {
      // Reset state
      ctx->block_count += 1;
      ctx->bit_count    = 0;
      SHA2_MEMSET(ctx->block.bytes, 0, sizeof(ctx->block.bytes));
    }
  }
  static void _sha1_pad_block(sha1_ctx* ctx, size_t bits_in_block, uint64_t bits_total)
  {
    const size_t byte_index     = bits_in_block / 8;
    const size_t byte_bit_index = bits_in_block - (byte_index * 8);
    uint8_t*     bytes          = ctx->block.bytes;
    if (SHA2_IS_BIG_ENDIAN) {
      const uint8_t null_mask = 0xFF >> (8 - byte_bit_index);
      const uint8_t set_mask  = 0b00000001 << byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    } else {
      const uint8_t null_mask = 0xFF << (8 - byte_bit_index);
      const uint8_t set_mask  = 0b10000000 >> byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    }
    // Check if len fits in rest of block
    if (byte_index >= (SHA2_BLOCK_SIZE(SHA1) - 64) / 8) {
      ctx->bit_count = SHA2_BLOCK_SIZE(SHA1);
      _sha1_hash_block(ctx);
    }
    //
    ctx->block.sizes[7] = SHA2_BYTE_SWAP_IF_LITTLE_WS(64, bits_total);
  }
  void sha1_append_bytes(sha1_ctx* ctx, uint8_t* data, uint64_t byte_count)
  {
    if (ctx->bit_count % 8 != 0) { return sha1_append_bits(ctx, data, byte_count * 8); }

    // Fill started block
    if (ctx->bit_count > 0) {
      const size_t missing_byte_count = (SHA2_BLOCK_SIZE(SHA1) - ctx->bit_count) / 8;
      const size_t copy_byte_count    = SHA2_MIN(missing_byte_count, byte_count);
      SHA2_MEMCPY(ctx->block.bytes + (ctx->bit_count / 8), data, copy_byte_count);
      data           += copy_byte_count;
      byte_count     -= copy_byte_count;
      ctx->bit_count += copy_byte_count * 8;
      if (ctx->bit_count == SHA2_BLOCK_SIZE(SHA1)) _sha1_hash_block(ctx);
    }

    // Do full blocks
    const uint8_t bytes_in_block = SHA2_BLOCK_SIZE(SHA1) / 8;
    while (byte_count >= bytes_in_block) {
      SHA2_MEMCPY(ctx->block.bytes, data, bytes_in_block);
      data           += bytes_in_block;
      byte_count     -= bytes_in_block;
      ctx->bit_count  = SHA2_BLOCK_SIZE(SHA1);
      _sha1_hash_block(ctx);
    }

    // Set rest
    if (byte_count > 0) {
      SHA2_MEMCPY(ctx->block.bytes, data, byte_count);
      ctx->bit_count += byte_count * 8;
    }
  }
  void sha1_append_bits(sha1_ctx* ctx, uint8_t* data, uint64_t bit_count)
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
      if (ctx->bit_count == SHA2_BLOCK_SIZE(SHA1) && bits_in_data_byte >= missing_bit_count) {
        _sha1_hash_block(ctx);
        byte_index_next = 0;
      }

      if (added_bit_count < bits_in_data_byte) {
        ctx->block.bytes[byte_index_next] = (byte & ~(0xFF >> bits_in_data_byte)) << missing_bit_count;
      }
      bit_count -= bits_in_data_byte;
    }
  }
  void sha1_append(sha1_ctx* ctx, uint8_t* data, uint64_t bit_count) { sha1_append_bits(ctx, data, bit_count); }

  // 224/256
  static void _sha2_256_hash_block(sha2_256_ctx* ctx)
  {
    static SHA2_WORD_TYPE(SHA2_256) W[64];
    sha2_block_256_t block = ctx->block;

    {
      // Init W state
      for (size_t t = 0; t < 16; t++) { W[t] = SHA2_BYTE_SWAP_IF_LITTLE(SHA2_256, block.words[t]); }
      for (size_t t = 16; t < 64; t++) {
        const SHA2_WORD_TYPE(SHA2_256) sigma_1 = SHA2_SIGMA_SMALL(SHA2_WORD_SIZE(SHA2_256), W[t - 2], 17, 19, 10);
        const SHA2_WORD_TYPE(SHA2_256) sigma_0 = SHA2_SIGMA_SMALL(SHA2_WORD_SIZE(SHA2_256), W[t - 15], 7, 18, 3);
        W[t]                                   = sigma_1 + W[t - 7] + sigma_0 + W[t - 16];
      }
    }

    SHA2_WORD_TYPE(SHA2_256) a, b, c, d, e, f, g, h;
    {
      (a = ctx->hash.words[0], b = ctx->hash.words[1], c = ctx->hash.words[2], d = ctx->hash.words[3]);
      (e = ctx->hash.words[4], f = ctx->hash.words[5], g = ctx->hash.words[6], h = ctx->hash.words[7]);
    }

    for (size_t t = 0; t < 64; t++) {
      const SHA2_WORD_TYPE(SHA2_256) sigma_1 = SHA2_SIGMA_LARGE(SHA2_WORD_SIZE(SHA2_256), e, 6, 11, 25);
      const SHA2_WORD_TYPE(SHA2_256) sigma_0 = SHA2_SIGMA_LARGE(SHA2_WORD_SIZE(SHA2_256), a, 2, 13, 22);
      const SHA2_WORD_TYPE(SHA2_256) ch      = SHA2_CH(SHA2_WORD_SIZE(SHA2_256), e, f, g);
      const SHA2_WORD_TYPE(SHA2_256) maj     = SHA2_MAJ(SHA2_WORD_SIZE(SHA2_256), a, b, c);
      const SHA2_WORD_TYPE(SHA2_256) T1      = h + sigma_1 + ch + SHA2_CONST_224_256[t] + W[t];
      const SHA2_WORD_TYPE(SHA2_256) T2      = sigma_0 + maj;
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
      // Reset state
      ctx->block_count += 1;
      ctx->bit_count    = 0;
      SHA2_MEMSET(ctx->block.bytes, 0, sizeof(ctx->block.bytes));
    }
  }
  static void _sha2_256_pad_block(sha2_256_ctx* ctx, size_t bits_in_block, uint64_t bits_total)
  {
    const size_t byte_index     = bits_in_block / 8;
    const size_t byte_bit_index = bits_in_block - (byte_index * 8);
    uint8_t*     bytes          = ctx->block.bytes;
    if (SHA2_IS_BIG_ENDIAN) {
      const uint8_t null_mask = 0xFF >> (8 - byte_bit_index);
      const uint8_t set_mask  = 0b00000001 << byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    } else {
      const uint8_t null_mask = 0xFF << (8 - byte_bit_index);
      const uint8_t set_mask  = 0b10000000 >> byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    }
    // Check if len fits in rest of block
    if (byte_index >= (SHA2_BLOCK_SIZE(SHA2_256) - 64) / 8) {
      ctx->bit_count = SHA2_BLOCK_SIZE(SHA2_256);
      _sha2_256_hash_block(ctx);
    }
    //
    ctx->block.sizes[7] = SHA2_BYTE_SWAP_IF_LITTLE_WS(64, bits_total);
  }
  void sha2_256_append_bytes(sha2_256_ctx* ctx, uint8_t* data, uint64_t byte_count)
  {
    if (ctx->bit_count % 8 != 0) { return sha2_256_append_bits(ctx, data, byte_count * 8); }

    // Fill started block
    if (ctx->bit_count > 0) {
      const size_t missing_byte_count = (SHA2_BLOCK_SIZE(SHA2_256) - ctx->bit_count) / 8;
      const size_t copy_byte_count    = SHA2_MIN(missing_byte_count, byte_count);
      SHA2_MEMCPY(ctx->block.bytes + (ctx->bit_count / 8), data, copy_byte_count);
      data           += copy_byte_count;
      byte_count     -= copy_byte_count;
      ctx->bit_count += copy_byte_count * 8;
      if (ctx->bit_count == SHA2_BLOCK_SIZE(SHA2_256)) _sha2_256_hash_block(ctx);
    }

    // Do full blocks
    const uint8_t bytes_in_block = SHA2_BLOCK_SIZE(SHA2_256) / 8;
    while (byte_count >= bytes_in_block) {
      SHA2_MEMCPY(ctx->block.bytes, data, bytes_in_block);
      data           += bytes_in_block;
      byte_count     -= bytes_in_block;
      ctx->bit_count  = SHA2_BLOCK_SIZE(SHA2_256);
      _sha2_256_hash_block(ctx);
    }

    // Set rest
    if (byte_count > 0) {
      SHA2_MEMCPY(ctx->block.bytes, data, byte_count);
      ctx->bit_count += byte_count * 8;
    }
  }
  void sha2_256_append_bits(sha2_256_ctx* ctx, uint8_t* data, uint64_t bit_count)
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
      if (ctx->bit_count == SHA2_BLOCK_SIZE(SHA2_256) && bits_in_data_byte >= missing_bit_count) {
        _sha2_256_hash_block(ctx);
        byte_index_next = 0;
      }

      if (added_bit_count < bits_in_data_byte) {
        ctx->block.bytes[byte_index_next] = (byte & ~(0xFF >> bits_in_data_byte)) << missing_bit_count;
      }
      bit_count -= bits_in_data_byte;
    }
  }
  void sha2_256_append(sha2_256_ctx* ctx, uint8_t* data, uint64_t bit_count) { sha2_256_append_bits(ctx, data, bit_count); }

  // 384/512
  static void _sha2_512_hash_block(sha2_512_ctx* ctx)
  {
    static SHA2_WORD_TYPE(SHA2_512) W[80];
    sha2_block_512_t block = ctx->block;

    {
      // Init W state
      for (size_t t = 0; t < 16; t++) { W[t] = SHA2_BYTE_SWAP_IF_LITTLE(SHA2_512, block.words[t]); }
      for (size_t t = 16; t < 80; t++) {
        const SHA2_WORD_TYPE(SHA2_512) sigma_1 = SHA2_SIGMA_SMALL(SHA2_WORD_SIZE(SHA2_512), W[t - 2], 19, 61, 6);
        const SHA2_WORD_TYPE(SHA2_512) sigma_0 = SHA2_SIGMA_SMALL(SHA2_WORD_SIZE(SHA2_512), W[t - 15], 1, 8, 7);
        W[t]                                   = sigma_1 + W[t - 7] + sigma_0 + W[t - 16];
      }
    }

    SHA2_WORD_TYPE(SHA2_512) a, b, c, d, e, f, g, h;
    {
      (a = ctx->hash.words[0], b = ctx->hash.words[1], c = ctx->hash.words[2], d = ctx->hash.words[3]);
      (e = ctx->hash.words[4], f = ctx->hash.words[5], g = ctx->hash.words[6], h = ctx->hash.words[7]);
    }

    for (size_t t = 0; t < 80; t++) {
      const SHA2_WORD_TYPE(SHA2_512) sigma_1 = SHA2_SIGMA_LARGE(SHA2_WORD_SIZE(SHA2_512), e, 14, 18, 41);
      const SHA2_WORD_TYPE(SHA2_512) sigma_0 = SHA2_SIGMA_LARGE(SHA2_WORD_SIZE(SHA2_512), a, 28, 34, 39);
      const SHA2_WORD_TYPE(SHA2_512) ch      = SHA2_CH(SHA2_WORD_SIZE(SHA2_512), e, f, g);
      const SHA2_WORD_TYPE(SHA2_512) maj     = SHA2_MAJ(SHA2_WORD_SIZE(SHA2_512), a, b, c);
      const SHA2_WORD_TYPE(SHA2_512) T1      = h + sigma_1 + ch + SHA2_CONST_384_512[t] + W[t];
      const SHA2_WORD_TYPE(SHA2_512) T2      = sigma_0 + maj;
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
      SHA2_MEMSET(ctx->block.bytes, 0, sizeof(ctx->block.bytes));
    }
  }
  static void _sha2_512_pad_block(sha2_512_ctx* ctx, size_t bits_in_block, uint64_t bits_total_h, uint64_t bits_total_l)
  {
    const size_t byte_index     = bits_in_block / 8;
    const size_t byte_bit_index = bits_in_block - (byte_index * 8);
    uint8_t*     bytes          = ctx->block.bytes;
    if (SHA2_IS_BIG_ENDIAN) {
      const uint8_t null_mask = 0xFF >> (8 - byte_bit_index);
      const uint8_t set_mask  = 0b00000001 << byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    } else {
      const uint8_t null_mask = 0xFF << (8 - byte_bit_index);
      const uint8_t set_mask  = 0b10000000 >> byte_bit_index;
      bytes[byte_index]       = (bytes[byte_index] & null_mask) | set_mask;
    }
    // Check if len fits in rest of block
    if (byte_index >= (SHA2_BLOCK_SIZE(SHA2_512) - 128) / 8) {
      ctx->bit_count = SHA2_BLOCK_SIZE(SHA2_512);
      _sha2_512_hash_block(ctx);
    }
    //
    ctx->block.words[SHA2_WORDS_IN_BLOCK(SHA2_512) - 1] = SHA2_BYTE_SWAP_IF_LITTLE_WS(64, bits_total_l);
    ctx->block.words[SHA2_WORDS_IN_BLOCK(SHA2_512) - 2] = SHA2_BYTE_SWAP_IF_LITTLE_WS(64, bits_total_h);
  }
  void sha2_512_append_bytes(sha2_512_ctx* ctx, uint8_t* data, uint64_t byte_count)
  {
    if (ctx->bit_count % 8 != 0) { sha2_512_append_bits(ctx, data, byte_count * 8); }

    // Fill started block
    if (ctx->bit_count > 0) {
      const size_t missing_byte_count = (SHA2_BLOCK_SIZE(SHA2_512) - ctx->bit_count) / 8;
      const size_t copy_byte_count    = SHA2_MIN(missing_byte_count, byte_count);
      SHA2_MEMCPY(ctx->block.bytes + (ctx->bit_count / 8), data, copy_byte_count);
      data           += copy_byte_count;
      byte_count     -= copy_byte_count;
      ctx->bit_count += copy_byte_count * 8;
      if (ctx->bit_count == SHA2_BLOCK_SIZE(SHA2_512)) _sha2_512_hash_block(ctx);
    }

    // Do full blocks
    const size_t bytes_in_block = SHA2_BLOCK_SIZE(SHA2_512) / 8;
    while (byte_count >= bytes_in_block) {
      SHA2_MEMCPY(ctx->block.bytes, data, bytes_in_block);
      data           += bytes_in_block;
      byte_count     -= bytes_in_block;
      ctx->bit_count  = SHA2_BLOCK_SIZE(SHA2_512);
      _sha2_512_hash_block(ctx);
    }

    // Set rest
    if (byte_count > 0) {
      SHA2_MEMCPY(ctx->block.bytes, data, byte_count);
      ctx->bit_count += byte_count * 8;
    }
  }
  void sha2_512_append_bits(sha2_512_ctx* ctx, uint8_t* data, uint64_t bit_count)
  {
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

      // Set start of next byte
      size_t byte_index_next = byte_index + 1;
      if (byte_index + 1 < SHA2_BLOCK_SIZE(SHA2_512) / 8 && bits_in_data_byte > missing_bit_count) {
        _sha2_512_hash_block(ctx);
        byte_index_next = 0;
      }

      if (added_bit_count < bits_in_data_byte) {
        ctx->block.bytes[byte_index_next] = (byte & ~(0xFF >> bits_in_data_byte)) << missing_bit_count;
      }
      bit_count -= bits_in_data_byte;
    }
  }
  void sha2_512_append(sha2_512_ctx* ctx, uint8_t* data, uint64_t bit_count) { sha2_512_append_bits(ctx, data, bit_count); }
#endif // SHA_2_IMPLEMENTATION

  // -------------------
  // Get Hash
  // -------------------

#ifdef SHA_2_IMPLEMENTATION
  sha1_t sha1_get_hash(sha1_ctx* ctx)
  {
    const uint64_t total_bits = ctx->block_count * SHA2_BLOCK_SIZE(SHA1) + ctx->bit_count;
    _sha1_pad_block(ctx, ctx->bit_count, total_bits);
    _sha1_hash_block(ctx);
    sha1_t hash;
    for (uint32_t i = 0; i < sizeof(hash.words) / sizeof(*hash.words); i++) { hash.words[i] = ctx->hash.words[i]; }
    sha1_reset(ctx);
    return hash;
  }
  sha2_224_t sha2_224_get_hash(sha2_256_ctx* ctx)
  {
    const uint64_t total_bits = ctx->block_count * SHA2_BLOCK_SIZE(SHA2_256) + ctx->bit_count;
    _sha2_256_pad_block(ctx, ctx->bit_count, total_bits);
    _sha2_256_hash_block(ctx);
    sha2_224_t hash;
    for (uint32_t i = 0; i < sizeof(hash.words) / sizeof(*hash.words); i++) { hash.words[i] = ctx->hash.words[i]; }
    sha2_224_reset(ctx);
    return hash;
  }
  sha2_256_t sha2_256_get_hash(sha2_256_ctx* ctx)
  {
    const uint64_t total_bits = ctx->block_count * SHA2_BLOCK_SIZE(SHA2_256) + ctx->bit_count;
    _sha2_256_pad_block(ctx, ctx->bit_count, total_bits);
    _sha2_256_hash_block(ctx);
    const sha2_256_t hash = ctx->hash;
    sha2_256_reset(ctx);
    return hash;
  }
  sha2_384_t sha2_384_get_hash(sha2_512_ctx* ctx)
  {
    static_assert(SHA2_BLOCK_SIZE(SHA2_384) == 1024, "Block size for SHA2_384 is expected to be 1024");
    const uint64_t total_bits_low   = ctx->block_count_low * SHA2_BLOCK_SIZE(SHA2_384) + ctx->bit_count;
    uint64_t       total_bits_high  = ctx->block_count_high * SHA2_BLOCK_SIZE(SHA2_384);
    total_bits_high                |= ctx->block_count_low >> (64 - 10); // 2^10 = 1024
    _sha2_512_pad_block(ctx, ctx->bit_count, total_bits_high, total_bits_low);
    _sha2_512_hash_block(ctx);
    sha2_384_t hash;
    for (uint32_t i = 0; i < sizeof(hash.words) / sizeof(*hash.words); i++) { hash.words[i] = ctx->hash.words[i]; }
    sha2_384_reset(ctx);
    return hash;
  }
  sha2_512_t sha2_512_get_hash(sha2_512_ctx* ctx)
  {
    static_assert(SHA2_BLOCK_SIZE(SHA2_512) == 1024, "Block size for SHA2_512 is expected to be 1024");
    const uint64_t total_bits_low   = ctx->block_count_low * SHA2_BLOCK_SIZE(SHA2_512) + ctx->bit_count;
    uint64_t       total_bits_high  = ctx->block_count_high * SHA2_BLOCK_SIZE(SHA2_512);
    total_bits_high                |= ctx->block_count_low >> (64 - 10); // 2^10 = 1024
    _sha2_512_pad_block(ctx, ctx->bit_count, total_bits_high, total_bits_low);
    _sha2_512_hash_block(ctx);
    const sha2_512_t hash = ctx->hash;
    sha2_384_reset(ctx);
    return hash;
  }
  sha2_224_t sha2_512_224_get_hash(sha2_512_ctx* ctx)
  {
    static_assert(SHA2_BLOCK_SIZE(SHA2_512) == 1024, "Block size for SHA2_512 is expected to be 1024");
    const uint64_t total_bits_low   = ctx->block_count_low * SHA2_BLOCK_SIZE(SHA2_512) + ctx->bit_count;
    uint64_t       total_bits_high  = ctx->block_count_high * SHA2_BLOCK_SIZE(SHA2_512);
    total_bits_high                |= ctx->block_count_low >> (64 - 10); // 2^10 = 1024
    _sha2_512_pad_block(ctx, ctx->bit_count, total_bits_high, total_bits_low);
    _sha2_512_hash_block(ctx);
    sha2_224_t hash;
    for (uint32_t i = 0; i < sizeof(hash.words) / sizeof(*hash.words);) {
      const uint64_t v   = ctx->hash.words[i / 2];
      hash.words[i]      = v >> 32;
      hash.words[i + 1]  = v & 0xFFFFFFFF;
      i                 += 2;
    }
    sha2_512_224_reset(ctx);
    return hash;
  }
  sha2_256_t sha2_512_256_get_hash(sha2_512_ctx* ctx)
  {
    static_assert(SHA2_BLOCK_SIZE(SHA2_512) == 1024, "Block size for SHA2_512 is expected to be 1024");
    const uint64_t total_bits_low   = ctx->block_count_low * SHA2_BLOCK_SIZE(SHA2_512) + ctx->bit_count;
    uint64_t       total_bits_high  = ctx->block_count_high * SHA2_BLOCK_SIZE(SHA2_512);
    total_bits_high                |= ctx->block_count_low >> (64 - 10); // 2^10 = 1024
    _sha2_512_pad_block(ctx, ctx->bit_count, total_bits_high, total_bits_low);
    _sha2_512_hash_block(ctx);
    sha2_256_t hash;
    for (uint32_t i = 0; i < sizeof(hash.words) / sizeof(*hash.words);) {
      const uint64_t v   = ctx->hash.words[i / 2];
      hash.words[i]      = v >> 32;
      hash.words[i + 1]  = v & 0xFFFFFFFF;
      i                 += 2;
    }
    sha2_512_256_reset(ctx);
    return hash;
  }
#endif // SHA_2_IMPLEMENTATION

// --------------------
// Words to bytes
// Convert the normal sha2_xxx_t containing words, to sha2_xxx_bytes_t containing bytes
// --------------------
#ifdef SHA_2_IMPLEMENTATION
  sha1_bytes_t sha1_to_bytes(sha1_t h)
  {
    sha1_bytes_t bytes;
    for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
      SHA2_WORD_TYPE(SHA1) word_swapped = SHA2_BYTE_SWAP_IF_LITTLE(SHA1, h.words[i]);
      SHA2_MEMCPY(bytes.bytes + i * 4, &word_swapped, 4);
    }
    return bytes;
  }
  sha2_224_bytes_t sha2_224_to_bytes(sha2_224_t h)
  {
    sha2_224_bytes_t bytes;
    for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
      SHA2_WORD_TYPE(SHA2_224) word_swapped = SHA2_BYTE_SWAP_IF_LITTLE(SHA2_224, h.words[i]);
      SHA2_MEMCPY(bytes.bytes + i * 4, &word_swapped, 4);
    }
    return bytes;
  }
  sha2_256_bytes_t sha2_256_to_bytes(sha2_256_t h)
  {
    sha2_256_bytes_t bytes;
    for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
      SHA2_WORD_TYPE(SHA2_256) word_swapped = SHA2_BYTE_SWAP_IF_LITTLE(SHA2_256, h.words[i]);
      SHA2_MEMCPY(bytes.bytes + i * 4, &word_swapped, 4);
    }
    return bytes;
  }
  sha2_384_bytes_t sha2_384_to_bytes(sha2_384_t h)
  {
    sha2_384_bytes_t bytes;
    for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
      SHA2_WORD_TYPE(SHA2_384) word_swapped = SHA2_BYTE_SWAP_IF_LITTLE(SHA2_384, h.words[i]);
      SHA2_MEMCPY(bytes.bytes + i * 8, &word_swapped, 8);
    }
    return bytes;
  }
  sha2_512_bytes_t sha2_512_to_bytes(sha2_512_t h)
  {
    sha2_512_bytes_t bytes;
    for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
      SHA2_WORD_TYPE(SHA2_512) word_swapped = SHA2_BYTE_SWAP_IF_LITTLE(SHA2_512, h.words[i]);
      SHA2_MEMCPY(bytes.bytes + i * 8, &word_swapped, 8);
    }
    return bytes;
  }
#endif // SHA_2_IMPLEMENTATION

  // ------------------------
  // Compare
  // ------------------------

#ifdef SHA_2_IMPLEMENTATION
  bool sha1_is_equal(sha1_t a, sha1_t b)
  {
    for (int i = 0; i < sizeof(a.words) / sizeof(*a.words); i++) {
      if (a.words[i] != b.words[i]) return false;
    }
    return true;
  }
  bool sha2_224_is_equal(sha2_224_t a, sha2_224_t b)
  {
    for (int i = 0; i < sizeof(a.words) / sizeof(*a.words); i++) {
      if (a.words[i] != b.words[i]) return false;
    }
    return true;
  }
  bool sha2_256_is_equal(sha2_256_t a, sha2_256_t b)
  {
    for (int i = 0; i < sizeof(a.words) / sizeof(*a.words); i++) {
      if (a.words[i] != b.words[i]) return false;
    }
    return true;
  }
  bool sha2_384_is_equal(sha2_384_t a, sha2_384_t b)
  {
    for (int i = 0; i < sizeof(a.words) / sizeof(*a.words); i++) {
      if (a.words[i] != b.words[i]) return false;
    }
    return true;
  }
  bool sha2_512_is_equal(sha2_512_t a, sha2_512_t b)
  {
    for (int i = 0; i < sizeof(a.words) / sizeof(*a.words); i++) {
      if (a.words[i] != b.words[i]) return false;
    }
    return true;
  }
#endif // SHA_2_IMPLEMENTATION

  // -------------------------
  // To String
  // -------------------------

#ifdef SHA_2_IMPLEMENTATION
  static void sha2_word_32_to_hex_string(char* buf, bool upper_case, _SHA2_WORD_TYPE(32) v)
  {
    for (size_t i = 0; i < (32 / 4); i++) {
      char bits = SHA2_AND(32, v, 0xF);
      if (bits < 10) buf[(32 / 4) - 1 - i] = bits + '0';
      else buf[(32 / 4) - 1 - i] = (bits - 10) + (upper_case ? 'A' : 'a');
      v = SHA2_SHR(32, v, 4);
    }
  }
  static void sha2_word_64_to_hex_string(char* buf, bool upper_case, _SHA2_WORD_TYPE(64) v)
  {
    for (size_t i = 0; i < (64 / 4); i++) {
      char bits = SHA2_AND(64, v, 0xF);
      if (bits < 10) buf[(64 / 4) - 1 - i] = bits + '0';
      else buf[(64 / 4) - 1 - i] = (bits - 10) + (upper_case ? 'A' : 'a');
      v = SHA2_SHR(64, v, 4);
    }
  }

  const char* sha1_to_string(sha1_t h, bool upper_case)
  {
    static char buf[(SHA2_HASH_SIZE(SHA1) / 4) + 1]; // 4bits per char
    for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
      sha2_word_32_to_hex_string(buf + i * 8, upper_case, h.words[i]);
    }
    buf[SHA2_HASH_SIZE(SHA1) / 4] = '\0';
    return buf;
  }
  const char* sha2_224_to_string(sha2_224_t h, bool upper_case)
  {
    static char buf[(SHA2_HASH_SIZE(SHA2_224) / 4) + 1]; // 4bits per char
    for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
      sha2_word_32_to_hex_string(buf + i * 8, upper_case, h.words[i]);
    }
    buf[SHA2_HASH_SIZE(SHA2_224) / 4] = '\0';
    return buf;
  }
  const char* sha2_256_to_string(sha2_256_t h, bool upper_case)
  {
    static char buf[(SHA2_HASH_SIZE(SHA2_256) / 4) + 1]; // 4bits per char
    for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
      sha2_word_32_to_hex_string(buf + i * 8, upper_case, h.words[i]);
    }
    buf[SHA2_HASH_SIZE(SHA2_256) / 4] = '\0';
    return buf;
  }
  const char* sha2_384_to_string(sha2_384_t h, bool upper_case)
  {
    static char buf[(SHA2_HASH_SIZE(SHA2_384) / 4) + 1]; // 4bits per char
    for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
      sha2_word_64_to_hex_string(buf + i * 16, upper_case, h.words[i]);
    }
    buf[SHA2_HASH_SIZE(SHA2_384) / 4] = '\0';
    return buf;
  }
  const char* sha2_512_to_string(sha2_512_t h, bool upper_case)
  {
    static char buf[(SHA2_HASH_SIZE(SHA2_512) / 4) + 1]; // 4bits per char
    for (size_t i = 0; i < sizeof(h.words) / sizeof(*h.words); i++) {
      sha2_word_64_to_hex_string(buf + i * 16, upper_case, h.words[i]);
    }
    buf[SHA2_HASH_SIZE(SHA2_512) / 4] = '\0';
    return buf;
  }
#endif // SHA_2_IMPLEMENTATION

#ifdef __cplusplus
}
#endif

#endif // _SHA_2_