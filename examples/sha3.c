#define SHA_IMPLEMENTATION
#include "../sha.h"

#include <stdio.h>

int main()
{
  sha3_ctx_t sha_ctx; // Used by all (224, 256, 384, 512)

  /*
    Each hash size (224,256,384 and 512) has a separate reset function,
    because the starting values are different.
  */
  sha3_256_reset(&sha_ctx);

  /*
    These functions basically all do the same

    If the current position is byte aligned, it will use sha3_256_append_bytes,
    where the leftover bits use sha3_256_append_bits.
    If the current position is not byte aligned, everything is appended using sha3_256_append_bits.

    For different hash sizes (224,256,384 and 512), there are different functions
    (eg. sha3_XXX_append_bytes, sha3_XXX_append_bits, sha3_XXX_append)
  */
  sha3_append_bytes(&sha_ctx, "TEST", 4);
  sha3_append_bits(&sha_ctx, "TEST", 4 * 8);
  sha3_append(&sha_ctx, "TEST", 4 * 8);

  /*
    sha2_get_hash writes the bytes of the hash.
    The correct byte order is dependent on the endianess and can be acquired with sha2_to_words.
    On a big endian system .words and .bytes are equal.
    On a little endian system, only .words or .bytes is valid at a time.
  */
  sha3_256_t hash;
  sha3_256_get_hash(&sha_ctx, hash.bytes);
  printf("HASH: %s\n", sha_256_bytes_to_string_static(hash.bytes, false));
  sha_256_to_words(hash.words, hash.bytes);
  printf("HASH: %s\n", sha_256_words_to_string_static(hash.words, false));
  printf("TEST: 94e27a9ccc8e04c816116c4f5f1d994a8e97eb9b4964e46b3fde8272f12c09d5\n");
}
