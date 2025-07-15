#define SHA_IMPLEMENTATION
#include "../sha.h"

#include <stdio.h>

int main()
{
  sha2_256_ctx_t sha_ctx; // Used by 224 and 256
  // sha2_512_ctx_t sha_ctx; // Used by 384 and 512

  /*
    Each hash size (224,256,384 and 512) has a separate reset function,
    because the starting values are different.
  */
  sha2_256_reset(&sha_ctx);

  /*
    These functions basically all do the same

    If the current position is byte aligned, it will use sha2_256_append_bytes,
    where the leftover bits use sha2_256_append_bits.
    If the current position is not byte aligned, everything is appended using sha2_256_append_bits.

    For different hash sizes (224,256,384 and 512), there are different functions
    (eg. sha2_XXX_append_bytes, sha2_XXX_append_bits, sha2_XXX_append)
  */
  sha2_256_append_bytes(&sha_ctx, "TEST", 4);
  sha2_256_append_bits(&sha_ctx, "TEST", 4 * 8);
  sha2_256_append(&sha_ctx, "TEST", 4 * 8);

  /*
    sha2_get_hash writes the words of the hash.
    The correct byte order is dependent on the endianess and can be acquired with sha2_to_bytes.
    On a big endian system .words and .bytes are equal.
    On a little endian system, only .words or .bytes is valid at a time.
  */
  sha2_256_t hash;
  sha2_256_get_hash(&sha_ctx, hash.words);
  printf("HASH: %s\n", sha_256_words_to_string_static(hash.words, false));
  sha2_256_to_bytes(hash.bytes, hash.words);
  printf("HASH: %s\n", sha_256_bytes_to_string_static(hash.bytes, false));
  printf("TEST: 7a645eb78586d5ccd7fc56055f8fa13966cdcd43eb2483c7be208c1fc5b93fb7\n");
}
