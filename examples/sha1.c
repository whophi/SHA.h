#define SHA_IMPLEMENTATION
#include "../sha.h"

#include <stdio.h>

int main()
{
  sha1_ctx_t sha1_ctx;
  sha1_reset(&sha1_ctx);

  /*
    These functions basically all do the same

    If the current position is byte aligned, it will use sha1_append_bytes,
    where the leftover bits use sha1_append_bits.
    If the current position is not byte aligned, everything is appended using sha1_append_bits.
  */
  sha1_append_bytes(&sha1_ctx, "TEST", 4);
  sha1_append_bits(&sha1_ctx, "TEST", 4 * 8);
  sha1_append(&sha1_ctx, "TEST", 4 * 8);

  /*
    sha1_get_hash writes the words of the hash.
    The correct byte order is dependent on the endianess and can be acquired with sha1_to_bytes.
    On a big endian system .words and .bytes are equal.
    On a little endian system, only .words or .bytes is valid at a time.
  */
  sha1_t hash;
  sha1_get_hash(&sha1_ctx, hash.words);
  printf("HASH: %s\n", sha1_words_to_string_static(hash.words, false));
  sha1_to_bytes(hash.bytes, hash.words);
  printf("HASH: %s\n", sha1_bytes_to_string_static(hash.bytes, false));
  printf("TEST: 63c653d0186c187d9e191350d888cf0a9a2541a0\n");
}
