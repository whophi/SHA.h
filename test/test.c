#include <stdio.h>
#include <time.h>

#define SHA_IMPLEMENTATION
#include "../sha.h"

void endianCheckPrint()
{
  int num = 1;
  if (*(char*)&num == 1) {
    printf("Your system is Little-Endian!\n");
  } else {
    printf("Your system is Big-Endian!\n");
  }
}

int main(int argc, char** argv)
{
  //
  // endianCheckPrint();
  //
  unsigned int index    = 1;
  const char*  sha_size = argv[index++];
  uint64_t     len      = atoll(argv[index++]);
  const char*  msg      = argv[index++];
  const size_t msg_len  = strlen(msg);
  uint8_t      msg_v[msg_len / 2];
  for (size_t i = 0; i + 1 < msg_len;) {
    uint8_t v;
    if ('0' <= msg[i] && msg[i] <= '9') v = msg[i] - '0';
    else if ('a' <= msg[i] && msg[i] <= 'f') v = 10 + (msg[i] - 'a');
    else if ('A' <= msg[i] && msg[i] <= 'F') v = 10 + (msg[i] - 'A');
    else exit(1);
    v *= 16;
    if ('0' <= msg[i + 1] && msg[i + 1] <= '9') v += msg[i + 1] - '0';
    else if ('a' <= msg[i + 1] && msg[i + 1] <= 'f') v += 10 + (msg[i + 1] - 'a');
    else if ('A' <= msg[i + 1] && msg[i + 1] <= 'F') v += 10 + (msg[i + 1] - 'A');
    else exit(1);
    msg_v[i / 2]  = v;
    i            += 2;
  }

  //
  bool upper_case = false;
  if (strcmp(sha_size, "1") == 0) {
    sha1_ctx_t ctx;
    sha1_reset(&ctx);
    sha1_append_bits(&ctx, msg_v, len);
    sha1_t hash;
    sha1_get_hash(&ctx, hash.words);
    printf("%s\n", sha1_words_to_string_static(hash.words, upper_case));
  } else if (strcmp(sha_size, "224") == 0) {
    sha2_256_ctx_t sha2_ctx;
    sha2_224_reset(&sha2_ctx);
    sha2_256_append_bits(&sha2_ctx, msg_v, len);
    sha_224_t hash;
    sha2_224_get_hash(&sha2_ctx, hash.words);
    printf("%s\n", sha_224_words_to_string_static(hash.words, upper_case));
  } else if (strcmp(sha_size, "256") == 0) {
    sha2_256_ctx_t sha2_ctx;
    sha2_256_reset(&sha2_ctx);
    sha2_256_append_bits(&sha2_ctx, msg_v, len);
    sha_256_t hash;
    sha2_256_get_hash(&sha2_ctx, hash.words);
    printf("%s\n", sha_256_words_to_string_static(hash.words, upper_case));
    // printf("%02x", *((uint8_t*)&hash.words[0]));
  } else if (strcmp(sha_size, "384") == 0) {
    sha2_512_ctx_t sha2_ctx;
    sha2_384_reset(&sha2_ctx);
    sha2_512_append_bits(&sha2_ctx, msg_v, len);
    sha_384_t hash;
    sha2_384_get_hash(&sha2_ctx, hash.words);
    printf("%s\n", sha_384_words_to_string_static(hash.words, upper_case));
  } else if (strcmp(sha_size, "512") == 0) {
    sha2_512_ctx_t sha2_ctx;
    sha2_512_reset(&sha2_ctx);
    sha2_512_append_bits(&sha2_ctx, msg_v, len);
    sha_512_t hash;
    sha2_512_get_hash(&sha2_ctx, hash.words);
    printf("%s\n", sha_512_words_to_string_static(hash.words, upper_case));
  } else if (strcmp(sha_size, "512_224") == 0) {
    sha2_512_ctx_t sha2_ctx;
    sha2_512_224_reset(&sha2_ctx);
    sha2_512_append_bits(&sha2_ctx, msg_v, len);
    sha_224_t hash;
    sha2_512_224_get_hash(&sha2_ctx, hash.words);
    printf("%s\n", sha_224_words_to_string_static(hash.words, upper_case));
  } else if (strcmp(sha_size, "512_256") == 0) {
    sha2_512_ctx_t sha2_ctx;
    sha2_512_256_reset(&sha2_ctx);
    sha2_512_append_bits(&sha2_ctx, msg_v, len);
    sha_256_t hash;
    sha2_512_256_get_hash(&sha2_ctx, hash.words);
    printf("%s\n", sha_256_words_to_string_static(hash.words, upper_case));
  } else if (strcmp(sha_size, "3_224") == 0) {
    sha3_ctx_t sha3_ctx_t;
    sha3_224_reset(&sha3_ctx_t);
    sha3_append_bits(&sha3_ctx_t, msg_v, len);
    sha_224_t hash;
    sha3_224_get_hash(&sha3_ctx_t, hash.bytes);
    // char buf[224 / 8 * 2 + 1];
    // sha_bytes_to_string(buf, hash.bytes, 224 / 8, upper_case);
    // printf("%s\n", buf);
    printf("%s\n", sha_224_bytes_to_string_static(hash.bytes, upper_case));
  } else if (strcmp(sha_size, "3_256") == 0) {
    sha3_ctx_t sha3_ctx_t;
    sha3_256_reset(&sha3_ctx_t);
    sha3_append_bits(&sha3_ctx_t, msg_v, len);
    sha_256_t hash;
    sha3_256_get_hash(&sha3_ctx_t, hash.bytes);
    printf("%s\n", sha_256_bytes_to_string_static(hash.bytes, upper_case));
  } else if (strcmp(sha_size, "3_384") == 0) {
    sha3_ctx_t sha3_ctx_t;
    sha3_384_reset(&sha3_ctx_t);
    sha3_append_bits(&sha3_ctx_t, msg_v, len);
    sha_384_t hash;
    sha3_384_get_hash(&sha3_ctx_t, hash.bytes);
    printf("%s\n", sha_384_bytes_to_string_static(hash.bytes, upper_case));
  } else if (strcmp(sha_size, "3_512") == 0) {
    sha3_ctx_t sha3_ctx_t;
    sha3_512_reset(&sha3_ctx_t);
    sha3_append_bits(&sha3_ctx_t, msg_v, len);
    sha_512_t hash;
    sha3_512_get_hash(&sha3_ctx_t, hash.bytes);
    printf("%s\n", sha_512_bytes_to_string_static(hash.bytes, upper_case));
  } else if (strcmp(sha_size, "shake_128") == 0) {
    unsigned int hash_bit_count = 128;
    if (index < argc) hash_bit_count = atoll(argv[index++]);
    sha3_ctx_t sha3_ctx_t;
    sha3_shake128_reset(&sha3_ctx_t, hash_bit_count);
    sha3_append_bits(&sha3_ctx_t, msg_v, len);
    const size_t hash_byte_count = (hash_bit_count + 7) / 8;
    uint8_t      hash[hash_byte_count];
    sha3_shake128_get_hash(&sha3_ctx_t, hash);
    char buf[3];
    buf[2] = '\0';
    for (size_t i = 0; i < hash_byte_count; i++) {
      sha_byte_to_string(buf, hash[i], false);
      printf("%s", buf);
    }
    printf("\n");
  } else if (strcmp(sha_size, "shake_256") == 0) {
    unsigned int hash_bit_count = 256;
    if (index < argc) hash_bit_count = atoll(argv[index++]);
    sha3_ctx_t sha3_ctx_t;
    sha3_shake256_reset(&sha3_ctx_t, hash_bit_count);
    sha3_append_bits(&sha3_ctx_t, msg_v, len);
    const size_t hash_byte_count = (hash_bit_count + 7) / 8;
    uint8_t      hash[hash_byte_count];
    sha3_shake256_get_hash(&sha3_ctx_t, hash);
    char buf[3];
    buf[2] = '\0';
    for (size_t i = 0; i < hash_byte_count; i++) {
      sha_byte_to_string(buf, hash[i], false);
      printf("%s", buf);
    }
    printf("\n");
  } else {
    printf("Unknown sha size %s\n", sha_size);
  }

  return 0;
}