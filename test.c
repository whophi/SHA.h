#include <stdio.h>
#include <time.h>

#define SHA_2_IMPLEMENTATION
#include "SHA-2.h"

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
  size_t       index    = 1;
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
    sha1_ctx ctx;
    sha1_reset(&ctx);
    sha1_append_bits(&ctx, msg_v, len);
    sha1_t hash = sha1_get_hash(&ctx);
    printf("%s\n", sha1_to_string(hash, upper_case));
  } else if (strcmp(sha_size, "224") == 0) {
    sha2_256_ctx sha2_ctx;
    sha2_224_reset(&sha2_ctx);
    sha2_256_append_bits(&sha2_ctx, msg_v, len);
    sha2_224_t hash = sha2_224_get_hash(&sha2_ctx);
    printf("%s\n", sha2_224_to_string(hash, upper_case));
  } else if (strcmp(sha_size, "256") == 0) {
    sha2_256_ctx sha2_ctx;
    sha2_256_reset(&sha2_ctx);
    sha2_256_append_bits(&sha2_ctx, msg_v, len);
    sha2_256_t hash = sha2_256_get_hash(&sha2_ctx);
    printf("%s\n", sha2_256_to_string(hash, upper_case));
    // printf("%02x", *((uint8_t*)&hash.words[0]));
  } else if (strcmp(sha_size, "384") == 0) {
    sha2_512_ctx sha2_ctx;
    sha2_384_reset(&sha2_ctx);
    sha2_512_append_bits(&sha2_ctx, msg_v, len);
    sha2_384_t hash = sha2_384_get_hash(&sha2_ctx);
    printf("%s\n", sha2_384_to_string(hash, upper_case));
  } else if (strcmp(sha_size, "512") == 0) {
    sha2_512_ctx sha2_ctx;
    sha2_512_reset(&sha2_ctx);
    sha2_512_append_bits(&sha2_ctx, msg_v, len);
    sha2_512_t hash = sha2_512_get_hash(&sha2_ctx);
    printf("%s\n", sha2_512_to_string(hash, upper_case));
  } else if (strcmp(sha_size, "512_224") == 0) {
    sha2_512_ctx sha2_ctx;
    sha2_512_224_reset(&sha2_ctx);
    sha2_512_append_bits(&sha2_ctx, msg_v, len);
    sha2_224_t hash = sha2_512_224_get_hash(&sha2_ctx);
    printf("%s\n", sha2_224_to_string(hash, upper_case));
  } else if (strcmp(sha_size, "512_256") == 0) {
    sha2_512_ctx sha2_ctx;
    sha2_512_256_reset(&sha2_ctx);
    sha2_512_append_bits(&sha2_ctx, msg_v, len);
    sha2_256_t hash = sha2_512_256_get_hash(&sha2_ctx);
    printf("%s\n", sha2_256_to_string(hash, upper_case));
  } else {
    printf("Unknown sha size %s\n", sha_size);
  }
  // sha2_256_t   hash_pow;
  // sha2_256_ctx sha2_pow_ctx;
  // sha2_256_reset(&sha2_pow_ctx);
  // printf(" ");
  // fflush(stdout);
  // for (size_t i = 0; i < UINT32_MAX; i++) {
  //   // srand(i);
  //   time_t t     = time(NULL);
  //   int    value = i; // rand() * rand();
  //   printf("\rTrying: %lld %d   ", t, value);
  //   fflush(stdout);
  //   // sha2_256_append_bytes(&sha2_pow_ctx, (uint8_t*)&t, sizeof(t));
  //   sha2_256_append_bytes(&sha2_pow_ctx, (uint8_t*)&value, sizeof(value));
  //   hash_pow = sha2_256_get_hash(&sha2_pow_ctx);
  //   // for (size_t i = 0; i < sizeof(hash_pow.words) / sizeof(*hash_pow.words); i++) { printf("%08x", hash_pow.words[i]); }
  //   if ((hash_pow.words[0] & 0xFFFF0000) == 0) break;
  // }
  // // printf("\n");
  // for (size_t i = 0; i < sizeof(hash_pow.words) / sizeof(*hash_pow.words); i++) { printf("%08x", hash_pow.words[i]); }
  // printf("\n");

  return 0;
}