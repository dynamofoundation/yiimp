#ifndef DYNAMO_H
#define DYNAMO_H

#include <cstdio>
#include <cstdlib>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
namespace dynamo {
#endif
void execute_program(char *output, const unsigned char *blockHeader,
                     const char *program, const char *prevBlockHash,
                     const char *merkleRoot);
#ifdef __cplusplus
}
#endif

static void dynamo_hash(const char *input, char *output, uint32_t len) {
  printf("Dynamo hash should be verified using execute_program.\n");
  exit(1);
}

#ifdef __cplusplus
}
#endif

#endif
