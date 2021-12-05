#include "dynamo.h"
#include "sha256.h"

#include <cstring>
#include <iterator>
#include <sstream>
#include <vector>

#ifdef __cplusplus
namespace dynamo {
#endif

inline constexpr unsigned char decodeHex(char in) {
  in = toupper(in);
  if ((in >= '0') && (in <= '9'))
    return in - '0';
  else if ((in >= 'A') && (in <= 'F'))
    return in - 'A' + 10;
  else
    return 0; // todo raise error
}

inline void parseHex(std::string input, unsigned char *output) {
  for (int i = 0; i < input.length(); i += 2) {
    unsigned char value = decodeHex(input[i]) * 16 + decodeHex(input[i + 1]);
    output[i / 2] = value;
  }
}

void execute_program(char *output, const unsigned char *blockHeader,
                     const char *program, const char *prevhash_hex,
                     const char *merkle_root) {
  // initial input is SHA256 of header data
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  uint32_t temp_result[8];
  SHA256_Update(&ctx, blockHeader, 80);
  SHA256_Final((unsigned char *)temp_result, &ctx);

  int line_ptr = 0;             // program execution line pointer
  int loop_counter = 0;         // counter for loop execution
  unsigned int memory_size = 0; // size of current memory pool
  uint32_t *memPool = NULL;     // memory pool

  std::stringstream stream(program);
  std::string line;
  while (std::getline(stream, line, '$')) {
    std::istringstream iss(line);
    std::vector<std::string> tokens{
        std::istream_iterator<std::string>{iss},
        std::istream_iterator<std::string>{}}; // split line into tokens
    // simple ADD and XOR functions with one constant argument
    if (tokens[0] == "ADD") {
      uint32_t arg1[8];
      parseHex(tokens[1], (unsigned char *)arg1);
      for (int i = 0; i < 8; i++)
        temp_result[i] += arg1[i];
    } else if (tokens[0] == "XOR") {
      uint32_t arg1[8];
      parseHex(tokens[1], (unsigned char *)arg1);
      for (int i = 0; i < 8; i++)
        temp_result[i] ^= arg1[i];
    }

    // hash algo which can be optionally repeated several times
    else if (tokens[0] == "SHA2") {
      if (tokens.size() == 2) { // includes a loop count
        loop_counter = atoi(tokens[1].c_str());
        for (int i = 0; i < loop_counter; i++) {
          if (tokens[0] == "SHA2") {
            unsigned char output[32];
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, (unsigned char *)temp_result, 32);
            SHA256_Final(output, &ctx);
            memcpy(temp_result, output, 32);
          }
        }
      } else { // just a single run
        unsigned char output[32];
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, (unsigned char *)temp_result, 32);
        SHA256_Final(output, &ctx);
        memcpy(temp_result, output, 32);
      }
    }

    // generate a block of memory based on a hashing algo
    else if (tokens[0] == "MEMGEN") {
      if (memPool != NULL)
        free(memPool);
      memory_size = atoi(tokens[2].c_str());
      memPool = (uint32_t *)malloc(memory_size * 32);
      for (int i = 0; i < memory_size; i++) {
        if (tokens[1] == "SHA2") {
          unsigned char output[32];
          SHA256_Init(&ctx);
          SHA256_Update(&ctx, (unsigned char *)temp_result, 32);
          SHA256_Final(output, &ctx);
          memcpy(temp_result, output, 32);
          memcpy(memPool + i * 8, temp_result, 32);
        }
      }
    }

    // add a constant to every value in the memory block
    else if (tokens[0] == "MEMADD") {
      if (memPool != NULL) {
        uint32_t arg1[8];
        parseHex(tokens[1], (unsigned char *)arg1);

        for (int i = 0; i < memory_size; i++) {
          for (int j = 0; j < 8; j++)
            memPool[i * 8 + j] += arg1[j];
        }
      }
    }

    // xor a constant with every value in the memory block
    else if (tokens[0] == "MEMXOR") {
      if (memPool != NULL) {
        uint32_t arg1[8];
        parseHex(tokens[1], (unsigned char *)arg1);

        for (int i = 0; i < memory_size; i++) {
          for (int j = 0; j < 8; j++)
            memPool[i * 8 + j] ^= arg1[j];
        }
      }
    }

    // read a value based on an index into the generated block of memory
    else if (tokens[0] == "READMEM") {
      if (memPool != NULL) {
        unsigned int index = 0;

        if (tokens[1] == "MERKLE") {
          uint32_t v0 = *(uint32_t *)merkle_root;
          index = v0 % memory_size;
          memcpy(temp_result, memPool + index * 8, 32);
        }

        else if (tokens[1] == "HASHPREV") {
          uint32_t arg1[8];
          parseHex(prevhash_hex, (unsigned char *)arg1);
          index = arg1[0] % memory_size;
          memcpy(temp_result, memPool + index * 8, 32);
        }
      }
    }

    line_ptr++;
  }

  if (memPool != NULL)
    free(memPool);

  memcpy(output, temp_result, 32);
}

#ifdef __cplusplus
}
#endif
