#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#define AES_BLOCK_SIZE   256 //(200 * 256)= 10 KB

#define AES_KEY_SIZE 16  // 128-bit
#define AES_IV_SIZE 12   // Recommended for GCM
#define AES_TAG_SIZE 16  // Authentication tag size

// Pre-shared key (example)
uint8_t aes_key[AES_KEY_SIZE] = {
  0x01,0x02,0x03,0x04,
  0x05,0x06,0x07,0x08,
  0x09,0x0A,0x0B,0x0C,
  0x0D,0x0E,0x0F,0x10
};

#include <stdint.h>

struct Message {
    uint8_t nonce[AES_IV_SIZE];
    uint8_t tag[AES_TAG_SIZE];
    uint8_t ciphertext[AES_BLOCK_SIZE];
};

#endif
