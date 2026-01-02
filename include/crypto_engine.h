#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include "esp_log.h"
#include <stdint.h>

#define AES_BLOCK_SIZE 128    // 1024, 512, 128, 
#define REPETITIONS 1024      // 128,256, 1024,

#define AES_IV_SIZE 12   // Recommended for GCM
#define AES_TAG_SIZE 16  // Authentication tag size


struct Message {
    uint8_t iv[AES_IV_SIZE];
    uint8_t tag[AES_TAG_SIZE];
    uint8_t ciphertext[AES_BLOCK_SIZE];
};

bool aes_encrypt(uint8_t* input, uint8_t* iv, uint8_t* output, uint8_t* tag);
bool aes_decrypt(uint8_t* input, uint8_t* iv, uint8_t* tag, uint8_t* output);

#endif
