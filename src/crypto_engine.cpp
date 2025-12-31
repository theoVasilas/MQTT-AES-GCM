#include "crypto_engine.h"
#include "helper_fun.h"

#include "mbedtls/gcm.h"
#include <Arduino.h>

// Encrypt data using AES-128-GCM
bool aes_encrypt(uint8_t* input, uint8_t* iv, uint8_t* output, uint8_t* tag) {
    
    // Initialize GCM context
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    // Set AES key
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, aes_key, AES_KEY_SIZE*8) != 0) {
        mbedtls_gcm_free(&ctx);
        return false;
    }

    //API call to perform encryption
    int ret = mbedtls_gcm_crypt_and_tag(
        &ctx,
        MBEDTLS_GCM_ENCRYPT,
        AES_BLOCK_SIZE,
        iv, AES_IV_SIZE,
        NULL, 0,           // No additional data
        input,
        output,
        AES_TAG_SIZE,
        tag
    );

    mbedtls_gcm_free(&ctx);
    return ret == 0;
}

// Decrypt data using AES-128-GCM
bool aes_decrypt(uint8_t* input, uint8_t* iv, uint8_t* tag, uint8_t* output) {

    // Initialize GCM context
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    // Set AES key               
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, aes_key, AES_KEY_SIZE*8) != 0) {
        mbedtls_gcm_free(&ctx);
        return false;
    }
    //API call to perform decryption
    int ret = mbedtls_gcm_auth_decrypt(
        &ctx,
        AES_BLOCK_SIZE,
        iv, AES_IV_SIZE,
        NULL, 0,           // No additional data
        tag, AES_TAG_SIZE,
        input,
        output
    );

    mbedtls_gcm_free(&ctx);
    return ret == 0;
}

