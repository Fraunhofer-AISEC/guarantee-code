/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  encryption.h
 *
 *  All Rights Reserved.
 */

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "sgx_key.h"
#include "sgx_tcrypto.h"
#include <stddef.h>

#define HASH_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif

int derive_secret_key(sgx_key_128bit_t *key, sgx_key_id_t *key_id);
int get_rand(void *dest, size_t len);
int encrypt(uint8_t *data, uint32_t data_len, uint8_t *ciphertext,
            uint8_t *iv,uint32_t iv_len, sgx_key_128bit_t *key,
            sgx_aes_gcm_128bit_tag_t *mac);
int decrypt(uint8_t *data, uint32_t data_len, uint8_t *ciphertext,
            uint8_t *iv, uint32_t iv_len, sgx_key_128bit_t *key,
            sgx_aes_gcm_128bit_tag_t *mac);
void hash_data(uint8_t *data, uint32_t data_len, uint8_t *hash);
void hash_init(const unsigned char* seed, uint32_t seed_len);
void hash_update(const uint8_t* data, uint32_t data_len);
void hash_finalize(uint8_t *hash);

#ifdef __cplusplus
}
#endif

#endif /* ENCRYPTION_H */
