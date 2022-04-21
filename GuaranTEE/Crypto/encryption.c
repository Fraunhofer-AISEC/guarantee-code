/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  encryption.c
 *
 *  Wrapper for the SGX crypto functions.
 *
 *  All Rights Reserved.
 */

#include "encryption.h"
#include "sgx_key.h"
#include "sgx_utils.h"
#include "tseal_migration_attr.h"
#include "sgx_trts.h"
#include <string.h>
#include <stdint.h>
#include "blake3.h"

blake3_hasher blake_ctx;

/*
 * Function: derive_secret_key
 *      Derives the sealing key using the given key ID. The resulting seal key
 *      is bound to MRSIGNER
 *
 *      Parameters:
 *          key: Pointer to the memory where the key should be written [IN]
 *          key_id: Pointer to the key ID used in the key generation process
 *                  [IN]
 *
 *      Return value:
 *          Returns 0 on success, -1 otherwise
 */
int derive_secret_key(sgx_key_128bit_t *key, sgx_key_id_t *key_id)
{
    sgx_report_t report;
    sgx_key_request_t key_request;
    sgx_status_t status;

    memset(&key_request, 0, sizeof(sgx_key_request_t));

    status = sgx_create_report(NULL, NULL, &report);
    if (status != SGX_SUCCESS) {
        return -1;
    }

    key_request.key_name = SGX_KEYSELECT_SEAL;
    key_request.key_policy = SGX_KEYPOLICY_MRSIGNER;
    memcpy(&key_request.cpu_svn, &report.body.cpu_svn, sizeof(sgx_cpu_svn_t));
    memcpy(&key_request.isv_svn, &report.body.isv_svn, sizeof(sgx_isv_svn_t));
    key_request.attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    key_request.attribute_mask.xfrm = 0x0;
    key_request.misc_mask = (unsigned int)TSEAL_DEFAULT_MISCMASK;
    memcpy(&key_request.config_svn, &report.body.config_svn,
           sizeof(sgx_config_svn_t));

    memcpy(&key_request.key_id, key_id, sizeof(sgx_key_id_t));

    status = sgx_get_key(&key_request, key);
    if (status != SGX_SUCCESS) {
        return -1;
    }

    return 0;
}

/*
 * Function: get_rand
 *      Gets a random byte sequence
 *
 *      Parameters:
 *          dest: Pointer to the memory where the random bytes should be
 *                written to [OUT]
 *          len: Length of the requested random byte sequence
 *
 *      Return value:
 *          Returns 0 on success, -1 otherwise
 */
int get_rand(void *dest, size_t len)
{
    sgx_status_t status;

    status = sgx_read_rand(dest, len);
    if (status != SGX_SUCCESS) {
        return -1;
    }

    return 0;
}

/*
 * Function: encrypt
 *      Encrypts given data using AES-GCM
 *
 *      Parameters:
 *          data: Pointer to the plaintext [IN]
 *          data_len: Plaintext length
 *          ciphertext: Pointer to the ciphertext buffer [OUT]
 *          iv: Pointer to the initialization vector [IN]
 *          iv_len: Length of the initialization vector
 *          key: Pointer to the key which should be used for encryption [IN]
 *          mac: Pointer to the memory the MAC should be saved [OUT]
 *
 *      Return value:
 *          Returns 0 on success, -1 otherwise
 */
int encrypt(uint8_t *data, uint32_t data_len, uint8_t *ciphertext, uint8_t *iv,
             uint32_t iv_len, sgx_key_128bit_t *key,
             sgx_aes_gcm_128bit_tag_t *mac)
{
    sgx_status_t status;

    status = sgx_rijndael128GCM_encrypt(key, data, data_len,
                                        ciphertext, iv, iv_len, NULL, 0, mac);
    if (status != SGX_SUCCESS) {
        return -1;
    }

    return 0;
}

/*
 * Function: decrypt
 *      Decrypts given data using AES-GCM
 *
 *      Parameters:
 *          data: Pointer to the plaintext [OUT]
 *          data_len: Plaintext length
 *          ciphertext: Pointer to the ciphertext buffer [IN]
 *          iv: Pointer to the initialization vector [IN]
 *          iv_len: Length of the initialization vector
 *          key: Pointer to the key which should be used for encryption [IN]
 *          mac: Pointer to the memory the MAC should be saved [IN]
 *
 *      Return value:
 *          Returns 0 on success, -1 otherwise
 */
int decrypt(uint8_t *data, uint32_t data_len, uint8_t *ciphertext, uint8_t *iv,
             uint32_t iv_len, sgx_key_128bit_t *key,
             sgx_aes_gcm_128bit_tag_t *mac)
{
    sgx_status_t status;

    status = sgx_rijndael128GCM_decrypt(key, ciphertext, data_len,
                                        data, iv, iv_len, NULL, 0, mac);
    if (status != SGX_SUCCESS) {
        return -1;
    }

    return 0;
}

/*
 * Function: hash_data
 *      Hashes data using the init, update, finalize API
 *
 *      Parameters:
 *          data: Pointer to the input data [IN]
 *          data_len: Length of the input data
 *          hash: Pointer to the hash [OUT]
 */
void hash_data(uint8_t *data, uint32_t data_len, uint8_t *hash)
{
    blake3_hasher ctx;

    blake3_hasher_init(&ctx);
    blake3_hasher_update(&ctx, data, data_len);
    blake3_hasher_finalize(&ctx, hash, BLAKE3_OUT_LEN);
}

/*
 * Function: hash_init
 *      Initializes the hash function by hashing an inital seed value
 *
 *      Parameters:
 *          seed: Pointer to the seed value [IN]
 *          seed_len: Length of the seed value in bytes
 */
void hash_init(const unsigned char* seed, uint32_t seed_len)
{
    blake3_hasher_init(&blake_ctx);
    blake3_hasher_update(&blake_ctx, seed, seed_len);
}

/*
 * Function: hash_update
 *      Updates the current hash state
 *
 *      Parameters:
 *          data: Pointer to the data [IN]
 *          data_len: Length of the data in bytes
 */
void hash_update(const uint8_t* data, uint32_t data_len)
{
    blake3_hasher_update(&blake_ctx, data, data_len);
}

/*
 * Function: hash_finalize
 *     Returns final hash and frees the internal data structures
 *
 *      Parameters:
 *          hash: Pointer to the hash [OUT]
 */
void hash_finalize(uint8_t *hash)
{
    blake3_hasher_finalize(&blake_ctx, hash, BLAKE3_OUT_LEN);
}
