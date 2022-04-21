/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  queue.h
 *
 *  All Rights Reserved.
 */

#ifndef QUEUE_H
#define QUEUE_H

#include <stdint.h>
#include "sgx_spinlock.h"
#include "sgx_tcrypto.h"
#include "encryption.h"

#define QUEUE_LENGTH 1000
#define ELEM_CAP 10000

// After how much buckets a feedback is requested
#define FEEDBACK_FREQ 10

struct id_batch {
    uint64_t ids[ELEM_CAP];
    uint8_t hash[HASH_SIZE];
};

// represents one encrypted address batch
struct enc_addr {
    sgx_aes_gcm_128bit_tag_t mac;
    char ciphertext[sizeof(struct id_batch)];
};

struct feedback {
    volatile int available;
    sgx_aes_gcm_128bit_tag_t mac;
    char ciphertext[sizeof(uint64_t)];
};

// layout of the shared memory space
struct shared_mem_space {
    uint64_t head;
    uint64_t tail;
    volatile size_t size;
    sgx_key_id_t key_id;
    struct feedback feedb;
    struct enc_addr data[QUEUE_LENGTH];
};

#ifdef __cplusplus
extern "C" {
#endif

int initialize_queue_sender(void *shared_memory_ptr);
int initialize_queue_receiver(void *shared_memory_ptr);
int put_id(uint64_t id);
int get_id(uint64_t *id);
int force_write(void);
int queue_empty(void);

#ifdef __cplusplus
}
#endif

#endif /* QUEUE_H */