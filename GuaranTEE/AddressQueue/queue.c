/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  queue.c
 *
 *  Implements a simple queue in the shared memory space.
 *
 *  All Rights Reserved.
 */

#include "queue.h"
#include "sgx_key.h"
#include "string.h"

struct shared_mem_space *shared_mem;
sgx_key_128bit_t key = { 0 };

union init_vec {
    uint8_t iv_arr[12];
    uint64_t iv_cntr;
}iv;

uint64_t ring_buf_index = 0;
struct id_batch batch;

uint64_t bucket_counter = 0;

int ids_in_buffer = 0;

/*
 * Function: init_key
 *      Initializes the shared key between ProveTEE and VerifyTEE
 *
 *      !!!!!!!! Should be done by enclave owner with proper key !!!!!!!!
 */
void init_key(void)
{
    // This has to be replaced with a proper implementation providing a real key
    memset(&key, 0, sizeof(key));
}

/*
 * Function: generate_new_key
 *      Derives a new key using a HKDF
 */
void generate_new_key(void)
{
    uint8_t hash[HASH_SIZE];

    hash_data((uint8_t*)&key, sizeof(key), hash);

    memcpy(&key, hash, sizeof(key));
}

/*
 * Function: initialize_queue_sender
 *      Initialization function for the sender
 *
 *      Parameters:
 *          shared_memory_ptr: Pointer to the memory space shared between
 *                             ProveTEE and VerifyTEE
 *
 *      Return value:
 *          Returns 0 on success, -1 otherwise
 */
int initialize_queue_sender(void *shared_memory_ptr)
{
    shared_mem = (struct shared_mem_space *)shared_memory_ptr;

    init_key();

    memset(iv.iv_arr, 0, sizeof(iv.iv_arr));
    shared_mem->head = 0;
    shared_mem->tail = 0;
    shared_mem->feedb.available = 0;

    // Initial value must be provided by enclave owner
    hash_init((unsigned char*)"INIT", 5);

    return 0;
}

/*
 * Function: initialize_queue_receiver
 *      Initialization function for the receiver (has to be called after the
 *      call to initialize_queue_sender)
 *
 *      Parameters:
 *          shared_memory_ptr: Pointer to the memory space shared between
 *                             ProveTEE and VerifyTEE
 *
 *      Return value:
 *          Returns 0 on success, -1 otherwise
 */
int initialize_queue_receiver(void *shared_memory_ptr)
{
    shared_mem = (struct shared_mem_space *)shared_memory_ptr;

    init_key();

    memset(iv.iv_arr, 0, sizeof(iv.iv_arr));

    ring_buf_index = ELEM_CAP;

    // Initial value must be provided by enclave owner
    hash_init((unsigned char*)"INIT", 5);

    return 0;
}

/*
 * Function: generate_feedback
 *      Encrypts the current bucket_counter to the feedback field in the shared
 *      memory space and sets the available flag afterwards.
 *
 *      Return value:
 *          Returns 0 on success, -1 otherwise
 */
int generate_feedback(void)
{
    int res = 0;

    // Wait until sender has received the old counter
    while (__atomic_load_n(&(shared_mem->feedb.available), __ATOMIC_SEQ_CST) == 1);

    if (iv.iv_cntr == UINT64_MAX) {
        iv.iv_cntr = 0;
    }

    res = encrypt((uint8_t*)&bucket_counter, sizeof(bucket_counter),
                  (uint8_t*)&shared_mem->feedb.ciphertext,
                  iv.iv_arr, sizeof(iv.iv_arr), &key,
                  &shared_mem->feedb.mac);

    iv.iv_cntr++;

    if (res) {
        return -1;
    }

    generate_new_key();

    __atomic_store_n(&(shared_mem->feedb.available), 1, __ATOMIC_SEQ_CST);

    return 0;
}

/*
 * Function: check_feedback
 *      Decrypts the encrypted bucket_counter in the feedback field in the
 *      shared memory space and clears the available flag afterwards. The
 *      decrypted value is crosschecked against the current bucket_counter.
 *      If the values do not match, the function fails.
 *
 *      Return value:
 *          Returns 0 on success, -1 otherwise
 */
int check_feedback(void)
{
    uint64_t ref_bucket_counter = 0;
    int res = 0;

    while (!__atomic_load_n(&(shared_mem->feedb.available), __ATOMIC_SEQ_CST));

    if (iv.iv_cntr == UINT64_MAX) {
        iv.iv_cntr = 0;
    }

    res = decrypt((uint8_t*)&ref_bucket_counter, sizeof(ref_bucket_counter),
                  (uint8_t*)&shared_mem->feedb.ciphertext, iv.iv_arr,
                  sizeof(iv.iv_arr), &key, &shared_mem->feedb.mac);

    iv.iv_cntr++;

    if (res) {
        return -1;
    }

    generate_new_key();

    __atomic_store_n(&(shared_mem->feedb.available), 0, __ATOMIC_SEQ_CST);

    return (ref_bucket_counter != bucket_counter);
}

/*
 * Function: queue_empty
 *      Checks if the queue is empty
 *
 *      Return value:
 *          Returns 1 if queue is empty, 0 otherwise
 */
int queue_empty(void)
{
    uint64_t size;
    size = __atomic_load_n(&(shared_mem->size), __ATOMIC_SEQ_CST);

    return (size == 0);
}

/*
 * Function: dequeue
 *      Dequeues one batch from the queue if the queue is not empty.
 *
 *      Return value:
 *          Returns 0 if queue is empty, 1 if a batch was dequeued.
 *          Returns -1 on error.
 */
int dequeue(void)
{
    int status = 0;

    if (__atomic_load_n(&(shared_mem->size), __ATOMIC_SEQ_CST) != 0) {

        if (iv.iv_cntr == UINT64_MAX) {
            iv.iv_cntr = 0;
        }

        int s = decrypt((unsigned char *)&batch, sizeof(struct id_batch),
                (unsigned char *)shared_mem->data[shared_mem->tail].ciphertext,
                iv.iv_arr, sizeof(iv.iv_arr), &key,
                &shared_mem->data[shared_mem->tail].mac);
        if (s) {
            return -1;
        }

        generate_new_key();

        shared_mem->tail = (shared_mem->tail + 1) % QUEUE_LENGTH;
        iv.iv_cntr += 1;
        status = 1;

        __atomic_fetch_sub(&(shared_mem->size), 1, __ATOMIC_SEQ_CST);

        if ((++bucket_counter % FEEDBACK_FREQ) == 0) {
            if (generate_feedback()) {
                return -1;
            }
        }
    }

    return status;
}

/*
 * Function: get_id_from_buf
 *      Fetches the next element from the internal buffer.
 *
 *      Parameters:
 *          id: Pointer to the element [OUT]
 *
 *      Return value:
 *          Returns 0 on success, -1 on error.
 */
int get_id_from_buf(uint64_t *id)
{
    uint8_t ref_hash[HASH_SIZE];

    *id = batch.ids[ring_buf_index++];
    hash_update((uint8_t*)id, sizeof(*id));

    if (ring_buf_index == ELEM_CAP) {
        // Check Hash
        hash_finalize(ref_hash);
        hash_init(ref_hash, HASH_SIZE);

        if (memcmp(ref_hash, batch.hash, HASH_SIZE) != 0) {
            return -1;
        }

        ring_buf_index = 0;
        ids_in_buffer = 0;
    }

    return 0;
}

/*
 * Function: get_id
 *      Gets the next element from the queue if the queue is not empty.
 *
 *      Parameters:
 *          id: Pointer to the element [OUT]
 *
 *      Return value:
 *          Returns 0 if queue is empty, 1 if element was dequeued.
 *          Returns -1 on error.
 */
int get_id(uint64_t *id)
{
    int status = 0;

    if (ids_in_buffer) {
        status = get_id_from_buf(id);
        if (status) {
            return status;
        }

        return 1;
    }

    status = dequeue();
    if (status == 1) {
        ids_in_buffer = 1;
        ring_buf_index = 0;

        status = get_id_from_buf(id);
        if (status) {
            return status;
        }

        return 1;
    }

    return status;
}

/*
 * Function: enqueue
 *      Enqueues one batch. The function waits until enough space is
 *      available in the queue.
 *
 *      Return value:
 *          Returns 0 on success, -1 on error.
 */
int enqueue(void)
{
    int status = 0;

    while (__atomic_load_n(&(shared_mem->size), __ATOMIC_SEQ_CST) == QUEUE_LENGTH);

    if (iv.iv_cntr == UINT64_MAX) {
        iv.iv_cntr = 0;
    }

    status =
        encrypt((unsigned char *)&batch, sizeof(struct id_batch),
            (unsigned char *)shared_mem->data[shared_mem->head].ciphertext,
            iv.iv_arr, sizeof(iv.iv_arr), &key,
            &shared_mem->data[shared_mem->head].mac);

    // Erase old hash from memory
    memset_s(batch.hash, HASH_SIZE, 0, HASH_SIZE);
    if (status) {
        return -1;
    }

    generate_new_key();

    iv.iv_cntr += 1;
    shared_mem->head = (shared_mem->head + 1) % QUEUE_LENGTH;

    __atomic_fetch_add(&(shared_mem->size), 1, __ATOMIC_SEQ_CST);

    if ((++bucket_counter % FEEDBACK_FREQ) == 0) {
        if (check_feedback()) {
            return -1;
        }
    }

    return status;
}

/*
 * Function: force_write
 *      Flushes the internal buffer to the queue.
 *
 *      Return value:
 *          Returns 0 on success, -1 on error.
 */
int force_write(void)
{
    // Don't send a batch of zeros
    if (ring_buf_index == 0) {
        return 0;
    }

    memset(batch.ids + ring_buf_index, 0,
           (ELEM_CAP - ring_buf_index) * sizeof(uint64_t));

    hash_update((uint8_t*)(batch.ids + ring_buf_index),
                (uint32_t)((ELEM_CAP - ring_buf_index) * sizeof(uint64_t)));

    hash_finalize(batch.hash);

    hash_init(batch.hash, HASH_SIZE);

    if (enqueue()) {
        return -1;
    }

    ring_buf_index = 0;

    return 0;
}

/*
 * Function: put_id
 *      Enqueues one element. If internal buffer is full, all elements are
 *      flushed to the queue.
 *
 *      Parameters:
 *          id: Element which should be enqueued.
 *
 *      Return value:
 *          Returns 0 on success, -1 on error.
 */
int put_id(uint64_t id)
{
    if (ring_buf_index == ELEM_CAP) {
        hash_finalize(batch.hash);

        hash_init(batch.hash, HASH_SIZE);

        if (enqueue()) {
            return -1;
        }

        ring_buf_index = 0;
    }

    batch.ids[ring_buf_index++] = id;
    hash_update((uint8_t*)&id, sizeof(id));

    return 0;
}
