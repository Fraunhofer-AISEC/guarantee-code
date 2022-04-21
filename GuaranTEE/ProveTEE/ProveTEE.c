/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  ProveTEE.c
 *
 *  Implements the trampoline part of the ProverTEE
 *
 *  All Rights Reserved.
 */

#include "ProveTEE_t.h"
#include <stdint.h>
#include "queue.h"
#include "common_ocalls.h"
#include "error_codes.h"

/*
 * Function: ecall_init_prover_tee
 *      Initializes the ProverTEE
 *
 *      Parameters:
 *          shared_mem_ptr: Pointer to memory shared between ProveTEE and
 *          VerifyTEE
 */
void ecall_init_prover_tee(uintptr_t shared_mem_ptr)
{
    sgx_printf("ProverTEE: Shared memory space at %p\n", shared_mem_ptr);

    if (initialize_queue_sender((void*)shared_mem_ptr)) {
        sgx_printf("Initializing shared memory queue failed\n");
        sgx_exit(QUEUE_ERROR);
    }
}

/*
 * Function: ecall_shutdown_prover_tee
 *      Flushes the internal buffer of the queue.
 */
void ecall_shutdown_prover_tee(void)
{
    if (force_write()) {
        sgx_printf("Failed to flush the internal queue buffer.\n");
        sgx_exit(QUEUE_ERROR);
    }
}


/*
 * Function: trampoline
 *      The trampoline is called from the instrumentation and the assembly part
 *      (trampoline.s) and pushes a single ID in the queue
 *
 *      Parameters:
 *          id: The ID which should be pushed into the queue
 */
void trampoline(uint64_t id)
{
    if (put_id(id)) {
        sgx_printf("Failed to enqueue one element.\n");
        sgx_exit(QUEUE_ERROR);
    }
}
