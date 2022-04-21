/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  App.c
 *
 *  The userspace host application for GuaranTEE
 *
 *  All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <pthread.h>
#include "queue.h"

#include "sgx_eid.h"
#include "sgx_urts.h"

#include "ProveTEE_u.h"
#include "sgx_utils.h"

#ifdef SGX_ATTESTATION
#include "server-tls.h"
#include "VerifyTEE_att_u.h"
#else
#include "VerifyTEE_u.h"
#endif /* SGX_ATTESTATION */


#define PROVETEE_FILENAME "bin/ProveTEE.signed.so"
#define VERIFYTEE_FILENAME "bin/VerifyTEE.signed.so"
#define FALSE 0
#define TRUE 1

void error(int error_nr, int line, const char* file);

#define ERRSAFE(x)  do { \
                        int s = x; \
                        if(s) { \
                            error(s, __LINE__, __FILE__); \
                        } \
                    } while (0)

sgx_enclave_id_t provetee_id = 0, verifytee_id = 0;
void *shared_mem = NULL;
int prover_sockfd = 0;

#ifdef SGX_ATTESTATION
int wolfssl_sockfd = 0;

// run() for the wolfssl tls server thread
void *start_wolfssl(void *arg)
{
    (void) arg;
    // wolfssl_run is the terminating condition for the endless loop, therefore shared
    if(pthread_mutex_lock(&mutex) == 0) {
        // set wolfssl_run to true for programm to accept tls connections over and over again
        wolfssl_run = TRUE;
        pthread_mutex_unlock(&mutex);
    }

    ERRSAFE(server_connect(verifytee_id, provetee_id, wolfssl_sockfd));
    return NULL;
}

#endif /* SGX_ATTESTATION */

void error(int error_nr, int line, const char* file)
{
    printf("Error %d in %s:%d Exiting\n", error_nr, file, line);

    sgx_destroy_enclave(provetee_id);
    sgx_destroy_enclave(verifytee_id);
    free(shared_mem);
    shared_mem = NULL;

    exit(-1);
}

void *start_target(void *arg)
{
    (void)arg;
    ERRSAFE(ecall_start_target(provetee_id, prover_sockfd));
    return NULL;
}

void *start_analyzer_thread(void *arg)
{
    (void)arg;
    ERRSAFE(ecall_start_analyzer_thread(verifytee_id));
    return NULL;
}

int main(int argc, char* argv[])
{
    int update = 0;
    int graph_fd;
    sgx_launch_token_t token = { 0 };
    pthread_t server_tid;
    pthread_t analyzer_tid;

    (void)argc;
    (void)argv;

    // load ProverTEE and VerifyTEE
    if (SGX_SUCCESS != sgx_create_enclave(PROVETEE_FILENAME, SGX_DEBUG_FLAG, &token, &update, &provetee_id, NULL)
        || SGX_SUCCESS != sgx_create_enclave(VERIFYTEE_FILENAME, SGX_DEBUG_FLAG, &token, &update, &verifytee_id, NULL)) {
        fprintf(stderr, "Failed to load enclaves.\n");
        goto destroy_enclave;
    }
    printf("Succeed to load ProverTEE and VerifyTEE.\n");
    // Create the sockets for the respective servers of ProveTEE and VerifyTEE
    if ((prover_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket for Prover SSL-Server\n");
        goto destroy_enclave;
    }

    // allocate shared memory
    shared_mem = malloc(sizeof(struct shared_mem_space));
    // initialize the enclaves
    ERRSAFE(ecall_init_prover_tee(provetee_id, (uintptr_t)shared_mem));
    ERRSAFE(ecall_init_verify_tee(verifytee_id, (uintptr_t)shared_mem));

    // start analyzer thread
    ERRSAFE(pthread_create(&analyzer_tid, NULL, &start_analyzer_thread, NULL));

    // start target thread
    ERRSAFE(pthread_create(&server_tid, NULL, &start_target, NULL));

    printf("Started analyzer and target thread\n");

    #ifdef SGX_ATTESTATION
    pthread_t wolfssl_tid;
    if ((wolfssl_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket for WolfSSL\n");
        close(prover_sockfd);
        goto destroy_enclave;
    }

    // start connection thread
    ERRSAFE(pthread_create(&wolfssl_tid, NULL, &start_wolfssl, NULL));
    printf("Started Attestation-TLS thread\n");
    #endif /* SGX_ATTESTATION */

    printf("\nPress any character to terminate the server\n");
    // wait for termination signal
    getchar();

    printf("Terminate ProverTEE and VerifyTEE\n");

    #ifdef SGX_ATTESTATION
    // set condition to terminate endless loop
    if (pthread_mutex_lock(&mutex) == 0) {
        wolfssl_run = FALSE;
        pthread_mutex_unlock(&mutex);
    } else {
        fprintf(stderr, "Error while stopping connection thread\n");
    }

    // interrupt accept(), catch thread, and close socketS
    shutdown(wolfssl_sockfd, SHUT_RD);
    ERRSAFE(pthread_join(wolfssl_tid, NULL));
    close(wolfssl_sockfd);
    #endif /* SGX_ATTESTATION */

    // Flushes the remaining IDs in the buffer
    ecall_shutdown_prover_tee(provetee_id);

    // interrupt accept() and close socket
    shutdown(prover_sockfd, SHUT_RD);
    close(prover_sockfd);
    sleep(1);

    ERRSAFE(ecall_kill_analyzer_thread(verifytee_id));
    ERRSAFE(pthread_join(analyzer_tid, NULL));

    ERRSAFE(pthread_join(server_tid, NULL));

    // print log to stdout
    ERRSAFE(ecall_print_log(verifytee_id, STDOUT_FILENO));

    printf("Print dot graph to valid_cfg.dot\n");
    if((graph_fd = open("valid_cfg.dot", O_CREAT | O_WRONLY | O_TRUNC,
                        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)) == 0) {
        fprintf(stderr, "Failed to create graph file. Abort\n");
        goto free_shared_mem;
    }

    ERRSAFE(ecall_print_graph(verifytee_id, graph_fd));

    if (close(graph_fd)) {
        fprintf(stderr, "Failed to close graph file. Abort\n");
        goto free_shared_mem;
    }

free_shared_mem:
    free(shared_mem);
    shared_mem = NULL;

destroy_enclave:
    sgx_destroy_enclave(provetee_id);
    sgx_destroy_enclave(verifytee_id);

    return 0;
}
