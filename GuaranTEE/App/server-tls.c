/* server-tls.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "server-tls.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

#define DEFAULT_PORT 11111

#define CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256"

// check wolfssl_run thread save
int is_running(void)
{
    int ret = 0;
    if(pthread_mutex_lock(&mutex) == 0)
    {
        ret = wolfssl_run;
        pthread_mutex_unlock(&mutex);
    }
    return ret;
}

// main function around accepting connections
int server_connect(sgx_enclave_id_t id, sgx_enclave_id_t prover_id, int sockfd)
{
    int                sgxStatus;
    int                connd;
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t          size = sizeof(clientAddr);
    int                ret = 0;

    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;
    WOLFSSL_METHOD* method;



    // Initialize wolfSSL
    enc_wolfSSL_Init(id, &sgxStatus);

#ifdef SGX_DEBUG
    enc_wolfSSL_Debugging_ON(id);
#else
    enc_wolfSSL_Debugging_OFF(id);
#endif

    int enable = 1;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    assert(ret != -1);

    // Create and initialize WOLFSSL_CTX
    sgxStatus = enc_wolfTLSv1_2_server_method(id, &method);
    if (sgxStatus != SGX_SUCCESS || method == NULL)
    {
        fprintf(stderr, "wolfTLSv1_2_server_method failure\n");
        return EXIT_FAILURE;
    }

    sgxStatus = enc_wolfSSL_CTX_new(id, &ctx, method);
    if (sgxStatus != SGX_SUCCESS || ctx == NULL)
    {
        fprintf(stderr, "wolfSSL_CTX_new failure\n");
        return EXIT_FAILURE;
    }

    sgxStatus = enc_create_key_and_x509(id, ctx);
    assert(sgxStatus == SGX_SUCCESS);

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_port        = htons(DEFAULT_PORT);
    servAddr.sin_addr.s_addr = INADDR_ANY;


    // Bind the server socket to our port
    if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind\n");
        return EXIT_FAILURE;
    }
    // endless loop till terminated in via App
    while(is_running()){

        // Listen for a new connection, allow 5 pending connections
        if (listen(sockfd, 5) == -1) {
            fprintf(stderr, "ERROR: failed to listen\n");
            return EXIT_FAILURE;
        }

        printf("Waiting for a connection...\n");

        // Accept client connections
        connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size);
        if(connd == -1 && errno == EINVAL)
            break;
        if(connd == -1)
        {
            fprintf(stderr, "ERROR: failed to accept the connection\nerrno: %d\n", errno);
            return EXIT_FAILURE;
        }

        sgxStatus = enc_wolfSSL_new(id, &ssl, ctx);

        if (sgxStatus != SGX_SUCCESS || ssl == NULL) {
            fprintf(stderr, "wolfSSL_new failure\n");
            return EXIT_FAILURE;
        }

        // Attach wolfSSL to the socket
        sgxStatus = enc_wolfSSL_set_fd(id, &ret, ssl, connd);
        if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
            fprintf(stderr, "wolfSSL_set_fd failure\n");
            return EXIT_FAILURE;
        }

        printf("Client connected successfully\n");

        // actually only flushes the batch caches
        ecall_shutdown_prover_tee(prover_id);
        sleep(1);
        // For single connection
        sgxStatus = enc_handle_connection(id, &ret, ssl);
        if (sgxStatus != SGX_SUCCESS || ret == -1)
        {
            fprintf(stderr, "Server failed to handle the connection\n");
            return EXIT_FAILURE;
        }

        // Connection cleanup
        enc_wolfSSL_free(id, ssl);
        close(connd);
        if (ret == -2)
        {
            fprintf(stderr, "break in server-tls.c line 175 triggered");
            break; // should theoretically never get triggered
        }
    }

    // Cleanup and return
    sgxStatus = enc_wolfSSL_CTX_free(id, ctx);
    sgxStatus = enc_wolfSSL_Cleanup(id, &ret);

    return 0;
}
