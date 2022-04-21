/* client-tls.c
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

/* the usual suspects */
#ifdef SGX_RATLS_MUTUAL
#include <assert.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define DEFAULT_PORT 11111

#include <sgx_quote.h>

#include "ra.h"
#ifdef SGX_RATLS_MUTUAL
#include "ra-attester.h"
#endif
#include "ra-challenger.h"

static
int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store) {

    (void) preverify;

    int ret = verify_sgx_cert_extensions(store->certs->buffer,
                                         store->certs->length);

    fprintf(stderr, "Verifying SGX certificate extensions ... %s\n",
            ret == 0 ? "Success" : "Failure");
    return !ret;
}

#ifdef SGX_RATLS_MUTUAL
extern struct ra_tls_options my_ra_tls_options;
#endif

int main(int argc, char** argv)
{
    int                sockfd;
    struct sockaddr_in servAddr;
    char               buff[256];
    size_t             len;

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;

    (void) argc;
    (void) argv;

    /* Initialize wolfSSL */
    wolfSSL_Init();



    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        return -1;
    }



    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }

#ifdef SGX_RATLS_MUTUAL
    uint8_t key[2048]; uint8_t crt[8192];
    int key_len = sizeof(key);
    int crt_len = sizeof(crt);

    create_key_and_x509(key, &key_len, crt, &crt_len, &my_ra_tls_options);
    int ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, key_len, SSL_FILETYPE_ASN1);
    assert(SSL_SUCCESS == ret);

    ret = wolfSSL_CTX_use_certificate_buffer(ctx, crt, crt_len, SSL_FILETYPE_ASN1);
    assert(SSL_SUCCESS == ret);
#endif

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;             /* using IPv4      */
    servAddr.sin_port   = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

    const char* srvaddr = "127.0.0.1";

    /* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, srvaddr, &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        return -1;
    }



    /* Connect to the server */
    if (connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr))
        == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        return -1;
    }

    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cert_verify_callback);

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        return -1;
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(ssl, sockfd);

    /* Connect to wolfSSL on the server side */
    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        return -1;
    }

    WOLFSSL_X509* srvcrt =
        wolfSSL_get_peer_certificate(ssl);

    int derSz;
    const unsigned char* der =
        wolfSSL_X509_get_der(srvcrt, &derSz);

    sgx_quote_t quote;
    get_quote_from_cert(der, derSz, &quote);
    sgx_report_body_t* body = &quote.report_body;

    printf("Server's SGX identity:\n");
    printf("MRENCLAVE = ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) printf("%02x", body->mr_enclave.m[i]);
    printf("\n");

    printf("MRSIGNER  = ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) printf("%02x", body->mr_signer.m[i]);
    printf("\n");

    const char* http_request = "GET /log HTTP/1.0\r\n\r\n";
    len = strlen(http_request);

    /* Send the message to the server */
    if (wolfSSL_write(ssl, http_request, len) != (int) len) {
        fprintf(stderr, "ERROR: failed to write\n");
        return -1;
    }

    /* Read the server data into our buff array */
    while(1)
    {
        memset(buff, 0, sizeof(buff));
        if (wolfSSL_read(ssl, buff, sizeof(buff)-1) == -1) {
            //fprintf(stderr, "ERROR: failed to read\n");
            break;
        }

        /* Print to stdout any data the server sends */
        printf("%s", buff);
    }



    /* Cleanup and return */
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
    close(sockfd);          /* Close the connection to the server       */
    return 0;               /* Return reporting a success               */
}
