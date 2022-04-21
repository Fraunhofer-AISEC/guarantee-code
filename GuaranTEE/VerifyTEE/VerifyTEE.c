#include "ocall_wrappers.h"
#include "error_codes.h"
#include "queue.h"
#include "log.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "sgx_trts.h"

#ifdef SGX_ATTESTATION
#include "VerifyTEE_att_t.h"
#else
#include "VerifyTEE_t.h"
#endif /* SGX_ATTESTATION */

extern struct ra_tls_options my_ra_tls_options;

/*
 * Function: ecall_init_verify_tee
 *      Initializes the VerifyTEE
 *
 *      Parameters:
 *          shared_mem_ptr: Pointer to memory shared between ProveTEE and
 *          VerifyTEE
 */
void ecall_init_verify_tee(uintptr_t shared_mem_ptr)
{
    sgx_printf("VerifyTEE: Shared memory space at %p\n", shared_mem_ptr);
    if (initialize_queue_receiver((void*)shared_mem_ptr))
    {
        sgx_printf("Initializing shared memory queue failed\n");
        sgx_exit(QUEUE_ERROR);
    }
}

#ifdef SGX_ATTESTATION
/*
 * Function: enc_handle_connection
 *      Handles incoming attestation connections. Answers with the log
 *      regardless of the request type. Has to be implemented properly in real
 *      world applications.
 *
 *      Parameters:
 *          ssl: Handle to the SSL connection
 *
 *      Return value:
 *          0 on success, -1 otherwise
 */
int enc_handle_connection(WOLFSSL *ssl)
{
    char buff[256] = { 0 };
    size_t len = 256;
    int ret = 0;

    ret = wolfSSL_read(ssl, buff, (int) len);
    if (ret == -1 || ret < 18)
        return -1;

    return send_log_ssl(ssl);
}

void enc_create_key_and_x509(WOLFSSL_CTX *ctx)
{
    uint8_t der_key[2048];
    uint8_t der_cert[8 * 1024];
    int32_t der_key_len = (int) sizeof(der_key);
    int32_t der_cert_len = (int) sizeof(der_cert);

    create_key_and_x509(der_key, &der_key_len,
                        der_cert, &der_cert_len,
                        &my_ra_tls_options);

    int ret;
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, der_cert, der_cert_len,
                                             SSL_FILETYPE_ASN1);
    assert(ret == SSL_SUCCESS);

    wolfSSL_CTX_use_PrivateKey_buffer(ctx, der_key, der_key_len,
                                      SSL_FILETYPE_ASN1);
    assert(ret == SSL_SUCCESS);
}

void enc_wolfSSL_Debugging_ON(void)
{
    wolfSSL_Debugging_ON();
}

void enc_wolfSSL_Debugging_OFF(void)
{
    wolfSSL_Debugging_OFF();
}

int enc_wolfSSL_Init(void)
{
    return wolfSSL_Init();
}

WOLFSSL_METHOD* enc_wolfTLSv1_2_server_method(void)
{
    return wolfTLSv1_2_server_method();
}

WOLFSSL_CTX* enc_wolfSSL_CTX_new(WOLFSSL_METHOD *method)
{
    return wolfSSL_CTX_new(method);
}

WOLFSSL* enc_wolfSSL_new(WOLFSSL_CTX *ctx)
{
    return wolfSSL_new(ctx);
}

int enc_wolfSSL_set_fd(WOLFSSL *ssl, int fd)
{
    return wolfSSL_set_fd(ssl, fd);
}

void enc_wolfSSL_free(WOLFSSL *ssl)
{
    wolfSSL_free(ssl);
}

void enc_wolfSSL_CTX_free(WOLFSSL_CTX *ctx)
{
    wolfSSL_CTX_free(ctx);
}

int enc_wolfSSL_Cleanup(void)
{
    return wolfSSL_Cleanup();
}
#endif /* SGX_ATTESTATION */
