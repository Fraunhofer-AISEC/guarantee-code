#include "Ocall_wrappers.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>
extern "C" {
    #include "lib.h"
}

#define FILE_1 "<!DOCTYPE html>\n<html>\n<body>\n<h1>SGX Server</h1>\n<p>File 1.</p>\n</body>\n</html>\n"
#define FILE_2 "<!DOCTYPE html>\n<html>\n<body>\n<h1>SGX Server</h1>\n<p>File 2.</p>\n</body>\n</html>\n"
#define TERMINATE "<!DOCTYPE html>\n<html>\n<body>\n<h1>SGX Server</h1>\n<p>Server terminates.</p>\n</body>\n</html>\n"
#define NOT_FOUND "HTTP/1.1 404 NOT FOUND\r\n\r\n<!DOCTYPE html>\n<html>\n<body>\n<h1>ERROR 404</h1>\n<p>File not found</p>\n</body>\n</html>\n"
#define INT_SRV_ERR "HTTP/1.1 500 INTERNAL SERVER ERROR\r\n\r\n<!DOCTYPE html>\n<html>\n<body>\n<h1>ERROR 500</h1>\n<p>Server FAILED</p>\n</body>\n</html>\n"

static void init_openssl()
{
	OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_ciphers();
	SSL_load_error_strings();
}

static void cleanup_openssl()
{
    EVP_cleanup();
}

static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLSv1_2_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        printe("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

static int password_cb(char *buf, int size, int rwflag, void *password)
{
    strncpy(buf, (char *)(password), size);
    buf[size - 1] = '\0';
    return strlen(buf);
}

static EVP_PKEY *generatePrivateKey()
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY_keygen(pctx, &pkey);
    return pkey;
}

static X509 *generateCertificate(EVP_PKEY *pkey)
{
    X509 *x509 = X509_new();
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), (long)60*60*24*365);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"YourCN", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_md5());
    return x509;
}

static X509 *loadCertificate()
{
    char cert_buf[2048];
    int fd = sgx_open("cert/mycert.pem", 0);
    BIO *cert_bio = BIO_new(BIO_s_mem());
    X509 *certificate;

    sgx_read(fd, cert_buf, sizeof(cert_buf));

    BIO_write(cert_bio, cert_buf, strlen(cert_buf));

    certificate = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);

    sgx_close(fd);
    BIO_free(cert_bio);

    return certificate;
}

static EVP_PKEY *loadPrivateKey()
{
    char key_buf[4096];
    int fd = sgx_open("cert/mykey.pem", 0);
    BIO *key_bio = BIO_new(BIO_s_mem());
    EVP_PKEY *key;

    sgx_read(fd, key_buf, sizeof(key_buf));

    BIO_write(key_bio, key_buf, strlen(key_buf));

    key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);

    if (key == NULL) {
        printe("Key is null");
        exit(EXIT_FAILURE);
    }

    sgx_close(fd);
    BIO_free(key_bio);

    return key;
}

static void configure_context(SSL_CTX *ctx)
{
    //EVP_PKEY *pkey = generatePrivateKey();
	//X509 *x509 = generateCertificate(pkey);
    X509 *x509 = loadCertificate();
    EVP_PKEY *pkey = loadPrivateKey();

	if (SSL_CTX_use_certificate(ctx, x509) <= 0) {
        printe("Load certificate failed");
        exit(EXIT_FAILURE);
    }

	if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        printe("Load private key failed");
        exit(EXIT_FAILURE);
    }

	/* RSA *rsa=RSA_generate_key(512, RSA_F4, NULL, NULL);
	SSL_CTX_set_tmp_rsa(ctx, rsa);
	RSA_free(rsa); */

	//SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
}

static int create_socket_server(int port)
{
    int s, optval = 1;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
    	printe("sgx_socket");
		exit(EXIT_FAILURE);
    }
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int)) < 0) {
		printe("sgx_setsockopt");
		exit(EXIT_FAILURE);
    }
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    	printe("sgx_bind");
		exit(EXIT_FAILURE);
    }
    if (listen(s, 128) < 0) {
    	printe("sgx_listen");
		exit(EXIT_FAILURE);
    }
    return s;
}

/* Very simple HTML parser, can only handle GET and handle request of two files */
int parse_request(const char *buffer)
{
    if (!strncmp(buffer, "GET ", 4)) {
        if (!strncmp(buffer + 4, "/file1.html ", 12)) {
            return 1;
        } else if (!strncmp(buffer + 4, "/file2.html ", 12)) {
            return 2;
        } else if (!strncmp(buffer + 4, "/terminate ", 11)) {
            return 0;
        } else {
            return -1;
        }
    }

    return -1;
}

int assemble_response(char *response_buffer, size_t resp_buf_len, const char *status_phrase, const char *status_code, const char *body)
{
    if (resp_buf_len < (strlen(status_phrase) + strlen(status_code) + strlen(body) + 15))
        return -1;

    strcpy(response_buffer, "HTTP/1.1 ");
    strcat(response_buffer, status_code);
    strcat(response_buffer, " ");
    strcat(response_buffer, status_phrase);
    strcat(response_buffer, "\r\n\r\n");
    strcat(response_buffer, body);

    return 0;
}

void ecall_start_tls_server(void)
{
    int sock;
    int terminate = 0;
    int nr_connections = 0;
    SSL_CTX *ctx;

    printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    sock = create_socket_server(4434);
    if(sock < 0) {
		printe("create_socket_client");
		exit(EXIT_FAILURE);
    }

    /* Handle SSL/TLS connections */
    while(!terminate) {
        struct sockaddr_in addr;
        int len = sizeof(addr);
        SSL *cli;
        unsigned char read_buf[1024];
        char response_buf[1024];
        int r = 0;
        //printl("Wait for new connection...");
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        nr_connections++;
        if (client < 0) {
            printe("Unable to accept");
            exit(EXIT_FAILURE);
        }

		cli = SSL_new(ctx);
        SSL_set_fd(cli, client);
		if (SSL_accept(cli) <= 0) {
            printe("SSL_accept");
            exit(EXIT_FAILURE);
        }

        //printl("ciphersuit: %s", SSL_get_current_cipher(cli)->name);
        /* Receive buffer from TLS server */
        r = SSL_read(cli, read_buf, sizeof(read_buf));
        //printl("read_buf: length = %d : %s", r, read_buf);

        int result = parse_request((const char *)read_buf);
        switch (result) {
            case 0: {
                terminate = 1;
                if (assemble_response(response_buf, sizeof(response_buf), "OK", "200", TERMINATE)) {
                    memcpy(response_buf, INT_SRV_ERR, sizeof(INT_SRV_ERR));
                };
                break;
            }
            case 1:
                if (assemble_response(response_buf, sizeof(response_buf), "OK", "200", FILE_1)) {
                    memcpy(response_buf, INT_SRV_ERR, sizeof(INT_SRV_ERR));
                };
                break;
            case 2:
                if (assemble_response(response_buf, sizeof(response_buf), "OK", "200", FILE_2)) {
                    memcpy(response_buf, INT_SRV_ERR, sizeof(INT_SRV_ERR));
                };
                break;
            default:
                memcpy(response_buf, NOT_FOUND, sizeof(NOT_FOUND));
        }
        memset(read_buf, 0, sizeof(read_buf));
        SSL_write(cli, response_buf, strlen((const char *)response_buf));

        //printl("Close SSL/TLS client");
        SSL_free(cli);
        sgx_close(client);
    }

    printl("Total number of connections: %d\n", nr_connections);

    sgx_close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
