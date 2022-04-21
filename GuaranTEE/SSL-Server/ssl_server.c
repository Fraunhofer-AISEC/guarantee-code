#include "ssl_server_ocall_wrappers.h"
#include "picohttpparser.h"
#include <errno.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "lib.h"

#define HTTP_OK "HTTP/1.1 200 OK\r\n\r\n"
#define HTTP_BAD_REQUEST "HTTP/1.1 400 Bad Request\r\n\r\n"

#define PORT 4433

RSA *signing_key = NULL;

struct sig {
    unsigned int size;
    unsigned char* signature;
};

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

static RSA *load_signing_key()
{
    char key_buf[4096];
    int fd = sgx_open("cert/signing_key.pem", 0);
    BIO *key_bio = BIO_new(BIO_s_mem());
    RSA *key;

    sgx_read(fd, key_buf, sizeof(key_buf));

    BIO_write(key_bio, key_buf, (int)strlen(key_buf));

    key = PEM_read_bio_RSAPrivateKey(key_bio, NULL, NULL, NULL);

    if (key == NULL) {
        printe("Key is null");
        exit(EXIT_FAILURE);
    }

    sgx_close(fd);
    BIO_free(key_bio);

    return key;
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

static X509 *loadCertificate()
{
    char cert_buf[2048];
    int fd = sgx_open("cert/mycert.pem", 0);
    BIO *cert_bio = BIO_new(BIO_s_mem());;
    X509 *certificate;

    sgx_read(fd, cert_buf, sizeof(cert_buf));

    BIO_write(cert_bio, cert_buf, (int)strlen(cert_buf));

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

    BIO_write(key_bio, key_buf, (int)strlen(key_buf));

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
}

static void create_socket_server(int port, int s)
{
    int optval = 1;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = (in_port_t)htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

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
    return;
}

unsigned char hex_to_char(char c)
{
    // 0 to 9
    if (48 <= c && c <= 57) {
        return (unsigned char)c - 48;
    }

    // A to F
    if (65 <= c && c <= 70) {
        return (unsigned char)c - 55;
    }

    // a to f
    if (97 <= c && c <= 102) {
        return (unsigned char)c - 87;
    }

    return 0;
}

void unhexlify(unsigned char *dst, size_t dst_len, const char *src)
{
    while (dst_len > 0) {
        *dst = (unsigned char)(hex_to_char(*src++) << 4);
        *dst++ |= hex_to_char(*src++);

        dst_len--;
    }
}

unsigned char* extract_hash(struct phr_header* headers, size_t num_headers)
{
    size_t content_len = 0;
    unsigned char *hash = NULL;

    for (size_t i = 0; i != num_headers; ++i) {
        if (strncmp("Content-Length", headers[i].name, 14) == 0) {
            content_len = strtoul(headers[i].value, NULL, 10);
        }

        if (strncmp("application/x-www-form-urlencoded", headers[i].value, 33) == 0) {
            const char* post_content = headers[i].value + 37;

            if (strncmp("hash=", post_content, 5) == 0) {
                post_content = post_content + 5;
                content_len = content_len - 5;

                if (content_len != (SHA256_DIGEST_LENGTH * 2)) {
                    return NULL;
                }

                hash = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
                if (!hash) {
                    return NULL;
                }

                unhexlify(hash, SHA256_DIGEST_LENGTH, post_content);

                return hash;
            }
        }
    }

    return NULL;
}

struct sig *sign_hash(unsigned char* hash, size_t hash_len)
{
    unsigned char *signature = NULL;
    unsigned int signature_len = 0;
    struct sig *result = NULL;

    if (signing_key == NULL) {
        signing_key = load_signing_key();

        if (!signing_key) {
            printe("Failed to load signing key");
		    exit(EXIT_FAILURE);
        }
    }

    signature = (unsigned char*)malloc((size_t)RSA_size(signing_key));
    if (!signature) {
        printe("Failed to request memory via malloc");
		exit(EXIT_FAILURE);
    }

    if (RSA_sign(NID_sha256, hash, (unsigned int)hash_len, signature, &signature_len, signing_key) != 1) {
        sgx_printf("OpenSSL error 0x%x\n", ERR_get_error());
        printe("Failed to sign hash");
		exit(EXIT_FAILURE);
    }

    result = (struct sig*)malloc(sizeof(struct sig));
    if (!result) {
        printe("Failed to request memory via malloc");
        free(signature);
		exit(EXIT_FAILURE);
    }

    result->size = signature_len;
    result->signature = signature;

    return result;
}

struct sig* base64_encode(const unsigned char* buffer, size_t buf_len)
{
    BIO *bio;
    BIO *b64;
    struct sig* res = NULL;

    res = (struct sig*)malloc(sizeof(struct sig));
    if (!res) {
        printe("Failed to request memory via malloc");
		exit(EXIT_FAILURE);
    }

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());

    BIO_push(b64, bio);
    BIO_write(b64, buffer, (int)buf_len);
    BIO_flush(b64);

    long ret = BIO_get_mem_data(bio, &(res->signature));
    if (ret <= 0) {
        printe("Failed to encode signature as BASE64");
		exit(EXIT_FAILURE);
    }

    res->size = (unsigned int)ret;

    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free(bio);
    BIO_free(b64);

    return res;
}

unsigned char* handle_request(SSL *ssl)
{
    char buf[4000] = { 0 };
    int rret = 0;
    int pret = 0, minor_version;
    struct phr_header headers[100];
    size_t buflen = 0, prevbuflen = 0, method_len, path_len, num_headers;
    const char *method;
    const char *path;
    int answered = 0;

    // From https://github.com/h2o/picohttpparser/#phr_parse_request
    while (1) {
        while ((rret = SSL_read(ssl, buf + buflen, (int)(sizeof(buf) - buflen))) == -1);

        prevbuflen = buflen;
        buflen += (unsigned)rret;

        num_headers = sizeof(headers) / sizeof(headers[0]);
        pret = phr_parse_request(buf, buflen, &method, &method_len, &path, &path_len,
                                 &minor_version, headers, &num_headers, prevbuflen);

        if (pret > 0) {
            break; /* successfully parsed the request */
        } else if (pret == -1) {
            printe("parse error");
		    exit(EXIT_FAILURE);
        }

        /* request is incomplete, continue the loop */
        assert(pret == -2);
        if (buflen == sizeof(buf)) {
            printe("request too long");
		    exit(EXIT_FAILURE);
        }
    }

    if (strncmp("/signature.html", path, path_len) == 0) {
        unsigned char* hash = NULL;

        if ((hash = extract_hash(headers, num_headers))) {
            struct sig* bin_sig = NULL;
            struct sig* base64_sig = NULL;

            bin_sig = sign_hash(hash, SHA256_DIGEST_LENGTH);
            base64_sig = base64_encode(bin_sig->signature, bin_sig->size);

            SSL_write(ssl, HTTP_OK, (int)strlen(HTTP_OK));
            SSL_write(ssl, base64_sig->signature, (int)base64_sig->size);
            answered = 1;

            free(bin_sig->signature);
            free(bin_sig);
            free(base64_sig->signature);
            free(base64_sig);
        }

        free(hash);
    }

    if (!answered) {
        SSL_write(ssl, HTTP_BAD_REQUEST, (int)strlen(HTTP_BAD_REQUEST));
    }

    return 0;
}


void ecall_start_target(int sock)
{
    int nr_connections = 0;
    SSL_CTX *ctx;

    printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    printl("Start SSL-Server on port %d", PORT);
    create_socket_server(PORT, sock);
    if(sock < 0) {
		printe("create_socket_client");
		exit(EXIT_FAILURE);
    }

    /* Handle SSL/TLS connections */
    while(1) {
        struct sockaddr_in addr;
        int len = sizeof(addr);
        SSL *cli;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client == -1)
            break;

        if (client < 0) {
            printe("Unable to accept %d", client);
            exit(EXIT_FAILURE);
        }

		cli = SSL_new(ctx);
        SSL_set_fd(cli, client);
		if (SSL_accept(cli) <= 0) {
            printe("SSL_accept");
            exit(EXIT_FAILURE);
        }
        nr_connections++;

        // Insert START tag for CFA
        #pragma clang cfa start

        handle_request(cli);

        // Insert END tag for CFA
        #pragma clang cfa end

        SSL_free(cli);
        sgx_close(client);
    }

    printl("Total number of connections: %d\n", nr_connections);

    SSL_CTX_free(ctx);
    cleanup_openssl();
}
