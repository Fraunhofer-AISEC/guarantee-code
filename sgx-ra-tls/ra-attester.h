#ifndef _RA_ATTESTER_H_
#define _RA_ATTESTER_H_

#include <sgx_quote.h>

struct ra_tls_options {
    sgx_spid_t spid;
    sgx_quote_sign_type_t quote_type;
    /* NULL-terminated string of domain name/IP, port and path prefix,
       e.g., api.trustedservices.intel.com/sgx/dev for development and
       api.trustedservices.intel.com/sgx for production. */
    const char ias_server[512];
    const char subscription_key[32];
};

struct ecdsa_ra_tls_options {
    char subscription_key[32];
};

void create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ra_tls_options* opts
);

void create_key_and_x509_pem
(
    uint8_t* pem_key,
    int* pem_key_len,
    uint8_t* pem_cert,
    int* pem_cert_len,
    const struct ra_tls_options* opts
);

#ifdef RATLS_ECDSA
void ecdsa_create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ecdsa_ra_tls_options* opts
);
#endif

void ra_tls_create_report(
    sgx_report_t* report
);
#endif
