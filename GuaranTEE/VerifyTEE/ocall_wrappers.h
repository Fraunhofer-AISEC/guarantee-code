#ifndef OCALL_WRAPPERS
#define OCALL_WRAPPERS

#include <stdint.h>
#include "common_ocalls.h"
#include "time.h"
#include "sgx_trts.h"

typedef long int ssize_t;

#ifdef __cplusplus
extern "C" {
#endif

time_t untrusted_time(time_t *t);
int sgx_write(int fd, const void *buf, int n);
int sgx_dprintf(int fd, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* OCALL_WRAPPERS */
