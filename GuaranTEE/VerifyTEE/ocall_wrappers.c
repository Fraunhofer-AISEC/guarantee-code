#include "ocall_wrappers.h"
#include <stdio.h>
#include <string.h>
#include "sgx_trts.h"

#ifdef SGX_ATTESTATION
#include "VerifyTEE_att_t.h"
#else
#include "VerifyTEE_t.h"
#endif /* SGX_ATTESTATION */

int sgx_printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    int result = 0;
    va_list ap;
    va_start(ap, fmt);
    result = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(NULL, buf);
    return result;
}

int sgx_dprintf(int fd, const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    int result = 0;
    va_list ap;
    va_start(ap, fmt);
    result = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    sgx_write(fd, buf, (int)strlen(buf));
    return result;
}

time_t untrusted_time(time_t *t)
{
    time_t result;
    if (ocall_time(&result, t) != SGX_SUCCESS) {
        return 0;
    }

    return result;
}

void sgx_exit(int exit_status)
{
	sgx_printf("sgx_exit: exit(%d) called!\n",exit_status);
	ocall_sgx_exit(exit_status);
}

int sgx_write(int fd, const void *buf, int n)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_write(&retv, fd, buf, n)) != SGX_SUCCESS) {
		sgx_printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		sgx_exit(EXIT_FAILURE);
	}
	return retv;
}

#ifdef SGX_ATTESTATION
double current_time(void)
{
    double curr;
    ocall_current_time(&curr);
    return curr;
}

int LowResTimer(void) /* low_res timer */
{
    int time;
    ocall_low_res_time(&time);
    return time;
}

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
    long int ret;
    ocall_recv(&ret, sockfd, buf, len, flags);
    return (size_t) ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
    long int ret;
    ocall_send(&ret, sockfd, buf, len, flags);
    return (size_t) ret;
}
#endif /* SGX_ATTESTATION */
