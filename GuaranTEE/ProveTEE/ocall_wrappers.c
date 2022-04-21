#include <stdio.h>
#include <assert.h>
#include "sgx_trts.h"
#include "ssl_enclave_types.h"
#include "ProveTEE_t.h"


int sgx_printf(const char *fmt, ...)
{
    int retval = 0;
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(&retval, buf);
    return retval;
}

void sgx_exit(int exit_status)
{
	sgx_printf("sgx_exit: exit(%d) called!\n",exit_status);
	assert(0); // SGX: just for debug purpose.
	//ocall_sgx_exit(exit_status);
}
