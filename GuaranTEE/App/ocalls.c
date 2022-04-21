#include "ocalls.h"
#include <stdlib.h>

time_t ocall_sgx_time(time_t *timep, int t_len)
{
	(void)t_len;
	return time(timep);
}

struct tm *ocall_sgx_localtime(const time_t *timep, int t_len)
{
	(void)t_len;
	return localtime(timep);
}

struct tm *ocall_sgx_gmtime_r(const time_t *timep, int t_len, struct tm *tmp, int tmp_len)
{
	(void)tmp_len;
	(void)t_len;
	return gmtime_r(timep, tmp);
}

int ocall_sgx_gettimeofday(void *tv, int tv_size)
{
	(void)tv_size;
	return gettimeofday((struct timeval *)tv, NULL);
}

int ocall_sgx_getsockopt(int s, int level, int optname, char *optval, int optval_len, int* optlen)
{
	(void)optval_len;
    return getsockopt(s, level, optname, optval, (socklen_t *)optlen);
}

int ocall_sgx_setsockopt(int s, int level, int optname, const void *optval, int optlen)
{
	return setsockopt(s, level, optname, optval, (unsigned)optlen);
}

int ocall_sgx_socket(int af, int type, int protocol)
{
	int retv;
	retv = socket(af, type, protocol);
	return retv;
}

int ocall_sgx_bind(int s, const void *addr, int addr_size)
{
	return bind(s, (struct sockaddr *)addr, (unsigned)addr_size);
}

int ocall_sgx_listen(int s, int backlog)
{
	return listen(s, backlog);
}

int ocall_sgx_connect(int s, const void *addr, int addrlen)
{
	int retv = connect(s, (struct sockaddr *)addr, (unsigned)addrlen);
	return retv;
}

int ocall_sgx_accept(int s, void *addr, int addr_size, int *addrlen)
{
	(void)addr_size;
	return accept(s, (struct sockaddr *)addr, (socklen_t *)addrlen);
}

int ocall_sgx_shutdown(int fd, int how)
{
	return shutdown(fd, how);
}

int ocall_sgx_read(int fd, void *buf, int n)
{
	return (int)read(fd, buf, (unsigned)n);
}

int ocall_sgx_write(int fd, const void *buf, int n)
{
	return (int)write(fd, buf, (unsigned)n);
}

int ocall_sgx_close(int fd)
{
	return close(fd);
}

int ocall_sgx_open(const char *path, int flags)
{
	return open(path, flags);
}

int ocall_sgx_getenv(const char *env, int envlen, char *ret_str, int ret_len)
{
	(void)envlen;
	(void)ret_len;

	const char *env_val = getenv(env);
	if (env_val == NULL) {
		return -1;
	}
	memcpy(ret_str, env_val, strlen(env_val)+1);
	return 0;
}

int ocall_print_string(const char *str)
{
    return printf("%s", str);
}

time_t ocall_time(time_t *tloc)
{
    return time(tloc);
}

void ocall_sgx_exit(int e)
{
	printf("Enclave error 0x%x\n", e);
	exit(e);
}

#ifdef SGX_ATTESTATION
static double current_time(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);

    return (double)(1000000 * tv.tv_sec + tv.tv_usec)/1000000.0f;
}

void ocall_current_time(double* time)
{
    if (!time) return;
    *time = current_time();
    return;
}

void ocall_low_res_time(int* time)
{
    struct timeval tv = {0};
    if (!time) return;
    *time = (int) tv.tv_sec;
    return;
}

ssize_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
    return recv(sockfd, buf, len, flags);
}

ssize_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
    return send(sockfd, buf, len, flags);
}
#endif /* SGX_ATTESTATION */
