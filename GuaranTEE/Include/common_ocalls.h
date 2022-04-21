#ifndef COMMON_OCALLS_H
#define COMMON_OCALLS_H

#if defined(__cplusplus)
extern "C" {
#endif

void sgx_exit(int exit_status);
int sgx_printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#endif /* COMMON_OCALLS_H */
