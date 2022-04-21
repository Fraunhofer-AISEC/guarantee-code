#ifndef VERIFYTEE_H
#define VERIFYTEE_H

#if defined(__cplusplus)
extern "C" {
#endif

void printf(const char *fmt, ...);
int sprintf(char* buf, const char *fmt, ...);
double current_time(void);

#if defined(__cplusplus)
}
#endif

#endif /* VERIFYTEE_H */
