/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *           Alina Weber-Hohengrund <alina.weber@aisec.fraunhofer.de>
 *
 *  log.h
 *
 *  All Rights Reserved.
 */

#ifndef LOG_H
#define LOG_H

#include <time.h>
#include <stdint.h>

#ifdef SGX_ATTESTATION
#include "VerifyTEE_att_t.h"
#else
#include "VerifyTEE_t.h"
#endif /* SGX_ATTESTATION */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct log {
    int id;
    time_t time;
    int is_malicious;
    struct log *next_log;
}log_t;

log_t *create_log(time_t time);
void set_malicious(log_t *log);
void print_log(int fd);

#ifdef SGX_ATTESTATION
int send_log_ssl(WOLFSSL* ssl);
#endif /* SGX_ATTESTATION */

#ifdef __cplusplus
}
#endif

#endif /* LOG_H */
