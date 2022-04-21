/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *           Alina Weber-Hohengrund <alina.weber@aisec.fraunhofer.de>
 *
 *  log.c
 *
 *  Implements the security log of the requests.
 *
 *  All Rights Reserved.
 */

#include "log.h"
#include "ocall_wrappers.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include "sgx_trts.h"

static log_t *head = NULL;
static log_t *last_log = NULL;
static int last_log_id = 0;

/*
 * Function: append_log
 *      Appends a given log to the log chain
 *
 *      Parameters:
 *          log: Pointer to the log which should be appended
 */
void append_log(log_t *log)
{
    if (head == NULL) {
        head = log;
        last_log = log;
    } else {
        last_log->next_log = log;
        last_log = log;
    }
}

/*
 * Function: create_log
 *      Creates a new log with the given timestamp
 *
 *      Parameters:
 *          time: Timestamp of the new log
 *
 *      Return value:
 *          Pointer to the newly created node or NULL in case of errors
 */
log_t *create_log(time_t time)
{
    log_t *new_log;

    new_log = (log_t*)malloc(sizeof(log_t));
    if (new_log == NULL) {
        return NULL;
    }

    new_log->id = ++last_log_id;
    new_log->time = time;
    new_log->is_malicious = 0;
    new_log->next_log = NULL;

    append_log(new_log);

    return new_log;
}

/*
 * Function: set_malicious
 *      Marks the log with given ID as malicious
 *
 *      Parameters:
 *          log: Pointer to the log entry which should be marked as malicious
 */
void set_malicious(log_t *log)
{
    log->is_malicious = 1;
}

/*
 * Function: print_log
 *      Prints the log to a given file descriptor
 *
 *      Parameters:
 *          fd: File decriptor the log is printed to
 */
void print_log(int fd)
{
    log_t *current_log = head;

    sgx_dprintf(fd, "Request log:\n============\n");

    while (current_log != NULL) {
        sgx_dprintf(fd, "Request %04d at %d ", current_log->id,
                    current_log->time);
        if (current_log->is_malicious) {
            sgx_dprintf(fd, "MALICIOUS\n");
        } else {
            sgx_dprintf(fd, "OK\n");
        }
        current_log = current_log->next_log;
    }

    sgx_dprintf(fd, "\n");
}

/*
 * Function: log_size
 *      Determines the log length
 *
 *      Return value:
 *          Length of the log
 */
size_t log_size(void)
{
    log_t *current_log = head;
    size_t counter = 0;

    while (current_log != NULL) {
        counter++;
        current_log = current_log->next_log;
    }

    return counter;
}

#ifdef SGX_ATTESTATION
/*
 * Function: send_log_ssl
 *      Sends the log over a SSL connection
 *
 *      Parameters:
 *          ssl: handle to the SSL connection
 *
 *      Return value:
 *          Returns 0 on success, -1 otherwise
 */
int send_log_ssl(WOLFSSL* ssl)
{
    log_t *current_log = head;
    char buf[50] = { 0 };

    snprintf(buf, sizeof(buf), "\nRequest log:\n============\n");
    if (wolfSSL_write(ssl, buf, (int)strnlen(buf, sizeof(buf))) <= 0)
        return -1;

    while (current_log != NULL) {
        snprintf(buf, sizeof(buf), "Request %04d at %ld ", current_log->id,
                 (uint64_t)current_log->time);
        if (wolfSSL_write(ssl, buf, (int)strnlen(buf, sizeof(buf))) <= 0)
            return -1;

        if (current_log->is_malicious) {
            snprintf(buf, sizeof(buf), "MALICIOUS\n");
            if (wolfSSL_write(ssl, buf, (int)strnlen(buf, sizeof(buf))) <= 0)
                return -1;
        } else {
            snprintf(buf, sizeof(buf), "OK\n");
            if (wolfSSL_write(ssl, buf, (int)strnlen(buf, sizeof(buf))) <= 0)
                return -1;
        }
        current_log = current_log->next_log;
    }

    snprintf(buf, sizeof(buf), "\n");
    if (wolfSSL_write(ssl, buf, (int)strnlen(buf, sizeof(buf))) <= 0)
        return -1;

    return 0;
}
#endif /* SGX_ATTESTATION */
