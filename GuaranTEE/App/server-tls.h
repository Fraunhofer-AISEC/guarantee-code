/* server-tls.h
*
* Copyright (C) 2006-2016 wolfSSL Inc.
*
* This file is part of wolfSSL.
*
* wolfSSL is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* wolfSSL is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
*/

#ifndef SERVER_TLS_H
#define SERVER_TLS_H

#include "sgx_urts.h"
#include "VerifyTEE_att_u.h"
#include "ProveTEE_u.h"
#include <pthread.h>

// shared between main- and connection thread. condition for endless loop
int wolfssl_run;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int server_connect(sgx_enclave_id_t id, sgx_enclave_id_t prover_id, int sockfd);

#endif /* SERVER_TLS_H */
