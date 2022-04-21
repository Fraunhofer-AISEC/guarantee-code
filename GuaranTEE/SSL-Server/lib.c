/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  lib.c
 *
 *  Implements helper functions for the SSL-Server.
 *
 *  All Rights Reserved.
 */

#include "lib.h"
#include <stddef.h>

// from https://www.techiedelight.com/implement-strcat-function-c/
char *strcat(char* dest, const char* src)
{
    char *ptr = dest;

    while (*ptr != '\0') {
        ptr++;
    }

    while (*src != '\0') {
        *ptr++ = *src++;
    }

    *ptr = '\0';

    return dest;
}

char *strcpy(char *dest, const char* src)
{
    char *ptr = dest;

    while (*src != '\0') {
        *ptr++ = *src++;
    }

    *ptr = '\0';

    return dest;
}

char *get_nth_occurrence(char *src, char c, unsigned int n)
{
    if (!n)
        return NULL;

    while (*src) {
        if (*src == c && --n == 0)
            return src;
        else
            src++;
    }

    return NULL;
}
