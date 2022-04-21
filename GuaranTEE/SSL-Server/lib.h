/*
 *  Copyright (C) 2022 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *
 *  lib.h
 *
 *  All Rights Reserved.
 */

#ifndef LIB_H
#define LIB_H

char *strcat(char* dest, const char* src);
char *strcpy(char *dest, const char* src);
char *get_nth_occurrence(char *src, char c, unsigned int n);

#endif /* LIB_H */
