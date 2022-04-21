#include "lib.h"

// see https://www.techiedelight.com/implement-strcat-function-c/
char *strcat(char* dest, const char* src)
{
    char *ptr = dest;

    while (*ptr != '\0') {
        ptr++;
    }

    while (*src != '\0')
        *ptr++ = *src++;

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
