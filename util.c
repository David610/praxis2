#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *memstr(char *haystack, size_t n, string needle) {
    char *end = haystack + n;

    // Iterate through the memory (haystack)
    while ((haystack = memchr(haystack, needle[0], end - haystack)) != NULL) {
        if (strncmp(haystack, needle, strlen(needle)) == 0) {
            return haystack;
        }
    }

    return NULL;
}

uint16_t safe_strtoul(const char *restrict nptr, char **restrict endptr,
                      int base, const string message) {
    errno = 0;
    uint16_t result =
        strtoul(nptr, endptr, base); // Convert string to unsigned int

    if (errno != 0) {
        fprintf(stderr, "%s\n", message);
        exit(EXIT_FAILURE);
    }
    return result;
}


uint16_t pseudo_hash(const unsigned char *buffer, size_t buf_len) {
    // we use tcp crc16 check here
    uint32_t hash = 0;
    // add zero padding to the end if buf_len not even
    size_t pad_length = buf_len % 2 ? buf_len + 1 : buf_len;
    uint8_t *int_buffer =  calloc(pad_length, sizeof *buffer);
    memcpy(int_buffer, buffer, buf_len);

    for (size_t i = 0; i < pad_length; i+=2) {
        hash += int_buffer[i] << 8 | int_buffer[i+1];
    }

    hash = (hash & 0xFFFF) + (hash >> 16);

    free(int_buffer);

    return (uint16_t) ~hash;
}



