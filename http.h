#pragma once

#include <stdlib.h>
#include <sys/types.h>

#include "util.h"

#define HTTP_MAX_SIZE 8192
#define HTTP_MAX_HEADERS 40

/**
 * Simple string tuple representing a HTTP header
 */
struct header {
    string key;
    string value;
};

/**
 * Representation of a HTTP request
 */
struct request {
    string method;
    string uri;
    struct header headers[HTTP_MAX_HEADERS];
    char *payload;
    ssize_t payload_length;
};

/**
 * The state of an ongoing HTTP connection
 *
 * `sock`: the socket connected to the client
 * `buffer`: buffer for the raw received data
 * `end`: end of unprocessed data in `buffer`
 * `current_request`: current, complete request, not yet answered to. Reuses
 *                    memory of `buffer`.
 */
struct connection_state {
    int sock;
    char buffer[HTTP_MAX_SIZE];
    char *end;
    struct request current_request;
};

/**
 * Parse HTTP request into the given structure.
 *
 * When a full request is read, `request` is populated with its corresponding
 * values, utilizing the existing memory in `buffer`, and the number of bytes
 * read is returned. Otherwise, `buffer` remains unchanged, and zero is
 * returned.
 */
ssize_t parse_request(char *buffer, size_t n, struct request *request);

/**
 * Get value of header in request if set, or NULL.
 */
string get_header(const struct request *request, const string name);
