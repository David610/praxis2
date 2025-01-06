/**
 * This file provides functions to parse and extract information from an HTTP
 * request, such as the request line, headers, and payload.
 */

#include "http.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/**
 * Non null-terminated string
 */
struct non_string {
    char *start;
    size_t n;
};

/**
 * Parse the request line of an HTTP request
 *
 * Returns whether a valid request line (excluding line separator) is parsed.
 * On valid request lines, `method` and `uri` are populated with the
 * corresponding values, reusing `buffer`'s memory.
 */
static bool parse_request_line(char *buffer, size_t n,
                               struct non_string *method,
                               struct non_string *uri) {
    const char *end = buffer + n;
    char *pos = buffer;

    method->start = buffer;
    if ((pos = memchr(buffer, ' ', end - buffer)) == NULL) {
        return false;
    }
    method->n = pos - buffer;
    buffer = pos + 1;

    uri->start = buffer;
    if ((pos = memchr(buffer, ' ', end - buffer)) == NULL) {
        return false;
    }
    uri->n = pos - buffer;
    buffer = pos + 1;

    return true;
}

/**
 * Parse HTTP header
 *
 * Returns whether a valid header (excluding line separator) is parsed. On
 * a valid header, `key` and `value` are populated with the corresponding
 * values, reusing `buffer`'s memory.
 */
static bool parse_header(char *buffer, size_t n, struct non_string *key,
                         struct non_string *value) {
    char *field_name_end = memchr(buffer, ':', n);
    if (!field_name_end) {
        return false;
    }

    *key = (struct non_string){.start = buffer, .n = field_name_end - buffer};
    *value = (struct non_string){.start = field_name_end + 1,
                                 .n = (buffer + n) - (field_name_end + 1)};

    return true;
}

ssize_t parse_request(char *buffer, size_t n, struct request *request) {
    char *line_separator = "\r\n";

    const char *end = buffer + n;
    char *pos = buffer;
    char *line_end;

    // Parse the request line
    if (!(line_end = memstr(pos, end - pos, line_separator))) {
        return 0; // Request line not received yet
    }
    struct non_string method = {0};
    struct non_string uri = {0};
    if (!parse_request_line(pos, line_end - pos, &method, &uri)) {
        return -1; // Error parsing request line
    }

    pos = line_end + strlen(line_separator); // Skip line separator

    // Parse headers
    struct {
        struct non_string key;
        struct non_string value;
    } headers[HTTP_MAX_HEADERS] = {0};
    size_t header_count = 0;

    while ((line_end = memstr(pos, end - pos, line_separator)) != pos) {
        if (header_count > HTTP_MAX_HEADERS) {
            fprintf(stderr, "Exceeded max header count.\n");
            exit(EXIT_FAILURE);
        }
        if (!line_end) {
            return 0; // Header not fully received
        }
        if (!parse_header(pos, line_end - pos, &(headers[header_count].key),
                          &(headers[header_count].value))) {
            return -1; // Error parsing header
        }
        pos = line_end + strlen(line_separator); // Skip line separator
        header_count += 1;
    }

    pos = line_end + strlen(line_separator); // Skip empty line

    // Parse payload length from headers
    for (size_t i = 0; i < header_count; i += 1) {
        if (strncmp(headers[i].key.start, "Content-Length", headers[i].key.n) ==
            0) {
            request->payload_length = strtoul(headers[i].value.start, NULL, 10);
            break;
        }
    }
    if (request->payload_length < 0) {
        if (request->method &&
            strncmp(request->method, "PUT", strlen("PUT")) == 0) {
            return -1; // Content-Length non-optional on PUT-requests
        }
        request->payload_length = 0;
    }
    request->payload = pos;
    if (pos + request->payload_length > end) {
        return 0; // Payload not yet received completely, try again.
    }

    // Request is valid: Bytes will be discarded after sending the reply,
    // so we can reuse `buffer` here to avoid dynamic memory allocation.
    // All relevant strings are followed by at least one byte, so we can
    // overwrite these with null-characters, yielding proper strings.

    method.start[method.n] = '\0';
    request->method = method.start;

    uri.start[uri.n] = '\0';
    request->uri = uri.start;

    for (size_t i = 0; i < header_count; i += 1) {
        headers[i].key.start[headers[i].key.n] = '\0';
        request->headers[i].key = headers[i].key.start;

        headers[i].value.start[headers[i].value.n] = '\0';
        request->headers[i].value = headers[i].value.start;
    }

    return (pos + request->payload_length) - buffer; // Parsed until `pos`
}

string get_header(const struct request *request, const string name) {
    for (size_t i = 0; i < HTTP_MAX_HEADERS; i += 1) {
        if (request->headers[i].key &&
            strcmp(request->headers[i].key, name) == 0) {
            return request->headers[i].value;
        }
    }
    return NULL; // Header not found
}

