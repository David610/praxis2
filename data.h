#pragma once

#include <stdbool.h>
#include <stdlib.h>

#include "util.h"

/**
 * A simple key-value entry
 *
 * Provides a simple, inefficient, key-value when combined with `get()`,
 * `set()`, and `delete()`.
 */
struct tuple {
    string key;
    char *value;
    size_t value_length;
};

/**
 * Get the value matching the key in an array of tuples
 *
 * Returns a pointer to the begin of the value, stores its length in
 * `value_length`.
 */
const char *get(const string key, struct tuple *tuples, size_t n_tuples,
                size_t *value_length);

/**
 * Set the value for the key in an array of tuples
 *
 * Returns true if a value was overwritten, false if it was created.
 */
bool set(const string key, char *value, size_t value_length,
         struct tuple *tuples, size_t n_tuples);

/**
 * Deletes the key in the array of tuples.
 *
 * Returns true if it existed.
 */
bool delete (const string key, struct tuple *tuples, size_t n_tuples);
