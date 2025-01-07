#include "data.h"

#include <string.h>

struct tuple *find(string key, struct tuple *tuples, size_t n_tuples) {
    for (size_t i = 0; i < n_tuples; i += 1) {
        // compare keys with 'strcmp'
        if (tuples[i].key && strcmp(key, tuples[i].key) == 0) {
            return &(tuples[i]);
        }
    }
    return NULL;
}

const char *get(const string key, struct tuple *tuples, size_t n_tuples,
                size_t *value_length) {
    struct tuple *tuple = find(key, tuples, n_tuples);
    if (tuple) {
        *value_length = tuple->value_length;
        return tuple->value;
    } else {
        return NULL;
    }
}

bool set(const string key, char *value, size_t value_length,
         struct tuple *tuples, size_t n_tuples) {
    // check if tuple already exists
    struct tuple *tuple = find(key, tuples, n_tuples);

    if (tuple) { // overwrite existing value
        free(tuple->value);
        tuple->value = (char *)malloc(value_length * sizeof(char));
        strcpy(tuple->value, value);
        tuple->value_length = value_length;
        return true;
    } else { // add tuple
        for (size_t i = 0; i < n_tuples; i += 1) {
            if (tuples[i].key == NULL) {
                tuples[i].key =
                    (char *)malloc((strlen(key) + 1) * sizeof(char));
                strcpy(tuples[i].key, key);
                tuples[i].value = (char *)malloc(value_length * sizeof(char));
                memcpy(tuples[i].value, value, value_length);
                tuples[i].value_length = value_length;
                return false;
            }
        }
    }
    return false; // fail silently if no space for a new tuple is available
}

bool delete (const string key, struct tuple *tuples, size_t n_tuples) {
    struct tuple *tuple = find(key, tuples, n_tuples);

    if (tuple) {
        free(tuple->key);
        tuple->key = NULL;
        free(tuple->value);
        tuple->value = NULL;
        tuple->value_length = 0;
        return true;
    } else {
        return false;
    }
}
