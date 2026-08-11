#include <string.h>
#include <stdlib.h>
#include "work.h"

int handle(const char *value) {
    char *copy = malloc(strlen(value) + 1);
    if (copy == NULL) {
        return -1;
    }
    strcpy(copy, value);
    int length = (int) strlen(copy);
    free(copy);
    return length;
}
