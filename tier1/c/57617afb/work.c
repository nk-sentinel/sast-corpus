#include <stdlib.h>
#include <string.h>
#include "work.h"

int handle(int value) {
    if (value < 0 || value > 4096) {
        return -1;
    }
    char *buffer = malloc((size_t) value * 16);
    if (buffer == NULL) {
        return -1;
    }
    memset(buffer, 0, (size_t) value * 16);
    free(buffer);
    return value;
}
