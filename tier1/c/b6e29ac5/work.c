#include <stdlib.h>
#include <string.h>
#include "work.h"

int handle(int value) {
    char *buffer = malloc(value * 16);
    if (buffer == NULL) {
        return -1;
    }
    memset(buffer, 0, value * 16);
    free(buffer);
    return value;
}
