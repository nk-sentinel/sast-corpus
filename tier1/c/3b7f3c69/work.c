#include <string.h>
#include <stdlib.h>
#include "work.h"

int handle(const char *value) {
    char *copy = strdup(value);
    if (copy == NULL) {
        return 1;
    }
    free(copy);
    return (int) strlen(copy);
}
