#include <stdio.h>
#include "reader.h"

int contents(const char *name) {
    char target[512];
    snprintf(target, sizeof(target), "/srv/reports/%s", name);
    FILE *handle = fopen(target, "r");
    if (handle == NULL) {
        return 1;
    }
    fclose(handle);
    return 0;
}
