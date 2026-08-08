#include <stdio.h>
#include <string.h>
#include "reader.h"

int contents(const char *name) {
    const char *leaf = strrchr(name, '/');
    leaf = (leaf == NULL) ? name : leaf + 1;
    if (strstr(leaf, "..") != NULL) {
        return 1;
    }
    char target[512];
    snprintf(target, sizeof(target), "/srv/reports/%s", leaf);
    FILE *handle = fopen(target, "r");
    if (handle == NULL) {
        return 1;
    }
    fclose(handle);
    return 0;
}
