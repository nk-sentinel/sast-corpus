#include <stdio.h>
#include <string.h>
#include "work.h"

int handle(const char *value) {
    char line[64];
    snprintf(line, sizeof(line), "account=%s", value);
    return (int) strlen(line);
}
