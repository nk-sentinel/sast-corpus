#include <string.h>
#include <stdio.h>
#include "work.h"

int handle(const char *value) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%s", value);
    return (int) strlen(buffer);
}
