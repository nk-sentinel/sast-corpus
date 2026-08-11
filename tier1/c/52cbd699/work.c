#include <stdio.h>
#include <string.h>
#include "work.h"

int handle(const char *value) {
    char line[64];
    sprintf(line, "account=%s", value);
    return (int) strlen(line);
}
