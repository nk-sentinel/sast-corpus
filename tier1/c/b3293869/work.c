#include <string.h>
#include <stdio.h>
#include "work.h"

int handle(const char *value) {
    char buffer[32];
    strcpy(buffer, value);
    return (int) strlen(buffer);
}
