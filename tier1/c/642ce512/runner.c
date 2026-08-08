#include <stdio.h>
#include <stdlib.h>
#include "runner.h"

int archive(const char *name) {
    char line[512];
    snprintf(line, sizeof(line), "tar -cf backup.tar %s", name);
    return system(line);
}
