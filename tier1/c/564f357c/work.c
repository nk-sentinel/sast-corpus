#include "work.h"

static const int slots[16] = {0};

int handle(int value) {
    if (value < 0 || value >= 16) {
        return -1;
    }
    return slots[value];
}
