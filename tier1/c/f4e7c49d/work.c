#include "work.h"

static int slots[16];

int handle(int value) {
    if (value < 0 || value >= 16) {
        return -1;
    }
    slots[value] = 1;
    return slots[value];
}
