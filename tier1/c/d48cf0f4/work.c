#include "work.h"

static int slots[16];

int handle(int value) {
    slots[value] = 1;
    return slots[value];
}
