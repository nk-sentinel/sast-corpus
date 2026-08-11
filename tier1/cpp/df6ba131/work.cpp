#include <vector>
#include "work.hpp"

int handle(int value) {
    std::vector<int> slots(16, 0);
    slots[value] = 1;
    return slots[value];
}
