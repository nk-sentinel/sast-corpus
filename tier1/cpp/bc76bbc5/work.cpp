#include <vector>
#include "work.hpp"

int handle(int value) {
    std::vector<int> slots(16, 0);
    return slots[value];
}
