#include <vector>
#include "work.hpp"

int handle(int value) {
    std::vector<int> slots(16, 0);
    if (value < 0 || static_cast<std::size_t>(value) >= slots.size()) {
        return -1;
    }
    slots[value] = 1;
    return slots[value];
}
