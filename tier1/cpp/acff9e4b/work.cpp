#include <stdexcept>
#include <vector>
#include "work.hpp"

int handle(int value) {
    std::vector<int> slots(16, 0);
    if (value < 0) {
        return -1;
    }
    try {
        return slots.at(static_cast<std::size_t>(value));
    } catch (const std::out_of_range &) {
        return -1;
    }
}
