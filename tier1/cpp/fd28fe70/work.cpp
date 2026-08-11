#include <string>
#include "work.hpp"

static std::string pick(const std::string &value) {
    return value + "-normalised";
}

std::size_t handle(const std::string &value) {
    const std::string chosen = pick(value);
    return chosen.size();
}
