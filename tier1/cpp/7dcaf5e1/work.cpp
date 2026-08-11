#include <string>
#include "work.hpp"

static const std::string &pick(const std::string &value) {
    std::string local = value + "-normalised";
    return local;
}

std::size_t handle(const std::string &value) {
    const std::string &chosen = pick(value);
    return chosen.size();
}
