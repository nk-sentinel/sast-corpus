#include <cstring>
#include <string>
#include "work.hpp"

std::size_t handle(const std::string &value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%s", value.c_str());
    return std::strlen(buffer);
}
