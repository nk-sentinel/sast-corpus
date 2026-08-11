#include <cstring>
#include <string>
#include "work.hpp"

std::size_t handle(const std::string &value) {
    char buffer[32];
    std::strcpy(buffer, value.c_str());
    return std::strlen(buffer);
}
