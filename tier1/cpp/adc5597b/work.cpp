#include <cstdlib>
#include <cstring>
#include <string>
#include "work.hpp"

std::size_t handle(const std::string &value) {
    char *copy = static_cast<char *>(std::malloc(value.size() + 1));
    std::strcpy(copy, value.c_str());
    std::size_t length = std::strlen(copy);
    std::free(copy);
    return length;
}
