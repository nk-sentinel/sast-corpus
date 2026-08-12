#include <cstring>
#include <string>

std::string render(const std::string& value) {
    char buffer[32];
    std::strcpy(buffer, value.c_str());
    return std::string(buffer);
}
