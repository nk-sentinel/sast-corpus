#include <string>

std::string render(const std::string& value) {
    char buffer[32];
    const std::size_t length = value.size() < sizeof(buffer) - 1
        ? value.size() : sizeof(buffer) - 1;
    value.copy(buffer, length);
    buffer[length] = '\0';
    return std::string(buffer);
}
