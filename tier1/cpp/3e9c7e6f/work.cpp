#include <cstdio>
#include <string>

std::string render(const std::string& value) {
    char out[256];
    std::snprintf(out, sizeof(out), value.c_str());
    return std::string(out);
}
