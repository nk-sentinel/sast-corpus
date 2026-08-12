#include <algorithm>
#include <string>

std::string render(const std::string& user) {
    std::string flat = user;
    flat.erase(std::remove_if(flat.begin(), flat.end(),
        [](char c) { return c == '\n' || c == '\r'; }), flat.end());
    return "level=info action=login user=" + flat;
}
