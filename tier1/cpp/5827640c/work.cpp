#include <string>

std::string render(const std::string& user) {
    return "level=info action=login user=" + user;
}
