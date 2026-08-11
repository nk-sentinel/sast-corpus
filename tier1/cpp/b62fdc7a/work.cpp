#include <fstream>
#include <string>
#include "work.hpp"

std::size_t handle(const std::string &value) {
    std::string target = "/srv/reports/" + value;
    std::ifstream stream(target);
    return stream.good() ? target.size() : 0;
}
