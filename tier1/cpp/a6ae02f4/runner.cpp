#include <cstdlib>
#include <string>
#include "runner.hpp"

int archive(const std::string &name) {
    std::string line = "tar -cf backup.tar " + name;
    return std::system(line.c_str());
}
