#include <filesystem>
#include <fstream>
#include <string>
#include "work.hpp"

std::size_t handle(const std::string &value) {
    std::filesystem::path base = "/srv/reports";
    std::filesystem::path target = base / std::filesystem::path(value).filename();
    std::ifstream stream(target);
    return stream.good() ? target.string().size() : 0;
}
