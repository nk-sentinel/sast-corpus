#include <string>
#include "runner.hpp"

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    return archive(std::string(argv[1]));
}
