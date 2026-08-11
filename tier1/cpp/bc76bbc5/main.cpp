#include <iostream>
#include "work.hpp"

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    std::cout << handle(std::atoi(argv[1])) << std::endl;
    return 0;
}
