#include <iostream>
#include <string>

std::string render(const std::string& value);

int main(int argc, char** argv) {
    std::cout << render(argc > 1 ? argv[1] : "") << std::endl;
    return 0;
}
