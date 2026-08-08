#include <string>
#include <unistd.h>
#include <sys/wait.h>
#include "runner.hpp"

int archive(const std::string &name) {
    pid_t pid = fork();
    if (pid == 0) {
        char *const argv[] = {const_cast<char *>("tar"), const_cast<char *>("-cf"),
                              const_cast<char *>("backup.tar"),
                              const_cast<char *>(name.c_str()), nullptr};
        execvp("tar", argv);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}
