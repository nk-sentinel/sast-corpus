#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include "runner.h"

int archive(const char *name) {
    pid_t pid = fork();
    if (pid == 0) {
        char *const argv[] = {"tar", "-cf", "backup.tar", (char *) name, NULL};
        execvp("tar", argv);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}
