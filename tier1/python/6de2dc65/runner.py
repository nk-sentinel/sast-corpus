import subprocess


def archive(name):
    argv = ["tar", "-cf", "backup.tar", name]
    return subprocess.run(argv, shell=False, capture_output=True).stdout
