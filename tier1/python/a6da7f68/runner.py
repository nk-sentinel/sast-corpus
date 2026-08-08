import subprocess


def archive(name):
    return subprocess.run(["tar", "-cf", "backup.tar", name], shell=False).returncode
