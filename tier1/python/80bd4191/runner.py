import subprocess


def archive(name):
    line = "tar -cf backup.tar " + name
    return subprocess.run(line, shell=True, capture_output=True).stdout
