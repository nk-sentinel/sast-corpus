import subprocess


def archive(name):
    cleaned = name.replace(";", "")
    return subprocess.run("tar -cf backup.tar " + cleaned, shell=True).returncode
