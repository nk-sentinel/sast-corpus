import re
import subprocess


def handle(name):
    if not re.match(r"[a-z-]+", name):
        return ""
    subprocess.run("/usr/bin/report " + name, shell=True, check=False)
    return name
