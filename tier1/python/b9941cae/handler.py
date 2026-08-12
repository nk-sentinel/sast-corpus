import re
import subprocess


def permitted(name):
    return bool(re.fullmatch(r"[a-z-]{1,20}", name))


def handle(name):
    permitted(name)
    subprocess.run("/usr/bin/report " + name, shell=True, check=False)
    return name
