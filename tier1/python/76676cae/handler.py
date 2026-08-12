import re
import subprocess


def permitted(name):
    return bool(re.fullmatch(r"[a-z-]{1,20}", name))


def handle(name):
    if not permitted(name):
        return ""
    subprocess.run(["/usr/bin/report", name], check=False)
    return name
