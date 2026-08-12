import re
import subprocess


def handle(name):
    if not re.fullmatch(r"[a-z-]{1,20}", name):
        return ""
    subprocess.run(["/usr/bin/report", name], check=False)
    return name
