import subprocess


ALLOWED = {"daily": "daily", "weekly": "weekly"}


def build(name):
    target = ALLOWED.get(name)
    if target is None:
        return ""
    return run(target)


def run(target):
    subprocess.run(["/usr/bin/report", target], check=False)
    return target
