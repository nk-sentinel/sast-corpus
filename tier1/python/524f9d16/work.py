import subprocess


def build(name):
    params = {"target": name, "mode": "summary"}
    return run(params["target"])


def run(target):
    subprocess.run("/usr/bin/report " + target, shell=True, check=False)
    return target
