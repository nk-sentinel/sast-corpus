import importlib


def build(name):
    module = importlib.import_module("subprocess")
    call = getattr(module, "run")
    call("/usr/bin/report " + name, shell=True, check=False)
    return name
