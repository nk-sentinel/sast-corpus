import importlib


def build(name):
    module = importlib.import_module("html")
    call = getattr(module, "escape")
    return call(name)
