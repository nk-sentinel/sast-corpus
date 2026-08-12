import sys

from work import build


def main():
    print(build(sys.argv[1] if len(sys.argv) > 1 else ""))
