import sys

from handler import handle


def main():
    print(handle(sys.argv[1] if len(sys.argv) > 1 else ""))
