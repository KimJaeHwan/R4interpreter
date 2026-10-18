"""Separate CPython program for cached-integer summary validation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys


def inner_add(value):
    return value + 5


def wrapped_add(value):
    return inner_add(value)


def main():
    value = int(sys.argv[1])
    marker = Path(sys.argv[2])
    if sys.argv[2] != "-":
        marker.write_text(json.dumps({"phase": "ready"}))
        os.kill(os.getpid(), 19)
    print(json.dumps({"result": wrapped_add(value)}))


if __name__ == "__main__":
    main()
