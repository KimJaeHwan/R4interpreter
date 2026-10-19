"""Independent CPython oracle for the two bounded integration workloads."""
import sys


def add_five(value):
    return value + 5


def branch_call(value):
    return add_five(5) if value == 0 else add_five(value)


def append_five(value):
    return value + "5"


if __name__ == "__main__":
    mode, value = sys.argv[1:3]
    print(branch_call(int(value)) if mode == "branch" else append_five(value))
