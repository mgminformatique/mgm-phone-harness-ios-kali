"""Shared validation for the local iPhone transport."""
import math


class Blocked(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def number(value, lo, hi):
    return type(value) in (int, float) and lo <= value <= hi and math.isfinite(value)
