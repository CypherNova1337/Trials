#!/usr/bin/env python3
"""Convenience launcher so you can run ./voidrecon.py <target> without -m."""

import sys

from voidrecon.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
