#!/usr/bin/env python3
"""Convenience launcher so you can run ./scryer.py <target> without -m."""

import sys

from scryer.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
