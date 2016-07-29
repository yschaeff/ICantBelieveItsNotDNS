#!/usr/bin/env python3

import sys

for line in sys.stdin.readlines():
    ## remove # and beyond
    ## don't cleanup empty lines!
    print(line.split("#")[0].rstrip())
