"""Root-level launcher — run as: python pscan.py <target> [options]"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from backend.cli.main import main

main()
