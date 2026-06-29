"""Thin shim for legacy editable installs (`pip install -e .`).

pyproject.toml is the authoritative package definition.
This file exists only for tooling that does not yet read pyproject.toml.
"""
from setuptools import setup

setup()
