"""Invoke canonical Compose/OAuth checks from the development Makefile."""

from __future__ import annotations

import runpy
from pathlib import Path

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).resolve().parents[1] / "remote/scripts/verify_container.py"), run_name="__main__")
