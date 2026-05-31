"""
pytest configuration for RAM module tests.

Adds scripts/ to sys.path so test files can import internal modules directly.
"""
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR / "scripts"))
