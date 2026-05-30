"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import os

import pytest

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "llm: mark test as requiring a live Anthropic API key (skipped when ANTHROPIC_API_KEY is unset)",
    )


def pytest_runtest_setup(item):
    if item.get_closest_marker("llm") and not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set — skipping LLM test")
