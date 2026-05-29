"""Tests for module registry and BaseForensicModule."""

import pytest

from backbone.registry import import_module_class, load_modules
from backbone.dev.stub_module import StubModule


def test_stub_module_inherits_base():
    mod = StubModule()
    assert mod.module_id == "stub"
    assert mod.supports_entity_type("file_path")
    assert not mod.supports_entity_type("pid")


@pytest.mark.asyncio
async def test_stub_module_scan_validates():
    mod = StubModule()
    result = await mod.scan("case-test")
    assert result["module"] == "stub"
    assert result["case_id"] == "case-test"


def test_load_modules_from_config():
    config = {"modules": [{"class": "backbone.dev.stub_module.StubModule"}]}
    registry = load_modules(config)
    assert "stub" in registry
    assert isinstance(registry["stub"], StubModule)


def test_import_module_class_rejects_non_subclass():
    with pytest.raises(TypeError):
        import_module_class("backbone.case_graph.CaseGraph")
