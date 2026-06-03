"""Tests for module registry and BaseForensicModule."""

from pathlib import Path

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


def test_load_modules_with_path_inserts_sys_path(tmp_path):
    marker = tmp_path / "pkg_marker"
    marker.mkdir()
    config = {
        "modules": [
            {
                "class": "backbone.dev.stub_module.StubModule",
                "path": str(marker),
            }
        ]
    }
    load_modules(config, config_dir=tmp_path)
    assert str(marker.resolve()) in __import__("sys").path


_DISK_MODULE_ROOT = (
    Path(__file__).resolve().parents[2] / "Modules" / "Disk" / "disk-agentic-architecture"
)


@pytest.mark.skipif(
    not (_DISK_MODULE_ROOT / "disk_module.py").is_file(),
    reason="disk module not present in workspace",
)
def test_load_disk_module_via_registry_path():
    repo_root = Path(__file__).resolve().parents[2]
    config = {
        "modules": [
            {
                "class": "disk_module.DiskModule",
                "path": str(_DISK_MODULE_ROOT),
                "kwargs": {"use_llm": False},
            }
        ]
    }
    registry = load_modules(config, config_dir=repo_root)
    assert registry["disk"].module_id == "disk"
