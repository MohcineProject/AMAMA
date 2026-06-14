"""Unit tests for the deterministic entity-type normaliser (summary #11).

Covers the four mislabels observed in the e2e run plus happy-path shapes and the
no-op case (declared already correct). No LLM / network — pure function tests.
"""

from __future__ import annotations

import pytest

from backbone.contracts.normalize import ENTITY_TYPES, normalize_entity, normalize_entity_type


@pytest.mark.parametrize(
    "value,declared,expected",
    [
        # --- the four mislabels from the e2e run ---
        ("SDELETE.EXE", "domain", "image_name"),
        ("VSSADMIN.EXE", "domain", "image_name"),
        ("193.93.62.0/24 (subnet)", "file_path", "ip"),
        ("SRL-FORGE\\fredr", "file_path", "user_sid"),
        # --- UPN / account ---
        ("fred.rocba@outlook.com", None, "user_sid"),
        ("S-1-5-21-1-2-3-500", "user_sid", "user_sid"),
        # --- network IOCs ---
        ("52.249.198.56", "ip", "ip"),
        ("evil.com", None, "domain"),
        ("sub.evil.co.uk", None, "domain"),
        ("https://bad.tld/payload", "url", "url"),
        # --- hashes ---
        ("d41d8cd98f00b204e9800998ecf8427e", None, "hash_md5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", None, "hash_sha1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", None, "hash_sha256"),
        # --- paths / registry / images ---
        ("C:\\Temp\\loader.exe", None, "file_path"),
        ("/usr/bin/wget", None, "file_path"),
        ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", None, "registry_key"),
        ("explorer.exe", "image_name", "image_name"),
    ],
)
def test_normalize_entity_type(value, declared, expected):
    assert normalize_entity_type(value, declared) == expected


def test_pid_preserved():
    """Numeric pid values can't be shape-detected — the declared type must survive."""
    assert normalize_entity_type("4812", "pid") == "pid"


def test_mutex_not_clobbered_by_object_namespace():
    """A Global\\Foo mutex must not be coerced to user_sid (DOMAIN\\user shape)."""
    assert normalize_entity_type("Global\\RAT_42", "mutex") == "mutex"


def test_unknown_shape_keeps_declared():
    assert normalize_entity_type("some_opaque_token", "mutex") == "mutex"


def test_unknown_shape_no_declared_falls_back_to_image_name():
    assert normalize_entity_type("some_opaque_token", None) == "image_name"


def test_no_op_when_declared_matches_shape():
    """When the declared type already matches the value's shape, it is returned unchanged."""
    for t in ("ip", "domain", "url", "registry_key"):
        sample = {
            "ip": "10.0.0.1",
            "domain": "evil.com",
            "url": "http://x.tld/",
            "registry_key": "HKCU\\Software\\Run",
        }[t]
        assert normalize_entity_type(sample, t) == t


def test_normalize_entity_mutates_in_place():
    ent = {"type": "domain", "value": "MIMIKATZ.EXE", "relationship": "process_image"}
    out = normalize_entity(ent)
    assert out is ent
    assert ent["type"] == "image_name"
    assert ent["value"] == "MIMIKATZ.EXE"  # value untouched


def test_inferred_types_are_in_enum():
    for v in ("1.2.3.4", "evil.com", "x.exe", "C:\\a\\b.dll", "HKLM\\x"):
        assert normalize_entity_type(v) in ENTITY_TYPES
