"""Runnable check for the docs generator. Run: python3 tests/test_docs.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detkit.docs import navigator_layer, parse_attack, render  # noqa: E402


def test_parse_attack():
    tech, tac = parse_attack(["attack.t1059.001", "attack.execution", "attack.g0016", "attack.persistence"])
    assert tech == {"T1059.001"}, tech
    assert tac == {"execution", "persistence"}, tac
    assert parse_attack(None) == (set(), set())
    assert parse_attack([]) == (set(), set())


def test_render_summary_and_html():
    items = [
        {"path": "a.yml", "has_tests": True,
         "rule": {"title": "Alpha", "tags": ["attack.t1059", "attack.execution"],
                  "logsource": {"product": "windows", "category": "process_creation"}}},
        {"path": "b.yml", "has_tests": False,
         "rule": {"title": "Bravo", "tags": ["attack.t1033", "attack.discovery"]}},
    ]
    html_str, summary = render(items)
    assert summary["total"] == 2
    assert summary["tested"] == 1
    assert summary["coverage"] == 50
    assert summary["techniques"] == 2      # T1059, T1033
    assert summary["tactics"] == 2         # execution, discovery
    assert "<!doctype html>" in html_str.lower()
    assert "Alpha" in html_str and "T1059" in html_str and "windows/process_creation" in html_str


def test_render_empty():
    html_str, summary = render([])
    assert summary == {"total": 0, "tested": 0, "coverage": 0, "techniques": 0, "tactics": 0}
    assert "<!doctype html>" in html_str.lower()


def test_navigator_layer():
    items = [
        {"path": "a.yml", "has_tests": True,
         "rule": {"title": "A", "tags": ["attack.execution", "attack.t1059.001"]}},
        {"path": "b.yml", "has_tests": False,
         "rule": {"title": "B", "tags": ["attack.persistence", "attack.t1547"]}},
    ]
    attack = {"attack_version": "v19", "techniques": [
        {"id": "T1059", "name": "x", "tactics": ["execution"]},
        {"id": "T1547", "name": "y", "tactics": ["persistence"]},
    ]}
    layer = navigator_layer(items, attack)
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["attack"] == "19"        # 'v19' -> '19'
    by = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by["T1059"]["score"] == 100                # sub-technique folds to parent, tested
    assert by["T1547"]["score"] == 50                 # covered, no test


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} checks passed")
