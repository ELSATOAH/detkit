"""Runnable check for the Sigma evaluator core.

No framework needed: `python tests/test_evaluator.py` runs every assert and
prints OK, or raises on the first failure. pytest also discovers it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detkit.evaluator import event_matches_rule  # noqa: E402


def test_equals_contains_and_not():
    det = {
        "selection": {"EventID": 4688, "CommandLine|contains": "whoami"},
        "filter": {"User": "SYSTEM"},
        "condition": "selection and not filter",
    }
    assert event_matches_rule(det, {"EventID": 4688, "CommandLine": "cmd /c whoami", "User": "alice"})
    assert not event_matches_rule(det, {"EventID": 4688, "CommandLine": "whoami", "User": "SYSTEM"})
    assert not event_matches_rule(det, {"EventID": 4688, "CommandLine": "ipconfig", "User": "alice"})


def test_numeric_string_coercion():
    det = {"sel": {"EventID": 4688}, "condition": "sel"}
    assert event_matches_rule(det, {"EventID": "4688"})  # log field arrives as string
    assert not event_matches_rule(det, {"EventID": 4689})


def test_list_value_is_or():
    det = {"sel": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe"]}, "condition": "sel"}
    assert event_matches_rule(det, {"Image": "C:\\Windows\\System32\\cmd.exe"})
    assert not event_matches_rule(det, {"Image": "C:\\Windows\\explorer.exe"})


def test_all_modifier_is_and():
    det = {"sel": {"CommandLine|contains|all": ["-enc", "bypass"]}, "condition": "sel"}
    assert event_matches_rule(det, {"CommandLine": "powershell -enc AAAA -ExecutionPolicy bypass"})
    assert not event_matches_rule(det, {"CommandLine": "powershell -enc AAAA"})


def test_missing_field_no_match():
    det = {"sel": {"CommandLine|contains": "whoami"}, "condition": "sel"}
    assert not event_matches_rule(det, {"EventID": 4688})


def test_one_of_them_and_all_of_prefix():
    det = {
        "selection_a": {"EventID": 1},
        "selection_b": {"EventID": 2},
        "condition": "1 of them",
    }
    assert event_matches_rule(det, {"EventID": 2})
    det2 = {
        "selection_a": {"EventID": 1},
        "selection_b": {"UserName": "root"},
        "condition": "all of selection*",
    }
    assert event_matches_rule(det2, {"EventID": 1, "UserName": "root"})
    assert not event_matches_rule(det2, {"EventID": 1})


def test_keyword_list_search():
    det = {"keywords": ["mimikatz", "sekurlsa"], "condition": "keywords"}
    assert event_matches_rule(det, {"CommandLine": "run sekurlsa::logonpasswords"})
    assert not event_matches_rule(det, {"CommandLine": "dir /s"})


def test_regex_modifier():
    det = {"sel": {"CommandLine|re": r"whoami(\.exe)?\s"}, "condition": "sel"}
    assert event_matches_rule(det, {"CommandLine": "whoami.exe /all"})
    assert not event_matches_rule(det, {"CommandLine": "whoamidaemon"})


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} checks passed")
