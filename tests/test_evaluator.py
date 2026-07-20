"""Runnable check for the Sigma evaluator core.

No framework needed: `python tests/test_evaluator.py` runs every assert and
prints OK, or raises on the first failure. pytest also discovers it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detkit.evaluator import event_matches_rule, scan_unsupported  # noqa: E402


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


def test_value_wildcard():
    # regression for dogfood bug #1: `v*.compute.firewalls.delete` was matched literally
    det = {"sel": {"MethodName": "v*.compute.firewalls.delete"}, "condition": "sel"}
    assert event_matches_rule(det, {"MethodName": "v1.compute.firewalls.delete"})
    assert not event_matches_rule(det, {"MethodName": "v1.compute.networks.delete"})
    det_q = {"sel": {"Code": "AC?E"}, "condition": "sel"}
    assert event_matches_rule(det_q, {"Code": "ACME"})
    assert not event_matches_rule(det_q, {"Code": "ACabE"})


def test_cidr_modifier():
    # regression for dogfood bug #3: |cidr degraded to string equality, so filters never fired
    det = {"filter": {"IpAddress|cidr": "10.0.0.0/8"}, "condition": "filter"}
    assert event_matches_rule(det, {"IpAddress": "10.20.30.40"})
    assert not event_matches_rule(det, {"IpAddress": "8.8.8.8"})
    assert not event_matches_rule(det, {"IpAddress": "not-an-ip"})


def test_scan_flags_unsupported():
    det = {"sel": {"CommandLine|base64offset|contains": "abc"}, "condition": "sel"}
    findings = scan_unsupported(det)
    assert any("base64offset" in f for f in findings)
    # nested/dotted fields are supported now, so they must NOT be flagged
    assert scan_unsupported({"sel": {"id.orig_h": "1.2.3.4"}, "condition": "sel"}) == []
    assert scan_unsupported({"sel": {"EventID": 1}, "condition": "sel"}) == []


def test_nested_field_access():
    det = {"sel": {"DeviceDetail.deviceId": "abc123"}, "condition": "sel"}
    assert event_matches_rule(det, {"DeviceDetail": {"deviceId": "abc123"}})   # nested dict
    assert event_matches_rule(det, {"DeviceDetail.deviceId": "abc123"})        # flattened key
    assert not event_matches_rule(det, {"DeviceDetail": {"deviceId": "other"}})
    assert not event_matches_rule(det, {"DeviceDetail": {}})
    assert not event_matches_rule(det, {"EventID": 1})


def test_nested_field_with_modifier():
    det = {"sel": {"gcp.audit.method_name|endswith": ".delete"}, "condition": "sel"}
    assert event_matches_rule(det, {"gcp": {"audit": {"method_name": "v1.compute.firewalls.delete"}}})
    assert not event_matches_rule(det, {"gcp": {"audit": {"method_name": "v1.compute.firewalls.list"}}})


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} checks passed")
