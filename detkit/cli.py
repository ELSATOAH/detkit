"""detkit command line: test / validate / generate."""
import argparse
import glob
import os
import re
import sys

from .evaluator import event_matches_rule, scan_unsupported

REQUIRED_KEYS = ("title", "logsource", "detection")


def _load_yaml(path):
    try:
        import yaml
    except ImportError:
        sys.exit("detkit needs PyYAML: pip install pyyaml")
    with open(path) as f:
        return yaml.safe_load(f)


def _discover_rules(path):
    if os.path.isfile(path):
        return [path]
    found = []
    for pat in ("**/*.yml", "**/*.yaml"):
        found += glob.glob(os.path.join(path, pat), recursive=True)
    return sorted({f for f in found if not f.endswith((".test.yml", ".test.yaml"))})


def _test_file_for(rule_path):
    base = rule_path.rsplit(".", 1)[0]
    for ext in (".test.yml", ".test.yaml"):
        if os.path.exists(base + ext):
            return base + ext
    return None


def cmd_test(args):
    rules = _discover_rules(args.path)
    if not rules:
        print(f"no rules found under {args.path!r}")
        return 1
    passed = failed = untested = 0
    for rule_path in rules:
        rule = _load_yaml(rule_path)
        detection = (rule or {}).get("detection")
        if isinstance(detection, dict):
            for warn in scan_unsupported(detection):
                print(f"  ! {rule_path}  WARN: {warn} (result may be unreliable)")
        test_path = _test_file_for(rule_path)
        if not test_path:
            untested += 1
            print(f"  ? {rule_path}  (no .test.yml)")
            continue
        cases = (_load_yaml(test_path) or {}).get("tests", [])
        for case in cases:
            want = case.get("expect", "match") == "match"
            try:
                got = event_matches_rule(detection, case.get("event", {}))
            except Exception as exc:  # a rule error should fail the test, not crash the run
                failed += 1
                print(f"  x {rule_path} :: {case.get('name', '?')}  ERROR: {exc}")
                continue
            if got == want:
                passed += 1
                print(f"  . {rule_path} :: {case.get('name', '?')}")
            else:
                failed += 1
                verb = "fired" if got else "did not fire"
                print(f"  x {rule_path} :: {case.get('name', '?')}  (rule {verb}, expected {case['expect']})")
    print(f"\n{passed} passed, {failed} failed, {untested} rule(s) without tests")
    return 1 if failed else 0


def _validate_rule(rule):
    errors = []
    for key in REQUIRED_KEYS:
        if key not in rule:
            errors.append(f"missing top-level key '{key}'")
    detection = rule.get("detection", {})
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("detection block missing 'condition'")
        else:
            defined = {k for k in detection if k != "condition"}
            referenced = set(re.findall(r"[A-Za-z0-9_]+\*?", str(detection["condition"])))
            keywords = {"and", "or", "not", "of", "them", "all"}
            for ref in referenced - keywords:
                if ref.isdigit():
                    continue
                if ref.endswith("*"):
                    if not any(d.startswith(ref[:-1]) for d in defined):
                        errors.append(f"condition references '{ref}' but no identifier matches")
                elif ref not in defined:
                    errors.append(f"condition references undefined identifier '{ref}'")
    return errors


def cmd_validate(args):
    rules = _discover_rules(args.path)
    if not rules:
        print(f"no rules found under {args.path!r}")
        return 1
    total_errors = total_warnings = 0
    for rule_path in rules:
        rule = _load_yaml(rule_path) or {}
        errors = _validate_rule(rule)
        detection = rule.get("detection")
        warns = scan_unsupported(detection) if isinstance(detection, dict) else []
        total_errors += len(errors)
        total_warnings += len(warns)
        print(f"  {'x' if errors else '!' if warns else '.'} {rule_path}")
        for e in errors:
            print(f"      - error: {e}")
        for w in warns:
            print(f"      - warn:  {w}")
    print(f"\n{total_errors} error(s), {total_warnings} warning(s)")
    return 1 if total_errors else 0


def cmd_generate(args):
    print(
        "`detkit generate` is not implemented yet.\n"
        "Planned: draft a Sigma rule AND its test cases from a natural-language\n"
        "threat description via an LLM; you review and commit the code.\n"
        "Design rule: generation must always emit tests, so every AI-drafted\n"
        "detection ships with a runnable check. LLM client stays swappable."
    )
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="detkit", description="Test Sigma detection rules as code.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_test = sub.add_parser("test", help="run rule tests against sample events")
    p_test.add_argument("path", nargs="?", default=".")
    p_test.set_defaults(func=cmd_test)

    p_val = sub.add_parser("validate", help="structurally validate rules")
    p_val.add_argument("path", nargs="?", default=".")
    p_val.set_defaults(func=cmd_validate)

    p_gen = sub.add_parser("generate", help="(planned) AI-draft a rule + tests")
    p_gen.set_defaults(func=cmd_generate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
