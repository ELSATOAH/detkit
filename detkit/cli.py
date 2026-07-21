"""detkit command line: test / validate / generate."""
import argparse
import glob
import json
import os
import re
import sys

from . import __version__, docs
from .evaluator import event_matches_rule, scan_unsupported

# Color only when writing to a terminal, and honor the NO_COLOR convention,
# so piped and CI output stays plain.
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_GREEN, _RED, _YELLOW, _DIM = "32", "31", "33", "2"


def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if _COLOR else text

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
    as_json = bool(getattr(args, "as_json", False))
    rules = _discover_rules(args.path)
    if not rules:
        if as_json:
            print(json.dumps({"rules": [], "passed": 0, "failed": 0, "untested": 0, "coverage_pct": 0, "results": []}))
        else:
            print(f"no rules found under {args.path!r}")
        return 1
    passed = failed = untested = 0
    results = []
    for rule_path in rules:
        rule = _load_yaml(rule_path)
        detection = (rule or {}).get("detection")
        if isinstance(detection, dict):
            for warn in scan_unsupported(detection):
                if not as_json:
                    print(f"  {_c('!', _YELLOW)} {rule_path}  WARN: {warn} (result may be unreliable)")
                results.append({"path": rule_path, "name": None, "status": "warn", "detail": warn})
        test_path = _test_file_for(rule_path)
        if not test_path:
            untested += 1
            if not as_json:
                print(f"  {_c('?', _DIM)} {rule_path}  (no .test.yml)")
            results.append({"path": rule_path, "name": None, "status": "untested", "detail": "no .test.yml"})
            continue
        cases = (_load_yaml(test_path) or {}).get("tests", [])
        for case in cases:
            name = case.get("name", "?")
            want = case.get("expect", "match") == "match"
            try:
                got = event_matches_rule(detection, case.get("event", {}))
            except Exception as exc:  # a rule error should fail the test, not crash the run
                failed += 1
                if not as_json:
                    print(f"  {_c('x', _RED)} {rule_path} :: {name}  ERROR: {exc}")
                results.append({"path": rule_path, "name": name, "status": "error", "detail": str(exc)})
                continue
            if got == want:
                passed += 1
                if not as_json:
                    print(f"  {_c('.', _GREEN)} {rule_path} :: {name}")
                results.append({"path": rule_path, "name": name, "status": "pass", "detail": None})
            else:
                failed += 1
                verb = "fired" if got else "did not fire"
                detail = f"rule {verb}, expected {case.get('expect')}"
                if not as_json:
                    print(f"  {_c('x', _RED)} {rule_path} :: {name}  ({detail})")
                results.append({"path": rule_path, "name": name, "status": "fail", "detail": detail})
    tested = len(rules) - untested
    pct = round(100 * tested / len(rules)) if rules else 0
    if as_json:
        print(json.dumps({
            "passed": passed,
            "failed": failed,
            "untested": untested,
            "rules": len(rules),
            "tested": tested,
            "coverage_pct": pct,
            "results": results,
        }))
    else:
        failed_str = _c(f"{failed} failed", _RED) if failed else f"{failed} failed"
        print(f"\n{_c(f'{passed} passed', _GREEN)}, {failed_str}")
        print(f"{tested} of {len(rules)} rules have tests ({pct}% coverage)")
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
        marker = _c("x", _RED) if errors else _c("!", _YELLOW) if warns else _c(".", _GREEN)
        print(f"  {marker} {rule_path}")
        for e in errors:
            print(f"      - error: {e}")
        for w in warns:
            print(f"      - warn:  {w}")
    print(f"\n{total_errors} error(s), {total_warnings} warning(s)")
    return 1 if total_errors else 0


_INIT_RULE = """\
title: Whoami Execution
id: 3a2b1c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Example rule from `detkit init` — detects whoami, a common recon command. Replace with your own.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'whoami'
  condition: selection
level: low
"""

_INIT_TEST = """\
# Sample events proving the rule fires (and stays quiet). This is the point of detkit.
tests:
  - name: fires on whoami
    event: { CommandLine: "cmd /c whoami /all" }
    expect: match
  - name: ignores an unrelated command
    event: { CommandLine: "ipconfig /all" }
    expect: no_match
"""

_INIT_WORKFLOW = """\
name: Detections
on: [pull_request, push]

jobs:
  detkit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.x'
      - run: pip install detkit
      - run: detkit test rules
"""


def cmd_init(args):
    files = {
        os.path.join("rules", "example_rule.yml"): _INIT_RULE,
        os.path.join("rules", "example_rule.test.yml"): _INIT_TEST,
        os.path.join(".github", "workflows", "detections.yml"): _INIT_WORKFLOW,
    }
    created = skipped = 0
    for rel, content in files.items():
        dest = os.path.join(args.path, rel)
        if os.path.exists(dest):
            skipped += 1
            print(f"  skipped (exists): {dest}")
            continue
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(dest, "w") as f:
            f.write(content)
        created += 1
        print(f"  created: {dest}")
    print(f"\n{created} file(s) created, {skipped} skipped.")
    if created:
        print("Next: run `detkit test rules` — you should see it pass.")
    return 0


def _load_attack_data():
    """Load the bundled ATT&CK matrix if present; None falls back to covered-only view."""
    try:
        from importlib.resources import files
        p = files("detkit").joinpath("attack_enterprise.json")
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def cmd_docs(args):
    rules = _discover_rules(args.path)
    if not rules:
        print(f"no rules found under {args.path!r}")
        return 1
    items = [
        {"path": rp, "rule": _load_yaml(rp) or {}, "has_tests": _test_file_for(rp) is not None}
        for rp in rules
    ]
    html_str, summary = docs.render(items, _load_attack_data())
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html_str)
    if "matrix_total" in summary:
        line = (
            f"{summary['total']} rules, {summary['tested']} tested ({summary['coverage']}%), "
            f"ATT&CK coverage {summary['matrix_covered']}/{summary['matrix_total']} techniques "
            f"across {summary['tactics']}/14 tactics"
        )
    else:
        line = (
            f"{summary['total']} rules, {summary['tested']} tested ({summary['coverage']}% coverage), "
            f"{summary['techniques']} ATT&CK techniques across {summary['tactics']}/14 tactics"
        )
    print(line)
    print(f"wrote {args.output}")
    return 0


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
    parser.add_argument("--version", action="version", version=f"detkit {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_test = sub.add_parser("test", help="run rule tests against sample events")
    p_test.add_argument("path", nargs="?", default=".")
    p_test.add_argument("--json", dest="as_json", action="store_true",
                        help="emit machine-readable JSON results")
    p_test.set_defaults(func=cmd_test)

    p_val = sub.add_parser("validate", help="structurally validate rules")
    p_val.add_argument("path", nargs="?", default=".")
    p_val.set_defaults(func=cmd_validate)

    p_init = sub.add_parser("init", help="scaffold a starter rule + test + CI workflow")
    p_init.add_argument("path", nargs="?", default=".")
    p_init.set_defaults(func=cmd_init)

    p_docs = sub.add_parser("docs", help="generate an HTML catalog + ATT&CK coverage map")
    p_docs.add_argument("path", nargs="?", default=".")
    p_docs.add_argument("-o", "--output", default="detkit-docs.html")
    p_docs.set_defaults(func=cmd_docs)

    p_gen = sub.add_parser("generate", help="(planned) AI-draft a rule + tests")
    p_gen.set_defaults(func=cmd_generate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
