"""Evaluate a Sigma rule's detection block against a single log event.

This is the core of detkit: unit-testing detection rules locally, the way
dbt tests data models. It implements the common Sigma subset.

# ponytail: common-subset evaluator (modifiers contains/startswith/endswith/re/cased/all,
# list-OR, `N of them | N of prefix*`, and/or/not/parens). Ceilings: no nested-field (dot)
# access, no |base64/|cidr modifiers, no count()/timeframe aggregation, matching is
# case-insensitive by default (real SIEM backends differ). Upgrade path: delegate to
# pySigma pipelines or a per-backend evaluator when a rule needs the full spec.
"""
import re

__all__ = ["event_matches_rule"]


def event_matches_rule(detection: dict, event: dict) -> bool:
    """Return True if `event` triggers the Sigma `detection` block."""
    if "condition" not in detection:
        raise ValueError("detection block missing 'condition'")
    condition = detection["condition"]
    identifiers = {k: v for k, v in detection.items() if k != "condition"}
    matches = {name: _matches_identifier(spec, event) for name, spec in identifiers.items()}
    conditions = condition if isinstance(condition, list) else [condition]
    return any(_eval_condition(str(c), matches) for c in conditions)


def _matches_identifier(spec, event) -> bool:
    if isinstance(spec, list):
        # list of maps => OR of maps; list of scalars => keyword search (any)
        return any(
            _matches_map(item, event) if isinstance(item, dict) else _keyword_match(item, event)
            for item in spec
        )
    if isinstance(spec, dict):
        return _matches_map(spec, event)
    return _keyword_match(spec, event)


def _matches_map(spec: dict, event: dict) -> bool:
    return all(_matches_field(key, expected, event) for key, expected in spec.items())


def _matches_field(key: str, expected, event: dict) -> bool:
    parts = key.split("|")
    field, mods = parts[0], [m.lower() for m in parts[1:]]
    if field not in event:
        return False
    ev = event[field]
    if isinstance(expected, list):
        results = [_match_scalar(ev, x, mods) for x in expected]
        return all(results) if "all" in mods else any(results)
    return _match_scalar(ev, expected, mods)


def _match_scalar(ev, expected, mods) -> bool:
    cased = "cased" in mods
    if "re" in mods:
        return re.search(str(expected), str(ev), 0 if cased else re.IGNORECASE) is not None
    if expected is None:
        return ev is None
    if isinstance(expected, bool):
        return ev == expected
    string_mod = any(m in mods for m in ("contains", "startswith", "endswith"))
    if isinstance(expected, (int, float)) and not string_mod:
        try:
            return float(ev) == float(expected)
        except (TypeError, ValueError):
            return str(ev) == str(expected)
    a, b = str(ev), str(expected)
    if not cased:
        a, b = a.lower(), b.lower()
    if "contains" in mods:
        return b in a
    if "startswith" in mods:
        return a.startswith(b)
    if "endswith" in mods:
        return a.endswith(b)
    return a == b


def _keyword_match(keyword, event: dict) -> bool:
    needle = str(keyword).lower()
    return any(needle in str(v).lower() for v in event.values())


def _eval_condition(condition: str, matches: dict) -> bool:
    def _select(target):
        if target == "them":
            return list(matches)
        if target.endswith("*"):
            return [n for n in matches if n.startswith(target[:-1])]
        return [target]

    def _repl_quant(m):
        quant, target = m.group(1), m.group(2)
        vals = [bool(matches.get(n, False)) for n in _select(target)]
        if quant == "all":
            return "true" if vals and all(vals) else "false"
        return "true" if sum(vals) >= int(quant) else "false"

    expr = re.sub(r"\b(\d+|all)\s+of\s+([A-Za-z0-9_*]+)", _repl_quant, condition)
    tokens = []
    for tok in re.findall(r"\(|\)|[A-Za-z0-9_*]+", expr):
        low = tok.lower()
        if low in ("and", "or", "not", "true", "false"):
            tokens.append(low)
        elif tok in ("(", ")"):
            tokens.append(tok)
        else:
            tokens.append("true" if matches.get(tok, False) else "false")
    return _parse_bool(tokens)


def _parse_bool(tokens) -> bool:
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def eat():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_or():
        v = parse_and()
        while peek() == "or":
            eat()
            v = parse_and() or v
        return v

    def parse_and():
        v = parse_not()
        while peek() == "and":
            eat()
            v = parse_not() and v
        return v

    def parse_not():
        if peek() == "not":
            eat()
            return not parse_not()
        return parse_atom()

    def parse_atom():
        tok = eat() if peek() is not None else None
        if tok == "(":
            v = parse_or()
            if peek() == ")":
                eat()
            return v
        if tok == "true":
            return True
        if tok == "false":
            return False
        raise ValueError(f"cannot parse condition near {tok!r}")

    if not tokens:
        raise ValueError("empty condition")
    return parse_or()
