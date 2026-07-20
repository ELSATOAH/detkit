# Contributing to detkit

Thanks for helping out. detkit is small on purpose, so getting started is quick.

## Setup

```bash
git clone https://github.com/ELSATOAH/detkit
cd detkit
pip install -e .                    # a venv or pipx works too
python3 tests/test_evaluator.py     # the whole test suite, no framework needed
detkit test examples/rules          # should print all green
```

## Where things live

- `detkit/evaluator.py` — the core: evaluate a Sigma `detection`/`condition` against one event. Most changes go here.
- `detkit/cli.py` — the `test` / `validate` / `init` commands.
- `tests/test_evaluator.py` — plain `assert`s; run it directly or with pytest.
- `examples/rules/` — a rule and its `*.test.yml`, which doubles as a spec for the format.

## The one rule

Never return a confident wrong answer. What the evaluator can't handle yet is listed by `scan_unsupported()` and printed as a `WARN` at runtime instead of guessing. If you add a feature, either handle it properly or leave the warning in place.

## Adding support for a Sigma feature

1. Add the logic in `evaluator.py` — `_match_scalar` for modifiers, `_resolve_field` for field access, `_eval_condition` for conditions.
2. If it was in `scan_unsupported()`'s warn list, drop it from there.
3. Add a test: one event that should match, one that shouldn't.

Known ceilings are marked with `# ponytail:` comments in `evaluator.py`.

## Good places to start

- `|base64` / `|base64offset` modifier support (currently warns).
- Nested fields that descend into arrays of objects (right now it only walks dicts).
- A `--json` output mode for `detkit test`, for pipelines that want structured results.

## Releases

Maintainers only, and it's one step: `gh release create vX.Y.Z --generate-notes`. The tag sets the version (setuptools-scm) and GitHub Actions builds and publishes to PyPI.

MIT licensed. By contributing, you agree your work ships under it.
