# detkit

[![CI](https://github.com/ELSATOAH/detkit/actions/workflows/ci.yml/badge.svg)](https://github.com/ELSATOAH/detkit/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/detkit-cli)](https://pypi.org/project/detkit-cli/) [![Python](https://img.shields.io/pypi/pyversions/detkit-cli)](https://pypi.org/project/detkit-cli/) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/ELSATOAH/detkit/blob/main/LICENSE)

Unit tests for your Sigma detection rules. Write a rule, add a couple of example log events, and detkit tells you whether it fires on the ones that should trip it and stays quiet on the ones that shouldn't. Wire it into CI and a broken detection fails the pull request instead of failing silently in production.

Think `dbt test`, but for detections.

![detkit catching a broken detection before it ships](https://raw.githubusercontent.com/ELSATOAH/detkit/main/detkit-demo.gif)

## Install

```bash
pipx install detkit-cli    # installs the `detkit` command
# or the latest from source:
pipx install git+https://github.com/ELSATOAH/detkit.git
```

Then:

```bash
detkit init          # drops a starter rule, its test, and a CI workflow
detkit test rules    # green on the first run
```

## How it works

Your rule is plain [Sigma](https://sigmahq.io/). Next to it you keep a `<rule>.test.yml` listing sample events and what you expect:

```yaml
# whoami_execution.test.yml
tests:
  - name: fires on whoami
    event: { EventID: 4688, CommandLine: "cmd /c whoami /all", User: "alice" }
    expect: match
  - name: not for SYSTEM
    event: { EventID: 4688, CommandLine: "whoami", User: "SYSTEM" }
    expect: no_match
```

`detkit test` runs every rule against its events and exits non-zero if any expectation is wrong. That's the whole idea:

```console
$ detkit test rules
  . process_exec.yml :: fires on the encoded command
  x process_exec.yml :: ignores the admin allowlist  (rule fired, expected no_match)

  1 passed, 1 failed, 0 rule(s) without tests
```

`detkit validate` does a quicker structural check: the required fields are there, and the condition only references identifiers that actually exist.

## In CI

Drop this in your rules repo and any PR that breaks a detection gets blocked before it merges:

```yaml
# .github/workflows/detections.yml
name: Detections
on: [pull_request]
jobs:
  detkit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ELSATOAH/detkit@v0
        with:
          path: rules
```

## pre-commit

Prefer to catch it before the commit lands? Add detkit to your [pre-commit](https://pre-commit.com) config:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/ELSATOAH/detkit
    rev: v0.1.3
    hooks:
      - id: detkit-test
        args: [rules]   # path to your rules
```

There's a `detkit-validate` hook too, for the lighter structural check.

## Coverage

Past a handful of rules you want to see what you're *not* covering. `detkit docs` builds a single self-contained HTML page: a catalog of every rule plus a MITRE ATT&CK heatmap of which techniques you detect, which you test, and which are gaps.

```bash
detkit docs rules -o coverage.html
```

Green is a technique with a tested rule, amber is a rule with no test, and the faint cells are the gaps. It's one file with no external assets, so you can commit it or publish it to GitHub Pages.

`detkit navigator` exports the same coverage as a [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer, so it drops straight into the tool your team already uses:

```bash
detkit navigator rules -o coverage.json
# then Open Existing Layer -> Upload at the Navigator
```

## What it handles

detkit runs your rules locally. No SIEM, no credentials, nothing leaves your machine or CI runner. I ran it against every rule in the SigmaHQ repo, and about 91% use only features it understands today: `contains`, `startswith`, `endswith`, `re`, value wildcards (`*` and `?`), `|cidr`, nested/dotted fields (`DeviceDetail.deviceId`), keyword lists, and `X of` / `all of` conditions.

It won't guess at the rest. If a rule uses something detkit can't evaluate yet, like `base64`/`windash` modifiers or arrays of objects, `test` and `validate` print a WARN naming the feature instead of returning an answer that might be wrong. A detection tool that's quietly wrong is worse than no tool.

## Why

Detections live in Git now, but the testing habit that comes with the rest of software never followed them there. dbt sorted this out for data models years ago; Sigma rules deserve the same. And it runs locally on purpose, because security logs aren't something you can hand to someone else's cloud just to check a rule.

## Roadmap

- `base64`/`windash` modifiers and arrays of objects (what it warns on today), probably via [pySigma](https://github.com/SigmaHQ/pySigma).
- `detkit generate`: draft a rule and its tests from a plain-English description. The tests come with it, not as an afterthought.
- Field mapping, so one rule can be checked against more than one log schema.
- A hosted option down the line for teams that want shared runs and history. The CLI stays free.

## Status

Early, but the core works and has tests (`python3 tests/test_evaluator.py`). Rough edges are marked with `# ponytail:` comments in the source. Issues and PRs welcome.

MIT.
