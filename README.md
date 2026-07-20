# detkit — dbt for detections

Test, validate, and CI-gate your Sigma detection rules **as code**, before they
ever reach production.

Detection engineers write rules in [Sigma](https://sigmahq.io/), commit them to
Git, and ship them to a SIEM — but there's no standard way to *unit-test* a rule
locally: does it actually fire on the attack it targets, and stay quiet on benign
traffic? Today that's checked by hand, or in prod. detkit closes that loop.

```
detkit test ./rules        # run every rule against its sample events
detkit validate ./rules    # structural + condition-reference checks
```

detkit is **open source (MIT)**, **self-hostable**, and **vendor-neutral** — it
sits *alongside* your SIEM (Wazuh, Elastic, Splunk, Sentinel), not in front of
it. Your logs and rules never leave your machine or CI runner.

## Quickstart

```bash
pip install pyyaml            # only runtime dependency
python -m detkit test examples/rules
```

Each rule gets a sibling `*.test.yml` describing sample events and whether the
rule should match:

```yaml
# whoami_execution.test.yml
tests:
  - name: fires on whoami run by a normal user
    event: { EventID: 4688, CommandLine: "cmd /c whoami /all", User: "alice" }
    expect: match
  - name: suppressed for SYSTEM
    event: { EventID: 4688, CommandLine: "whoami", User: "SYSTEM" }
    expect: no_match
```

`detkit test` exits non-zero on any failure, so you can drop it straight into CI
and block a pull request that breaks a detection.

## Why this, why now

- **Detection-as-code is mainstream** (SigmaHQ, Elastic detection-rules, Splunk
  ESCU) but the *test* step is missing — the same gap dbt filled for analytics.
- **Self-host is a hard requirement, not a preference:** security telemetry can't
  be shipped to someone else's cloud. That's the wedge closed SaaS SOC tools
  (Dropzone, Prophet, Intezer) structurally can't serve.
- **The community distributes it:** good detection tooling spreads bottom-up on
  GitHub (see Nuclei). detkit is built to be forked, extended, and shared.

## Roadmap

- `detkit generate` — AI-draft a rule **and its tests** from a natural-language
  threat description (tests are mandatory, never optional).
- More log schemas / field-mapping so one rule tests against multiple log sources.
- Full Sigma-spec coverage via [pySigma](https://github.com/SigmaHQ/pySigma)
  (nested fields, `base64`/`cidr` modifiers, correlation rules).
- A GitHub Action for one-line CI gating.
- Managed cloud (hosted runs, SSO, shared rule/test libraries) — the paid tier.
  The tool stays free forever.

## Status

Early. The core — evaluating a Sigma rule's `detection`/`condition` against a log
event, and a test runner around it — works today (`python tests/test_evaluator.py`).
Known limits are marked with `# ponytail:` comments in `detkit/evaluator.py`.

MIT licensed. Contributions welcome.
