import json
from detkit.cli import main


def test_cmd_test_json_parses(tmp_path, capsys):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yml").write_text(
        "title: t\nlogsource: {product: windows}\ndetection:\n"
        "  selection: {CommandLine|contains: whoami}\n  condition: selection\n",
        encoding="utf-8",
    )
    (rules / "r.test.yml").write_text(
        "tests:\n  - name: hit\n    event: {CommandLine: whoami}\n    expect: match\n",
        encoding="utf-8",
    )
    code = main(["test", str(rules), "--json"])
    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert "passed" in data and "results" in data
    assert data["coverage_pct"] == 100
    assert code in (0, 1)
