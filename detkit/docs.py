"""Generate a self-contained HTML detection catalog + MITRE ATT&CK coverage map.

Pure rendering: takes already-loaded rules and returns (html, summary). No file or
CLI imports here, so it stays testable and free of circular dependencies.

# ponytail: v1 coverage is built from the ATT&CK tags the rules already carry
# (attack.t1059.001 / attack.execution). It shows what you COVER, grouped by tactic.
# It does NOT diff against the full MITRE matrix, so it can't show techniques you have
# zero rules for (true gap analysis) — that needs the MITRE dataset, a clean v2.
"""
import html
import re

# ATT&CK tactics in kill-chain order; slugs match Sigma's tag style (attack.<slug>).
TACTICS = [
    ("reconnaissance", "Reconnaissance"),
    ("resource_development", "Resource Development"),
    ("initial_access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege_escalation", "Privilege Escalation"),
    ("defense_evasion", "Defense Evasion"),
    ("credential_access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral_movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command_and_control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]
_TACTIC_SLUGS = {slug for slug, _ in TACTICS}
_TECH_RE = re.compile(r"^t\d{4}(\.\d{3})?$")


def parse_attack(tags):
    """Split Sigma attack.* tags into (technique IDs, tactic slugs)."""
    techniques, tactics = set(), set()
    for tag in tags or []:
        t = str(tag).lower()
        if t.startswith("attack."):
            t = t[len("attack."):]
        if _TECH_RE.match(t):
            techniques.add(t.upper())
        elif t in _TACTIC_SLUGS:
            tactics.add(t)
    return techniques, tactics


def _logsource(rule):
    ls = rule.get("logsource", {}) or {}
    return "/".join(p for p in (ls.get("product"), ls.get("category"), ls.get("service")) if p)


def _extract(item):
    rule = item.get("rule") or {}
    techniques, tactics = parse_attack(rule.get("tags"))
    return {
        "title": rule.get("title") or item.get("path", "(untitled)"),
        "logsource": _logsource(rule),
        "level": rule.get("level", "") or "",
        "techniques": techniques,
        "tactics": tactics,
        "has_tests": bool(item.get("has_tests")),
    }


def render(items):
    """items: [{"path", "rule" (dict), "has_tests" (bool)}] -> (html_str, summary)."""
    rules = [_extract(it) for it in items]
    total = len(rules)
    tested = sum(1 for r in rules if r["has_tests"])
    all_tech = set().union(*(r["techniques"] for r in rules)) if rules else set()
    all_tac = set().union(*(r["tactics"] for r in rules)) if rules else set()

    # tactic slug -> {technique: tested?}, plus techniques with no tactic tag
    grid = {slug: {} for slug, _ in TACTICS}
    other = {}
    for r in rules:
        buckets = [grid[t] for t in r["tactics"]] or [other]
        for bucket in buckets:
            for tech in r["techniques"]:
                bucket[tech] = bucket.get(tech, False) or r["has_tests"]

    summary = {
        "total": total,
        "tested": tested,
        "coverage": round(100 * tested / total) if total else 0,
        "techniques": len(all_tech),
        "tactics": len(all_tac & _TACTIC_SLUGS),
    }
    return _page(rules, grid, other, summary), summary


def _cells(techs):
    if not techs:
        return '<div class="cell empty">no rules</div>'
    return "".join(
        f'<div class="cell {"t" if tested else "c"}">{html.escape(t)}</div>'
        for t, tested in sorted(techs.items())
    )


def _page(rules, grid, other, s):
    esc = html.escape
    columns = [(name, grid[slug]) for slug, name in TACTICS]
    if other:
        columns.append(("Other", other))
    matrix = "".join(
        f'<div class="col"><div class="ch">{esc(name)}<b>{len(techs)}</b></div>{_cells(techs)}</div>'
        for name, techs in columns
    )
    rows = "".join(
        "<tr><td>{title}</td><td class='mono'>{tech}</td><td class='mono'>{ls}</td>"
        "<td class='mono'>{lvl}</td><td>{t}</td></tr>".format(
            title=esc(r["title"]),
            tech=esc(", ".join(sorted(r["techniques"])) or "—"),
            ls=esc(r["logsource"] or "—"),
            lvl=esc(r["level"] or "—"),
            t='<span class="ok">&#10003; tested</span>' if r["has_tests"] else '<span class="no">&mdash; none</span>',
        )
        for r in sorted(rules, key=lambda x: x["title"].lower())
    )
    kpis = (
        f'<div class="kpi"><div class="k">Rules</div><div class="v">{s["total"]}</div></div>'
        f'<div class="kpi"><div class="k">Have tests</div><div class="v">{s["coverage"]}%</div>'
        f'<div class="bar"><i style="width:{s["coverage"]}%"></i></div></div>'
        f'<div class="kpi"><div class="k">ATT&amp;CK techniques</div><div class="v">{s["techniques"]}</div></div>'
        f'<div class="kpi"><div class="k">Tactics covered</div><div class="v">{s["tactics"]}<span class="of">/14</span></div></div>'
    )
    return _TEMPLATE.format(
        css=_CSS, total=s["total"], coverage=s["coverage"], kpis=kpis, matrix=matrix, rows=rows
    )


_CSS = """
:root{
--bg:#f6f8fa;--surface:#fff;--fg:#1c2128;--muted:#59636e;--line:#d0d7de;
--accent:#8250df;--t-bg:#dafbe1;--t-fg:#116329;--t-br:#4ac26b;
--c-bg:#fff8c5;--c-fg:#7d4e00;--c-br:#d4a72c;--g-fg:#8b949e;--g-br:#d8dee4;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root{
--bg:#0b0f14;--surface:#131a22;--fg:#e6edf3;--muted:#8b949e;--line:#222b35;
--accent:#a371f7;--t-bg:#122820;--t-fg:#56d364;--t-br:#238636;
--c-bg:#2b2410;--c-fg:#e3b341;--c-br:#9e7700;--g-fg:#6a737d;--g-br:#2a333d;
}}
*{box-sizing:border-box}
body{margin:0 auto;max-width:1160px;padding:2.5rem 1.5rem;background:var(--bg);color:var(--fg);
font:15px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:1rem;flex-wrap:wrap;
border-bottom:1px solid var(--line);padding-bottom:1rem;margin-bottom:2rem}
.brand{font:700 1.5rem/1 var(--mono);letter-spacing:-.02em}
.brand .cur{color:var(--accent)}
.brand .tag{display:block;margin-top:.45rem;font:400 .9rem/1 var(--sans);color:var(--muted);letter-spacing:0}
.meta{font:.76rem/1.6 var(--mono);color:var(--muted);text-align:right}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.9rem;margin-bottom:2.5rem}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:1rem 1.1rem}
.kpi .k{font:600 .67rem/1 var(--mono);letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
.kpi .v{margin-top:.55rem;font:700 2rem/1 var(--mono);font-variant-numeric:tabular-nums}
.kpi .v .of{font-size:1rem;color:var(--muted);font-weight:400}
.bar{margin-top:.75rem;height:4px;border-radius:2px;background:var(--line);overflow:hidden}
.bar i{display:block;height:100%;background:var(--accent)}
.sec{font:600 .72rem/1 var(--mono);letter-spacing:.11em;text-transform:uppercase;color:var(--muted);
margin:0 0 .9rem;display:flex;align-items:center;gap:.55rem}
.sec::before{content:"";width:9px;height:9px;background:var(--accent);border-radius:2px}
.matrix{display:flex;gap:7px;overflow-x:auto;padding:1rem;background:var(--surface);
border:1px solid var(--line);border-radius:12px}
.col{flex:0 0 128px;min-width:128px}
.ch{display:flex;justify-content:space-between;align-items:flex-start;gap:.3rem;min-height:2.6em;
padding-bottom:.5rem;font:600 .63rem/1.3 var(--mono);letter-spacing:.03em;text-transform:uppercase;color:var(--muted)}
.ch b{flex:none;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:20px;padding:1px 7px;font-size:.62rem}
.cell{font:600 12px/1.3 var(--mono);padding:6px 8px;border-radius:6px;margin-bottom:5px;border:1px solid transparent}
.cell.t{background:var(--t-bg);color:var(--t-fg);border-left:3px solid var(--t-br)}
.cell.c{background:var(--c-bg);color:var(--c-fg);border-color:var(--c-br)}
.cell.empty{color:var(--g-fg);border:1px dashed var(--g-br);text-align:center;font-weight:400;font-size:10px}
.legend{display:flex;gap:1.3rem;flex-wrap:wrap;margin:.9rem 0 0;font:.8rem/1 var(--sans);color:var(--muted)}
.legend span{display:flex;align-items:center;gap:.5rem}
.legend .sw{width:26px;height:16px;border-radius:4px;border:1px solid transparent}
.legend .sw.t{background:var(--t-bg);border-left:3px solid var(--t-br)}
.legend .sw.c{background:var(--c-bg);border-color:var(--c-br)}
.legend .sw.g{border:1px dashed var(--g-br)}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th{text-align:left;padding:.75rem .9rem;background:var(--surface);border-bottom:1px solid var(--line);
font:600 .67rem/1 var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
td{padding:.7rem .9rem;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
tbody tr{transition:background .12s}
tbody tr:hover{background:var(--surface)}
.mono{font:12px/1.4 var(--mono);color:var(--muted)}
.ok{font:600 .8rem/1 var(--mono);color:var(--t-fg)}
.no{font:.8rem/1 var(--mono);color:var(--muted)}
footer{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--line);font:.77rem/1.6 var(--mono);color:var(--muted)}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
@media (max-width:520px){body{padding:1.5rem 1rem}.brand{font-size:1.25rem}}
"""

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>detkit — detection catalog</title>
<style>{css}</style></head><body>
<div class="top">
<div class="brand">detkit<span class="cur">_</span><span class="tag">detection catalog &amp; ATT&amp;CK coverage</span></div>
<div class="meta">{total} rules &middot; {coverage}% tested</div>
</div>
<div class="kpis">{kpis}</div>
<h2 class="sec">ATT&amp;CK coverage</h2>
<div class="matrix">{matrix}</div>
<p class="legend">
<span><span class="sw t"></span> tested</span>
<span><span class="sw c"></span> covered, no test</span>
<span><span class="sw g"></span> no rules</span>
</p>
<h2 class="sec" style="margin-top:2.5rem">Rules</h2>
<div class="tablewrap"><table>
<thead><tr><th>Rule</th><th>ATT&amp;CK</th><th>Log source</th><th>Level</th><th>Tests</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<footer>Coverage is derived from the ATT&amp;CK tags already in your rules &mdash; it shows what you cover, not gaps against the full MITRE matrix.</footer>
</body></html>"""
