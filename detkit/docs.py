"""Generate a self-contained HTML detection catalog + MITRE ATT&CK coverage map.

Pure rendering: takes already-loaded rules (and an optional ATT&CK dataset) and
returns (html, summary). No file/CLI imports, so it stays testable and circular-free.

Coverage view:
- Without an ATT&CK dataset, the grid shows only the techniques your rules carry.
- With one (bundled attack_enterprise.json), it shows the FULL matrix per tactic:
  your covered techniques stand out and everything else renders as a faint gap,
  so you can see what you're blind to.
"""
import html
import re

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


def _matrix(attack_data):
    """attack_data -> ({tactic: {tech: name}}, {tech: name}). Empty if no data."""
    by_tactic, names = {slug: {} for slug, _ in TACTICS}, {}
    for t in (attack_data or {}).get("techniques", []):
        tid, name = t.get("id", "").upper(), t.get("name", "")
        if not tid:
            continue
        names[tid] = name
        for slug in t.get("tactics", []):
            if slug in by_tactic:
                by_tactic[slug][tid] = name
    return by_tactic, names


def render(items, attack_data=None):
    """items: [{"path","rule","has_tests"}], attack_data: parsed json or None."""
    rules = [_extract(it) for it in items]
    total = len(rules)
    tested = sum(1 for r in rules if r["has_tests"])
    all_tech = set().union(*(r["techniques"] for r in rules)) if rules else set()
    all_tac = set().union(*(r["tactics"] for r in rules)) if rules else set()

    full, names = _matrix(attack_data)
    matrix_on = bool(attack_data)
    universe = {t for techs in full.values() for t in techs}
    tech_tactics = {}                       # parent technique -> {tactic slugs} (authoritative)
    for slug, techs in full.items():
        for t in techs:
            tech_tactics.setdefault(t, set()).add(slug)

    covered = {slug: {} for slug, _ in TACTICS}   # tactic -> {tech: tested?}
    other = {}
    for r in rules:
        for tech in r["techniques"]:
            parent = tech.split(".")[0]     # fold sub-techniques (T1059.001 -> T1059)
            if matrix_on and parent in universe:
                for slug in tech_tactics[parent]:   # place by MITRE's mapping, not rule tags
                    covered[slug][parent] = covered[slug].get(parent, False) or r["has_tests"]
            else:
                key = parent if matrix_on else tech
                for b in ([covered[t] for t in r["tactics"] if t in covered] or [other]):
                    b[key] = b.get(key, False) or r["has_tests"]

    summary = {
        "total": total,
        "tested": tested,
        "coverage": round(100 * tested / total) if total else 0,
        "techniques": len(all_tech),
        "tactics": len(all_tac & _TACTIC_SLUGS),
    }
    if matrix_on:
        covered_parents = set()
        for slug in _TACTIC_SLUGS:
            covered_parents |= set(covered[slug])
        summary["matrix_total"] = len(universe)
        summary["matrix_covered"] = len(covered_parents & universe)
        summary["tactics"] = sum(1 for slug in _TACTIC_SLUGS if covered[slug])
    return _page(rules, covered, other, full, names, matrix_on, summary), summary


def _covered_by_technique(items):
    """{parent technique id: tested?} across all rules — folds sub-techniques to parent."""
    out = {}
    for it in items:
        r = _extract(it)
        for tech in r["techniques"]:
            parent = tech.split(".")[0]
            out[parent] = out.get(parent, False) or r["has_tests"]
    return out


def navigator_layer(items, attack_data=None, name="detkit coverage"):
    """Build a MITRE ATT&CK Navigator layer (dict) from rule coverage.

    score 100 = has detkit tests (green), 50 = covered but untested (amber);
    gaps are left out so Navigator shows them uncolored. Import at
    https://mitre-attack.github.io/attack-navigator/.
    """
    covered = _covered_by_technique(items)
    full, _ = _matrix(attack_data)
    universe = {t for techs in full.values() for t in techs}
    version = str((attack_data or {}).get("attack_version", "")).lstrip("vV") or "17"
    techniques = [
        {
            "techniqueID": tech,
            "score": 100 if tested else 50,
            "enabled": True,
            "comment": "tested" if tested else "covered (no detkit test)",
        }
        for tech, tested in sorted(covered.items())
        if not universe or tech in universe
    ]
    return {
        "name": name,
        "domain": "enterprise-attack",
        "description": "detkit detection coverage. score 100 = has detkit tests, 50 = covered but untested.",
        "versions": {"attack": version, "navigator": "5.1.0", "layer": "4.5"},
        "sorting": 0,
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#fff8c5", "#8ec843"], "minValue": 50, "maxValue": 100},
        "legendItems": [
            {"label": "covered, no test", "color": "#fff8c5"},
            {"label": "tested", "color": "#8ec843"},
        ],
    }


def _cells(cov, official, names):
    """cov: {tech: tested?}. official: {tech: name} (full matrix) or None."""
    if official is None:                       # v1: only covered techniques
        if not cov:
            return '<div class="cell empty">no rules</div>'
        techs = [(t, "t" if tested else "c") for t, tested in sorted(cov.items())]
    else:                                      # full matrix: covered + gaps
        techs = []
        for t in sorted(set(official) | set(cov)):
            techs.append((t, ("t" if cov[t] else "c") if t in cov else "gap"))
    out = []
    for t, state in techs:
        title = html.escape(names.get(t, ""))
        out.append(f'<div class="cell {state}" title="{title}">{html.escape(t)}</div>')
    return "".join(out)


def _page(rules, covered, other, full, names, matrix_on, s):
    esc = html.escape
    cols = []
    entries = [(slug, name, covered[slug]) for slug, name in TACTICS]
    if other:
        entries.append(("", "Other", other))
    for slug, name, cov in entries:
        official = full.get(slug, {}) if (matrix_on and slug) else (None if not matrix_on else {})
        if matrix_on and slug:
            badge = f"{len(cov)}/{len(official) or len(cov)}"
        else:
            badge = str(len(cov))
        empty = "" if cov else " empty-tactic"
        cols.append(
            f'<div class="col{empty}" data-tactic="{slug}" tabindex="0" role="button" '
            f'aria-label="Filter rules by {esc(name)}"><div class="ch">{esc(name)}<b>{badge}</b></div>'
            f'{_cells(cov, official, names)}</div>'
        )
    matrix = "".join(cols)

    rows = []
    for r in sorted(rules, key=lambda x: x["title"].lower()):
        techs = ", ".join(sorted(r["techniques"])) or "—"
        search = esc(" ".join([r["title"], techs, r["logsource"], r["level"]]).lower())
        rows.append(
            "<tr data-tested='{td}' data-tactics='{tac}' data-search='{sr}'>"
            "<td>{title}</td><td class='mono'>{tech}</td><td class='mono'>{ls}</td>"
            "<td class='mono'>{lvl}</td><td>{t}</td></tr>".format(
                td="1" if r["has_tests"] else "0",
                tac=esc(" ".join(sorted(r["tactics"]))),
                sr=search,
                title=esc(r["title"]),
                tech=esc(techs),
                ls=esc(r["logsource"] or "—"),
                lvl=esc(r["level"] or "—"),
                t='<span class="ok">&#10003; tested</span>' if r["has_tests"] else '<span class="no">&mdash; none</span>',
            )
        )
    tech_tile = (
        f'{s["matrix_covered"]}<span class="of">/{s["matrix_total"]}</span>' if matrix_on else str(s["techniques"])
    )
    kpis = (
        f'<div class="kpi"><div class="k">Rules</div><div class="v">{s["total"]}</div></div>'
        f'<div class="kpi"><div class="k">Have tests</div><div class="v">{s["coverage"]}%</div>'
        f'<div class="bar"><i style="width:{s["coverage"]}%"></i></div></div>'
        f'<div class="kpi"><div class="k">ATT&amp;CK techniques</div><div class="v">{tech_tile}</div></div>'
        f'<div class="kpi"><div class="k">Tactics covered</div><div class="v">{s["tactics"]}<span class="of">/14</span></div></div>'
    )
    return _TEMPLATE.format(
        css=_CSS, script=_JS, total=s["total"], coverage=s["coverage"],
        kpis=kpis, matrix=matrix, rows="".join(rows),
    )


_CSS = """
:root{
--bg:#f6f8fa;--surface:#fff;--fg:#1c2128;--muted:#59636e;--line:#d0d7de;
--accent:#8250df;--t-bg:#dafbe1;--t-fg:#116329;--t-br:#4ac26b;
--c-bg:#fff8c5;--c-fg:#7d4e00;--c-br:#d4a72c;--g-fg:#9aa4ae;--g-br:#e2e7eb;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root{
--bg:#0b0f14;--surface:#131a22;--fg:#e6edf3;--muted:#8b949e;--line:#222b35;
--accent:#a371f7;--t-bg:#122820;--t-fg:#56d364;--t-br:#238636;
--c-bg:#2b2410;--c-fg:#e3b341;--c-br:#9e7700;--g-fg:#545d68;--g-br:#20272f;
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
border:1px solid var(--line);border-radius:12px;align-items:flex-start}
.col{flex:0 0 128px;min-width:128px;border-radius:8px;padding:2px}
.col[data-tactic]{cursor:pointer}
.col:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.col.sel{background:var(--surface);box-shadow:0 0 0 1px var(--accent) inset}
.col.empty-tactic{opacity:.5}
.ch{display:flex;justify-content:space-between;align-items:flex-start;gap:.3rem;min-height:2.6em;
padding:.3rem .3rem .5rem;font:600 .63rem/1.3 var(--mono);letter-spacing:.03em;text-transform:uppercase;color:var(--muted)}
.ch b{flex:none;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:20px;padding:1px 7px;font-size:.6rem}
.cell{font:600 12px/1.3 var(--mono);padding:6px 8px;border-radius:6px;margin-bottom:5px;border:1px solid transparent}
.cell.t{background:var(--t-bg);color:var(--t-fg);border-left:3px solid var(--t-br)}
.cell.c{background:var(--c-bg);color:var(--c-fg);border-color:var(--c-br)}
.cell.gap{color:var(--g-fg);border-color:var(--g-br);font-weight:400;font-size:10.5px;padding:4px 7px}
.cell.empty{color:var(--g-fg);border:1px dashed var(--g-br);text-align:center;font-weight:400;font-size:10px}
.legend{display:flex;gap:1.3rem;flex-wrap:wrap;margin:.9rem 0 0;font:.8rem/1 var(--sans);color:var(--muted)}
.legend span{display:flex;align-items:center;gap:.5rem}
.legend .sw{width:26px;height:16px;border-radius:4px;border:1px solid transparent}
.legend .sw.t{background:var(--t-bg);border-left:3px solid var(--t-br)}
.legend .sw.c{background:var(--c-bg);border-color:var(--c-br)}
.legend .sw.gap{border-color:var(--g-br)}
.controls{display:flex;gap:.75rem;align-items:center;flex-wrap:wrap;margin:0 0 .9rem}
.controls input[type=search]{flex:1;min-width:200px;padding:.5rem .7rem;border:1px solid var(--line);
border-radius:8px;background:var(--surface);color:var(--fg);font:.9rem var(--sans)}
.controls input[type=search]:focus-visible{outline:2px solid var(--accent);outline-offset:1px;border-color:var(--accent)}
.controls label{font:.85rem var(--sans);color:var(--muted);display:flex;align-items:center;gap:.4rem;cursor:pointer}
.controls .cnt{font:.8rem var(--mono);color:var(--muted);margin-left:auto}
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

_JS = """<script>
(function(){
  var rows=[].slice.call(document.querySelectorAll('#rules tbody tr'));
  var q=document.getElementById('q'), to=document.getElementById('tested-only');
  var sg=document.getElementById('show-gaps'), sgWrap=document.getElementById('gaps-wrap');
  var cols=[].slice.call(document.querySelectorAll('.col[data-tactic]'));
  var count=document.getElementById('count'), active=null;
  function apply(){
    var term=(q.value||'').toLowerCase(), tOnly=to.checked, shown=0;
    rows.forEach(function(r){
      var okQ=!term||r.getAttribute('data-search').indexOf(term)>-1;
      var okT=!tOnly||r.getAttribute('data-tested')==='1';
      var okA=!active||(' '+r.getAttribute('data-tactics')+' ').indexOf(' '+active+' ')>-1;
      var vis=okQ&&okT&&okA; r.hidden=!vis; if(vis)shown++;
    });
    count.textContent=shown;
  }
  cols.forEach(function(c){
    var slug=c.getAttribute('data-tactic'); if(!slug)return;
    function toggle(){active=(active===slug)?null:slug;
      cols.forEach(function(x){x.classList.toggle('sel',active&&x.getAttribute('data-tactic')===active);});apply();}
    c.addEventListener('click',toggle);
    c.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();toggle();}});
  });
  q.addEventListener('input',apply); to.addEventListener('change',apply);
  var gaps=document.querySelectorAll('.cell.gap');
  if(!gaps.length){ if(sgWrap) sgWrap.style.display='none'; }
  else if(sg){ sg.addEventListener('change',function(){
    [].forEach.call(gaps,function(g){g.hidden=!sg.checked;}); }); }
})();
</script>"""

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>detkit — detection catalog</title>
<style>{css}</style></head><body>
<div class="top">
<div class="brand">detkit<span class="cur">_</span><span class="tag">detection catalog &amp; ATT&amp;CK coverage</span></div>
<div class="meta">{total} rules &middot; {coverage}% tested<br>generated locally</div>
</div>
<div class="kpis">{kpis}</div>
<h2 class="sec">ATT&amp;CK coverage</h2>
<div class="matrix">{matrix}</div>
<p class="legend">
<span><span class="sw t"></span> tested</span>
<span><span class="sw c"></span> covered, no test</span>
<span><span class="sw gap"></span> gap / no rule</span>
<span id="gaps-wrap"><label><input id="show-gaps" type="checkbox" checked> show gaps</label></span>
</p>
<h2 class="sec" style="margin-top:2.5rem">Rules</h2>
<div class="controls">
<input id="q" type="search" placeholder="Search rules by name, technique, log source&hellip;" aria-label="Search rules">
<label><input id="tested-only" type="checkbox"> tested only</label>
<span class="cnt"><b id="count">{total}</b> of {total} rules</span>
</div>
<div class="tablewrap"><table id="rules">
<thead><tr><th>Rule</th><th>ATT&amp;CK</th><th>Log source</th><th>Level</th><th>Tests</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<footer>Click a tactic to filter the rules. Coverage is derived from the ATT&amp;CK tags in your rules.</footer>
{script}
</body></html>"""
