"""Self-contained single-file HTML report for STRIX_CLOUD findings.

The goal is operator ergonomics: run the tool, open ONE html file in any
browser, and see everything — filter by severity/provider, search, read the
ATT&CK mapping and impact, and one-click **copy the read-only verification
command**. No server, no external assets, no dependencies.

Security: findings contain attacker-influenced strings (resource names, tags,
evidence). Every dynamic value is HTML-escaped, and the verify command is copied
via ``dataset`` (never injected as HTML), so a hostile resource name cannot
execute script in the report.
"""
from __future__ import annotations

import html as _html
import json
from typing import List

from agents.common.findings import Finding, Report
from agents.report import narrative

_STYLE = """
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c232c;--ink:#e6edf3;--muted:#9aa7b4;
--border:#2a3139;--accent:#4dd0d8;--crit:#ef4444;--high:#f97316;--med:#eab308;
--low:#22c55e;--info:#64748b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.5}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px 80px}
h1{font-size:1.5rem;margin:0 0 2px;letter-spacing:-.01em}
.meta{color:var(--muted);font-size:.85rem;font-family:ui-monospace,Consolas,monospace}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}
.pill{padding:6px 12px;border-radius:999px;font-weight:700;font-size:.82rem;color:#0b0f14}
.pill.crit{background:var(--crit);color:#fff}.pill.high{background:var(--high)}
.pill.med{background:var(--med)}.pill.low{background:var(--low)}
.pill.info{background:var(--info);color:#fff}
.pill.total{background:var(--panel2);color:var(--ink);border:1px solid var(--border)}
.starthere{background:var(--panel2);border:1px solid var(--border);border-radius:12px;padding:12px 18px;margin:8px 0}
.starthere h2{margin:0 0 8px;font-size:1rem;color:var(--accent)}
.starthere ol{margin:0;padding-left:20px}.starthere li{margin:7px 0}
.starthere .s{color:var(--muted);font-size:.85rem;margin:2px 0}
.starthere code{background:#0b0f14;border:1px solid var(--border);border-radius:6px;padding:1px 6px;font-size:.78rem}
.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:14px 0 22px;
position:sticky;top:0;background:var(--bg);padding:10px 0;border-bottom:1px solid var(--border);z-index:5}
.controls input,.controls select{background:var(--panel2);color:var(--ink);border:1px solid var(--border);
border-radius:8px;padding:8px 10px;font-size:.9rem}
.controls input{flex:1;min-width:200px}
.sevbtn{cursor:pointer;border:1px solid var(--border);background:var(--panel);color:var(--ink);
padding:6px 10px;border-radius:8px;font-size:.8rem;font-weight:600}
.sevbtn.off{opacity:.35}
.f{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--border);
border-radius:12px;padding:16px 18px;margin:12px 0}
.f[data-sev="CRITICAL"]{border-left-color:var(--crit)}
.f[data-sev="HIGH"]{border-left-color:var(--high)}
.f[data-sev="MEDIUM"]{border-left-color:var(--med)}
.f[data-sev="LOW"]{border-left-color:var(--low)}
.f[data-sev="INFO"]{border-left-color:var(--info)}
.f h3{margin:0 0 6px;font-size:1.05rem}
.chip{font-size:.7rem;font-weight:800;text-transform:uppercase;padding:2px 8px;border-radius:6px;
color:#0b0f14;margin-right:8px;vertical-align:middle}
.chip.CRITICAL{background:var(--crit);color:#fff}.chip.HIGH{background:var(--high)}
.chip.MEDIUM{background:var(--med)}.chip.LOW{background:var(--low)}.chip.INFO{background:var(--info);color:#fff}
.rmeta{color:var(--muted);font-size:.82rem;font-family:ui-monospace,Consolas,monospace;margin:2px 0 8px}
.tag{display:inline-block;background:var(--panel2);border:1px solid var(--border);color:var(--accent);
border-radius:6px;padding:1px 7px;font-size:.72rem;font-family:ui-monospace,Consolas,monospace;margin:0 4px 4px 0}
.lbl{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;margin-top:10px}
.verify{display:flex;gap:8px;align-items:center;margin-top:4px}
.verify code{flex:1;background:#0b0f14;border:1px solid var(--border);border-radius:8px;padding:8px 10px;
font-family:ui-monospace,Consolas,monospace;font-size:.82rem;overflow-x:auto;white-space:pre}
.copy{cursor:pointer;background:var(--accent);color:#04252a;border:0;border-radius:8px;padding:8px 12px;font-weight:700}
details{margin-top:8px}summary{cursor:pointer;color:var(--muted);font-size:.82rem}
pre{background:#0b0f14;border:1px solid var(--border);border-radius:8px;padding:10px;overflow-x:auto;
font-size:.78rem;color:var(--muted)}
.empty{color:var(--muted);text-align:center;padding:40px}
footer{color:var(--muted);font-size:.78rem;margin-top:30px;border-top:1px solid var(--border);padding-top:14px}
"""

_SCRIPT = """
const q=document.getElementById('q');
const prov=document.getElementById('prov');
const sevState={CRITICAL:1,HIGH:1,MEDIUM:1,LOW:1,INFO:1};
function apply(){
  const term=(q.value||'').toLowerCase();
  const p=prov.value;
  document.querySelectorAll('.f').forEach(function(el){
    const okSev=sevState[el.dataset.sev];
    const okProv=(p==='all'||el.dataset.prov===p);
    const okText=(!term||el.dataset.text.indexOf(term)>-1);
    el.style.display=(okSev&&okProv&&okText)?'':'none';
  });
}
document.querySelectorAll('.sevbtn').forEach(function(b){
  b.addEventListener('click',function(){
    const s=b.dataset.sev;sevState[s]=!sevState[s];
    b.classList.toggle('off',!sevState[s]);apply();
  });
});
q.addEventListener('input',apply);prov.addEventListener('change',apply);
document.querySelectorAll('.copy').forEach(function(b){
  b.addEventListener('click',function(){
    const cmd=b.dataset.cmd||'';
    navigator.clipboard&&navigator.clipboard.writeText(cmd);
    const t=b.textContent;b.textContent='copied';setTimeout(function(){b.textContent=t;},1200);
  });
});
"""


def _esc(value) -> str:
    return _html.escape("" if value is None else str(value))


def _finding_html(f: Finding) -> str:
    sev = f.severity.name
    text_blob = " ".join(
        str(x) for x in (f.check_id, f.title, f.resource_id, f.provider, f.account_id, f.description)
    ).lower()
    text_blob += " " + " ".join(f.mitre).lower()
    tags = "".join('<span class="tag">' + _esc(m) + "</span>" for m in f.mitre)
    loc = " · ".join(p for p in (f.provider, f.account_id, f.region) if p)
    parts = [
        '<article class="f" data-sev="' + _esc(sev) + '" data-prov="' + _esc(f.provider)
        + '" data-text="' + _esc(text_blob) + '">',
        '<h3><span class="chip ' + _esc(sev) + '">' + _esc(sev) + "</span>" + _esc(f.title) + "</h3>",
        '<div class="rmeta">' + _esc(f.resource_id) + " (" + _esc(f.resource_type) + ") — "
        + _esc(loc) + " · " + _esc(f.check_id) + "</div>",
    ]
    if tags:
        parts.append("<div>" + tags + "</div>")
    if f.description:
        parts.append('<div class="lbl">Impact</div><div>' + _esc(f.description) + "</div>")
    if f.verification:
        parts.append('<div class="lbl">Verify (read-only)</div>')
        parts.append(
            '<div class="verify"><code>' + _esc(f.verification) + "</code>"
            + '<button class="copy" data-cmd="' + _esc(f.verification) + '">copy</button></div>'
        )
    if f.remediation:
        parts.append('<div class="lbl">Fix</div><div>' + _esc(f.remediation) + "</div>")
    if f.evidence:
        ev = json.dumps(f.evidence, indent=2, sort_keys=True, default=str)
        parts.append("<details><summary>evidence</summary><pre>" + _esc(ev) + "</pre></details>")
    parts.append("</article>")
    return "".join(parts)


def _start_here_html(report: Report) -> str:
    items = narrative.start_here(report)
    if not items:
        return ""
    lis = []
    for it in items:
        head = ('<span class="chip ' + _esc(it["severity"]) + '">' + _esc(it["severity"])
                + "</span>" + _esc(it["title"]))
        sub = "".join('<div class="s">• ' + _esc(step) + "</div>" for step in it.get("steps", []))
        if it.get("verification"):
            sub += '<div class="s">verify: <code>' + _esc(it["verification"]) + "</code></div>"
        lis.append("<li>" + head + sub + "</li>")
    return '<section class="starthere"><h2>Start here</h2><ol>' + "".join(lis) + "</ol></section>"


def render_html(report: Report) -> str:
    items: List[Finding] = [f for f in report.findings if f.is_failure or f.status == "error"]
    items.sort(key=lambda f: (-int(f.severity), f.check_id, f.resource_id))
    summary = report.summary()
    by_sev = summary["by_severity"]

    pills = ['<span class="pill total">' + str(summary["failures"]) + " failures / "
             + str(summary["total"]) + " checks</span>"]
    for sev, cls in (("CRITICAL", "crit"), ("HIGH", "high"), ("MEDIUM", "med"),
                     ("LOW", "low"), ("INFO", "info")):
        if by_sev.get(sev):
            pills.append('<span class="pill ' + cls + '">' + sev.title() + " " + str(by_sev[sev]) + "</span>")

    sevbtns = "".join(
        '<span class="sevbtn" data-sev="' + s + '">' + s.title() + "</span>"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    meta = " · ".join(
        p for p in (
            "run " + _esc(report.run_id) if report.run_id else "",
            "operator " + _esc(report.operator) if report.operator else "",
            _esc(report.started_at),
        ) if p
    )

    body = "".join(_finding_html(f) for f in items) or '<div class="empty">No failing findings. 🎯</div>'

    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>STRIX_CLOUD report</title><style>" + _STYLE + "</style></head><body><div class=\"wrap\">"
        "<h1>STRIX_CLOUD findings</h1><div class=\"meta\">" + meta + "</div>"
        '<div class="pills">' + "".join(pills) + "</div>"
        + _start_here_html(report)
        + '<div class="controls">'
        '<input id="q" placeholder="search resource, check, ATT&amp;CK…">'
        '<select id="prov"><option value="all">all providers</option>'
        '<option value="aws">aws</option><option value="azure">azure</option>'
        '<option value="gcp">gcp</option></select>' + sevbtns + "</div>"
        + body +
        "<footer>Read-only CSPM findings. Verification commands are non-destructive. "
        "Generated by STRIX_CLOUD.</footer>"
        "</div><script>" + _SCRIPT + "</script></body></html>"
    )
