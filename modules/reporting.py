"""
Module: Reporting — HTML / Markdown / JSON / ATT&CK Navigator
Professional pentest report with MITRE ATT&CK mapping and CVSS v3.1 scoring.
"""
import datetime
import json
import html as _html
from pathlib import Path

from utils.helpers import (
    print_banner, dedupe_findings, add_finding,
    success, warn, info, error, prompt, pause,
    BABY_BLUE, LIGHT_PINK, SOFT_WHITE, PURE_WHITE, BOLD, RST,
)
from config.settings import SESSION, OUTPUT_DIR, redact_obj, redact_text
from modules.mitre_data import (
    TACTICS, TACTIC_COLORS, TECHNIQUES,
    SEVERITY_CVSS, suggest_techniques, suggest_cvss,
    enrich_finding, techniques_by_tactic,
)

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_COLORS_HTML = {
    "Critical": "#e74c3c",
    "High":     "#e67e22",
    "Medium":   "#f39c12",
    "Low":      "#27ae60",
    "Info":     "#3498db",
}
SEV_BG_HTML = {
    "Critical": "#fdf2f2",
    "High":     "#fef9f2",
    "Medium":   "#fefdf2",
    "Low":      "#f2fdf4",
    "Info":     "#f2f8fd",
}

VERSION = "5.0"


# ─────────────────────────────────────────────────────────────────────────────
# MITRE & CVSS enrichment
# ─────────────────────────────────────────────────────────────────────────────

def _enrich_all(findings: list[dict]) -> list[dict]:
    return [enrich_finding(f) for f in findings]


def _overall_risk(findings: list[dict]) -> tuple[float, str]:
    """Return (max_cvss_score, severity_label) across all findings."""
    max_score = 0.0
    for f in findings:
        score = f.get("cvss", {}).get("score", 0.0) or 0.0
        if score > max_score:
            max_score = score
    if max_score >= 9.0:
        return max_score, "Critical"
    if max_score >= 7.0:
        return max_score, "High"
    if max_score >= 4.0:
        return max_score, "Medium"
    if max_score > 0.0:
        return max_score, "Low"
    return 0.0, "Info"


def _covered_tactics(findings: list[dict]) -> set[str]:
    covered: set[str] = set()
    for f in findings:
        for tid in f.get("mitre_ids", []):
            data = TECHNIQUES.get(tid, {})
            if data.get("tactic"):
                covered.add(data["tactic"])
    return covered


# ─────────────────────────────────────────────────────────────────────────────
# Executive Summary narrative
# ─────────────────────────────────────────────────────────────────────────────

def _exec_narrative(engagement, domain, tester, findings, owned_u, owned_m, risk_score, risk_level):
    total  = len(findings)
    crits  = [f for f in findings if f.get("severity") == "Critical"]
    highs  = [f for f in findings if f.get("severity") == "High"]
    mediums= [f for f in findings if f.get("severity") == "Medium"]

    col = SEV_COLORS_HTML.get(risk_level, "#7f8c8d")

    parts = [
        f"During the <strong>{_html.escape(engagement)}</strong> engagement, an authorized "
        f"Active Directory security assessment was conducted against the "
        f"<strong>{_html.escape(domain)}</strong> environment."
    ]

    if total == 0:
        parts.append("No security findings were identified during this assessment.")
    else:
        sev_breakdown = []
        counts = {s: sum(1 for f in findings if f.get("severity") == s)
                  for s in ["Critical", "High", "Medium", "Low", "Info"]}
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            if counts[sev]:
                c = SEV_COLORS_HTML[sev]
                sev_breakdown.append(
                    f"<span style='color:{c};font-weight:600'>{counts[sev]} {sev}</span>"
                )
        parts.append(
            f"The assessment identified <strong>{total}</strong> security finding(s): "
            + ", ".join(sev_breakdown) + "."
        )

        if crits:
            names = ", ".join(
                f"<em>{_html.escape(f['name'])}</em>" for f in crits[:3]
            )
            suffix = f" and {len(crits) - 3} more" if len(crits) > 3 else ""
            parts.append(
                f"<strong style='color:{SEV_COLORS_HTML['Critical']}'>Critical</strong> "
                f"findings include {names}{suffix}, representing an immediate risk of "
                f"full domain compromise."
            )

    if owned_u or owned_m:
        parts.append(
            f"The assessment demonstrated compromise of "
            f"<strong>{len(owned_u)}</strong> user account(s) and "
            f"<strong>{len(owned_m)}</strong> system(s)."
        )

    if total > 0:
        parts.append(
            f"The overall risk rating is <strong style='color:{col}'>{risk_level} "
            f"(CVSS {risk_score:.1f})</strong>. "
            f"Immediate remediation is recommended for all Critical and High findings."
        )

    return " ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# HTML helpers
# ─────────────────────────────────────────────────────────────────────────────

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
  background: #f0f2f5;
  color: #1a1a2e;
  font-size: 14px;
  line-height: 1.6;
}
a { color: #2980b9; text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Header ── */
.report-header {
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
  color: #fff;
  padding: 48px 56px 36px;
  border-bottom: 4px solid #e74c3c;
}
.report-header h1 { font-size: 2.2em; font-weight: 700; letter-spacing: -0.5px; }
.report-header .subtitle { color: #a0aec0; margin-top: 6px; font-size: 0.95em; }
.header-meta {
  display: flex; gap: 32px; flex-wrap: wrap;
  margin-top: 24px; color: #cbd5e0; font-size: 0.88em;
}
.header-meta span strong { color: #fff; }

/* ── Risk badge ── */
.risk-badge {
  display: inline-flex; flex-direction: column; align-items: center;
  background: rgba(255,255,255,0.08);
  border: 1px solid rgba(255,255,255,0.15);
  border-radius: 12px; padding: 16px 28px;
  margin-left: auto;
}
.risk-badge .risk-score { font-size: 3em; font-weight: 800; line-height: 1; }
.risk-badge .risk-label { font-size: 0.8em; letter-spacing: 1px; text-transform: uppercase; margin-top: 4px; }

/* ── Layout ── */
.container { max-width: 1280px; margin: 0 auto; padding: 36px 40px; }
.section { background: #fff; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,.08); padding: 28px 32px; margin-bottom: 28px; }
.section-title {
  font-size: 1.15em; font-weight: 700; color: #1a1a2e;
  border-bottom: 2px solid #e74c3c;
  padding-bottom: 10px; margin-bottom: 20px;
  display: flex; align-items: center; gap: 10px;
}
.section-title .icon { font-size: 1.1em; }

/* ── Stat grid ── */
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 14px; margin-bottom: 24px; }
.stat-card {
  background: #f8f9fa; border-radius: 8px;
  padding: 18px 12px; text-align: center;
  border-top: 3px solid #ddd;
}
.stat-card .stat-num { font-size: 2.2em; font-weight: 800; line-height: 1; }
.stat-card .stat-lbl { font-size: 0.78em; color: #666; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }

/* ── Severity badge ── */
.sev-badge {
  display: inline-block; padding: 2px 10px; border-radius: 20px;
  font-size: 0.78em; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.5px; color: #fff;
}

/* ── MITRE pill ── */
.mitre-pill {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 0.75em; font-weight: 600;
  background: #eef2ff; color: #3730a3;
  border: 1px solid #c7d2fe; margin: 1px 2px;
  font-family: 'Courier New', monospace;
  cursor: default;
}
.mitre-pill:hover { background: #3730a3; color: #fff; }

/* ── CVSS badge ── */
.cvss-badge {
  display: inline-block; padding: 3px 10px; border-radius: 4px;
  font-size: 0.8em; font-weight: 700; border: 1px solid;
}

/* ── Finding card ── */
.finding-card {
  border: 1px solid #e5e7eb; border-radius: 8px;
  margin-bottom: 18px; overflow: hidden;
}
.finding-header {
  display: flex; align-items: center; gap: 12px;
  padding: 14px 20px;
  border-bottom: 1px solid #e5e7eb;
}
.finding-id { font-size: 0.85em; font-weight: 700; color: #6b7280; min-width: 28px; }
.finding-name { font-weight: 700; font-size: 1.05em; flex: 1; }
.finding-body { padding: 18px 20px; }
.finding-body table { width: 100%; border-collapse: collapse; }
.finding-body td { padding: 8px 12px; vertical-align: top; border-bottom: 1px solid #f3f4f6; }
.finding-body td:first-child { font-weight: 600; color: #4b5563; width: 160px; white-space: nowrap; }
.finding-body tr:last-child td { border-bottom: none; }

/* ── ATT&CK Coverage ── */
.tactic-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }
.tactic-card {
  border-radius: 8px; padding: 14px 16px;
  border: 1px solid #e5e7eb;
  position: relative; overflow: hidden;
}
.tactic-card.covered { border-left: 4px solid; }
.tactic-card .tactic-name { font-weight: 700; font-size: 0.9em; margin-bottom: 4px; }
.tactic-card .tactic-count { font-size: 0.8em; color: #6b7280; }
.tactic-card .tactic-badge {
  position: absolute; top: 8px; right: 10px;
  font-size: 0.7em; font-weight: 700; padding: 1px 6px;
  border-radius: 10px; color: #fff;
}

/* ── Timeline ── */
.timeline-table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
.timeline-table th {
  background: #1a1a2e; color: #fff;
  padding: 10px 14px; text-align: left; font-weight: 600;
}
.timeline-table td { padding: 8px 14px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
.timeline-table tr:nth-child(even) td { background: #f9fafb; }
.timeline-table .cmd-cell {
  font-family: 'Courier New', monospace; font-size: 0.88em;
  color: #1a1a2e; word-break: break-all;
}
.timeline-table .time-cell { color: #6b7280; white-space: nowrap; min-width: 160px; }

/* ── Findings overview table ── */
.overview-table { width: 100%; border-collapse: collapse; }
.overview-table th {
  background: #1a1a2e; color: #fff;
  padding: 10px 14px; text-align: left; font-weight: 600; font-size: 0.88em;
}
.overview-table td { padding: 10px 14px; border-bottom: 1px solid #f3f4f6; vertical-align: top; font-size: 0.88em; }
.overview-table tr:hover td { background: #f9fafb; }

/* ── Footer ── */
.report-footer {
  text-align: center; padding: 28px; color: #9ca3af;
  font-size: 0.82em; border-top: 1px solid #e5e7eb; margin-top: 12px;
}

/* Print */
@media print {
  body { background: #fff; }
  .section { box-shadow: none; border: 1px solid #e5e7eb; page-break-inside: avoid; }
  .report-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
"""


def _sev_badge_html(sev: str) -> str:
    col = SEV_COLORS_HTML.get(sev, "#7f8c8d")
    return f'<span class="sev-badge" style="background:{col}">{_html.escape(sev)}</span>'


def _cvss_badge_html(score: float, vector: str) -> str:
    if score >= 9.0:
        col, bg = "#e74c3c", "#fdf2f2"
    elif score >= 7.0:
        col, bg = "#e67e22", "#fef9f2"
    elif score >= 4.0:
        col, bg = "#f39c12", "#fefdf2"
    elif score > 0.0:
        col, bg = "#27ae60", "#f2fdf4"
    else:
        col, bg = "#3498db", "#f2f8fd"
    tip = _html.escape(vector)
    return (
        f'<span class="cvss-badge" style="color:{col};background:{bg};border-color:{col}" '
        f'title="{tip}">CVSS {score:.1f}</span>'
    )


def _mitre_pills_html(mitre_ids: list[str]) -> str:
    if not mitre_ids:
        return '<span style="color:#9ca3af;font-size:0.8em">—</span>'
    pills = []
    for tid in mitre_ids:
        tech = TECHNIQUES.get(tid, {})
        name = tech.get("name", tid)
        tip  = _html.escape(f"{tid}: {name}")
        pills.append(f'<span class="mitre-pill" title="{tip}">{_html.escape(tid)}</span>')
    return "".join(pills)


def _html_stat_grid(counts: dict, owned_u: list, owned_m: list, cmds_run: int) -> str:
    cards = []
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        col = SEV_COLORS_HTML[sev]
        cards.append(
            f'<div class="stat-card" style="border-top-color:{col}">'
            f'<div class="stat-num" style="color:{col}">{counts.get(sev, 0)}</div>'
            f'<div class="stat-lbl">{sev}</div></div>'
        )
    total = sum(counts.values())
    cards.append(
        f'<div class="stat-card" style="border-top-color:#1a1a2e">'
        f'<div class="stat-num" style="color:#1a1a2e">{total}</div>'
        f'<div class="stat-lbl">Total</div></div>'
    )
    cards.append(
        f'<div class="stat-card" style="border-top-color:#9b59b6">'
        f'<div class="stat-num" style="color:#9b59b6">{len(owned_u)}</div>'
        f'<div class="stat-lbl">Owned Users</div></div>'
    )
    cards.append(
        f'<div class="stat-card" style="border-top-color:#16a085">'
        f'<div class="stat-num" style="color:#16a085">{len(owned_m)}</div>'
        f'<div class="stat-lbl">Owned Hosts</div></div>'
    )
    cards.append(
        f'<div class="stat-card" style="border-top-color:#6b7280">'
        f'<div class="stat-num" style="color:#6b7280">{cmds_run}</div>'
        f'<div class="stat-lbl">Commands</div></div>'
    )
    return '<div class="stat-grid">' + "".join(cards) + "</div>"


def _html_attack_coverage(findings: list[dict]) -> str:
    covered = _covered_tactics(findings)
    tactic_techniques: dict[str, list[str]] = {}
    for f in findings:
        for tid in f.get("mitre_ids", []):
            tech = TECHNIQUES.get(tid, {})
            tac  = tech.get("tactic", "")
            if tac:
                tactic_techniques.setdefault(tac, [])
                if tid not in tactic_techniques[tac]:
                    tactic_techniques[tac].append(tid)

    cards = []
    for tac_id, tac_label in TACTICS.items():
        col    = TACTIC_COLORS.get(tac_id, "#666")
        is_cov = tac_id in covered
        tids   = tactic_techniques.get(tac_id, [])
        count  = len(tids)
        bg     = SEV_BG_HTML.get("Info", "#f8f9fa") if not is_cov else "#fff"
        border = f"border-left-color:{col};" if is_cov else ""
        badge  = (
            f'<span class="tactic-badge" style="background:{col}">■ {count}</span>'
            if is_cov else
            '<span class="tactic-badge" style="background:#d1d5db;color:#6b7280">○</span>'
        )
        technique_names = ""
        if tids:
            technique_names = "<br>".join(
                f'<span style="font-size:0.75em;color:#6b7280">↳ {_html.escape(TECHNIQUES[t]["name"])}</span>'
                for t in tids[:4]
            )
            if len(tids) > 4:
                technique_names += f'<br><span style="font-size:0.73em;color:#9ca3af">+{len(tids)-4} more</span>'

        cards.append(
            f'<div class="tactic-card {"covered" if is_cov else ""}" style="background:{bg};{border}">'
            f'{badge}'
            f'<div class="tactic-name" style="color:{"" if not is_cov else col}">{_html.escape(tac_label)}</div>'
            + (f'<div style="margin-top:6px">{technique_names}</div>' if technique_names else
               '<div class="tactic-count">Not observed</div>')
            + "</div>"
        )
    return '<div class="tactic-grid">' + "".join(cards) + "</div>"


def _html_overview_table(findings: list[dict]) -> str:
    rows = ""
    for f in findings:
        sev  = f.get("severity", "Info")
        col  = SEV_COLORS_HTML.get(sev, "#888")
        bg   = SEV_BG_HTML.get(sev, "#fff")
        cvss = f.get("cvss", {})
        score_val = cvss.get("score", 0.0) if cvss else 0.0
        score_html = _cvss_badge_html(score_val, cvss.get("vector", "")) if cvss else "—"
        mitre_html = _mitre_pills_html(f.get("mitre_ids", []))
        rows += (
            f'<tr style="background:{bg}">'
            f'<td style="font-weight:700;color:{col}">{f.get("id","")}</td>'
            f'<td style="font-weight:600">{_html.escape(str(f.get("name","")))}</td>'
            f'<td>{_sev_badge_html(sev)}</td>'
            f'<td>{score_html}</td>'
            f'<td>{mitre_html}</td>'
            f'</tr>'
        )
    return (
        '<table class="overview-table">'
        '<tr><th>#</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>MITRE ATT&CK</th></tr>'
        + rows + "</table>"
    )


def _html_finding_cards(findings: list[dict]) -> str:
    cards = []
    for f in findings:
        sev    = f.get("severity", "Info")
        col    = SEV_COLORS_HTML.get(sev, "#888")
        bg     = SEV_BG_HTML.get(sev, "#fff")
        cvss   = f.get("cvss", {}) or {}
        score  = cvss.get("score", 0.0)
        vector = cvss.get("vector", "")
        mids   = f.get("mitre_ids", [])

        # Build technique detail links
        mitre_detail = ""
        if mids:
            rows_m = []
            for tid in mids:
                tech = TECHNIQUES.get(tid, {})
                tname = tech.get("name", tid)
                tac   = TACTICS.get(tech.get("tactic", ""), "")
                url   = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                rows_m.append(
                    f'<a class="mitre-pill" href="{url}" target="_blank" '
                    f'title="{_html.escape(tname)} | {_html.escape(tac)}">'
                    f'{_html.escape(tid)}</a>'
                    f'<span style="font-size:0.8em;color:#4b5563;margin-right:10px"> '
                    f'{_html.escape(tname)}</span>'
                )
            mitre_detail = "<br>".join(rows_m)

        evidence = redact_text(str(f.get("evidence", "") or ""))
        rec      = _html.escape(redact_text(str(f.get("recommendation", "") or "")))
        desc     = _html.escape(redact_text(str(f.get("description", "") or "")))
        ts       = f.get("timestamp", "")

        rows_body = f"""
        <tr>
          <td>Severity</td>
          <td>{_sev_badge_html(sev)}</td>
        </tr>
        <tr>
          <td>CVSS v3.1</td>
          <td>{_cvss_badge_html(score, vector)}
            <span style="font-family:monospace;font-size:0.78em;color:#6b7280;margin-left:8px">{_html.escape(vector)}</span>
          </td>
        </tr>
        <tr>
          <td>MITRE ATT&CK</td>
          <td>{mitre_detail if mitre_detail else '<span style="color:#9ca3af">—</span>'}</td>
        </tr>
        <tr>
          <td>Description</td>
          <td>{desc}</td>
        </tr>
        <tr>
          <td>Recommendation</td>
          <td>{rec}</td>
        </tr>
        """
        if evidence:
            rows_body += f'<tr><td>Evidence</td><td><code style="font-size:0.85em">{_html.escape(evidence)}</code></td></tr>'
        if ts:
            rows_body += f'<tr><td>Timestamp</td><td style="color:#9ca3af;font-size:0.82em">{_html.escape(str(ts))}</td></tr>'

        cards.append(
            f'<div class="finding-card" id="finding-{f.get("id","")}">'
            f'<div class="finding-header" style="background:{bg}">'
            f'<span class="finding-id">#{f.get("id","")}</span>'
            f'<span class="finding-name">{_html.escape(str(f.get("name","")))}</span>'
            f'{_sev_badge_html(sev)}'
            f'{_cvss_badge_html(score, vector)}'
            f'</div>'
            f'<div class="finding-body"><table>{rows_body}</table></div>'
            f'</div>'
        )
    return "\n".join(cards)


def _html_timeline(commands: list[dict], limit: int = 50) -> str:
    if not commands:
        return '<p style="color:#9ca3af;font-style:italic">No commands recorded in this session.</p>'
    rows = ""
    for i, cmd in enumerate(commands[-limit:], 1):
        t   = str(cmd.get("time", ""))
        c   = redact_text(str(cmd.get("cmd", "")))
        rows += (
            f"<tr>"
            f'<td class="time-cell">{_html.escape(t[:19])}</td>'
            f'<td class="cmd-cell">{_html.escape(c)}</td>'
            f"</tr>"
        )
    total = len(commands)
    note  = f" (last {limit} of {total})" if total > limit else f" ({total} total)"
    return (
        f'<p style="font-size:0.82em;color:#6b7280;margin-bottom:12px">Attack timeline{note}</p>'
        f'<table class="timeline-table">'
        f"<tr><th>Time</th><th>Command</th></tr>"
        + rows + "</table>"
    )


def _html_owned_assets(owned_u: list, owned_m: list) -> str:
    if not owned_u and not owned_m:
        return '<p style="color:#9ca3af;font-style:italic">No owned assets recorded.</p>'
    out = ""
    if owned_u:
        out += '<p style="font-weight:600;margin-bottom:8px">Owned Users</p>'
        out += '<table class="overview-table"><tr><th>User</th><th>Method</th><th>Time</th></tr>'
        for u in owned_u:
            if isinstance(u, dict):
                out += (
                    f'<tr><td style="font-weight:600">{_html.escape(str(u.get("user","?")))}</td>'
                    f'<td>{_html.escape(str(u.get("method","")))}</td>'
                    f'<td style="color:#6b7280">{_html.escape(str(u.get("time",""))[:19])}</td></tr>'
                )
            else:
                out += f'<tr><td colspan="3">{_html.escape(str(u))}</td></tr>'
        out += "</table><br>"
    if owned_m:
        out += '<p style="font-weight:600;margin-bottom:8px">Owned Machines</p>'
        out += '<table class="overview-table"><tr><th>Machine</th><th>Method</th><th>Time</th></tr>'
        for m in owned_m:
            if isinstance(m, dict):
                out += (
                    f'<tr><td style="font-weight:600">{_html.escape(str(m.get("machine","?")))}</td>'
                    f'<td>{_html.escape(str(m.get("method","")))}</td>'
                    f'<td style="color:#6b7280">{_html.escape(str(m.get("time",""))[:19])}</td></tr>'
                )
            else:
                out += f'<tr><td colspan="3">{_html.escape(str(m))}</td></tr>'
        out += "</table>"
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Full HTML report
# ─────────────────────────────────────────────────────────────────────────────

def _build_html(
    engagement: str,
    tester: str,
    domain: str,
    dc: str,
    findings: list[dict],
    owned_u: list,
    owned_m: list,
    commands: list[dict],
    loot: dict,
) -> str:
    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ["Critical", "High", "Medium", "Low", "Info"]}
    cmds_run = len(commands)
    risk_score, risk_level = _overall_risk(findings)
    risk_col  = SEV_COLORS_HTML.get(risk_level, "#7f8c8d")
    narrative = _exec_narrative(
        engagement, domain, tester, findings, owned_u, owned_m, risk_score, risk_level
    )
    today = datetime.date.today().isoformat()

    # ── Header ──
    header = f"""
<div class="report-header">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:20px">
    <div>
      <div style="color:#e74c3c;font-size:0.78em;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">
        PENETRATION TEST REPORT — CONFIDENTIAL
      </div>
      <h1>{_html.escape(engagement)}</h1>
      <div class="subtitle">Active Directory Security Assessment</div>
      <div class="header-meta">
        <span><strong>Date:</strong> {today}</span>
        <span><strong>Tester:</strong> {_html.escape(tester)}</span>
        <span><strong>Target:</strong> {_html.escape(domain)}</span>
        <span><strong>DC:</strong> {_html.escape(dc)}</span>
        <span><strong>Generated by:</strong> AdStrike v{VERSION}</span>
      </div>
    </div>
    <div class="risk-badge">
      <div class="risk-score" style="color:{risk_col}">{risk_score:.1f}</div>
      <div class="risk-label" style="color:{risk_col}">{risk_level} Risk</div>
      <div style="font-size:0.72em;color:#718096;margin-top:2px">Overall CVSS</div>
    </div>
  </div>
</div>
"""

    # ── Sections ──
    stat_grid = _html_stat_grid(counts, owned_u, owned_m, cmds_run)
    coverage  = _html_attack_coverage(findings)
    overview  = _html_overview_table(findings)
    cards     = _html_finding_cards(findings)
    timeline  = _html_timeline(commands)
    assets    = _html_owned_assets(owned_u, owned_m)

    sections = f"""
<div class="container">

  <!-- Executive Summary -->
  <div class="section">
    <div class="section-title"><span class="icon">📋</span>Executive Summary</div>
    {stat_grid}
    <p style="line-height:1.8;color:#374151">{narrative}</p>
  </div>

  <!-- ATT&CK Coverage -->
  <div class="section">
    <div class="section-title"><span class="icon">🎯</span>MITRE ATT&CK® Coverage</div>
    <p style="color:#6b7280;font-size:0.88em;margin-bottom:16px">
      Tactics and techniques observed during this assessment, mapped to the MITRE ATT&CK Enterprise framework.
      <strong style="color:#3730a3">Blue highlighted</strong> cards indicate a technique was identified in at least one finding.
    </p>
    {coverage}
  </div>

  <!-- Findings Overview Table -->
  <div class="section">
    <div class="section-title"><span class="icon">🔍</span>Findings Overview</div>
    {overview}
  </div>

  <!-- Detailed Findings -->
  <div class="section">
    <div class="section-title"><span class="icon">⚠️</span>Detailed Findings</div>
    {cards if cards else '<p style="color:#9ca3af;font-style:italic">No findings recorded.</p>'}
  </div>

  <!-- Owned Assets -->
  <div class="section">
    <div class="section-title"><span class="icon">🔑</span>Compromised Assets</div>
    {assets}
  </div>

  <!-- Attack Timeline -->
  <div class="section">
    <div class="section-title"><span class="icon">📅</span>Attack Timeline</div>
    {timeline}
  </div>

</div>

<div class="report-footer">
  <div style="margin-bottom:6px">
    Generated by <strong>AdStrike v{VERSION}</strong> &mdash; creator: tmrswrr &mdash;
    MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation.
  </div>
  <div style="color:#e74c3c;font-weight:600">
    CONFIDENTIAL &mdash; For authorised use only. Do not distribute without written permission.
  </div>
</div>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_html.escape(engagement)} — AdStrike Report</title>
  <style>{_CSS}</style>
</head>
<body>
{header}
{sections}
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# ATT&CK Navigator layer
# ─────────────────────────────────────────────────────────────────────────────

def _build_navigator(engagement: str, findings: list[dict]) -> dict:
    technique_scores: dict[str, dict] = {}
    for f in findings:
        sev   = f.get("severity", "Info")
        score = SEV_ORDER.get(sev, 4)
        color = SEV_COLORS_HTML.get(sev, "#7f8c8d")
        for tid in f.get("mitre_ids", []):
            tech = TECHNIQUES.get(tid, {})
            tac  = tech.get("tactic", "")
            if not tac:
                continue
            existing = technique_scores.get(tid)
            if existing is None or score < existing["_sev_order"]:
                technique_scores[tid] = {
                    "techniqueID": tid,
                    "tactic":      tac,
                    "score":       1,
                    "color":       color,
                    "comment":     f"{f.get('name','')} [{sev}]",
                    "_sev_order":  score,
                    "enabled":     True,
                }

    techniques_out = [
        {k: v for k, v in t.items() if not k.startswith("_")}
        for t in technique_scores.values()
    ]

    return {
        "name": f"AdStrike — {engagement}",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Generated by AdStrike v{VERSION} for engagement: {engagement}",
        "techniques": techniques_out,
        "gradient": {
            "colors": ["#ffffff", "#e74c3c"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [
            {"label": sev, "color": col}
            for sev, col in SEV_COLORS_HTML.items()
        ],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1a2e",
        "selectTechniquesAcrossTactics": True,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Markdown report
# ─────────────────────────────────────────────────────────────────────────────

def _build_markdown(
    engagement: str,
    tester: str,
    domain: str,
    dc: str,
    findings: list[dict],
    owned_u: list,
    owned_m: list,
    loot: dict,
    cmds_run: int,
) -> str:
    today = datetime.date.today().isoformat()
    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ["Critical", "High", "Medium", "Low", "Info"]}
    risk_score, risk_level = _overall_risk(findings)

    lines = [
        f"# {engagement} — Security Assessment Report",
        "",
        f"**Date:** {today} | **Tester:** {tester} | **Target:** {domain} ({dc})",
        f"**Overall Risk:** {risk_level} (CVSS {risk_score:.1f})",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|:---------|------:|",
    ]
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")
    lines += [
        f"| **Total** | **{sum(counts.values())}** |",
        "",
        f"- Domain: `{domain}`",
        f"- Domain Controller: `{dc}`",
        f"- Commands run: `{cmds_run}`",
        f"- Owned users: `{len(owned_u)}`",
        f"- Owned machines: `{len(owned_m)}`",
        "",
        "---",
        "",
        "## MITRE ATT&CK Coverage",
        "",
    ]

    covered = _covered_tactics(findings)
    for tac_id, tac_label in TACTICS.items():
        mark = "✅" if tac_id in covered else "⬜"
        tids = [
            tid for f in findings for tid in f.get("mitre_ids", [])
            if TECHNIQUES.get(tid, {}).get("tactic") == tac_id
        ]
        unique_tids = list(dict.fromkeys(tids))
        ids_str = ", ".join(f"`{t}`" for t in unique_tids) if unique_tids else "—"
        lines.append(f"| {mark} | **{tac_label}** | {ids_str} |")

    lines = [
        *lines[:lines.index("## MITRE ATT&CK Coverage") + 2],
        "| | Tactic | Techniques |",
        "|:---:|:-------|:-----------|",
        *lines[lines.index("## MITRE ATT&CK Coverage") + 2:],
        "",
        "---",
        "",
        "## Findings",
        "",
    ]

    for f in findings:
        sev   = f.get("severity", "Info")
        cvss  = f.get("cvss", {}) or {}
        score = cvss.get("score", 0.0)
        vec   = cvss.get("vector", "")
        mids  = f.get("mitre_ids", [])
        _proof = str(f.get("proof_level", "observed"))
        _cmd   = str(f.get("command", "")).strip()
        lines += [
            f"### {f.get('id','')}. {f.get('name','')}",
            "",
            f"**Severity:** {sev}  ",
            f"**Proof:** {_proof}  ",
            f"**CVSS v3.1:** {score:.1f} — `{vec}`  ",
            f"**MITRE ATT&CK:** {', '.join(mids) if mids else '—'}",
            "",
            f"**Description:** {redact_text(str(f.get('description','')))}",
            "",
        ]
        if _cmd:
            lines += [f"**Evidence (command):** `{redact_text(_cmd)}`", ""]
        lines += [
            f"**Recommendation:** {redact_text(str(f.get('recommendation','')))}",
            "",
        ]
        if f.get("evidence"):
            lines += [f"**Evidence:** `{redact_text(str(f.get('evidence','')))}`", ""]

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# JSON report
# ─────────────────────────────────────────────────────────────────────────────

def _build_json(
    engagement: str,
    tester: str,
    domain: str,
    dc: str,
    findings: list[dict],
    owned_u: list,
    owned_m: list,
    loot: dict,
    commands: list[dict],
) -> dict:
    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ["Critical", "High", "Medium", "Low", "Info"]}
    risk_score, risk_level = _overall_risk(findings)
    covered = sorted(_covered_tactics(findings))

    clean_findings = []
    for f in findings:
        cf = redact_obj(dict(f))
        clean_findings.append(cf)

    return {
        "schema_version":  "2.0",
        "generated_by":    f"AdStrike v{VERSION}",
        "generated_at":    datetime.datetime.now().isoformat(),
        "engagement":      engagement,
        "tester":          tester,
        "target": {
            "domain": domain,
            "dc_ip":  dc,
        },
        "risk": {
            "overall_cvss":     risk_score,
            "overall_severity": risk_level,
        },
        "summary": counts,
        "commands_run":    len(commands),
        "owned_users":     redact_obj(owned_u),
        "owned_machines":  redact_obj(owned_m),
        "loot_keys":       list(loot.keys()),
        "mitre_tactics_covered": covered,
        "findings":        clean_findings,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Interactive manual finding entry
# ─────────────────────────────────────────────────────────────────────────────

def _prompt_manual_finding(idx: int) -> dict | None:
    try:
        name = prompt("Finding name (blank to finish)")
    except EOFError:
        return None
    if not name:
        return None
    sev  = prompt("Severity [Critical/High/Medium/Low/Info]") or "Medium"
    desc = prompt("Description") or ""
    rec  = prompt("Recommendation") or ""
    ev   = prompt("Evidence (optional)") or ""
    return {
        "id":             idx,
        "name":           name,
        "severity":       sev,
        "description":    desc,
        "recommendation": rec,
        "evidence":       ev,
        "timestamp":      datetime.datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run():
    print_banner("REPORT GENERATOR", "HTML · Markdown · JSON · ATT&CK Navigator")

    try:
        engagement = SESSION.get("engagement") or prompt("Engagement name") or "AdStrike"
    except EOFError:
        engagement = SESSION.get("engagement") or "AdStrike"

    tester   = SESSION.get("username", "tmrswrr")
    domain   = SESSION.get("domain", "Unknown")
    dc       = SESSION.get("dc_ip", "Unknown")
    commands = list(SESSION.get("commands_run", []))
    loot     = dict(SESSION.get("loot", {}))

    findings = dedupe_findings(SESSION.get("findings", []))
    SESSION["findings"] = findings

    owned_u = redact_obj(SESSION.get("owned_users", []))
    owned_m = redact_obj(SESSION.get("owned_machines", []))

    if not findings:
        warn("No auto-tracked findings. Add manually?")
        while True:
            f = _prompt_manual_finding(len(findings) + 1)
            if f is None:
                break
            findings.append(f)

    # Sort by severity
    findings.sort(key=lambda x: SEV_ORDER.get(x.get("severity", "Info"), 4))

    # MITRE + CVSS enrichment
    info("Enriching findings with MITRE ATT&CK and CVSS v3.1 scores...")
    findings = _enrich_all(findings)

    # Print enrichment summary
    for f in findings:
        mids = f.get("mitre_ids", [])
        cvss = f.get("cvss", {}) or {}
        score = cvss.get("score", 0.0)
        sev  = f.get("severity", "Info")
        from utils.helpers import SEV_COLOR, SOFT_WHITE
        col = SEV_COLOR.get(sev, "")
        ids_str = ", ".join(mids[:3]) + ("…" if len(mids) > 3 else "") if mids else "—"
        print(
            f"  {col}[{sev:<8}]{RST} "
            f"{BOLD}{f.get('name',''):<40}{RST} "
            f"{SOFT_WHITE}CVSS {score:.1f}  {ids_str}{RST}"
        )

    # Write outputs
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = Path(SESSION.get("output_dir") or str(OUTPUT_DIR)) / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    base = str(report_dir / f"adstrike_report_{ts}")

    # HTML
    html_content = _build_html(
        engagement, tester, domain, dc,
        findings, owned_u, owned_m, commands, loot
    )
    with open(f"{base}.html", "w", encoding="utf-8") as fh:
        fh.write(html_content)
    success(f"HTML     → {base}.html")

    # Markdown
    md_content = _build_markdown(
        engagement, tester, domain, dc,
        findings, owned_u, owned_m, loot, len(commands)
    )
    with open(f"{base}.md", "w", encoding="utf-8") as fh:
        fh.write(md_content)
    success(f"Markdown → {base}.md")

    # JSON
    json_data = _build_json(
        engagement, tester, domain, dc,
        findings, owned_u, owned_m, loot, commands
    )
    with open(f"{base}.json", "w", encoding="utf-8") as fh:
        json.dump(json_data, fh, indent=2, default=str)
    success(f"JSON     → {base}.json")

    # ATT&CK Navigator layer
    nav_data = _build_navigator(engagement, findings)
    nav_path = f"{base}_navigator.json"
    with open(nav_path, "w", encoding="utf-8") as fh:
        json.dump(nav_data, fh, indent=2)
    success(f"Navigator→ {nav_path}")
    info("Import the Navigator layer at: https://mitre-attack.github.io/attack-navigator/")

    # Risk summary
    risk_score, risk_level = _overall_risk(findings)
    col = SEV_COLORS_HTML.get(risk_level, "#888")
    print(f"\n  {BOLD}Overall Risk:{RST} {risk_level} (CVSS {risk_score:.1f})")
    covered = _covered_tactics(findings)
    print(f"  {BOLD}Tactics covered:{RST} {len(covered)}/{len(TACTICS)}")

    pause()
    return {
        "html":      f"{base}.html",
        "markdown":  f"{base}.md",
        "json":      f"{base}.json",
        "navigator": nav_path,
    }
