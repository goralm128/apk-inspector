from pathlib import Path
from typing import Optional
from apk_inspector.reports.models import ApkSummary
from apk_inspector.utils.logger import get_logger
import json

logger = get_logger()

def _load_json(report_json: Path) -> Optional[dict]:
    try:
        return json.loads(report_json.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error(f"[!] Failed to load JSON report: {e}")
        return None

def _render_permissions(data: dict) -> str:
    manifest = data.get("static_analysis", {}).get("manifest_analysis", {})
    permissions = manifest.get("permissions", [])
    dangerous = set(manifest.get("dangerous_permissions", []))
    suspicious = set(manifest.get("suspicious_permissions", []))
    risky = {
        "android.permission.WRITE_SMS",
        "android.permission.KILL_BACKGROUND_PROCESSES",
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.CHANGE_WIFI_STATE"
    }

    if not permissions:
        return ""

    def badge(label, color):
        return f"<span style='background:{color}; color:white; padding:2px 6px; border-radius:6px; font-size:0.85em'>{label}</span>"

    html = ['<h3>🔐 Permissions Overview</h3>']
    html.append('<table style="width:100%; border-collapse: collapse; margin-bottom:20px;">')
    html.append('<thead><tr><th>Permission</th><th style="text-align:center;">Flags</th></tr></thead><tbody>')

    for perm in sorted(set(permissions)):
        flags = []
        if perm in dangerous:
            flags.append(badge("Dangerous", "#dc3545"))
        if perm in suspicious:
            flags.append(badge("Suspicious", "#ffc107"))
        if perm in risky:
            flags.append(badge("High Risk", "#6f42c1"))

        html.append(f"<tr><td>{perm}</td><td style='text-align:center'>{' '.join(flags) or '-'}</td></tr>")

    html.append("</tbody></table>")
    return "\n".join(html)

def _render_risk_table(data: dict) -> str:
    rb = data.get("risk_breakdown", {})
    if not rb:
        return ""
    return f"""
<h3>🧮 Risk Breakdown</h3>
<table style="width:100%; border-collapse: collapse; margin-top:10px;">
  <thead>
    <tr>
      <th>Static</th><th>Dynamic</th><th>Bonus</th>
      <th>YARA</th><th>Hooks</th><th>Total</th>
    </tr>
  </thead>
  <tbody>
    <tr style="text-align:center;">
      <td>{rb.get("static_score", 0)}</td>
      <td>{rb.get("dynamic_score", 0)}</td>
      <td>{rb.get("dynamic_rule_bonus", 0)}</td>
      <td>{rb.get("yara_score", 0)}</td>
      <td>{rb.get("hook_score", 0)}</td>
      <td>{rb.get("total_score", 0)}</td>
    </tr>
  </tbody>
</table>
"""

def _render_charts(apk_dir: Path, charts: list) -> str:
    html = ['<div class="charts">']
    for fname, label in charts:
        if (apk_dir / fname).exists():
            html.append(f'''
  <div class="chart">
    <strong>{label}</strong><br>
    <img src="{fname}" alt="{label}">
  </div>''')
        else:
            logger.warning(f"[~] Missing chart: {fname}")
    html.append('</div>')
    return "\n".join(html)

def generate_per_apk_dashboard(
    summary: ApkSummary, apk_dir: Path, report_json: Path
) -> Optional[Path]:
    pkg = summary.apk_package
    out = apk_dir / f"{pkg}_dashboard.html"
    data = _load_json(report_json)
    if data is None:
        return None

    risk_table = _render_risk_table(data)
    permissions_table = _render_permissions(data)
    charts = [("yara_tag_pie.png", "Tag Distribution"),
              ("risk_breakdown.png", "Risk Breakdown")]
    charts_section = _render_charts(apk_dir, charts)

    pretty_json = json.dumps(data, indent=2)
    escaped_json = (
        pretty_json.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
    )

    yara_summary = apk_dir / "yara_summary.csv"
    yara_results = apk_dir / "yara_results.json"

    yara_links = ""
    if yara_summary.exists():
        yara_links += f'<a class="button" href="{yara_summary.name}" download>⬇ YARA Summary (CSV)</a>'
    if yara_results.exists():
        yara_links += f'<a class="button" href="{yara_results.name}" download>⬇ YARA Results (JSON)</a>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>APK Dashboard: {pkg}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {{
      --primary: #2a9d8f;
      --bg-light: #ffffff; --fg-light: #333333;
      --bg-dark: #1e1e1e; --fg-dark: #dddddd;
    }}
    body {{
      font-family: sans-serif;
      margin: 40px;
      background-color: var(--bg-light);
      color: var(--fg-light);
      transition: background-color 0.3s, color 0.3s;
    }}
    .dark-mode {{
      background-color: var(--bg-dark);
      color: var(--fg-dark);
    }}
    h2 {{ color: var(--primary); }}
    .meta {{ margin-bottom: 20px; }}
    .charts {{
      display: flex; flex-wrap: wrap; gap: 20px;
    }}
    .chart {{
      flex: 1 1 300px; max-width: 600px;
    }}
    .chart img {{
      width: 100%; height: auto;
    }}
    .download {{ margin-bottom: 20px; }}
    .button {{
      display: inline-block;
      margin: 10px 10px 0 0;
      padding: 10px 15px;
      background: var(--primary);
      color: #fff;
      text-decoration: none;
      border-radius: 5px;
      font-weight: bold;
    }}
    .button:hover {{
      background: #21867a;
    }}
    pre {{
      background: #f6f8fa; padding: 10px; border-radius: 6px;
      border: 1px solid #ccc; white-space: pre-wrap;
      max-height: 600px; overflow-y: auto;
      font-family: monospace;
    }}
    .dark-mode pre {{
      background: #2a2a2a;
      border-color: #444;
      color: #ddd;
    }}
    .toggle-switch {{
      position: fixed;
      top: 20px;
      right: 20px;
      cursor: pointer;
      font-size: 1.2em;
    }}
    table th, table td {{
      padding: 8px; border: 1px solid #ccc;
    }}
    .dark-mode table th, .dark-mode table td {{
      border-color: #555;
    }}
  </style>
</head>
<body>
  <div class="toggle-switch" onclick="toggleDarkMode()">🌓 Toggle Dark Mode</div>
  <h2>{summary.apk_name}</h2>
  <div class="meta">
    <strong>Package:</strong> {pkg}<br>
    <strong>SHA256:</strong> {summary.sha256}<br>
    <strong>Classification:</strong> {summary.classification}<br>
    <strong>Risk Score:</strong> {summary.risk_score}<br>
    <strong>CVSS Band:</strong> {summary.cvss_risk_band}
  </div>

  <div class="download">
    <a class="button" href="{report_json.name}" download>⬇ Full JSON Report</a>
    {yara_links}
  </div>

  {charts_section}
  {risk_table}
  {permissions_table}

  <details open>
    <summary>🔍 View Embedded JSON</summary>
    <pre>{escaped_json}</pre>
  </details>

  <script>
    function toggleDarkMode() {{
      document.body.classList.toggle('dark-mode');
      localStorage.setItem('dark-mode', document.body.classList.contains('dark-mode'));
    }}
    window.addEventListener('load', function() {{
      if (localStorage.getItem('dark-mode') === 'true') {{
        document.body.classList.add('dark-mode');
      }}
    }});
  </script>
</body>
</html>
"""
    out.write_text(html, encoding="utf-8")
    logger.info(f"[✓] Dashboard saved: {out.name}")
    return out
