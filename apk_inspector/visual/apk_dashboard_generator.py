from pathlib import Path
from typing import Optional
from apk_inspector.reports.models import ApkSummary
from apk_inspector.utils.logger import get_logger
import json


def _load_json(report_json: Path) -> Optional[dict]:
    try:
        return json.loads(report_json.read_text(encoding="utf-8"))
    except Exception as e:
        get_logger().error(f"[!] Failed to load JSON report: {e}")
        return None


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
            get_logger().warning(f"[~] Missing chart: {fname}")
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
    charts = [("yara_tag_pie.png", "Tag Distribution"),
              ("risk_breakdown.png", "Risk Breakdown")]
    charts_section = _render_charts(apk_dir, charts)

    pretty_json = json.dumps(data, indent=2)
    escaped_json = (
        pretty_json.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
    )

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
    .download {{ margin-top: 30px; }}
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
  {charts_section}
  {risk_table}
  <div class="download">
    <strong>📄 JSON Report:</strong>
    <details open>
      <summary>🔍 View Embedded JSON</summary>
      <pre>{escaped_json}</pre>
    </details>
    <p><a href="{report_json.name}" download>⬇ Download report.json</a></p>
  </div>
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
    get_logger().info(f"[✓] Dashboard saved: {out.name}")
    return out
