from pathlib import Path
from typing import List, Optional
from apk_inspector.reports.models import ApkSummary
from apk_inspector.utils.logger import get_logger
import json
from datetime import datetime


def generate_per_apk_dashboard(summary: ApkSummary, apk_dir: Path, report_json: Path) -> Optional[Path]:
    pkg = summary.apk_package
    output_path = apk_dir / f"{pkg}_dashboard.html"
    charts = [
        ("yara_tag_pie.png", "Tag Distribution"),
        ("risk_breakdown.png", "Risk Breakdown")
    ]

    risk_table_html = ""
    pretty_json = ""
    escaped_json = ""

    if report_json.exists():
        try:
            data = json.loads(report_json.read_text(encoding="utf-8"))
            pretty_json = json.dumps(data, indent=2)
            escaped_json = pretty_json.replace("<", "&lt;").replace(">", "&gt;")

            if "risk_breakdown" in data:
                breakdown = data["risk_breakdown"]
                risk_table_html = """
<h3>🧮 Risk Breakdown Table</h3>
<table style="width:100%; border-collapse: collapse; margin-top: 10px;">
<thead>
<tr>
<th>Static</th><th>Dynamic</th><th>Dyn Bonus</th>
<th>YARA</th><th>Hooks</th><th>Total</th>
</tr>
</thead>
<tbody>
<tr style="text-align:center;">
<td>{static}</td><td>{dynamic}</td><td>{bonus}</td>
<td>{yara}</td><td>{hooks}</td><td>{total}</td>
</tr>
</tbody>
</table>
""".format(
    static=breakdown.get("static_score", 0),
    dynamic=breakdown.get("dynamic_score", 0),
    bonus=breakdown.get("dynamic_rule_bonus", 0),
    yara=breakdown.get("yara_score", 0),
    hooks=breakdown.get("hook_score", 0),
    total=breakdown.get("total_score", 0)
)

        except Exception as e:
            get_logger().error(f"[!] Failed to read or format report.json: {e}")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>APK Dashboard: {pkg}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {{
  --primary: #2a9d8f; --bg-light: #ffffff; --fg-light: #333333;
  --bg-dark: #1e1e1e; --fg-dark: #dddddd;
}}
body {{
  font-family: sans-serif; margin: 40px;
  background-color: var(--bg-light); color: var(--fg-light);
  transition: background-color 0.3s, color 0.3s;
}}
.dark-mode {{ background-color: var(--bg-dark); color: var(--fg-dark); }}
h2 {{ color: var(--primary); }}
.meta {{ margin-bottom: 20px; }}
.charts {{ display: flex; flex-wrap: wrap; gap: 20px; }}
.chart {{ flex: 1 1 400px; max-width: 600px; }}
.chart img {{ width: 100%; height: auto; }}
.download {{ margin-top: 30px; }}
.json-preview {{ background: #f6f8fa; padding: 10px; border-radius: 6px;
                 border: 1px solid #ccc; max-height: 600px; overflow-y: auto;
                 white-space: pre-wrap; font-family: monospace; }}
.dark-mode .json-preview {{ background: #2a2a2a; border-color: #444; color: #ddd; }}
.json-filter {{ margin-top: 10px; }}
.toggle-switch {{
  position: fixed; top: 20px; right: 20px;
  cursor: pointer; font-size: 1.2em;
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

<div class="charts">"""

    for filename, label in charts:
        path = apk_dir / filename
        if path.exists():
            html += f"""
  <div class="chart">
    <strong>{label}</strong><br>
    <img src="{filename}" alt="{label}">
  </div>"""
        else:
            get_logger().warning(f"[~] Missing chart: {filename}")

    html += "</div>" + risk_table_html

    if pretty_json:
        html += f"""
<div class="download">
  <strong>📄 Full JSON Report:</strong>
  <details open>
    <summary>🔍 View embedded JSON</summary>
    <div class="json-filter">
      <input type="text" id="jsonFilter" placeholder="Type to filter..." style="width:100%; padding:8px;">
    </div>
    <pre class="json-preview" id="jsonPreview"><code>{escaped_json}</code></pre>
  </details>
  <p><a href="{report_json.name}" download>⬇ Download report.json</a></p>
</div>"""

    html += """
<script>
function toggleDarkMode() {
  document.body.classList.toggle('dark-mode');
  localStorage.setItem('dark-mode', document.body.classList.contains('dark-mode'));
}
window.addEventListener('load', function() {
  if (localStorage.getItem('dark-mode') === 'true') {
    document.body.classList.add('dark-mode');
  }
  const filter = document.getElementById('jsonFilter');
  if (filter) {
    filter.addEventListener('input', function() {
      const raw = document.getElementById('jsonPreview').innerText;
      const lines = raw.split('\\n');
      const query = this.value.toLowerCase();
      const filtered = lines.filter(l => l.toLowerCase().includes(query));
      document.getElementById('jsonPreview').innerHTML = '<code>' + filtered.join('\\n') + '</code>';
    });
  }
});
</script>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    get_logger().info(f"[✓] Dashboard saved: {output_path.name}")
    return output_path
