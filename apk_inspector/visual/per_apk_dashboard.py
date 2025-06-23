from pathlib import Path
from typing import List, Optional
from apk_inspector.reports.models import ApkSummary
from apk_inspector.utils.logger import get_logger
import json

def generate_per_apk_dashboard(summary: ApkSummary, apk_dir: Path, report_json: Path) -> Optional[Path]:
    pkg = summary.apk_package
    output_path = apk_dir / f"{pkg}_dashboard.html"
    charts = [
        ("yara_tag_pie.png", "Tag Distribution"),
        #("stacked_family.png", "Malware Family vs Category"),
        #("stacked_severity.png", "Severity vs Category"),
        ("risk_breakdown.png", "Risk Breakdown")
    ]

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>APK Dashboard: {pkg}</title>
    <style>
        body {{ font-family: sans-serif; margin: 40px; }}
        h2 {{ color: #2a9d8f; }}
        img {{ max-width: 600px; margin: 20px 0; }}
        .meta {{ margin-bottom: 20px; }}
        .download {{ margin-top: 30px; }}
        pre {{ background: #f6f8fa; padding: 10px; border-radius: 6px; overflow: auto; max-height: 600px; }}
        details summary {{ cursor: pointer; font-weight: bold; color: #264653; }}
    </style>
</head>
<body>
    <h2>{summary.apk_name}</h2>
    <div class="meta">
        <strong>Package:</strong> {pkg}<br>
        <strong>SHA256:</strong> {summary.sha256}<br>
        <strong>Classification:</strong> {summary.classification}<br>
        <strong>Risk Score:</strong> {summary.risk_score}<br>
        <strong>CVSS Band:</strong> {summary.cvss_risk_band}
    </div>
"""

    for filename, label in charts:
        path = apk_dir / filename
        if path.exists():
            html += f'<div><strong>{label}</strong><br><img src="{filename}" alt="{label}"></div>\n'
        else:
            get_logger().warning(f"[~] Missing chart: {filename}")

    if report_json.exists():
        try:
            report_data = report_json.read_text(encoding="utf-8")
            pretty_json = json.dumps(json.loads(report_data), indent=2)
            html += f"""
            <div class="download">
                <strong>📄 Full JSON Report:</strong><br>
                <details>
                    <summary>Click to view embedded JSON report</summary>
                    <pre>{pretty_json}</pre>
                </details>
                <p><a href="{report_json.name}" download>Download report.json</a></p>
            </div>
            """
        except Exception as e:
            get_logger().error(f"[!] Failed to read or format report.json: {e}")

    html += "</body></html>"
    output_path.write_text(html, encoding="utf-8")
    get_logger().info(f"[✓] Dashboard saved: {output_path.name}")
    return output_path


def generate_index_page(summaries: List[ApkSummary], run_dir: Path, filename: str = "index.html") -> Path:
    index_path = run_dir / filename
    rows = "\n".join([
        f"""<tr>
            <td><a href="{summary.apk_package}/{summary.apk_package}_dashboard.html">{summary.apk_package}</a></td>
            <td>{summary.classification}</td>
            <td style="text-align:center;">{summary.risk_score}</td>
            <td>{summary.cvss_risk_band}</td>
        </tr>""" for summary in summaries
    ])

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>APK Analysis Index</title>
    <style>
        body {{ font-family: sans-serif; margin: 40px; }}
        h1 {{ color: #2a9d8f; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; border-bottom: 1px solid #ccc; text-align: left; }}
        th {{ background-color: #f4f4f4; }}
        td:nth-child(3) {{ text-align: center; }}
        a {{ color: #264653; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <h1>APK Analysis Summary</h1>
    <table>
        <thead>
            <tr>
                <th style="width: 40%;">Package</th>
                <th style="width: 20%;">Classification</th>
                <th style="width: 20%;">Risk Score</th>
                <th style="width: 20%;">CVSS Band</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"""

    index_path.write_text(html, encoding="utf-8")
    get_logger().info(f"[✓] Summary index generated: {index_path.name}")
    return index_path
