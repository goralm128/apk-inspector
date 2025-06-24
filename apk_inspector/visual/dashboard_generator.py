from datetime import datetime
from pathlib import Path
from typing import List, Optional
import json
from apk_inspector.reports.models import ApkSummary
from apk_inspector.utils.logger import get_logger


# --- Theme and Utility Loaders ---

def load_theme_variants() -> dict:
    return {
        "Default": {"--bg": "#ffffff", "--fg": "#333333"},
        "Ocean": {"--bg": "#2b303b", "--fg": "#c0c5ce"},
        "Solarized": {"--bg": "#fdf6e3", "--fg": "#657b83"},
        "Cyberpunk": {"--bg": "#0f0f0f", "--fg": "#39ff14"},
    }


def load_combined_json(run_dir: Path, logger) -> str:
    path = run_dir / "combined_summary.json"
    if not path.exists():
        return ""
    try:
        return json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=2)
    except Exception as e:
        logger.error(f"Error loading combined_summary.json: {e}")
        return ""


def find_summary_chart(run_dir: Path) -> Optional[str]:
    for name in ["summary_chart.png", "summary_heatmap.png", "risk_overview.png"]:
        if (run_dir / name).exists():
            return name
    return None


# --- HTML Component Builders ---

def render_cvss_badge(band: str) -> str:
    color = {
        "Low": "#28a745", "Medium": "#ffc107",
        "High": "#dc3545", "Critical": "#721c24"
    }.get(band, "#6c757d")
    return f'<span class="badge" style="background:{color}">{band}</span>'


def build_table_rows(summaries: List[ApkSummary]) -> str:
    return "\n".join(
        f"<tr>"
        f"<td><a href='{s.apk_package}/{s.apk_package}_dashboard.html'>{s.apk_package}</a></td>"
        f"<td>{s.classification}</td>"
        f"<td style='text-align:center'>{s.risk_score}</td>"
        f"<td style='text-align:center'>{render_cvss_badge(s.cvss_risk_band)}</td>"
        f"</tr>"
        for s in summaries
    )


def build_theme_css(themes: dict) -> str:
    return "\n".join(
        f".theme-{name} {{ background-color: {vals['--bg']}; color: {vals['--fg']}; }}"
        for name, vals in themes.items()
    )


# --- Main Page Generator ---

def generate_index_page(
    summaries: List[ApkSummary],
    run_dir: Path,
    filename: str = "index.html",
    theme_overrides: Optional[dict] = None
) -> Path:
    logger = get_logger()
    index_path = run_dir / filename

    summaries.sort(key=lambda s: s.risk_score, reverse=True)
    themes = load_theme_variants()
    if theme_overrides:
        themes["Custom"] = theme_overrides

    rows = build_table_rows(summaries)
    combined_json = load_combined_json(run_dir, logger)
    chart = find_summary_chart(run_dir)
    theme_css = build_theme_css(themes)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M")

    theme_selector_html = "".join(f"<option value='{name}'>{name}</option>" for name in themes)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>APK Analysis Summary</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {{ font-family: sans-serif; margin: 40px; transition: background 0.3s; }}
    .badge {{ padding: 4px 8px; border-radius: 10px; color: #fff; font-weight: bold; }}
    {theme_css}
    .theme-selector, .search-box {{ margin-bottom: 20px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 12px; border: 1px solid #ccc; }}
    th {{ cursor: pointer; }}
  </style>
</head>
<body class="theme-Default">
  <h1>APK Analysis Summary</h1>
  <p>Generated at: {timestamp} UTC</p>

  <div class="theme-selector">
    Theme:
    <select id="themeSelect">{theme_selector_html}</select>
  </div>

  <div class="search-box">
    <input type="text" id="globalSearch" placeholder="Search..." style="padding:6px;width:100%;">
  </div>

  {"<div><strong>📊 Summary Chart</strong><br><img src='" + chart + "' style='max-width:100%;'></div>" if chart else ""}

  <table id="apk-table">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Package ▲▼</th>
        <th onclick="sortTable(1)">Classification ▲▼</th>
        <th onclick="sortTable(2)">Risk Score ▲▼</th>
        <th onclick="sortTable(3)">CVSS Band ▲▼</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>

  {'<details><summary>🔍 JSON Preview</summary><pre id="jsonPreview" style="background:#f6f8fa;padding:10px;max-height:400px;overflow:auto;"></pre></details>' if combined_json else ''}

  <script>
    { 'document.getElementById("jsonPreview").innerText = ' + json.dumps(combined_json) + ';' if combined_json else '' }

    document.getElementById("globalSearch").oninput = function() {{
      const term = this.value.toLowerCase();
      document.querySelectorAll("#apk-table tbody tr").forEach(row => {{
        row.style.display = [...row.cells].some(cell => cell.innerText.toLowerCase().includes(term)) ? "" : "none";
      }});
    }};

    function sortTable(colIndex) {{
      const tbody = document.querySelector("#apk-table tbody");
      [...tbody.rows].sort((a, b) => {{
        const x = a.cells[colIndex].innerText, y = b.cells[colIndex].innerText;
        return isNaN(x) ? x.localeCompare(y) : y - x;
      }}).forEach(row => tbody.appendChild(row));
    }}

    document.getElementById("themeSelect").onchange = e => {{
      document.body.className = "theme-" + e.target.value;
    }};
  </script>
</body>
</html>
"""
    index_path.write_text(html, encoding="utf-8")
    logger.info(f"[✓] Summary index generated: {index_path.name}")
    return index_path
