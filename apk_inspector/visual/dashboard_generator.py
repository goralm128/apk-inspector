from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from datetime import datetime
import shutil
from apk_inspector.utils.logger import get_logger


def generate_html_dashboard(
    run_dir: Path,
    report_json_path: Path,
    summary_csv_path: Path,
    charts: list,
    logger=None
):
    
    logger = logger or get_logger()
    try:
        template_dir = Path(__file__).parent / "templates"
        output_html = run_dir / "dashboard.html"

        # Ensure template directory exists
        if not template_dir.exists():
            logger.error(f"[✗] Template directory not found: {template_dir}")
            return

        # Setup Jinja2
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )

        template = env.get_template("dashboard.html")

        # Copy chart images to output directory (optional if not already there)
        chart_filenames = []
        for chart_path in charts:
            if chart_path.exists():
                target_path = run_dir / chart_path.name
                if chart_path.resolve() != target_path.resolve():
                    shutil.copy(chart_path, target_path)
                chart_filenames.append(chart_path.name)
            else:
                logger.warning(f"[!] Chart not found: {chart_path}")

        # Render template
        rendered = template.render(
            report_json=report_json_path.name,
            summary_csv=summary_csv_path.name,
            charts=chart_filenames,
            generated_on=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        )

        output_html.write_text(rendered, encoding="utf-8")
        logger.info(f"[✓] Dashboard saved to: {output_html.resolve()}")

    except Exception as e:
        logger.exception(f"[✗] Failed to generate HTML dashboard: {e}")
