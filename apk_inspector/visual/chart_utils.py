import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from typing import List, Dict, Optional

from apk_inspector.utils.logger import get_logger


def generate_stacked_chart(
    reports: List[Dict],
    index_field: str,
    column_field: str,
    title: str,
    filename: str,
    run_dir: Path
) -> None:
    """
    Generate a stacked bar chart from YARA metadata across APK reports.

    Args:
        reports (List[Dict]): List of full APK report dictionaries.
        index_field (str): Metadata field to use as chart row/category (e.g., "malware_family").
        column_field (str): Metadata field to use as the stacked segments (e.g., "category").
        title (str): Title for the chart.
        filename (str): Output filename for the saved PNG.
        run_dir (Path): Directory to save the output chart.
        logger (Optional[Logger]): Logger instance for debug or info output.
    """
    
    
    logger = get_logger()

    rows = []

    for report in reports:
        yara_matches = report.get("yara_matches", [])
        for match in yara_matches:
            meta = match.get("meta", {})
            index_val = str(meta.get(index_field, "unknown")).lower()
            column_val = str(meta.get(column_field, "uncategorized")).lower()
            rows.append({index_field: index_val, column_field: column_val})

    if not rows:
        if logger:
            logger.warning(f"No metadata to plot for index={index_field} and column={column_field}.")
        return

    df = pd.DataFrame(rows)
    pivot = df.pivot_table(index=index_field, columns=column_field, aggfunc="size", fill_value=0)
    pivot = pivot.sort_index()
    
    # Optional severity ordering
    if index_field == "severity":
        severity_order = ["critical", "high", "medium", "low", "info"]
        pivot = pivot.reindex(severity_order, fill_value=0)

    plt.figure(figsize=(10, 6))
    pivot.plot(kind="bar", stacked=True, colormap="tab20", figsize=(12, 6))

    plt.title(title)
    plt.xlabel(index_field.replace("_", " ").title())
    plt.ylabel("Match Count")
    plt.xticks(rotation=45 if index_field != "severity" else 0, ha="right")
    plt.tight_layout()

    output_path = run_dir / filename
    plt.savefig(output_path)
    plt.close()

    if logger:
        logger.info(f" Saved stacked chart: {title} → {output_path.resolve()}")
