import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from typing import List, Dict, Optional
from collections import Counter
from apk_inspector.reports.models import ApkSummary
from apk_inspector.utils.logger import get_logger
from apk_inspector.visual.chart_theme import apply_default_theme
import textwrap

apply_default_theme()

CATEGORY_COLOR_MAP = {
    "overlay_abuse": "#8c564b",
    "crypto_usage": "#1f77b4",
    "network_exfiltration": "#2ca02c",
    "reflection": "#c7c7c7",
    "sensitive_string": "#17becf",
    "telemetry": "#ff7f0e",
    "native_exec": "#9467bd",
    "device_id_leak": "#d62728",
    "system_behavior": "#8dd3c7",
    "uncategorized": "#999999",
    "unknown": "#aaaaaa"
}


def generate_stacked_chart(
    reports: List[Dict],
    index_field: str,
    column_field: str,
    title: str,
    filename: str,
    run_dir: Path
) -> Optional[Path]:
    logger = get_logger()
    rows = []

    for report in reports:
        for match in report.get("yara_matches", []):
            meta = match.get("meta", {})
            rows.append({
                index_field: str(meta.get(index_field, "unknown")).lower() or "unknown",
                column_field: str(meta.get(column_field, "uncategorized")).lower() or "uncategorized"
            })

    if not rows:
        logger.warning(f"No data for chart: {index_field} x {column_field}")
        return None

    df = pd.DataFrame(rows)
    pivot = df.pivot_table(index=index_field, columns=column_field, aggfunc="size", fill_value=0)
    if index_field == "severity":
        pivot = pivot.reindex(["info", "low", "medium", "high", "critical"], fill_value=0)

    fig, ax = plt.subplots(figsize=(12, 6))
    pivot.plot(kind="bar", stacked=True,
               color=[CATEGORY_COLOR_MAP.get(c, "#999999") for c in pivot.columns],
               ax=ax)

    ax.set_title(textwrap.shorten(title, 80, placeholder="..."))
    ax.set_xlabel(index_field.replace("_", " ").title())
    ax.set_ylabel("Match Count")
    ax.set_xticklabels([label.title() for label in pivot.index],
                       rotation=45 if index_field != "severity" else 0, ha="right")

    if len(reports) == 1 and pivot.values.max() <= 25:
        for container in ax.containers:
            ax.bar_label(container, label_type="center", fontsize=8)

    run_dir.mkdir(parents=True, exist_ok=True)
    output_path = run_dir / filename
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)
    logger.info(f"[✓] Saved stacked chart: {output_path}")
    return output_path


def generate_tag_pie_chart(tag_counts: Counter, title: str, output_path: Path, top_n: int = 8, dark_mode: bool = False):
    """
    Generates a pie chart of the top YARA tag counts with a legend.

    Args:
        tag_counts (Counter): Tag frequency counter.
        title (str): Chart title.
        output_path (Path): Path to save the chart image.
        top_n (int): Number of top tags to show individually.
        dark_mode (bool): Use dark theme styling.
    """
    if not tag_counts:
        return

    # Style settings
    bg_color = "#1e1e1e" if dark_mode else "white"
    text_color = "white" if dark_mode else "black"
    edge_color = "#cccccc" if dark_mode else "black"

    # Get top tags + group the rest as 'other'
    most_common = tag_counts.most_common(top_n)
    labels = [tag for tag, _ in most_common]
    sizes = [count for _, count in most_common]
    other_total = sum(tag_counts.values()) - sum(sizes)

    if other_total > 0:
        labels.append("other")
        sizes.append(other_total)

    def autopct_format(pct):
        return f"{pct:.1f}%" if pct >= 5 else ""  # Only show labels for 5%+

    fig, ax = plt.subplots(figsize=(7, 6), facecolor=bg_color)
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=None,
        autopct=autopct_format,
        startangle=140,
        wedgeprops={"edgecolor": edge_color},
        pctdistance=0.8
    )

    ax.legend(
        wedges,
        labels,
        title="YARA Tags",
        loc="center left",
        bbox_to_anchor=(1, 0.5),
        facecolor=bg_color,
        labelcolor=text_color
    )
    ax.set_title(title, color=text_color)
    ax.set_facecolor(bg_color)

    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=300, facecolor=fig.get_facecolor())
    plt.close()
    
def generate_risk_breakdown_chart(summary: ApkSummary, apk_dir: Path) -> Optional[Path]:
    logger = get_logger()
    breakdown = summary.risk_breakdown or {}
    if not breakdown:
        logger.warning(f"[~] No risk breakdown for {summary.apk_name}")
        return None
    

    labels = list(breakdown.keys())
    scores = list(breakdown.values())

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(labels, scores, color="#2a9d8f")
    ax.set_title(f"Risk Breakdown: {summary.apk_name}")
    ax.set_ylabel("Score")
    ax.set_xlabel("Component")
    ax.set_ylim(0, 100)
    ax.grid(axis="y", linestyle="--", alpha=0.6)
    plt.xticks(rotation=30, ha="right")

    output_path = apk_dir / "risk_breakdown.png"
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)
    logger.info(f"[✓] Saved risk chart: {output_path}")
    return output_path
