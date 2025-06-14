import pandas as pd
import plotly.express as px
from typing import List, Dict

def visualize_tag_heatmap(events: List[Dict[str, any]], output_path: str = "tag_heatmap.html"):
    rows = []
    for ev in events:
        for tag in ev.get("tags", []):
            rows.append({
                "tag": tag,
                "category": ev.get("category", "unknown"),
                "score": ev.get("score", 0)
            })

    df = pd.DataFrame(rows)
    if df.empty:
        print("No tag data to visualize.")
        return

    agg = df.groupby("tag").agg({
        "score": "sum",
        "tag": "count"
    }).rename(columns={"tag": "frequency"})
    agg["avg_score"] = agg["score"] / agg["frequency"]

    fig = px.scatter(
        agg.reset_index(),
        x="frequency",
        y="avg_score",
        size="frequency",
        hover_name="tag",
        title="Tag Risk Heatmap"
    )
    fig.write_html(output_path)
    print(f"[✓] Heatmap saved to {output_path}")
