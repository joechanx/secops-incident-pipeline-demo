from __future__ import annotations

import json
from pathlib import Path

import pandas as pd


def export_outputs(incidents: pd.DataFrame, output_dir: str, markdown: bool = True) -> dict:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    incidents_path = out / "incidents.csv"
    metrics_path = out / "metrics.json"
    summary_path = out / "incident_summary.md"

    incidents.to_csv(incidents_path, index=False)

    metrics = {
        "incident_count": int(len(incidents)),
        "p1_count": int((incidents["priority"] == "P1").sum()) if len(incidents) else 0,
        "p2_count": int((incidents["priority"] == "P2").sum()) if len(incidents) else 0,
        "max_risk_score": int(incidents["risk_score"].max()) if len(incidents) else 0,
        "sources_present": sorted(
            {src for x in incidents["source_types"].dropna().astype(str) for src in x.split(",")}
        ) if len(incidents) else [],
    }
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    if markdown:
        lines = [
            "# Incident Summary",
            "",
            f"- Total incidents: **{metrics['incident_count']}**",
            f"- P1 incidents: **{metrics['p1_count']}**",
            f"- P2 incidents: **{metrics['p2_count']}**",
            f"- Max risk score: **{metrics['max_risk_score']}**",
            "",
            "## Top incidents",
            "",
        ]
        top = incidents.head(5)
        for _, row in top.iterrows():
            lines.extend(
                [
                    f"### {row['incident_id']} – {row['priority']} – score {row['risk_score']}",
                    f"- Time: {row['start_time']} to {row['end_time']}",
                    f"- Asset: {row['asset_id']} / {row.get('hostname', '')}",
                    f"- User: {row['user_id']}",
                    f"- Sources: {row['source_types']}",
                    f"- Title(s): {row['titles']}",
                    f"- Action: {row['recommended_action']}",
                    "",
                ]
            )
        summary_path.write_text("\n".join(lines), encoding="utf-8")

    return {
        "incidents_csv": str(incidents_path),
        "metrics_json": str(metrics_path),
        "incident_summary_md": str(summary_path),
    }
