from __future__ import annotations

import os

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from src.pipeline.correlate import correlate_events
from src.pipeline.enrich import enrich_events
from src.pipeline.export import export_outputs
from src.pipeline.ingest import ingest_sources
from src.pipeline.normalize import normalize_events
from src.pipeline.score import apply_scoring
from src.utils.config import load_yaml
from src.utils.logger import get_logger

console = Console()
logger = get_logger(__name__)


@click.command()
@click.option("--config", "config_path", default="config/pipeline.yaml", show_default=True)
def main(config_path: str) -> None:
    load_dotenv()

    pipeline_config = load_yaml(config_path)
    rules = load_yaml(os.getenv("SCORING_RULES", pipeline_config["scoring_rules"]))

    logger.info("Loading sources")
    datasets = ingest_sources(
        raw_dir=os.getenv("RAW_DATA_DIR", pipeline_config["raw_data_dir"]),
        ref_dir=os.getenv("REF_DATA_DIR", pipeline_config["ref_data_dir"]),
        source_map_path=pipeline_config["source_map"],
    )

    logger.info("Normalizing events")
    events = normalize_events(datasets)

    logger.info("Enriching events")
    enriched = enrich_events(
        events=events,
        users_df=datasets["users"],
        assets_df=datasets["assets"],
        vuln_df=datasets["vuln_findings"],
    )

    logger.info("Correlating incidents")
    incidents = correlate_events(
        enriched, int(os.getenv("CORRELATION_WINDOW_MINUTES", pipeline_config["correlation_window_minutes"]))
    )

    logger.info("Scoring incidents")
    scored = apply_scoring(incidents, rules)

    logger.info("Exporting outputs")
    outputs = export_outputs(
        scored,
        output_dir=os.getenv("OUTPUT_DIR", pipeline_config["output_dir"]),
        markdown=str(os.getenv("ENABLE_MARKDOWN_SUMMARY", "true")).lower() == "true",
    )

    table = Table(title="Pipeline Result")
    table.add_column("Incident ID")
    table.add_column("Priority")
    table.add_column("Risk Score")
    table.add_column("Sources")
    table.add_column("Asset")
    table.add_column("User")
    for _, row in scored.head(5).iterrows():
        table.add_row(
            str(row["incident_id"]),
            str(row["priority"]),
            str(row["risk_score"]),
            str(row["source_types"]),
            str(row["asset_id"]),
            str(row["user_id"]),
        )
    console.print(table)
    console.print(f"Outputs written to: {outputs}")


if __name__ == "__main__":
    main()
