from src.pipeline.correlate import correlate_events
from src.pipeline.enrich import enrich_events
from src.pipeline.export import export_outputs
from src.pipeline.ingest import ingest_sources
from src.pipeline.normalize import normalize_events
from src.pipeline.score import apply_scoring
from src.utils.config import load_yaml


def test_pipeline_end_to_end(tmp_path):
    datasets = ingest_sources("data/raw", "data/ref", "config/source_map.yaml")
    events = normalize_events(datasets)
    enriched = enrich_events(events, datasets["users"], datasets["assets"], datasets["vuln_findings"])
    incidents = correlate_events(enriched, 15)
    scored = apply_scoring(incidents, load_yaml("config/scoring_rules.yaml"))
    outputs = export_outputs(scored, str(tmp_path), markdown=True)

    assert (tmp_path / "incidents.csv").exists()
    assert (tmp_path / "metrics.json").exists()
    assert (tmp_path / "incident_summary.md").exists()
    assert outputs["incidents_csv"].endswith("incidents.csv")
