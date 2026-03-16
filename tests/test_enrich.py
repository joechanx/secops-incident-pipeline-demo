from src.pipeline.enrich import enrich_events
from src.pipeline.ingest import ingest_sources
from src.pipeline.normalize import normalize_events


def test_enrich_adds_context_columns():
    datasets = ingest_sources("data/raw", "data/ref", "config/source_map.yaml")
    events = normalize_events(datasets)
    enriched = enrich_events(events, datasets["users"], datasets["assets"], datasets["vuln_findings"])

    assert "privileged_user" in enriched.columns
    assert "criticality" in enriched.columns
    assert "known_exploitable_vuln" in enriched.columns
