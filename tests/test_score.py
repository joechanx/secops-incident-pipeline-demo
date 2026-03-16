from src.pipeline.correlate import correlate_events
from src.pipeline.enrich import enrich_events
from src.pipeline.ingest import ingest_sources
from src.pipeline.normalize import normalize_events
from src.pipeline.score import apply_scoring
from src.utils.config import load_yaml


def test_scoring_assigns_priorities():
    datasets = ingest_sources("data/raw", "data/ref", "config/source_map.yaml")
    events = normalize_events(datasets)
    enriched = enrich_events(events, datasets["users"], datasets["assets"], datasets["vuln_findings"])
    incidents = correlate_events(enriched, 15)
    rules = load_yaml("config/scoring_rules.yaml")
    scored = apply_scoring(incidents, rules)

    assert "risk_score" in scored.columns
    assert "priority" in scored.columns
    assert scored["risk_score"].max() >= 70
