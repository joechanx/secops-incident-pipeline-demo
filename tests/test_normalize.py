from src.pipeline.ingest import ingest_sources
from src.pipeline.normalize import normalize_events


def test_normalize_events_returns_expected_columns():
    datasets = ingest_sources("data/raw", "data/ref", "config/source_map.yaml")
    events = normalize_events(datasets)

    assert len(events) > 0
    assert "event_id" in events.columns
    assert "source_type" in events.columns
    assert set(events["source_type"].unique()) == {"idp", "edr", "firewall"}
