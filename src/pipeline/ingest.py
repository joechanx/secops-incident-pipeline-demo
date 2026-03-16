from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.utils.config import load_yaml


def _read_jsonl(path: Path) -> pd.DataFrame:
    return pd.read_json(path, lines=True)


def _read_csv(path: Path) -> pd.DataFrame:
    return pd.read_csv(path)


def ingest_sources(raw_dir: str, ref_dir: str, source_map_path: str) -> dict[str, pd.DataFrame]:
    source_map = load_yaml(source_map_path)
    datasets: dict[str, pd.DataFrame] = {}

    for source_name, meta in source_map.items():
        kind = meta["kind"]
        path = meta["path"]

        if source_name in {"users", "assets"}:
            full_path = Path(ref_dir) / path
        else:
            full_path = Path(raw_dir) / path

        if kind == "jsonl":
            datasets[source_name] = _read_jsonl(full_path)
        elif kind == "csv":
            datasets[source_name] = _read_csv(full_path)
        else:
            raise ValueError(f"Unsupported source kind: {kind}")

    return datasets
