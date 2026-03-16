from __future__ import annotations

from typing import Any

import pandas as pd


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
RANK_TO_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}


def _series_any_bool(chunk: pd.DataFrame, column: str) -> bool:
    if column not in chunk.columns:
        return False
    return bool(chunk[column].astype("boolean").fillna(False).any())


def correlate_events(events: pd.DataFrame, window_minutes: int = 15) -> pd.DataFrame:
    working = events.copy()

    working["time_bucket"] = working["event_time"].dt.floor(f"{window_minutes}min")
    working["correlation_key"] = working["asset_id"].fillna(working["user_id"]).fillna("unknown")
    working["severity_rank"] = working["severity"].map(SEVERITY_RANK).fillna(1)

    grouped = working.groupby(["correlation_key", "time_bucket"], as_index=False)

    incident_rows: list[dict[str, Any]] = []
    for idx, (_, chunk) in enumerate(grouped):
        max_rank = int(chunk["severity_rank"].max())
        incident_rows.append(
            {
                "incident_id": f"INC-{idx+1:04d}",
                "start_time": chunk["event_time"].min(),
                "end_time": chunk["event_time"].max(),
                "correlation_key": chunk["correlation_key"].iloc[0],
                "event_count": int(len(chunk)),
                "source_types": ",".join(sorted(chunk["source_type"].dropna().astype(str).unique())),
                "asset_id": chunk["asset_id"].dropna().iloc[0] if chunk["asset_id"].notna().any() else pd.NA,
                "user_id": chunk["user_id"].dropna().iloc[0] if chunk["user_id"].notna().any() else pd.NA,
                "hostname": chunk["hostname"].dropna().iloc[0] if "hostname" in chunk and chunk["hostname"].notna().any() else pd.NA,
                "criticality": chunk["criticality"].dropna().iloc[0] if "criticality" in chunk and chunk["criticality"].notna().any() else pd.NA,
                "business_unit": chunk["business_unit"].dropna().iloc[0] if "business_unit" in chunk and chunk["business_unit"].notna().any() else pd.NA,
                "privileged_user": _series_any_bool(chunk, "privileged_user"),
                "known_exploitable_vuln": _series_any_bool(chunk, "known_exploitable_vuln"),
                "suspicious_country": _series_any_bool(chunk, "suspicious_country"),
                "possible_c2": _series_any_bool(chunk, "possible_c2"),
                "repeated_events": _series_any_bool(chunk, "repeated_hint") or len(chunk) > 1,
                "severity": RANK_TO_SEVERITY[max_rank],
                "titles": " | ".join(chunk["title"].astype(str).tolist()),
            }
        )

    incidents = pd.DataFrame(incident_rows)
    return incidents.sort_values(["start_time", "event_count"], ascending=[True, False]).reset_index(drop=True)
