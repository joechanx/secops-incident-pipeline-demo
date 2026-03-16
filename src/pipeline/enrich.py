from __future__ import annotations

import pandas as pd


def _severity_to_rank(severity: str) -> int:
    mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return mapping.get(str(severity).lower(), 0)


def build_asset_vuln_context(vuln_df: pd.DataFrame) -> pd.DataFrame:
    working = vuln_df.copy()
    working["open_exploitable"] = (
        working["exploit_known"].astype(str).str.lower().eq("true")
        & working["status"].astype(str).str.lower().eq("open")
    )
    working["severity_rank"] = working["severity"].map(_severity_to_rank)

    grouped = (
        working.groupby("asset_id", as_index=False)
        .agg(
            highest_vuln_severity_rank=("severity_rank", "max"),
            open_exploitable_count=("open_exploitable", "sum"),
        )
    )
    grouped["known_exploitable_vuln"] = grouped["open_exploitable_count"] > 0
    return grouped


def enrich_events(
    events: pd.DataFrame,
    users_df: pd.DataFrame,
    assets_df: pd.DataFrame,
    vuln_df: pd.DataFrame,
) -> pd.DataFrame:
    users = users_df.copy()
    users["privileged_user"] = users["privileged_user"].astype(str).str.lower().eq("true")

    assets = assets_df.copy()
    assets["public_facing"] = assets["public_facing"].astype(str).str.lower().eq("true")
    asset_vuln = build_asset_vuln_context(vuln_df)

    enriched = events.merge(users, on="user_id", how="left")
    enriched = enriched.merge(
        assets,
        left_on="asset_id",
        right_on="asset_id",
        how="left",
        suffixes=("", "_asset"),
    )

    owner_map = assets[
        ["asset_id", "owner_user_id", "criticality", "business_unit", "hostname", "public_facing"]
    ].rename(
        columns={
            "asset_id": "owned_asset_id",
            "criticality": "owned_asset_criticality",
            "business_unit": "owned_asset_business_unit",
            "hostname": "owned_asset_hostname",
            "public_facing": "owned_asset_public_facing",
        }
    )
    enriched = enriched.merge(owner_map, left_on="user_id", right_on="owner_user_id", how="left")

    enriched["asset_id"] = enriched["asset_id"].fillna(enriched["owned_asset_id"])
    enriched["criticality"] = enriched["criticality"].fillna(enriched["owned_asset_criticality"])
    enriched["business_unit"] = enriched["business_unit"].fillna(enriched["owned_asset_business_unit"])
    enriched["hostname"] = enriched["hostname"].fillna(enriched["owned_asset_hostname"])
    enriched["public_facing"] = enriched["public_facing"].where(
        enriched["public_facing"].notna(),
        enriched["owned_asset_public_facing"],
    )
    enriched["public_facing"] = enriched["public_facing"].astype("boolean")

    enriched = enriched.merge(asset_vuln, on="asset_id", how="left")
    enriched["known_exploitable_vuln"] = enriched["known_exploitable_vuln"].fillna(False).astype(bool)

    return enriched
