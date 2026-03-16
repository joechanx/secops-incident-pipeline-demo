from __future__ import annotations

import numpy as np
import pandas as pd


COMMON_COLUMNS = [
    "event_id",
    "event_time",
    "source_type",
    "user_id",
    "asset_id",
    "src_ip",
    "severity",
    "event_category",
    "title",
    "suspicious_country",
    "possible_c2",
    "repeated_hint",
]


def _normalize_idp(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame()
    out["event_id"] = df["event_id"]
    out["event_time"] = pd.to_datetime(df["event_time"], utc=True)
    out["source_type"] = "idp"
    out["user_id"] = df["user_id"]
    out["asset_id"] = pd.NA
    out["src_ip"] = df["src_ip"]

    out["severity"] = np.where(
        (df["country"] != "TW") & (df["mfa_result"].isin(["failed", "bypassed"])),
        "high",
        np.where(df["action"].eq("password_reset"), "low", "medium"),
    )

    out["event_category"] = "identity"
    out["title"] = (
        "Identity event: " + df["action"].astype(str) + " / MFA=" + df["mfa_result"].astype(str)
    )
    out["suspicious_country"] = (df["country"] != "TW").fillna(False)
    out["possible_c2"] = False

    repeated = df.groupby(["user_id", "src_ip"])["event_id"].transform("count").gt(1)
    out["repeated_hint"] = repeated.fillna(False)
    return out


def _normalize_edr(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame()
    out["event_id"] = df["alert_id"]
    out["event_time"] = pd.to_datetime(df["event_time"], utc=True)
    out["source_type"] = "edr"
    out["user_id"] = pd.NA
    out["asset_id"] = df["asset_id"]
    out["src_ip"] = pd.NA
    out["severity"] = df["severity"].str.lower().fillna("medium")
    out["event_category"] = "endpoint"
    out["title"] = "EDR " + df["tactic"].astype(str) + " / " + df["technique"].astype(str)
    out["suspicious_country"] = False
    out["possible_c2"] = False
    out["repeated_hint"] = False
    return out


def _normalize_firewall(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame()
    out["event_id"] = df["session_id"]
    out["event_time"] = pd.to_datetime(df["event_time"], utc=True)
    out["source_type"] = "firewall"
    out["user_id"] = pd.NA
    out["asset_id"] = df["src_asset_id"]
    out["src_ip"] = df["src_ip"]
    out["severity"] = np.where(df["threat_tag"].eq("possible_c2"), "high", "low")
    out["event_category"] = "network"
    out["title"] = "Firewall traffic to " + df["dst_ip"].astype(str) + ":" + df["dst_port"].astype(str)
    out["suspicious_country"] = False
    out["possible_c2"] = df["threat_tag"].eq("possible_c2").fillna(False)
    out["repeated_hint"] = False
    return out


def normalize_events(raw_datasets: dict[str, pd.DataFrame]) -> pd.DataFrame:
    frames = [
        _normalize_idp(raw_datasets["idp_events"]),
        _normalize_edr(raw_datasets["edr_alerts"]),
        _normalize_firewall(raw_datasets["firewall_logs"]),
    ]
    events = pd.concat(frames, ignore_index=True)
    return events[COMMON_COLUMNS].sort_values("event_time").reset_index(drop=True)
