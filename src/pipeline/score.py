from __future__ import annotations

import pandas as pd


def apply_scoring(incidents: pd.DataFrame, rules: dict) -> pd.DataFrame:
    scored = incidents.copy()
    base_scores = rules["base_scores"]
    modifiers = rules["modifiers"]
    thresholds = rules["priority_thresholds"]

    scored["risk_score"] = scored["severity"].map(base_scores).fillna(0).astype(int)

    for column, modifier_name in [
        ("privileged_user", "privileged_user"),
        ("known_exploitable_vuln", "known_exploitable_vuln"),
        ("suspicious_country", "suspicious_country"),
        ("possible_c2", "possible_c2"),
        ("repeated_events", "repeated_events"),
    ]:
        scored.loc[scored[column].fillna(False), "risk_score"] += int(modifiers[modifier_name])

    scored.loc[scored["criticality"].astype(str).str.lower().eq("critical"), "risk_score"] += int(
        modifiers["critical_asset"]
    )

    def _priority(score: int) -> str:
        if score >= thresholds["P1"]:
            return "P1"
        if score >= thresholds["P2"]:
            return "P2"
        if score >= thresholds["P3"]:
            return "P3"
        return "P4"

    def _recommended_action(row: pd.Series) -> str:
        if row["possible_c2"]:
            return "Isolate host, review outbound connections, collect forensic evidence."
        if row["suspicious_country"] and row["privileged_user"]:
            return "Review identity activity, force password reset, verify MFA and access logs."
        if row["known_exploitable_vuln"]:
            return "Validate exposure, prioritize patching, and inspect for signs of exploitation."
        return "Review incident details and confirm whether escalation is needed."

    scored["priority"] = scored["risk_score"].apply(_priority)
    scored["recommended_action"] = scored.apply(_recommended_action, axis=1)

    return scored.sort_values(["risk_score", "event_count"], ascending=[False, False]).reset_index(drop=True)
