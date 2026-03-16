# secops-incident-pipeline-demo

A Python demo pipeline that ingests **synthetic security events** from multiple sources, normalizes and enriches them, correlates related activity, scores incident risk, and exports a triaged incident queue plus an executive summary.

This repo is designed as a **portfolio/demo project** for GitHub and freelance profiles. It intentionally uses **fictional company context**, **synthetic data**, and **config-driven rules** so it can be shared publicly.

## Business context

**AcmeRetail Taiwan** is a fictional mid-sized retail company with:

- 350 employees
- 3 office locations
- an e-commerce platform
- mixed IT assets: internal AD, VPN, cloud apps, Linux app servers, POS systems

The company receives security-related events from multiple tools, but the raw alerts are hard to triage because:

- data formats differ by source
- context is spread across users, assets, and vulnerabilities
- the same incident can produce multiple alerts
- manual review does not scale

This pipeline demonstrates a simple but realistic workflow:

1. Ingest raw events from multiple sources
2. Normalize them to a common schema
3. Enrich them with user / asset / vulnerability context
4. Correlate related activity into incidents
5. Score risk using config-driven rules
6. Export an incident queue and markdown summary

## Demo data sources

Raw event sources:

- `idp_events.jsonl` – identity / login events
- `edr_alerts.jsonl` – endpoint detection alerts
- `firewall_logs.csv` – outbound network sessions
- `vuln_findings.csv` – vulnerability findings

Reference data:

- `users.csv`
- `assets.csv`

All data is synthetic.

## Project structure

```text
secops-incident-pipeline-demo/
├─ README.md
├─ requirements.txt
├─ pyproject.toml
├─ Makefile
├─ .env.example
├─ .gitignore
├─ config/
│  ├─ pipeline.yaml
│  ├─ scoring_rules.yaml
│  └─ source_map.yaml
├─ data/
│  ├─ raw/
│  ├─ ref/
│  └─ output/
├─ src/
│  ├─ main.py
│  ├─ pipeline/
│  │  ├─ ingest.py
│  │  ├─ normalize.py
│  │  ├─ enrich.py
│  │  ├─ correlate.py
│  │  ├─ score.py
│  │  └─ export.py
│  └─ utils/
│     ├─ config.py
│     └─ logger.py
└─ tests/
```

## Quick start

### 1) Create a virtual environment

#### macOS / Linux
```bash
python -m venv .venv
source .venv/bin/activate
```

#### Windows PowerShell
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
```

### 3) Configure environment variables

```bash
cp .env.example .env
```

### 4) Run the pipeline

```bash
python -m src.main --config config/pipeline.yaml
```

### 5) Run tests

```bash
pytest
```

## What the pipeline outputs

The run writes files under `data/output/`:

- `incidents.csv` – triaged incident queue
- `incident_summary.md` – human-readable markdown summary
- `metrics.json` – basic run metrics

## Risk scoring model

The scoring logic is intentionally simple and easy to explain:

- start from a base score derived from severity
- add modifiers such as:
  - privileged user
  - critical asset
  - known exploitable vulnerability
  - suspicious country
  - possible command-and-control traffic
  - repeated events

Thresholds are configured in `config/scoring_rules.yaml`.

## Example use cases for a portfolio

This project demonstrates:

- Python ETL / pipeline design
- multi-source data normalization
- context enrichment from reference data
- simple event correlation
- rule-based risk scoring
- config-driven behavior
- testable project structure

## Future improvements

Possible extensions for a second version:

- DuckDB storage and ad hoc queries
- Streamlit dashboard
- HTML report export
- GitHub Actions CI
- Docker image
- data quality checks with Pandera
- API-based ingestion instead of local files
