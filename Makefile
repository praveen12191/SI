VENV := ./.venv/bin
DB   := data/out/perimeter.duckdb
RAW  := data/raw/scan.zst
JSON := data/out/scan.jsonl.gz

.PHONY: all setup download ingest resolve findings enrich score app evals clean

all: score

setup:
	python3 -m venv .venv && $(VENV)/pip install -q -r requirements.txt

download:
	$(VENV)/python pipeline/01_download.py $(RAW)

# Streams. Never materialises the 89 GB.
ingest: $(RAW)
	set -o pipefail; zstd -dc $(RAW) | $(VENV)/python pipeline/02_ingest.py $(JSON)

resolve: $(JSON)
	$(VENV)/python pipeline/03_resolve.py $(JSON) $(DB)

findings: resolve
	$(VENV)/python pipeline/04_findings.py $(DB)

enrich: findings          # needs ANTHROPIC_API_KEY; add DRY=--dry-run to rehearse
	$(VENV)/python pipeline/05_enrich.py $(DB) $(DRY)

score: findings
	$(VENV)/python pipeline/06_score.py $(DB)

app:
	$(VENV)/uvicorn app.main:app --reload --port 8000

evals:
	$(VENV)/python evals/run_evals.py --version $(or $(V),v1)

clean:
	rm -f $(DB) $(JSON) data/out/traces.sqlite
