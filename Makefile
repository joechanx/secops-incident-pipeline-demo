install:
	pip install -r requirements.txt

run:
	python -m src.main --config config/pipeline.yaml

test:
	pytest -q
