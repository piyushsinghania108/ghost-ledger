setup:
	python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt && cp -n .env.example .env || true

run:
	. venv/bin/activate && streamlit run app.py

test:
	python3 -m pytest tests/ -v

clean:
	rm -rf __pycache__ .pytest_cache ghost_ledger.db
