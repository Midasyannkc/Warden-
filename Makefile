.PHONY: install test report rescan incidents
install:
	pip install -r requirements.txt --break-system-packages
test:
	python3 -m pytest -q
report:
	python3 -m warden
rescan:
	rm -f out/raw_scan_cache.json && python3 -m warden
incidents:
	python3 scripts/incidents.py
