.PHONY: scan samples
samples:
	python make_samples.py
scan: samples
	python scan.py samples/ || true
