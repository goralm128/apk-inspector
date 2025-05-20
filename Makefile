.PHONY: test setup clean

test:
	python tools/dev.py test

setup:
	python tools/dev.py setup

clean:
	python tools/dev.py clean
