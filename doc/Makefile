
MKDOCS := ./venv/bin/python3 -m mkdocs

build: site/ FORCE
site/: docs/ FORCE
	$(MKDOCS) build

serve: site/ FORCE
	$(MKDOCS) serve

FORCE:

