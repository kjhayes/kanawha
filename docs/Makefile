
default:
	@

MKDOCS := python3 -m mkdocs

build: site/ FORCE
site/: docs/ FORCE
	$(MKDOCS) build

serve: site/ FORCE
	$(MKDOCS) serve

FORCE:

clean: FORCE
	$(MKDOCS) clean

default: build

