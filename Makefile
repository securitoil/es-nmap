.PHONY: build push test

build: template
	faas build -f es_nmap.yml --build-arg "ADDITIONAL_PACKAGE=nmap nmap-scripts"

template:
	faas template pull https://github.com/securitoil/faas-templates.git


push:
	docker push kulinacs/es_nmap

test:
	tox
