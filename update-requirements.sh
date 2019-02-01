#!/bin/bash
set -e
rm *requirements.txt || true

pip-compile --generate-hashes --output-file requirements.txt requirements.in
pip-compile --generate-hashes --output-file test-requirements.txt test-requirements.in

pip-compile2 --generate-hashes --output-file requirements-py2.txt requirements.in
pip-compile2 --generate-hashes --output-file test-requirements-py2.txt test-requirements.in
