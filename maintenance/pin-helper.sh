#!/bin/bash
# This runs in docker to pin our requirements files

set -e

pip install pip-tools

rm -f *"requirements${SUFFIX}.txt"
pip-compile --generate-hashes --output-file "requirements${SUFFIX}.txt" requirements.in
pip-compile --generate-hashes --output-file "test-requirements${SUFFIX}.txt" test-requirements.in
