#!/bin/bash
set -e
rm *requirements.txt

pip-compile --output-file requirements.txt requirements.in
pip-compile --output-file test-requirements.txt test-requirements.in
