#!/bin/bash

set -e
set -x

docker run -t -v $PWD:/src -w /src -e SUFFIX=-py2 python:2.7 maintenance/pin-helper.sh
docker run -t -v $PWD:/src -w /src python:3.6 maintenance/pin-helper.sh
