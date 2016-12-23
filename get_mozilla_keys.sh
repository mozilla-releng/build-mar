#!/bin/bash
# Get official mozilla keys
set -e
BASEURL="https://hg.mozilla.org/mozilla-central/raw-file/tip/toolkit/mozapps/update/updater"

function get_key() {
    filename=$1
    name=$2
    url="$BASEURL/$filename"
    echo "# From $url"
    echo -n "$name = b\"\"\""
    curl -s $url | openssl x509 -inform DER -pubkey -noout | head -c -1
    echo '"""'
    echo
}

(
echo "#"
echo "# Automatically generated - do not edit!"
echo "#"
echo "# flake8: noqa"
get_key "release_primary.der" "release1"
get_key "release_secondary.der" "release2"

get_key "nightly_aurora_level3_primary.der" "nightly1"
get_key "nightly_aurora_level3_secondary.der" "nightly2"

get_key "dep1.der" "dep1"
get_key "dep2.der" "dep2"
) > mardor/mozilla.py
