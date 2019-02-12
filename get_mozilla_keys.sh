#!/bin/bash
# Get official mozilla keys
set -e

SHA1_REV="58402b43c9e1e22d8a9976ee9a7e4ffeee1bbbf2"
# TODO update this rev when we land the autograph-stage key in-tree
SHA384_REV="92f6879a8f9fc7e727d7c281c9fa9f538cb96cb5"

function get_key() {
    filename=$1
    name=$2
    rev=${3-default}
    url="https://hg.mozilla.org/mozilla-central/raw-file/${rev}/toolkit/mozapps/update/updater/${filename}"
    echo "# From $url"
    echo -n "$name = b\"\"\""
    curl -s $url | openssl x509 -inform DER -pubkey -noout | head -c -1
    echo '"""'
}

function get_pem_key() {
    filename=$1
    name=$2
    rev=${3-default}
    url="https://hg.mozilla.org/mozilla-central/raw-file/${rev}/toolkit/mozapps/update/updater/${filename}"
    echo "# From $url"
    echo -n "$name = b\"\"\""
    curl -s $url
    echo '"""'
}

(
echo "#"
echo "# Automatically generated - do not edit!"
echo "#"
echo "# flake8: noqa"
get_key "release_primary.der" "release1_sha384" $SHA384_REV
echo
get_key "release_secondary.der" "release2_sha384" $SHA384_REV
echo
get_key "release_primary.der" "release1_sha1" $SHA1_REV
echo
get_key "release_secondary.der" "release2_sha1" $SHA1_REV
echo

get_key "nightly_aurora_level3_primary.der" "nightly1_sha384" $SHA384_REV
echo
get_key "nightly_aurora_level3_secondary.der" "nightly2_sha384" $SHA384_REV
echo
get_key "nightly_aurora_level3_primary.der" "nightly1_sha1" $SHA1_REV
echo
get_key "nightly_aurora_level3_secondary.der" "nightly2_sha1" $SHA1_REV
echo

get_key "dep1.der" "dep1_sha384" $SHA384_REV
echo
get_key "dep2.der" "dep2_sha384" $SHA384_REV
echo
get_key "dep1.der" "dep1_sha1" $SHA1_REV
echo
get_key "dep2.der" "dep2_sha1" $SHA1_REV
echo

get_pem_key "autograph_stage.pem" "autograph_stage_sha384" $SHA384_REV
) > src/mardor/mozilla.py
