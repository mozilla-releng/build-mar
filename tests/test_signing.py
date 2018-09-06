# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pytest
from pytest import raises

from mardor.signing import format_hash
from mardor.signing import get_privatekey
from mardor.signing import get_publickey
from mardor.signing import make_hasher
from mardor.signing import make_dummy_signature
from mardor.signing import make_rsa_keypair
from mardor.signing import sign_hash
from mardor.signing import verify_signature
from mardor.signing import get_signature_data


def test_sign_hash(test_keys):
    priv, pub = test_keys[2048]

    hsh = b"1" * 20

    sig = sign_hash(priv, hsh, 'sha1')

    assert len(sig) == 256

    assert verify_signature(pub, sig, hsh, 'sha1')

    assert not verify_signature(pub, sig, b"2" * 20, 'sha1')


def test_get_signature_data(mar_uu):
    with mar_uu.open('rb') as f:
        with raises(IOError):
            list(get_signature_data(f, mar_uu.size))


@pytest.mark.parametrize("algo_id, size", [
    (1, 256),
    (2, 512),])
def test_dummy_sigs(algo_id, size):
    s = make_dummy_signature(algo_id)
    assert len(s) == size


def test_dummy_dig_bad_algo():
    with raises(ValueError):
        make_dummy_signature(99)


def test_format_hash():
    h = make_hasher(1).finalize()
    h = format_hash(h, 'sha1')

    assert h
