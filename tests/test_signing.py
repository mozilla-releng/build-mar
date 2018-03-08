# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pytest

from mardor.signing import make_rsa_keypair
from mardor.signing import make_signer_v1
from mardor.signing import make_signer_v2
from mardor.signing import make_verifier_v1
from mardor.signing import make_verifier_v2


@pytest.mark.parametrize('key_size, signer, verifier', [
    (2048, make_signer_v1, make_verifier_v1),
    (4096, make_signer_v2, make_verifier_v2),
])
def test_good_keysize(key_size, signer, verifier, test_keys):
    priv, pub = test_keys[key_size]

    assert verifier(pub, b'')
    assert signer(priv)


@pytest.mark.parametrize('key_size, signer, verifier', [
    (4096, make_signer_v1, make_verifier_v1),
    (2048, make_signer_v2, make_verifier_v2),
])
def test_bad_keysize(key_size, signer, verifier, test_keys):
    priv, pub = test_keys[key_size]

    with pytest.raises(ValueError):
        verifier(pub, b'')

    with pytest.raises(ValueError):
        signer(priv)

@pytest.mark.parametrize('key_size, signer, verifier', [
    (2048, make_signer_v1, make_verifier_v1),
    (4096, make_signer_v2, make_verifier_v2),
])
def test_verify_with_privatekey(key_size, signer, verifier, test_keys):
    priv, pub = test_keys[key_size]

    assert verifier(priv, b'')
