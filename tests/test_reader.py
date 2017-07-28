# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import bz2
import os
import struct

import pytest
import six

from mardor.reader import MarReader
from mardor.signing import make_rsa_keypair

if six.PY2:
    from backports import lzma
else:
    import lzma

TEST_MAR_BZ2 = os.path.join(os.path.dirname(__file__), 'test-bz2.mar')
TEST_MAR_XZ = os.path.join(os.path.dirname(__file__), 'test-xz.mar')
TEST_PUBKEY = os.path.join(os.path.dirname(__file__), 'test.pubkey')


def test_parsing():
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        mardata = m.mardata
        index = mardata.index
        entries = index.entries
        assert len(entries) == 5
        assert entries[0] == dict(offset=392, size=141, flags=0o664,
                                  name='update.manifest')
        assert entries[1] == dict(offset=533, size=76, flags=0o664,
                                  name='defaults/pref/channel-prefs.js')
        assert mardata.additional.count == 1
        assert mardata.additional.sections[0].channel == 'thunderbird-comm-esr'
        assert mardata.additional.sections[0].productversion == '100.0'
        assert mardata.signatures.count == 1


def test_verify():
    pubkey = open(TEST_PUBKEY, 'rb').read()
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        assert m.verify(pubkey)


def test_verify_nosig(mar_cu):
    pubkey = open(TEST_PUBKEY, 'rb').read()
    with MarReader(mar_cu.open('rb')) as m:
        assert not m.verify(pubkey)

def test_verify_nosig_extra(mar_cue):
    pubkey = open(TEST_PUBKEY, 'rb').read()
    with MarReader(mar_cue.open('rb')) as m:
        assert not m.verify(pubkey)


def test_verify_wrongkey():
    private, public = make_rsa_keypair(2048)
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        assert not m.verify(public)


def test_verify_unsupportedalgo():
    pubkey = open(TEST_PUBKEY, 'rb').read()
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        m.mardata.signatures.sigs[0].algorithm_id = 3
        with pytest.raises(ValueError, message='Unsupported algorithm'):
            m.verify(pubkey)


def test_extract_bz2(tmpdir):
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        m.extract(str(tmpdir))
        assert sorted(tmpdir.listdir()) == [
            tmpdir.join(f) for f in [
                'Contents',
                'defaults',
                'update-settings.ini',
                'update.manifest',
            ]]
        # Check the contents. These should already be uncompressed
        assert (tmpdir.join('defaults/pref/channel-prefs.js').read('rb') ==
                b'pref("app.update.channel", "release");\n')


def test_extract_nodecompress(tmpdir):
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        m.extract(str(tmpdir), decompress=None)
        assert sorted(tmpdir.listdir()) == [
            tmpdir.join(f) for f in [
                'Contents',
                'defaults',
                'update-settings.ini',
                'update.manifest',
            ]]
        # Check the contents. These should already be uncompressed
        contents = tmpdir.join('defaults/pref/channel-prefs.js').read('rb')
        assert contents.startswith(b'BZh')
        assert (bz2.decompress(contents) ==
                b'pref("app.update.channel", "release");\n')


def test_extract_badpath(tmpdir):
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        # Mess with the name
        e = m.mardata.index.entries[0]
        e.name = "../" + e.name
        with pytest.raises(ValueError):
            m.extract(str(tmpdir))


def test_extract_xz(tmpdir):
    with MarReader(open(TEST_MAR_XZ, 'rb')) as m:
        m.extract(str(tmpdir))
        assert sorted(tmpdir.listdir()) == [
            tmpdir.join(f) for f in [
                'Contents',
                'defaults',
                'update-settings.ini',
                'update.manifest',
            ]]
        # Check the contents. These should already be uncompressed
        assert (tmpdir.join('defaults/pref/channel-prefs.js').read('rb') ==
                b'pref("app.update.channel", "release");\n')


def test_compression_type_bz2():
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        assert m.compression_type == 'bz2'

def test_compression_type_xz():
    with MarReader(open(TEST_MAR_XZ, 'rb')) as m:
        assert m.compression_type == 'xz'

def test_compression_type_none(mar_uu):
    with MarReader(mar_uu.open('rb')) as m:
        assert m.compression_type is None

def test_signature_type():
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        assert m.signature_type == 'sha1'

def test_signature_type(mar_uu):
    with MarReader(mar_uu.open('rb')) as m:
        assert m.signature_type is None

# TODO: Test sha384 signed
