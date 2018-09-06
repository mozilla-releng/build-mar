# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import bz2
import os
import struct

import pytest
import six

from mardor.reader import MarReader
from mardor.signing import get_publickey
from mardor.signing import make_hasher
from mardor.signing import verify_signature

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

        assert m.get_errors() is None


def test_verify():
    pubkey = open(TEST_PUBKEY, 'rb').read()
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        assert m.verify(pubkey)


def test_verify_nosig(mar_cu):
    pubkey = open(TEST_PUBKEY, 'rb').read()
    with MarReader(mar_cu.open('rb')) as m:
        assert not m.verify(pubkey)
        assert m.get_errors() is None

def test_verify_nosig_extra(mar_cue):
    pubkey = open(TEST_PUBKEY, 'rb').read()
    with MarReader(mar_cue.open('rb')) as m:
        assert not m.verify(pubkey)
        assert m.get_errors() is None


def test_extract_mode(mar_cu, tmpdir):
    with MarReader(mar_cu.open('rb')) as m:
        m.extract(str(tmpdir))
        assert tmpdir.join('message.txt').stat().mode & 0o777 == 0o755


def test_verify_wrongkey(test_keys):
    private, public = test_keys[2048]
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


def test_extract_baddecompression(tmpdir):
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        with pytest.raises(ValueError):
            m.extract(str(tmpdir), decompress='devnull')


def test_compression_type_bz2():
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        assert m.compression_type == 'bz2'

def test_compression_type_xz():
    with MarReader(open(TEST_MAR_XZ, 'rb')) as m:
        assert m.compression_type == 'xz'

def test_compression_type_none(mar_uu):
    with MarReader(mar_uu.open('rb')) as m:
        assert m.compression_type is None

def test_signature_type_sha1():
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        assert m.signature_type == 'sha1'

def test_signature_type_none(mar_uu):
    with MarReader(mar_uu.open('rb')) as m:
        assert m.signature_type is None

def test_signature_type_sha384(mar_sha384):
    with MarReader(mar_sha384.open('rb')) as m:
        assert m.signature_type == 'sha384'

def test_signature_type_unknown():
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        m.mardata.signatures.sigs[0].algorithm_id = 99
        assert m.signature_type == 'unknown'

def test_calculate_hashes():
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        hashes = m.calculate_hashes()
        assert len(hashes) == 1
        assert hashes[0][0] == 1
        assert hashes[0][1][:20] == b'\xcd%\x0e\x82z%7\xdb\x96\xb4^\x063ZFV8\xfa\xe8k'

        pubkey = open(TEST_PUBKEY, 'rb').read()
        assert verify_signature(pubkey, m.mardata.signatures.sigs[0].signature, hashes[0][1], 'sha1')


def test_check_bad_signature_algorithm(mar_sha384, tmpdir):
    # Make a copy of mar_sha384
    tmpmar = tmpdir.join('test.mar')
    mar_sha384.copy(tmpmar)
    with tmpmar.open('r+b') as f:
        with MarReader(f) as m:
            assert m.mardata.signatures.count == 1
            offset = m.mardata.signatures.offset
            offset += 12

        f.seek(offset)
        f.write(b'\x12\x34\x56\x78')
        f.seek(0)

        with MarReader(f) as m:
            assert m.mardata.signatures.count == 1
            assert m.mardata.signatures.sigs[0].algorithm_id == 0x12345678
            assert m.get_errors() == ["Unknown signature algorithm: 0x12345678"]


def test_check_bad_extra_section_id(mar_sha384, tmpdir):
    # Make a copy of mar_sha384
    tmpmar = tmpdir.join('test.mar')
    mar_sha384.copy(tmpmar)
    with tmpmar.open('r+b') as f:
        with MarReader(f) as m:
            assert m.mardata.additional.count == 1
            offset = m.mardata.additional.offset
            offset += 8

        f.seek(offset)
        f.write(b'\x12\x34\x56\x78')
        f.seek(0)

        with MarReader(f) as m:
            assert m.mardata.additional.count == 1
            assert m.mardata.additional.sections[0].id == 0x12345678
            assert m.get_errors() == ["Unknown extra section type: 0x12345678"]



def test_check_bad_file_entry_before(mar_sha384, tmpdir):
    # Make a copy of mar_sha384
    tmpmar = tmpdir.join('test.mar')
    mar_sha384.copy(tmpmar)
    with tmpmar.open('r+b') as f:
        with MarReader(f) as m:
            offset = m.mardata.header.index_offset
            offset += 4

        f.seek(offset)
        f.write(b'\x00\x00\x00\x00')
        f.seek(0)

        with MarReader(f) as m:
            assert m.get_errors() == ["Entry 'message.txt' starts before data block"]


def test_check_bad_file_entry_after(mar_sha384, tmpdir):
    # Make a copy of mar_sha384
    tmpmar = tmpdir.join('test.mar')
    mar_sha384.copy(tmpmar)
    with tmpmar.open('r+b') as f:
        with MarReader(f) as m:
            offset = m.mardata.header.index_offset
            offset += 4

        f.seek(offset)
        f.write(b'\x12\x34\x56\x78')
        f.seek(0)

        with MarReader(f) as m:
            assert m.get_errors() == ["Entry 'message.txt' starts after data block",
                                      "Entry 'message.txt' ends past data block"]


def test_check_bad_file_entry_size(mar_sha384, tmpdir):
    # Make a copy of mar_sha384
    tmpmar = tmpdir.join('test.mar')
    mar_sha384.copy(tmpmar)
    with tmpmar.open('r+b') as f:
        with MarReader(f) as m:
            offset = m.mardata.header.index_offset
            offset += 8

        f.seek(offset)
        f.write(b'\x12\x34\x56\x78')
        f.seek(0)

        with MarReader(f) as m:
            assert m.get_errors() == ["Entry 'message.txt' ends past data block"]
