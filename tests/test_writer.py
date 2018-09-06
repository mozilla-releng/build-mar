# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import bz2

import pytest
import six
from mock import patch

from mardor.format import extras_header

from mardor.reader import MarReader
from mardor.writer import MarWriter
from mardor.writer import add_signature_block

from mardor.signing import make_hasher
from mardor.signing import sign_hash
from mardor.signing import get_publickey
from mardor.signing import get_privatekey


def test_writer(tmpdir):
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('wb') as f:
        with MarWriter(f) as m:
            with tmpdir.as_cwd():
                m.add('message.txt')

    assert mar_p.size() > 0

    with mar_p.open('rb') as f:
        with MarReader(f) as m:
            assert m.mardata.additional is None
            assert m.mardata.signatures is None
            assert len(m.mardata.index.entries) == 1
            assert m.mardata.index.entries[0].name == 'message.txt'
            m.extract(str(tmpdir.join('extracted')))
            assert (tmpdir.join('extracted', 'message.txt').read('rb') ==
                    b'hello world')


def test_writer_adddir(tmpdir):
    tmpdir.mkdir('foo')
    message_p = tmpdir.join('foo', 'message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('wb') as f:
        with MarWriter(f) as m:
            with tmpdir.as_cwd():
                m.add('foo')

    assert mar_p.size() > 0

    with mar_p.open('rb') as f:
        with MarReader(f) as m:
            assert m.mardata.additional is None
            assert m.mardata.signatures is None
            assert len(m.mardata.index.entries) == 1
            assert m.mardata.index.entries[0].name == 'foo/message.txt'
            m.extract(str(tmpdir.join('extracted')))
            data = tmpdir.join('extracted', 'foo', 'message.txt').read('rb')
            assert data == b'hello world'


def test_writer_uncompressed(tmpdir):
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('wb') as f:
        with MarWriter(f) as m:
            with tmpdir.as_cwd():
                m.add('message.txt', compress=None)

    assert mar_p.size() > 0

    with mar_p.open('rb') as f:
        with MarReader(f) as m:
            assert m.mardata.additional is None
            assert m.mardata.signatures is None
            assert len(m.mardata.index.entries) == 1
            assert m.mardata.index.entries[0].name == 'message.txt'
            m.extract(str(tmpdir.join('extracted')))
            assert (tmpdir.join('extracted', 'message.txt').read('rb') ==
                    b'hello world')


def test_writer_compressed(tmpdir):
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('wb') as f:
        with MarWriter(f) as m:
            with tmpdir.as_cwd():
                m.add('message.txt', compress='bz2')

    assert mar_p.size() > 0

    message_compressed = bz2.compress(b'hello world')

    with mar_p.open('rb') as f:
        with MarReader(f) as m:
            assert m.mardata.additional is None
            assert m.mardata.signatures is None
            assert len(m.mardata.index.entries) == 1
            assert m.mardata.index.entries[0].name == 'message.txt'
            m.extract(str(tmpdir.join('extracted')), decompress=None)
            assert (tmpdir.join('extracted', 'message.txt').read('rb') ==
                    message_compressed)


def test_additional(tmpdir):
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('w+b') as f:
        with MarWriter(f, productversion='99.9', channel='release') as m:
            with tmpdir.as_cwd():
                m.add('message.txt')

    assert mar_p.size() > 0
    with mar_p.open('rb') as f:
        with MarReader(f) as m:
            assert m.mardata.additional.count == 1
            assert m.mardata.additional.sections[0].productversion == '99.9'
            assert m.mardata.additional.sections[0].channel == 'release'
            assert m.mardata.signatures.count == 0
            assert len(m.mardata.index.entries) == 1
            assert m.mardata.index.entries[0].name == 'message.txt'
            m.extract(str(tmpdir.join('extracted')))
            assert (tmpdir.join('extracted', 'message.txt').read('rb') ==
                    b'hello world')


def test_bad_parameters(tmpdir):
    mar_p = tmpdir.join('test.mar')
    f = mar_p.open('w+b')
    with pytest.raises(ValueError):
        MarWriter(f, productversion='foo')
    with pytest.raises(ValueError):
        MarWriter(f, channel='bar')
    with pytest.raises(ValueError):
        MarWriter(f, signing_key='SECRET')
    with pytest.raises(ValueError):
        MarWriter(f, signing_algorithm='crc')
    with pytest.raises(ValueError):
        message_p = tmpdir.join('message.txt')
        message_p.write('hello world')
        with MarWriter(f) as m:
            with tmpdir.as_cwd():
                m.add_file('message.txt', compress='deflate')


@pytest.mark.parametrize('key_size, algo_id', [
    (2048, 'sha1'),
    (4096, 'sha384'),])
def test_signing(tmpdir, key_size, algo_id, test_keys):
    private_key, public_key = test_keys[key_size]

    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('w+b') as f:
        with MarWriter(f, signing_key=private_key, channel='release',
                       productversion='99.9', signing_algorithm=algo_id) as m:
            with tmpdir.as_cwd():
                m.add('message.txt')

    assert mar_p.size() > 0
    with mar_p.open('rb') as f:
        with MarReader(f) as m:
            assert m.mardata.additional.count == 1
            assert m.mardata.signatures.count == 1
            assert len(m.mardata.index.entries) == 1
            assert m.mardata.index.entries[0].name == 'message.txt'
            m.extract(str(tmpdir.join('extracted')))
            assert (tmpdir.join('extracted', 'message.txt').read('rb') ==
                    b'hello world')
            assert m.verify(public_key)


def test_addfile_as_dir(tmpdir):
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('wb') as f:
        with MarWriter(f) as m:
            with tmpdir.as_cwd():
                with pytest.raises(ValueError):
                    m.add_dir('message.txt', None)


def test_adddir_as_file(tmpdir):
    message_p = tmpdir.join('subdir', 'message.txt')
    tmpdir.join('subdir').mkdir()
    message_p.write('hello world')
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('wb') as f:
        with MarWriter(f) as m:
            with tmpdir.as_cwd():
                with pytest.raises(ValueError):
                    m.add_file('subdir', None)


def test_xz_writer(tmpdir):
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('wb') as f:
        with MarWriter(f) as m:
            with tmpdir.as_cwd():
                m.add('message.txt', compress='xz')

    assert mar_p.size() > 0

    with mar_p.open('rb') as f:
        with MarReader(f) as m:
            assert m.mardata.additional is None
            assert m.mardata.signatures is None
            assert len(m.mardata.index.entries) == 1
            assert m.mardata.index.entries[0].name == 'message.txt'
            m.extract(str(tmpdir.join('extracted')))
            assert (tmpdir.join('extracted', 'message.txt').read('rb') ==
                    b'hello world')


def test_writer_badmode(tmpdir, test_keys):
    private_key, public_key = test_keys[2048]
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('wb') as f:
        with pytest.raises(ValueError):
            MarWriter(f, signing_key=private_key, channel='release',
                      productversion='99.9', signing_algorithm='sha1')


def test_empty_mar(tmpdir):
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('w+b') as f:
        with MarWriter(f) as m:
            pass

    with mar_p.open('rb') as f:
        with MarReader(f) as m:
            assert len(m.mardata.index.entries) == 0
            assert not m.mardata.signatures


def test_add_signature(tmpdir, mar_cue, test_keys):
    dest_mar = tmpdir.join('test.mar')

    # Add a dummy signature
    with mar_cue.open('rb') as s, dest_mar.open('w+b') as f:
        add_signature_block(s, f, 'sha384')

    with MarReader(mar_cue.open('rb')) as m, dest_mar.open('rb') as f, MarReader(f) as m1:
        assert m.productinfo == m1.productinfo
        assert m.mardata.additional.sections == m1.mardata.additional.sections

        assert len(m.mardata.index.entries) == len(m1.mardata.index.entries)
        assert m1.mardata.signatures.count == 1

        hashes = m1.calculate_hashes()
        assert len(hashes) == 1
        assert hashes[0][1][:20] == b"\r\xa9x\x7f#\xf2m\x93a\xcc\xafJ=\x85\xa3Ss\xb43;"


    # Now sign the hash using the test keys, and add the signature back into the file
    private_key, public_key = test_keys[4096]

    sig = sign_hash(private_key, hashes[0][1], 'sha384')
    # Add the signature back into the file
    with mar_cue.open('rb') as s, dest_mar.open('w+b') as f:
        add_signature_block(s, f, 'sha384', sig)

    with dest_mar.open('rb') as f, MarReader(f) as m1:
        assert m1.verify(public_key)

    # Assert file contents are the same
    with dest_mar.open('rb') as f, MarReader(f) as m1:
        with MarReader(mar_cue.open('rb')) as m:
            offset_delta = m1.mardata.data_offset - m.mardata.data_offset
            for (e, e1) in zip(m.mardata.index.entries, m1.mardata.index.entries):
                assert e.name == e1.name
                assert e.flags == e1.flags
                assert e.size == e1.size
                assert e.offset == e1.offset - offset_delta

                s = b''.join(m.extract_entry(e, decompress=None))
                s1 = b''.join(m1.extract_entry(e1, decompress=None))
                assert len(s) == e.size
                assert len(s1) == e1.size
                assert s == s1


def test_padding(tmpdir):
    """Check that adding a signature preserves the original padding"""
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    def padded_write(self, productversion, channel):
        self.fileobj.seek(self.additional_offset)
        extras = extras_header.build(dict(
            count=1,
            sections=[dict(
                channel=six.u(channel),
                productversion=six.u(productversion),
                size=len(channel) + len(productversion) + 2 + 8 + 10,
                padding=b'\x00' * 10,
            )],
        ))
        self.fileobj.write(extras)
        self.last_offset = self.fileobj.tell()

    with patch.object(MarWriter, 'write_additional', padded_write):
        mar_p = tmpdir.join('test.mar')
        with mar_p.open('w+b') as f:
            with MarWriter(f, productversion='99.0', channel='1') as m:
                with tmpdir.as_cwd():
                    m.add('message.txt', compress='bz2')

    with mar_p.open('rb') as f:
        with MarReader(f) as m:
            assert m.mardata.additional.sections[0].padding == b'\x00' * 10
