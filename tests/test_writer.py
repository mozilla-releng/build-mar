# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import bz2

import pytest

from mardor.reader import MarReader
from mardor.signing import make_rsa_keypair
from mardor.writer import MarWriter


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
                m.add('message.txt')

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


@pytest.mark.parametrize('key_size, algo_id', [
    (2048, 1),
    (4096, 2),])
def test_signing(tmpdir, key_size, algo_id):
    private_key, public_key = make_rsa_keypair(key_size)

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
