# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from itertools import repeat
import os

import hypothesis.strategies as st
import pytest
from hypothesis import assume
from hypothesis import given

from mardor.utils import auto_decompress_stream
from mardor.utils import bz2_compress_stream
from mardor.utils import bz2_decompress_stream
from mardor.utils import filesize
from mardor.utils import mkdir
from mardor.utils import safejoin
from mardor.utils import takeexactly


@given(st.lists(st.binary()))
def test_takeexactly(data):
    n = len(b''.join(data))
    for i in range(n+1):
        assert len(b''.join(takeexactly(data, i))) == i


@given(st.lists(st.binary()))
def test_takeexactly_notenough(data):
    n = len(b''.join(data))
    with pytest.raises(ValueError):
        b''.join(takeexactly(data, n+1))


@given(st.lists(st.binary()), st.integers(min_value=1, max_value=9))
def test_bz2_streams(data, level):
    stream = bz2_decompress_stream(bz2_compress_stream(data, level))
    assert b''.join(stream) == b''.join(data)


def test_bz2_stream_large():
    # This is only to test the case where the compressor returns data before
    # the stream ends
    n = 70000
    stream = repeat(b'hello', n)
    stream = bz2_decompress_stream(bz2_compress_stream(stream, level=1))
    assert b''.join(stream) == b'hello' * n


def test_bz2_stream_exact_blocksize():
    stream = [b'0' * 100000]
    stream = bz2_decompress_stream(bz2_compress_stream(stream, level=1))
    assert b''.join(stream) == b'0' * 100000


def test_auto_decompress():
    n = 10000
    stream = repeat(b'hello', n)
    stream = auto_decompress_stream(bz2_compress_stream(stream))
    assert b''.join(stream) == b'hello' * n

    n = 10000
    stream = repeat(b'hello', n)
    stream = auto_decompress_stream(stream)
    assert b''.join(stream) == b'hello' * n


def test_mkdir(tmpdir):
    d = tmpdir.join('foo')
    mkdir(str(d))
    assert d.isdir()


def test_mkdir_existing(tmpdir):
    d = tmpdir.join('foo')
    d.mkdir()
    mkdir(str(d))
    assert d.isdir()


def test_mkdir_existingfile(tmpdir):
    d = tmpdir.join('foo')
    d.write('helloworld')
    with pytest.raises(OSError):
        mkdir(str(d))


def test_safejoin():
    assert safejoin('/path/to/t', 'tnew/foo/bar') == '/path/to/t/tnew/foo/bar'
    with pytest.raises(ValueError):
        safejoin('/path/to/t', '../tnew/foo/bar')


def test_filesize():
    assert os.path.getsize(__file__) == filesize(open(__file__, 'rb'))
