# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from itertools import repeat

import pytest

from mardor.utils import (takeexactly, bz2_compress_stream,
                          bz2_decompress_stream, auto_decompress_stream, mkdir)

from hypothesis import given, assume
import hypothesis.strategies as st


@given(st.lists(st.binary()), st.integers(min_value=0))
def test_takeexactly(data, n):
    assume(len(b''.join(data)) >= n)

    assert len(b''.join(takeexactly(data, n))) == n


@given(st.lists(st.binary()), st.integers(min_value=0))
def test_takeexactly_notenough(data, n):
    assume(len(b''.join(data)) < n)

    with pytest.raises(ValueError):
        b''.join(takeexactly(data, n))


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
