# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Utilities for reading/writing MAR files."""
import bz2
import os
from functools import partial
from itertools import chain

import six

if six.PY2:
    from backports import lzma
else:
    import lzma


def mkdir(path):
    """Make a directory and its parents.

    Args:
        path (str): path to create

    Returns:
        None

    Raises:
        OSError if the directory cannot be created.

    """
    try:
        os.makedirs(path)
        # sanity check
        if not os.path.isdir(path):  # pragma: no cover
            raise IOError('path is not a directory')
    except OSError as e:
        # EEXIST
        if e.errno == 17 and os.path.isdir(path):
            return
        raise


def file_iter(f):
    """Yield blocks of data from file object `f`.

    Args:
        f (file-like object): file-like object that must suport .read(n)

    Yields:
        blocks of data from `f`

    """
    for block in iter(partial(f.read, 1024**2), b''):
        yield block


def takeexactly(iterable, size):
    """Yield blocks from `iterable` until exactly len(size) have been returned.

    Args:
        iterable (iterable): Any iterable that yields sliceable objects that
                             have length.
        size (int): How much data to consume

    Yields:
        blocks from `iterable` such that
        sum(len(block) for block in takeexactly(iterable, size)) == size

    Raises:
        ValueError if there is less than `size` data in `iterable`

    """
    total = 0
    for block in iterable:
        n = min(len(block), size - total)
        block = block[:n]
        if block:
            yield block
        total += len(block)
        if total >= size:
            break
    if total < size:
        raise ValueError('not enough data (yielded {} of {})')

    # sanity check; this should never happen
    if total != size:  # pragma: no cover
        raise ValueError('yielded too much data')


def write_to_file(src, dst):
    """Write data from `src` into `dst`.

    Args:
        src (iterable): iterable that yields blocks of data to write
        dst (file-like object): file-like object that must support
            .write(block)

    Returns:
        number of bytes written to `dst`

    """
    n = 0
    for block in src:
        dst.write(block)
        n += len(block)
    return n


def bz2_compress_stream(src, level=9):
    """Compress data from `src`.

    Args:
        src (iterable): iterable that yields blocks of data to compress
        level (int): compression level (1-9) default is 9

    Yields:
        blocks of compressed data

    """
    compressor = bz2.BZ2Compressor(level)
    for block in src:
        encoded = compressor.compress(block)
        if encoded:
            yield encoded
    yield compressor.flush()


def bz2_decompress_stream(src):
    """Decompress data from `src`.

    Args:
        src (iterable): iterable that yields blocks of compressed data

    Yields:
        blocks of uncompressed data

    """
    dec = bz2.BZ2Decompressor()
    for block in src:
        decoded = dec.decompress(block)
        if decoded:
            yield decoded


def xz_compress_stream(src):
    """Compress data from `src`.

    Args:
        src (iterable): iterable that yields blocks of data to compress

    Yields:
        blocks of compressed data

    """
    compressor = lzma.LZMACompressor(
        check=lzma.CHECK_CRC64,
        filters=[
            {"id": lzma.FILTER_X86},
            {"id": lzma.FILTER_LZMA2,
             "preset": lzma.PRESET_DEFAULT},
        ])
    for block in src:
        encoded = compressor.compress(block)
        if encoded:
            yield encoded
    yield compressor.flush()


def xz_decompress_stream(src):
    """Decompress data from `src`.

    Args:
        src (iterable): iterable that yields blocks of compressed data

    Yields:
        blocks of uncompressed data

    """
    dec = lzma.LZMADecompressor()
    for block in src:
        decoded = dec.decompress(block)
        if decoded:
            yield decoded

    if dec.unused_data:
        raise IOError('Read unused data at end of compressed stream')


def guess_compression(block):
    """Return the compression type of the data.

    Args:
        block (bytes): block of data to identify

    Returns:
        One of None, 'bz2', or 'xz'

    """
    if block.startswith(b'BZh'):
        return 'bz2'
    elif block.startswith(b'\xfd7zXZ\x00'):
        return 'xz'
    return None


def auto_decompress_stream(src):
    """Decompress data from `src` if required.

    If the first block of `src` appears to be compressed, then the entire
    stream will be uncompressed. Otherwise the stream will be passed along
    as-is.

    Args:
        src (iterable): iterable that yields blocks of data

    Yields:
        blocks of uncompressed data

    """
    block = next(src)
    compression = guess_compression(block)
    if compression == 'bz2':
        src = bz2_decompress_stream(chain([block], src))
    elif compression == 'xz':
        src = xz_decompress_stream(chain([block], src))
    else:
        src = chain([block], src)

    for block in src:
        yield block


def path_is_inside(path, dirname):
    """Return True if path is under dirname."""
    path = os.path.abspath(path)
    dirname = os.path.abspath(dirname)
    while len(path) >= len(dirname):
        if path == dirname:
            return True
        newpath = os.path.dirname(path)
        if newpath == path:
            return False
        path = newpath
    return False


def safejoin(base, *elements):
    """Safely joins paths together.

    The result will always be a subdirectory under `base`, otherwise ValueError
    is raised.

    Args:
        base (str): base path
        elements (list of strings): path elements to join to base

    Returns:
        elements joined to base

    """
    # TODO: do we really want to be absolute here?
    base = os.path.abspath(base)
    path = os.path.join(base, *elements)
    path = os.path.normpath(path)
    if not path_is_inside(path, base):
        raise ValueError('target path is outside of the base path')
    return path


def filesize(fileobj):
    """Return the number of bytes in the fileobj.

    This function seeks to the end of the file, and then back to the original position.

    """
    current = fileobj.tell()
    fileobj.seek(0, 2)
    end = fileobj.tell()
    fileobj.seek(current)
    return end
