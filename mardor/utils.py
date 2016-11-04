"""Utilities for reading/writing MAR files."""
import os
import bz2
from functools import partial
from itertools import chain


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
        assert os.path.isdir(path)
    except OSError as e:
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

    assert total == size


def file_writer(src, dst):
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
    if block.startswith(b'BZh'):
        src = bz2_decompress_stream(chain([block], src))
    else:
        src = chain([block], src)

    for block in src:
        yield block
