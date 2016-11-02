#!/usr/bin/env python
import os
import bz2
from functools import partial
from itertools import chain


def mkdir(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno == 17:
            return
        raise


def file_iter(f):
    for block in iter(partial(f.read, 1024**2), b''):
        yield block


def imaxsize(iterable, size):
    '''
    yields blocks from iterable until at most len(size) have been returned
    '''
    total = 0
    for block in iterable:
        n = min(len(block), size - total)
        block = block[:n]
        if not block:
            break
        yield block
        total += len(block)


def file_writer(src, dst):
    n = 0
    for block in src:
        dst.write(block)
        n += len(block)
    return n


def bz2_decompress_stream(src):
    dec = bz2.BZ2Decompressor()
    for block in src:
        decoded = dec.decompress(block)
        if decoded:
            yield decoded


def auto_decompress_stream(src):
    block = next(src)
    if block.startswith(b'BZh'):
        src = bz2_decompress_stream(chain([block], src))
    else:
        src = chain([block], src)

    for block in src:
        yield block


def bz2_compress_stream(src, level=9):
    compressor = bz2.BZ2Compressor(level)
    for block in src:
        encoded = compressor.compress(block)
        if encoded:
            yield encoded
    encoded = compressor.flush()
    if encoded:
        yield encoded
