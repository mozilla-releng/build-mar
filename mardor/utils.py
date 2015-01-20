import os
from functools import partial


def read_file(fp, blocksize=8192):
    """Yields blocks of data from file object fp"""
    for block in iter(partial(fp.read, blocksize), b''):
        yield block


def safe_join(parent, path):
    """Returns $parent/$path

    Raises IOError in case the resulting path ends up outside of parent for
    some reason (e.g. by using ../../..)
    """
    while os.path.isabs(path):
        path = path.lstrip("/")
        drive, tail = os.path.splitdrive(path)
        path = tail

    path = os.path.normpath(path)
    if path.startswith("../"):
        raise IOError("unsafe join of %s/%s" % (parent, path))

    return os.path.join(parent, path)
