# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""MAR reading support.

This module provides the MarReader class which is used to read, extract, and
verify MAR files.
"""

import os

from mardor.format import mar
from mardor.signing import get_signature_data
from mardor.signing import make_hasher
from mardor.signing import verify_signature
from mardor.utils import auto_decompress_stream
from mardor.utils import bz2_decompress_stream
from mardor.utils import file_iter
from mardor.utils import guess_compression
from mardor.utils import mkdir
from mardor.utils import safejoin
from mardor.utils import takeexactly
from mardor.utils import write_to_file
from mardor.utils import xz_decompress_stream


class MarReader(object):
    """Support for reading, extracting, and verifying MAR files.

    Example::
        with MarReader(open('test.mar', 'rb')) as m:
            m.extract('/tmp/extracted')
    """

    def __init__(self, fileobj):
        """Initialize a new MarReader object.

        Note:
            Files should always be opened in binary mode.

        Args:
            fileobj (file object): A file-like object open in read mode where
                the MAR data will be read from. This object must also be
                seekable (i.e.  support .seek() and .tell()).
        """
        self.fileobj = fileobj

        self.mardata = mar.parse_stream(self.fileobj)

    def __enter__(self):
        """Support the context manager protocol."""
        return self

    def __exit__(self, type_, value, tb):
        """Support the context manager protocol."""
        pass

    @property
    def compression_type(self):
        """Return the latest compresion type used in this MAR.

        Returns:
            One of None, 'bz2', or 'xz'

        """
        best_compression = None
        for e in self.mardata.index.entries:
            self.fileobj.seek(e.offset)
            magic = self.fileobj.read(10)
            compression = guess_compression(magic)
            if compression == 'xz':
                best_compression = 'xz'
                break
            elif compression == 'bz2' and best_compression is None:
                best_compression = 'bz2'
        return best_compression

    @property
    def signature_type(self):
        """Return the signature type used in this MAR.

        Returns:
            One of None, 'unknown', 'sha1', or 'sha384'

        """
        if not self.mardata.signatures:
            return None

        for sig in self.mardata.signatures.sigs:
            if sig.algorithm_id == 1:
                return 'sha1'
            elif sig.algorithm_id == 2:
                return 'sha384'
        else:
            return 'unknown'

    def extract_entry(self, e, decompress='auto'):
        """Yield blocks of data for this entry from this MAR file.

        Args:
            e (:obj:`mardor.format.index_entry`): An index_entry object that
                refers to this file's size and offset inside the MAR file.
            path (str): Where on disk to extract this file to.
            decompress (str, optional): Controls whether files are decompressed
                when extracted. Must be one of None, 'auto', 'bz2', or 'xz'.
                Defaults to 'auto'

        Yields:
            Blocks of data for `e`

        """
        self.fileobj.seek(e.offset)
        stream = file_iter(self.fileobj)
        stream = takeexactly(stream, e.size)
        if decompress == 'auto':
            stream = auto_decompress_stream(stream)
        elif decompress == 'bz2':
            stream = bz2_decompress_stream(stream)
        elif decompress == 'xz':
            stream = xz_decompress_stream(stream)
        elif decompress is None:
            pass
        else:
            raise ValueError("Unsupported decompression type: {}".format(decompress))

        for block in stream:
            yield block

    def extract(self, destdir, decompress='auto'):
        """Extract the entire MAR file into a directory.

        Args:
            destdir (str): A local directory on disk into which the contents of
                this MAR file will be extracted. Required parent directories
                will be created as necessary.
            decompress (obj, optional): Controls whether files are decompressed
                when extracted. Must be one of 'auto' or None. Defaults to
                'auto'.
        """
        for e in self.mardata.index.entries:
            name = e.name
            entry_path = safejoin(destdir, name)
            entry_dir = os.path.dirname(entry_path)
            mkdir(entry_dir)
            with open(entry_path, 'wb') as f:
                write_to_file(self.extract_entry(e, decompress), f)
                os.chmod(entry_path, e.flags)

    def verify(self, verify_key):
        """Verify that this MAR file has a valid signature.

        Args:
            verify_key (str): PEM formatted public key

        Returns:
            True if the MAR file's signature matches its contents
            False otherwise; this includes cases where there is no signature.

        """
        if not self.mardata.signatures or not self.mardata.signatures.sigs:
            # This MAR file can't be verified since it has no signatures
            return False

        hashers = []
        for sig in self.mardata.signatures.sigs:
            hashers.append((sig.algorithm_id, sig.signature, make_hasher(sig.algorithm_id)))

        assert len(hashers) == len(self.mardata.signatures.sigs)

        for block in get_signature_data(self.fileobj,
                                        self.mardata.signatures.filesize):
            [h.update(block) for (_, _, h) in hashers]

        for algo_id, sig, h in hashers:
            if not verify_signature(verify_key, sig, h.finalize(), h.algorithm.name):
                return False
        else:
            return True

    @property
    def productinfo(self):
        """Return the productversion and channel of this MAR if present."""
        if not self.mardata.additional:
            return None

        for s in self.mardata.additional.sections:
            if s.id == 1:
                return str(s.productversion), str(s.channel)

        return None

    def calculate_hashes(self):
        """Return hashes of the contents of this MAR file.

        The hashes depend on the algorithms defined in the MAR file's signature block.

        Returns:
            A list of (algorithm_id, hash) tuples

        """
        hashers = []
        if not self.mardata.signatures:
            return []

        for s in self.mardata.signatures.sigs:
            h = make_hasher(s.algorithm_id)
            hashers.append((s.algorithm_id, h))

        for block in get_signature_data(self.fileobj, self.mardata.signatures.filesize):
            [h.update(block) for (_, h) in hashers]

        return [(algo_id, h.finalize()) for (algo_id, h) in hashers]
