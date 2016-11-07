# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""MAR reading support.

This module provides the MarReader class which is used to read, extract, and
verify MAR files.
"""

import os

from cryptography.exceptions import InvalidSignature

from mardor.utils import (file_iter, takeexactly, auto_decompress_stream,
                          write_to_file, mkdir, safejoin)
from mardor.format import mar
from mardor.signing import get_signature_data, make_verifier_v1


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

    def extract_entry(self, e, decompress='auto'):
        """Yield blocks of data for this entry from this MAR file.

        Args:
            e (:obj:`mardor.format.index_entry`): An index_entry object that
                refers to this file's size and offset inside the MAR file.
            path (str): Where on disk to extract this file to.
            decompress (obj, optional): Controls whether files are decompressed
                when extracted. Must be one of 'auto' or None. Defaults to
                'auto'.

        Yields:
            Blocks of data for `e`
        """
        self.fileobj.seek(e.offset)
        stream = file_iter(self.fileobj)
        stream = takeexactly(stream, e.size)
        if decompress == 'auto':
            stream = auto_decompress_stream(stream)
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
            print('extracting to', entry_path)
            entry_dir = os.path.dirname(entry_path)
            mkdir(entry_dir)
            with open(entry_path, 'wb') as f:
                write_to_file(self.extract_entry(e, decompress), f)

    def verify(self, verify_key):
        """Verify that this MAR file has a valid signature.

        Args:
            verify_key (str): PEM formatted public key

        Returns:
            True if the MAR file's signature matches its contents
            False otherwise; this includes cases where there is no signature.
        """
        if not self.mardata.signatures:
            # This MAR file can't be verified since it has no signatures
            return False

        verifiers = []
        for sig in self.mardata.signatures.sigs:
            if sig.algorithm_id == 1:
                verifier = make_verifier_v1(verify_key, sig.signature)
                verifiers.append(verifier)
            else:
                raise ValueError('Unsupported algorithm')

        for block in get_signature_data(self.fileobj,
                                        self.mardata.signatures.filesize):
            [v.update(block) for v in verifiers]

        for v in verifiers:
            try:
                v.verify()
            except InvalidSignature:
                return False
        else:
            return True
