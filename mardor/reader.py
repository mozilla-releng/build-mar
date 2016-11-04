'''MAR reading functionality

This module provides the MarReader class which is used to read, extract, and
verify MAR files.
'''

import os

from cryptography.exceptions import InvalidSignature

from mardor.utils import (file_iter, takeexactly, auto_decompress_stream,
                          file_writer, mkdir)
from mardor.format import mar
from mardor.signing import calculate_signatures, make_verifier_v1


class MarReader(object):
    def __init__(self, fileobj, decompress='auto'):
        assert decompress in ('auto', None)
        self.fileobj = fileobj
        self.mardata = mar.parse_stream(self.fileobj)
        self.decompress = decompress

    def close(self):
        self.fileobj.flush()

    def __enter__(self):
        return self

    def __exit__(self, type_, value, tb):
        self.close()

    def extract_entry(self, e, path):
        with open(path, 'wb') as f:
            self.fileobj.seek(e.offset)
            stream = file_iter(self.fileobj)
            stream = takeexactly(stream, e.size)
            if self.decompress == 'auto':
                stream = auto_decompress_stream(stream)
            file_writer(stream, f)

    def extract(self, destdir):
        for e in self.mardata.index.entries:
            name = e.name
            # TODO: Sanity check these
            entry_path = os.path.join(destdir, name)
            entry_dir = os.path.dirname(entry_path)
            mkdir(entry_dir)
            self.extract_entry(e, entry_path)

    def verify(self, verify_key):
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

        calculate_signatures(self.fileobj, self.mardata.signatures.filesize,
                             verifiers)
        for v in verifiers:
            try:
                v.verify()
            except InvalidSignature:
                return False
        else:
            return True
