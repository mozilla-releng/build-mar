# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""MAR writing support.

This module provides the MarWriter class which is used to write MAR files.
"""
import os
import tempfile
from enum import Enum

from mardor.format import extras_header
from mardor.format import index_header
from mardor.format import mar_header
from mardor.format import sigs_header
from mardor.signing import SigningAlgo
from mardor.signing import get_signature_data
from mardor.signing import make_signer_v1
from mardor.signing import make_signer_v2
from mardor.utils import bz2_compress_stream
from mardor.utils import file_iter
from mardor.utils import write_to_file
from mardor.utils import xz_compress_stream


class Compression(Enum):
    """
    Enum representing types of compression we can do.

    none: no compression
    bz2: bz2 compression
    xz: xz compression
    """

    none = 0
    bz2 = 1
    xz = 2


class MarWriter(object):
    """Class for writing MAR files.

    Example::
        with MarWriter(open('test.mar', 'w+b')) as m:
            m.add('/tmp/data')
    """

    def __init__(self, fileobj,
                 productversion=None, channel=None,
                 signing_key=None,
                 signing_algorithm=SigningAlgo.SHA384,
                 xz_compression=False,
                 ):
        """Initialize a new MarWriter object.

        Note:
            Files should always be opened in binary mode.

        Args:
            fileobj (file object): A file-like object open in read/write mode
                (e.g. 'w+b' mode) where the MAR data will be written to. This
                object must also be seekable (i.e.  support .seek() and
                .tell()).
            productversion (str): product version string to encode in the MAR
                header
            channel (str): channel name to encode in the MAR header
                productversion and channel must be specified together
            signing_key (str): PEM encoded private key used for signing
            signing_algorithm (SigningAlgo):
        """
        self.xz_compression = xz_compression
        self.fileobj = fileobj
        if xz_compression:
            self.data_fileobj = tempfile.TemporaryFile()
        else:
            self.data_fileobj = fileobj
        self.entries = []
        self.signature_offset = 8
        self.additional_offset = None
        self.last_offset = 8
        self.filesize = 0
        if (productversion or channel) and not (productversion and channel):
            raise ValueError('productversion and channel must be specified'
                             ' together')
        self.productversion = productversion
        self.channel = channel
        self.signing_key = signing_key
        self.signing_algorithm = signing_algorithm

        if productversion and channel:
            self.use_old_format = False
        else:
            self.use_old_format = True

        if self.use_old_format and self.signing_key:
            raise ValueError("productversion and channel must be specified when signing_key is")

        self.write_header()
        if not self.use_old_format:
            fake_sigs = self.dummy_signatures()
            self.write_signatures(fake_sigs)
            self.write_additional(productversion, channel)

        # Sync up the file pointer positions
        if xz_compression:
            self.data_offset = self.fileobj.tell()
            self.data_fileobj.seek(self.data_offset)

    def flush(self):
        """Flush data written to our file object."""
        self.fileobj.flush()

    def __enter__(self):
        """Support the context manager protocol.

        On exit, .finish() will be called and then the data will be flushed to
        our file object.

        Example:
            with MarWriter(file_obj) as m:
                m.add('/path/to/directory')
        """
        return self

    def __exit__(self, type_, value, tb):
        """Support the context manager protocol.

        Finalizes writing to the MAR file.

        Calls .finish() and then .flush()
        """
        self.finish()
        self.flush()

    def add(self, path, compress=Compression.bz2):
        """Add `path` to the MAR file.

        If `path` is a file, it will be added directly.
        If `path` is a directory, it will be traversed recursively and all
        files inside will be added.

        Args:
            path (str): path to file or directory on disk to add to this MAR
                file
            compress (obj): instance of Compression. defaults to
                            Compression.bz2.
        """
        if os.path.isdir(path):
            self.add_dir(path, compress)
        else:
            self.add_file(path, compress)

    def add_dir(self, path, compress):
        """Add all files under directory `path` to the MAR file.

        Args:
            path (str): path to directory to add to this MAR file
            compress (obj): instance of Compression. defaults to
                            Compression.bz2.
        """
        if not os.path.isdir(path):
            raise ValueError('{} is not a directory'.format(path))
        for root, dirs, files in os.walk(path):
            for f in files:
                self.add_file(os.path.join(root, f), compress)

    def add_fileobj(self, fileobj, path, compress):
        """Add the contents of a file object to the MAR file.

        Args:
            fileobj (file-like object): open file object data will be read from
            path (str): name of this file in the MAR file
            compress (obj): instance of Compression. defaults to
                            Compression.bz2.
        """
        self.data_fileobj.seek(self.last_offset)

        f = file_iter(fileobj)
        if compress == Compression.bz2:
            f = bz2_compress_stream(f)
        size = write_to_file(f, self.data_fileobj)

        # On Windows, convert \ to /
        # very difficult to mock this out for coverage on linux
        if os.sep == '\\':  # pragma: no cover
            path = path.replace('\\', '/')

        e = dict(
            name=path,
            offset=self.last_offset,
            size=size,
            flags=os.stat(path).st_mode & 0o777,
        )
        self.entries.append(e)
        self.last_offset += e['size']

    def add_file(self, path, compress):
        """Add a single file to the MAR file.

        Args:
            path (str): path to a file to add to this MAR file.
            compress (obj): instance of Compression. defaults to
                            Compression.bz2.
        """
        if not os.path.isfile(path):
            raise ValueError('{} is not a file'.format(path))
        self.fileobj.seek(self.last_offset)

        with open(path, 'rb') as f:
            self.add_fileobj(f, path, compress)

    def write_header(self):
        """Write the MAR header to the file.

        The MAR header includes the MAR magic bytes as well as the offset to
        where the index data can be found.
        """
        self.fileobj.seek(0)
        header = mar_header.build(dict(index_offset=self.last_offset))
        self.fileobj.write(header)

    def get_signers(self):
        """Create signing objects for signing this MAR file.

        Returns:
            A list of signing objects. This may be an empty list in case no
            signing key was provided.
        """
        signers = []
        if self.signing_key and self.signing_algorithm == SigningAlgo.SHA1:
            # Algorithm 1: 2048 RSA key w/ SHA1 hash
            signer = make_signer_v1(self.signing_key)
            signers.append((1, signer))
        elif self.signing_key and self.signing_algorithm == SigningAlgo.SHA384:
            # Algorithm 2: 4096 RSA key w/ SHA384 hash
            signer = make_signer_v2(self.signing_key)
            signers.append((2, signer))
        return signers

    def dummy_signatures(self):
        """Create a dummy signature.

        This is used when initially writing the MAR header and we don't know
        what the final signature data will be.

        Returns:
            Fake signature data suitable for writing to the header with
            .write_signatures()
        """
        signers = self.get_signers()
        signatures = []
        for algo_id, signer in signers:
            if algo_id == 1:
                signatures.append((1, b'0' * 256))
            elif algo_id == 2:
                signatures.append((2, b'0' * 512))
        return signatures

    def calculate_signatures(self):
        """Calculate the signatures for this MAR file.

        Returns:
            A list of signature tuples: [(algorithm_id, signature_data), ...]
        """
        signers = self.get_signers()
        for block in get_signature_data(self.fileobj, self.filesize):
            [sig.update(block) for (_, sig) in signers]

        signatures = [(algo_id, sig.finalize()) for (algo_id, sig) in signers]
        return signatures

    def write_signatures(self, signatures):
        """Write signature data to the MAR file.

        Args:
            signatures (list): list of signature tuples of the form
                (algorithm_id, signature_data)
        """
        self.fileobj.seek(self.signature_offset)
        sig_entries = [dict(algorithm_id=id_,
                            size=len(sig),
                            signature=sig)
                       for (id_, sig) in signatures]

        sigs = sigs_header.build(dict(
            filesize=self.filesize,
            count=len(signatures),
            sigs=sig_entries,
        ))
        self.fileobj.write(sigs)
        signatures_len = len(sigs)
        self.additional_offset = self.signature_offset + signatures_len
        # sanity check; this should never happen
        if not self.additional_offset == self.fileobj.tell():  # pragma: no cover
            raise IOError('ended up at unexpected offset')

    def write_additional(self, productversion, channel):
        """Write the additional information to the MAR header.

        Args:
            productversion (str): product and version string
            channel (str): channel string
        """
        self.fileobj.seek(self.additional_offset)
        extras = extras_header.build(dict(
            count=1,
            sections=[dict(
                channel=channel,
                productversion=productversion,
                size=len(channel) + len(productversion) + 2 + 8,
                padding='',
            )],
        ))

        self.fileobj.write(extras)
        self.last_offset = self.fileobj.tell()

    def write_index(self):
        """Write the index of all our files to the MAR file."""
        self.fileobj.seek(self.last_offset)
        index = index_header.build(dict(entries=self.entries))
        self.fileobj.write(index)
        self.filesize = self.fileobj.tell()

    def finish(self):
        """Finalize the MAR file.

        The MAR header, index and signatures need to be updated once we've
        finished adding all the files.
        """
        if self.xz_compression:
            # Compress the data, and write to the real file
            self.data_fileobj.seek(self.data_offset)
            self.fileobj.seek(self.data_offset)
            write_to_file(xz_compress_stream(file_iter(self.data_fileobj)), self.fileobj)
            self.last_offset = self.fileobj.tell()
            self.data_fileobj.close()

        # Update the last_offset in the mar header
        self.write_header()
        # Write out the index of contents
        self.write_index()

        if not self.use_old_format:
            # Refresh the signature
            sigs = self.calculate_signatures()
            self.write_signatures(sigs)
