import struct
import os
import bz2

from mardor.bits import unpackint, packint, unpacklongint
from mardor.utils import safe_join, read_file
from mardor.signing import MarSignature, generate_signature
import mardor.signing

import logging
log = logging.getLogger(__name__)


class MarInfo:
    """Represents information about a member of a MAR file. The following
    attributes are supported:
        `size`:     the file's size
        `name`:     the file's name
        `flags`:    file permission flags
        `_offset`:  where in the MAR file this member exists
    """
    size = None
    name = None
    flags = None
    _offset = None

    # The member info is serialized as a sequence of 4-byte integers
    # representing the offset, size, and flags of the file followed by a null
    # terminated string representing the filename
    _member_fmt = ">LLL"

    @classmethod
    def from_fileobj(cls, fp):
        """Return a MarInfo object by reading open file object `fp`"""
        self = cls()
        data = fp.read(12)
        if not data:
            # EOF
            return None
        if len(data) != 12:
            raise ValueError("Malformed mar?")
        self._offset, self.size, self.flags = struct.unpack(
            cls._member_fmt, data)
        name = b""
        while True:
            c = fp.read(1)
            if c is None:
                raise ValueError("Malformed mar?")
            if c == b"\x00":
                break
            name += c
        self.name = name.decode("ascii")
        return self

    def __repr__(self):
        return "<%s %o %s bytes starting at %i>" % (
            self.name, self.flags, self.size, self._offset)

    def to_bytes(self):
        return struct.pack(self._member_fmt, self._offset, self.size, self.flags) + \
            self.name.encode("ascii") + b"\x00"


class MarFile:
    """Represents a MAR file on disk.

    `name`:     filename of MAR file
    `mode`:     either 'r' or 'w', depending on if you're reading or writing.
                defaults to 'r'
    """

    # TODO: Handle writing the product information block

    def __init__(self, name, mode="r", signature_versions=[]):
        if mode not in "rw":
            raise ValueError("Mode must be either 'r' or 'w'")

        self.name = name
        self.mode = mode
        if mode == 'w':
            self.fileobj = open(name, 'wb')
        else:
            self.fileobj = open(name, 'rb')

        self.members = []

        # Current offset of our index in the file. This gets updated as we add
        # files to the MAR. This also refers to the end of the file until we've
        # actually written the index
        self.index_offset = 8

        # Flag to indicate that we need to re-write the index
        self.rewrite_index = False

        # Signatures, if any
        self.signatures = []
        self.signature_versions = signature_versions

        if mode == "r":
            # Read the file's index
            self._read_index()
        elif mode == "w":
            self._prepare_index()

    def _prepare_index(self):
        # Create placeholder signatures
        if self.signature_versions:
            # Space for num_signatures and file size
            self.index_offset += 4 + 8

        # Write the magic and placeholder for the index
        self.fileobj.write(b"MAR1" + packint(self.index_offset))

        if self.signature_versions:
            # Write placeholder for file size
            self.fileobj.write(struct.pack(">Q", 0))

            # Write num_signatures
            self.fileobj.write(packint(len(self.signature_versions)))

            for algo_id, keyfile in self.signature_versions:
                sig = MarSignature(algo_id, keyfile)
                sig._offset = self.index_offset
                self.index_offset += sig.size
                self.signatures.append(sig)
                # algoid
                self.fileobj.write(packint(algo_id))
                # numbytes
                self.fileobj.write(packint(sig.sigsize))
                # space for signature
                self.fileobj.write("\0" * sig.sigsize)

    def _read_index(self):
        fp = self.fileobj
        fp.seek(0)
        # Read the header
        header = fp.read(8)
        magic, self.index_offset = struct.unpack(">4sL", header)
        log.debug("index_offset is %i", self.index_offset)
        if magic != b"MAR1":
            raise ValueError("Bad magic")
        fp.seek(self.index_offset)

        # Read the index_size, we don't use it though
        # We just read all the info sections from here to the end of the file
        fp.read(4)

        self.members = []

        while True:
            info = MarInfo.from_fileobj(fp)
            if not info:
                break
            self.members.append(info)

        # Sort them by where they are in the file
        self.members.sort(key=lambda info: info._offset)

        # Read the signature block
        # This present if the first file data begins at offset > 8
        first_offset = self.members[0]._offset
        log.debug("first offset is %i", first_offset)
        if first_offset > 8:
            log.debug("reading signatures")
            fp.seek(8)
            file_size = unpacklongint(fp.read(8))
            # Check that the file size matches
            fp.seek(0, 2)
            assert fp.tell() == file_size
            fp.seek(16)
            num_sigs = unpackint(fp.read(4))
            log.debug("file_size: %i bytes", file_size)
            log.debug("%i signatures present", num_sigs)
            for i in range(num_sigs):
                sig = MarSignature.from_fileobj(fp)
                for algo_id, keyfile in self.signature_versions:
                    if algo_id == sig.algo_id:
                        sig.keyfile = keyfile
                        break
                else:
                    log.info("no key specified to validate %i"
                             " signature", sig.algo_id)
                self.signatures.append(sig)

        # Read additional sections; this is also only present if we have a
        # signature block
            num_additional_sections = unpackint(fp.read(4))
            log.debug("%i additional sections present",
                      num_additional_sections)
            for i in range(num_additional_sections):
                block_size = unpackint(fp.read(4))
                block_id = unpackint(fp.read(4))
                block_data = fp.read(block_size - 8)
                log.debug("%i %i bytes: %s",
                          block_id, block_size, repr(block_data))

    def verify_signatures(self):
        if not mardor.signing.crypto:
            log.warning("no crypto modules loaded to check signatures "
                        "(did you install the cryptography module?)")
            raise IOError("Verification failed")

        if not self.signatures:
            log.info("no signatures to verify")
            return

        fp = self.fileobj

        for sig in self.signatures:
            sig.init_verifier()

        generate_signature(fp, self._update_signatures)

        for sig in self.signatures:
            if not sig.verify_signature():
                raise IOError("Verification failed")
            else:
                log.info("Verification OK (%s)", sig.algo_name)

    def _update_signatures(self, data):
        for sig in self.signatures:
            sig.update(data)

    def add(self, path, name=None, fileobj=None, flags=None):
        """Adds `path` to this MAR file.

        If `name` is set, the file is named with `name` in the MAR, otherwise
        use the normalized version of `path`.

        If `fileobj` is set, file data is read from it, otherwise the file
        located at `path` will be opened and read.

        If `flags` is set, it will be used as the permission flags in the MAR,
        otherwise the permissions of `path` will be used.
        """
        if self.mode != "w":
            raise ValueError("File not opened for writing")

        # If path refers to a directory, add all the files inside of it
        if os.path.isdir(path):
            self.add_dir(path)
            return

        info = MarInfo()
        info._offset = self.index_offset
        info.size = 0
        if not fileobj:
            fileobj = open(path, 'rb')
            info.flags = flags or os.stat(path).st_mode & 0o777
            info.name = name or os.path.normpath(path)
        else:
            assert flags
            info.flags = flags
            info.name = name or path

        self.fileobj.seek(self.index_offset)
        for block in read_file(fileobj):
            self.fileobj.write(block)
            info.size += len(block)

        # Shift our index, and mark that we have to re-write it on close
        self.index_offset += info.size
        self.rewrite_index = True
        self.members.append(info)

    def add_dir(self, path):
        """Add all of the files under `path` to the MAR file"""
        for root, dirs, files in os.walk(path):
            for f in files:
                self.add(os.path.join(root, f))

    def close(self):
        """Close the MAR file, writing out the new index if required.

        Furthur modifications to the file are not allowed."""
        if self.mode == "w":
            if self.rewrite_index:
                self._write_index()

            if self.mode == "w" and self.signatures:
                # Update file size
                self.fileobj.seek(0, 2)
                totalsize = self.fileobj.tell()
                self.fileobj.seek(8)
                self.fileobj.write(struct.pack(">Q", totalsize))

                self.fileobj.flush()
                fileobj = open(self.name, 'rb')
                generate_signature(fileobj, self._update_signatures)
                for sig in self.signatures:
                    # print sig._offset
                    sig.write_signature(self.fileobj)

        self.fileobj.close()
        self.fileobj = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, value, traceback):
        self.close()

    def _write_index(self):
        """Writes the index of all members at the end of the file"""
        log.debug("rewriting index at %i", self.index_offset + 4)
        self.fileobj.seek(self.index_offset + 4)
        index_size = 0
        for m in self.members:
            member_bytes = m.to_bytes()
            index_size += len(member_bytes)

        for m in self.members:
            member_bytes = m.to_bytes()
            self.fileobj.write(member_bytes)
        self.fileobj.seek(self.index_offset)
        self.fileobj.write(packint(index_size))

        # Update the offset to the index
        self.fileobj.seek(4)
        self.fileobj.write(packint(self.index_offset))

    def extractall(self, path=".", members=None):
        """Extracts members into `path`. If members is None (the default), then
        all members are extracted."""
        if members is None:
            members = self.members
        for m in members:
            self.extract(m, path)

    def extract(self, member, path="."):
        """Extract `member` into `path` which defaults to the current
        directory. Absolute paths are converted to be relative to `path`

        Returns the path the member was extracted to."""
        dstpath = safe_join(path, member.name)
        dirname = os.path.dirname(dstpath)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

        self.fileobj.seek(member._offset)
        # TODO: Should this be done all in memory?
        open(dstpath, "wb").write(self.fileobj.read(member.size))
        os.chmod(dstpath, member.flags)

        return dstpath


class BZ2MarFile(MarFile):
    """Subclass of MarFile that compresses/decompresses members using BZ2.

    BZ2 compression is used for most update MARs."""
    def extract(self, member, path="."):
        """Extract and decompress `member` into `path` which defaults to the
        current directory."""
        dstpath = safe_join(path, member.name)
        dirname = os.path.dirname(dstpath)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

        self.fileobj.seek(member._offset)
        decomp = bz2.BZ2Decompressor()
        output = open(dstpath, "wb")
        toread = member.size
        while True:
            thisblock = min(128 * 1024, toread)
            block = self.fileobj.read(thisblock)
            if not block:
                break
            toread -= len(block)
            output.write(decomp.decompress(block))
        output.close()
        os.chmod(dstpath, member.flags)

        return dstpath

    def add(self, path, name=None, fileobj=None, mode=None):
        """Adds `path` compressed with BZ2 to this MAR file.

        If `name` is set, the file is named with `name` in the MAR, otherwise
        use the normalized version of `path`.

        If `fileobj` is set, file data is read from it, otherwise the file
        located at `path` will be opened and read.

        If `flags` is set, it will be used as the permission flags in the MAR,
        otherwise the permissions of `path` will be used.
        """
        if self.mode != "w":
            raise ValueError("File not opened for writing")
        if os.path.isdir(path):
            self.add_dir(path)
            return
        info = MarInfo()
        info.name = name or os.path.normpath(path)
        info.size = 0
        if not fileobj:
            info.flags = os.stat(path).st_mode & 0o777
        else:
            info.flags = mode
        info._offset = self.index_offset

        if not fileobj:
            f = open(path, 'rb')
        else:
            f = fileobj
        comp = bz2.BZ2Compressor(9)
        self.fileobj.seek(self.index_offset)
        for block in read_file(f, 512 * 1024):
            block = comp.compress(block)
            info.size += len(block)
            self.fileobj.write(block)
        block = comp.flush()
        info.size += len(block)
        self.fileobj.write(block)

        self.index_offset += info.size
        self.rewrite_index = True
        self.members.append(info)
