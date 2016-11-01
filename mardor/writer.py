import os

from mardor.utils import openfile, bz2_compress_stream, file_writer
from mardor.format import mar_header, sigs_header, extras_header, index_header
from mardor.signing import make_signer_v1, calculate_signatures


class MarWriter(object):
    def __init__(self, filename_or_fileobj, compress='bz2',
                 productversion=None, channel=None,
                 signing_key=None,
                 ):
        self.fileobj = openfile(filename_or_fileobj, 'w+')
        self.entries = []
        self.signature_offset = 8
        self.additional_offset = None
        self.last_offset = 8
        self.filesize = 0
        self.compress = compress
        if productversion or channel:
            assert productversion and channel
        self.productversion = productversion
        self.channel = channel
        self.signing_key = signing_key

        if productversion and channel:
            self.use_old_format = False
        else:
            self.use_old_format = True

        self.write_header()
        if not self.use_old_format:
            fake_sigs = self.dummy_signatures()
            self.write_signatures(fake_sigs)
            self.write_additional(productversion, channel)

    def close(self):
        self.fileobj.flush()

    def __enter__(self):
        return self

    def __exit__(self, type_, value, tb):
        self.finish()
        self.close()

    def add(self, path):
        if os.path.isdir(path):
            self.add_dir(path)
        else:
            self.add_file(path)

    def add_dir(self, path):
        for root, dirs, files in os.walk(path):
            for f in files:
                self.add_file(os.path.join(root, f))

    def add_file(self, path):
        self.fileobj.seek(self.last_offset)

        with open(path) as f:
            if self.compress == 'bz2':
                f = bz2_compress_stream(f)
            size = file_writer(f, self.fileobj)

        # was Container
        e = dict(
            name=path,
            offset=self.last_offset,
            size=size,
            flags=os.stat(path).st_mode & 0o777,
        )
        self.entries.append(e)
        self.last_offset += e.size

    def write_header(self):
        self.fileobj.seek(0)
        header = mar_header.build(dict(index_offset=self.last_offset))
        self.fileobj.write(header)

    def get_signers(self):
        signers = []
        if self.signing_key:
            # Algorithm 1: 2048 RSA key w/ SHA1 hash
            signer = make_signer_v1(self.signing_key)
            signers.append(signer)
        return signers

    def dummy_signatures(self):
        signers = self.get_signers()
        return [(1, b'0' * 256)] * len(signers)

    def calculate_signatures(self):
        signers = self.get_signers()
        calculate_signatures(self.fileobj, self.filesize, signers)

        # NB: This only supports 1 signature of type 1 right now
        signatures = [(1, sig.finalize()) for sig in signers]
        return signatures

    def write_signatures(self, signatures):
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
        assert self.additional_offset == self.fileobj.tell()

    def write_additional(self, productversion, channel):
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
        self.fileobj.seek(self.last_offset)
        index = index_header.build(dict(entries=self.entries))
        self.fileobj.write(index)
        self.filesize = self.fileobj.tell()

    def finish(self):
        # Update the last_offset in the mar header
        self.write_header()
        # Write out the index of contents
        self.write_index()

        if not self.use_old_format:
            # Refresh the signature
            sigs = self.calculate_signatures()
            self.write_signatures(sigs)
            return
