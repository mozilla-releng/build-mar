from mardor.bits import unpackint
from mardor.utils import read_file

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    crypto = True
except ImportError:
    crypto = False

import logging
log = logging.getLogger(__name__)


def generate_signature(fp, updatefunc):
    fp.seek(0)
    # Magic
    updatefunc(fp.read(4))
    # index_offset
    updatefunc(fp.read(4))
    # file size
    updatefunc(fp.read(8))
    # number of signatures
    num_sigs = fp.read(4)
    updatefunc(num_sigs)
    num_sigs = unpackint(num_sigs)
    for i in range(num_sigs):
        # signature algo
        updatefunc(fp.read(4))

        # signature size
        sigsize = fp.read(4)
        updatefunc(sigsize)
        sigsize = unpackint(sigsize)

        # Read this, but don't update the signature with it
        fp.read(sigsize)

    # Read the rest of the file
    for block in read_file(fp):
        updatefunc(block)


class MarSignature:
    """Represents a signature"""
    size = None
    sigsize = None
    algo_id = None
    algo_name = None
    signature = None
    _offset = None  # where in the file this signature is located
    keyfile = None  # what key to use

    @classmethod
    def from_fileobj(cls, fp):
        _offset = fp.tell()
        algo_id = unpackint(fp.read(4))
        self = cls(algo_id)
        self._offset = _offset
        sigsize = unpackint(fp.read(4))
        assert sigsize == self.sigsize
        log.debug("signature data at %i to %i", fp.tell(), fp.tell() + sigsize)
        self.signature = fp.read(self.sigsize)
        log.debug("ver %i signature %i bytes at %i", algo_id, sigsize, _offset)
        return self

    def __init__(self, algo_id, keyfile=None):
        self.algo_id = algo_id
        self.keyfile = keyfile
        if self.algo_id == 1:
            self.sigsize = 256
            self.size = self.sigsize + 4 + 4
            self._verifier = None
            self.algo_name = "RSA-PKCS1-SHA1"
        else:
            raise ValueError("Unsupported signature algorithm: %s" % algo_id)

    def init_verifier(self):
        if self.algo_id == 1:
            key = serialization.load_pem_public_key(
                open(self.keyfile, 'rb').read(), default_backend())
            # Read the signature
            verifier = key.verifier(
                self.signature,
                padding.PKCS1v15(),
                hashes.SHA1(),
            )
            self._verifier = verifier

    def update(self, data):
        self._verifier.update(data)

    def verify_signature(self):
        if self.algo_id == 1:
            try:
                return self._verifier.verify() is None
            except InvalidSignature:
                return False

    def write_signature(self, fp):
        assert False
