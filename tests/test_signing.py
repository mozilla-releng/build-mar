from unittest import TestCase
import os

from mardor.marfile import MarFile

TEST_MAR = os.path.join(os.path.dirname(__file__), 'test.mar')

# This was extracted via:
# curl
# https://hg.mozilla.org/mozilla-central/raw-file/58e4264903ba/toolkit/mozapps/update/updater/release_primary.der
# | openssl x509 -inform DER -pubkey -noout
TEST_KEY = os.path.join(os.path.dirname(__file__), 'test.pubkey')


class TestMarSignatures(TestCase):
    def test_verify(self):
        """Check that our test mar is signed correctly"""
        marfile = MarFile(TEST_MAR, signature_versions=[(1, TEST_KEY)])
        marfile.verify_signatures()
