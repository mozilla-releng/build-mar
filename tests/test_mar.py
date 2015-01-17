from unittest import TestCase
import shutil
import os
import tempfile
import hashlib

from mar.mar import MarFile

TEST_MAR = os.path.join(os.path.dirname(__file__), 'test.mar')

def sha1sum(b):
    """Returns the sha1sum of a byte string"""
    h = hashlib.new('sha1')
    h.update(b)
    return h.hexdigest()


def test_list():
    m = MarFile(TEST_MAR)
    assert repr(m.members[0]) == "<update.manifest 664 141 bytes starting at 392>", m.members[0]
    assert repr(m.members[1]) == "<defaults/pref/channel-prefs.js 664 76 bytes starting at 533>", m.members[1]


class TestMar(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.marfile = MarFile(TEST_MAR)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_extract(self):
        m = self.marfile.members[0]
        self.marfile.extract(m, self.tmpdir)
        fn = os.path.join(self.tmpdir, m.name)

        # Check that the size matches what's in the manifest
        self.assertEquals(os.path.getsize(fn), m.size)

        # Check that the contents match
        data = open(fn, 'rb').read()
        h = sha1sum(data)
        self.assertEquals("6a7890e740f1e18a425b51fefbde2f6b86f91a12", h)


class TestExceptions(TestCase):
    def test_badmar(self):
        self.assertRaises(ValueError, MarFile, __file__)
