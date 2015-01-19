from unittest import TestCase
import shutil
import os
import tempfile
import hashlib

from mar.mar import MarFile, BZ2MarFile, read_file, safe_join

TEST_MAR = os.path.join(os.path.dirname(__file__), 'test.mar')


def test_read_file():
    data = []
    for block in read_file(open(__file__, 'rb')):
        data.append(block)
    assert b''.join(data) == open(__file__, 'rb').read()


class TestSafeJoin(TestCase):
    def test_normal(self):
        self.assertEquals(safe_join("/a/b/c", "foo/bar"), "/a/b/c/foo/bar")

    def test_absolute(self):
        self.assertEquals(safe_join("/a/b/c", "/foo/bar"), "/a/b/c/foo/bar")
        # TODO: Test windows support. os.path.isabs returns False for C:/ foo
        # on linux

    def test_unsafe(self):
        self.assertRaises(IOError, safe_join, "/a/b/c", "foo/../../bar")


def sha1sum(b):
    """Returns the sha1sum of a byte string"""
    h = hashlib.new('sha1')
    h.update(b)
    return h.hexdigest()


def test_list():
    with MarFile(TEST_MAR) as m:
        assert repr(m.members[0]) == "<update.manifest 664 141 bytes starting at 392>", m.members[0]
        assert repr(m.members[1]) == "<defaults/pref/channel-prefs.js 664 76 bytes starting at 533>", m.members[1]

    with BZ2MarFile(TEST_MAR) as m:
        assert repr(m.members[0]) == "<update.manifest 664 141 bytes starting at 392>", m.members[0]
        assert repr(m.members[1]) == "<defaults/pref/channel-prefs.js 664 76 bytes starting at 533>", m.members[1]


class TestReadingMar(TestCase):
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


class TestReadingBZ2Mar(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.marfile = BZ2MarFile(TEST_MAR)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_extract_bz2(self):
        m = self.marfile.members[0]
        self.marfile.extract(m, self.tmpdir)
        fn = os.path.join(self.tmpdir, m.name)

        # The size in the manifest is of the compressed data, so we need to
        # check that we've extracted the correct number of uncompressed bytes
        # here
        self.assertEquals(os.path.getsize(fn), 308)

        # Check that the contents match
        data = open(fn, 'rb').read()
        h = sha1sum(data)
        self.assertEquals("5177f5938923e94820d8565a1a0f25d19b4821d1", h)


class TestWritingMar(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_add(self):
        marfile = os.path.join(self.tmpdir, 'test.mar')
        with MarFile(marfile, 'w') as m:
            m.add(__file__)

        with MarFile(marfile) as m:
            self.assertEquals(len(m.members), 1)
            self.assertEquals(m.members[0].size, os.path.getsize(__file__))
            #assert False, os.path.join(self.tmpdir, m.members[0].name)
            #assert False, m.members[0]
            extracted = m.extract(m.members[0], self.tmpdir)
            self.assertEquals(
                open(extracted, 'rb').read(),
                open(__file__, 'rb').read()
            )


class TestExceptions(TestCase):
    def test_badmar(self):
        self.assertRaises(ValueError, MarFile, __file__)
