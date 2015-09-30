from unittest import TestCase
import shutil
import os
import tempfile
import hashlib

from mardor.marfile import MarFile, BZ2MarFile, AdditionalInfo

TEST_MAR = os.path.join(os.path.dirname(__file__), 'test.mar')


def sha1sum(b):
    """Returns the sha1sum of a byte string"""
    h = hashlib.new('sha1')
    h.update(b)
    return h.hexdigest()


def test_list():
    for marfile in MarFile(TEST_MAR), MarFile(open(TEST_MAR, "rb")):
        with marfile as m:
            assert repr(m.members[0]) == "<update.manifest 664 141 bytes starting at 392>", m.members[0]
            assert repr(m.members[1]) == "<defaults/pref/channel-prefs.js 664 76 bytes starting at 533>", m.members[1]
            assert len(m.additional_info) == 1
            assert m.additional_info[0].name == "PRODUCT INFORMATION"
            assert m.additional_info[0].info == {'MARChannelName': 'thunderbird-comm-esr', 'ProductVersion': '100.0'}

    for marfile in BZ2MarFile(TEST_MAR), BZ2MarFile(open(TEST_MAR, "rb")):
        with marfile as m:
            assert repr(m.members[0]) == "<update.manifest 664 141 bytes starting at 392>", m.members[0]
            assert repr(m.members[1]) == "<defaults/pref/channel-prefs.js 664 76 bytes starting at 533>", m.members[1]
            assert len(m.additional_info) == 1
            assert m.additional_info[0].name == "PRODUCT INFORMATION"
            assert m.additional_info[0].info == {'MARChannelName': 'thunderbird-comm-esr', 'ProductVersion': '100.0'}


class TestReadingMar(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.marfile = MarFile(TEST_MAR)
        self.marfile_fo = MarFile(open(TEST_MAR, "rb"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_extract(self):
        m = self.marfile.members[0]
        for marfile in self.marfile, self.marfile_fo:
            marfile.extract(m, self.tmpdir)
            fn = os.path.join(self.tmpdir, m.name)

            # Check that the size matches what's in the manifest
            self.assertEquals(os.path.getsize(fn), m.size)

            # Check that the contents match
            data = open(fn, 'rb').read()
            h = sha1sum(data)
            self.assertEquals("6a7890e740f1e18a425b51fefbde2f6b86f91a12", h)

    def test_extractall(self):
        for marfile in self.marfile, self.marfile_fo:
            marfile.extractall(self.tmpdir)

            all_files = []
            for root, dirs, files in os.walk(self.tmpdir):
                for f in files:
                    all_files.append(os.path.join(root, f))

            for member in marfile.members:
                self.assertTrue(os.path.join(self.tmpdir, member.name) in all_files)


class TestReadingBZ2Mar(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.marfile = BZ2MarFile(TEST_MAR)
        self.marfile_fo = BZ2MarFile(open(TEST_MAR, "rb"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_extract_bz2(self):
        for marfile in self.marfile, self.marfile_fo:
            m = marfile.members[0]
            marfile.extract(m, self.tmpdir)
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
        marfile_fo = os.path.join(self.tmpdir, 'test2.mar')
        with MarFile(marfile, 'w') as m:
            m.add(__file__)
        with MarFile(open(marfile_fo, "wb")) as m:
            m.add(__file__)


        for mar in MarFile(marfile), MarFile(open(marfile_fo, "rb")):
            with mar as m:
                self.assertEquals(len(m.members), 1)
                self.assertEquals(m.members[0].size, os.path.getsize(__file__))
                self.assertEquals(m.members[0].flags, os.stat(__file__).st_mode & 0o777)
                extracted = m.extract(m.members[0], self.tmpdir)
                self.assertEquals(
                    open(extracted, 'rb').read(),
                    open(__file__, 'rb').read()
                )

    def test_additional_info(self):
        marfile = os.path.join(self.tmpdir, 'test.mar')
        marfile_fo = os.path.join(self.tmpdir, 'test2.mar')
        for mar in MarFile(marfile, 'w'), MarFile(open(marfile_fo, 'wb')):
            with mar as m:
                info = AdditionalInfo.from_info({'MARChannelName': 'test1', 'ProductVersion': '123'})
                m.additional_info.append(info)
                m.add(__file__)

        for mar in MarFile(marfile), MarFile(open(marfile_fo, 'rb')):
            with mar as m:
                self.assertEquals(len(m.additional_info), 1)
                self.assertEquals(m.additional_info[0].name, 'PRODUCT INFORMATION')
                self.assertEquals(m.additional_info[0].info, {'MARChannelName': 'test1', 'ProductVersion': '123'})

    def test_add_dir(self):
        marfile = os.path.join(self.tmpdir, 'test.mar')
        marfile_fo = os.path.join(self.tmpdir, 'test2.mar')
        dirname = os.path.dirname(__file__)
        with MarFile(marfile, 'w') as m:
            m.add(dirname)
        with MarFile(open(marfile_fo, 'wb')) as m:
            m.add(dirname)

        # List out the files in dirname so we can compare
        my_files = []
        for root, dirs, files in os.walk(dirname):
            for f in files:
                my_files.append(os.path.join(root, f))

        for mar in MarFile(marfile), MarFile(open(marfile_fo, 'rb')):
            with mar as m:
                self.assertEquals(len(m.members), len(my_files))
                for member in m.members:
                    self.assertTrue(member.name in my_files)
                    self.assertEquals(member.size, os.path.getsize(member.name))
                    self.assertEquals(member.flags, os.stat(member.name).st_mode & 0o777)

                    extracted = m.extract(member, self.tmpdir)
                    self.assertNotEquals(extracted, member.name)
                    self.assertEquals(
                        open(extracted, 'rb').read(),
                        open(member.name, 'rb').read()
                    )

    def test_bz2_add(self):
        marfile = os.path.join(self.tmpdir, 'test.mar')
        marfile_fo = os.path.join(self.tmpdir, 'test2.mar')
        with BZ2MarFile(marfile, 'w') as m:
            m.add(__file__)
        with BZ2MarFile(open(marfile_fo, 'wb')) as m:
            m.add(__file__)

        for marfile in BZ2MarFile(marfile), BZ2MarFile(open(marfile_fo, "rb")):
            with marfile as m:
                self.assertEquals(len(m.members), 1)
                extracted = m.extract(m.members[0], self.tmpdir)
                self.assertEquals(
                    open(extracted, 'rb').read(),
                    open(__file__, 'rb').read()
                )

    def test_bz2_add_dir(self):
        marfile = os.path.join(self.tmpdir, 'test.mar')
        marfile_fo = os.path.join(self.tmpdir, 'test2.mar')
        dirname = os.path.dirname(__file__)
        with BZ2MarFile(marfile, 'w') as m:
            m.add(dirname)
        with BZ2MarFile(open(marfile_fo, 'wb')) as m:
            m.add(dirname)

        # List out the files in dirname so we can compare
        my_files = []
        for root, dirs, files in os.walk(dirname):
            for f in files:
                my_files.append(os.path.join(root, f))

        for marfile in BZ2MarFile(marfile), BZ2MarFile(open(marfile_fo, "rb")):
            with marfile as m:
                self.assertEquals(len(m.members), len(my_files))
                for member in m.members:
                    self.assertTrue(member.name in my_files)
                    self.assertEquals(member.flags, os.stat(member.name).st_mode & 0o777)

                    extracted = m.extract(member, self.tmpdir)
                    self.assertNotEquals(extracted, member.name)
                    self.assertEquals(
                        open(extracted, 'rb').read(),
                        open(member.name, 'rb').read()
                    )


class TestExceptions(TestCase):
    def test_badmar(self):
        self.assertRaises(ValueError, MarFile, __file__)

    def test_badmar_fo(self):
        self.assertRaises(ValueError, MarFile, open(__file__, "rb"))
