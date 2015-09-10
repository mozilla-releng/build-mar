from unittest import TestCase

from hypothesis.strategies import text
from hypothesis import given

from mardor.utils import read_file, safe_join


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


@given(text(), text())
def test_safe_join(a, b):
    result = safe_join(a, b)
    assert result.startswith(a)
