from mar.mar import MarFile
import os

TEST_MAR = os.path.join(os.path.dirname(__file__), 'test.mar')


def test_list():
    m = MarFile(TEST_MAR)
    assert repr(m.members[0]) == "<update.manifest 664 141 bytes starting at 392>", m.members[0]
