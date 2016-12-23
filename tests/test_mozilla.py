import os
from mardor.mozilla import (release1, release2,
                            nightly1, nightly2,
                            dep1, dep2)


from mardor.reader import MarReader


def test_testmar_sig():
    TEST_MAR = os.path.join(os.path.dirname(__file__), 'test.mar')
    with MarReader(open(TEST_MAR, 'rb')) as m:
        assert m.verify(release1)
