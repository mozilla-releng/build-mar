import os

from mardor.mozilla import dep1_sha1
from mardor.mozilla import dep1_sha384
from mardor.mozilla import dep2_sha1
from mardor.mozilla import dep2_sha384
from mardor.mozilla import nightly1_sha1
from mardor.mozilla import nightly1_sha384
from mardor.mozilla import nightly2_sha1
from mardor.mozilla import nightly2_sha384
from mardor.mozilla import release1_sha1
from mardor.mozilla import release1_sha384
from mardor.mozilla import release2_sha1
from mardor.mozilla import release2_sha384
from mardor.reader import MarReader


def test_testmar_sig_bz2():
    TEST_MAR = os.path.join(os.path.dirname(__file__), 'test-bz2.mar')
    with MarReader(open(TEST_MAR, 'rb')) as m:
        assert m.verify(release1_sha1)
