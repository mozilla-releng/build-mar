from mardor.reader import MarReader
import os

TEST_MAR = os.path.join(os.path.dirname(__file__), 'test.mar')

def check_listing(marfile):
    # Checks that the listing of the mar file is as expected
    mardata = marfile.mardata
    index = mardata.index
    entries = index.entries
    assert len(entries) == 5
    assert entries[0] == dict(offset=392, size=141, flags=0o664, name='update.manifest')
    assert mardata.additional.count == 1
    assert mardata.additional.sections[0].channel == 'thunderbird-comm-esr'
    assert mardata.additional.sections[0].productversion == '100.0'


def test_reader():
    m = MarReader(TEST_MAR)
    check_listing(m)
