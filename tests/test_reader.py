from mardor.reader import MarReader
import os

TEST_MAR = os.path.join(os.path.dirname(__file__), 'test.mar')
TEST_PUBKEY = os.path.join(os.path.dirname(__file__), 'test.pubkey')


def test_reader():
    with MarReader(open(TEST_MAR, 'rb')) as m:
        mardata = m.mardata
        index = mardata.index
        entries = index.entries
        assert len(entries) == 5
        assert entries[0] == dict(offset=392, size=141, flags=0o664,
                                  name='update.manifest')
        assert entries[1] == dict(offset=533, size=76, flags=0o664,
                                  name='defaults/pref/channel-prefs.js')
        assert mardata.additional.count == 1
        assert mardata.additional.sections[0].channel == 'thunderbird-comm-esr'
        assert mardata.additional.sections[0].productversion == '100.0'
        assert mardata.signatures.count == 1


def test_verification():
    with MarReader(open(TEST_MAR, 'rb'), verify_key=TEST_PUBKEY) as m:
        assert m.verify()
