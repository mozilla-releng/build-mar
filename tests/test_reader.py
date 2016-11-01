from mardor.reader import MarReader
import os
import bz2

TEST_MAR = os.path.join(os.path.dirname(__file__), 'test.mar')
TEST_PUBKEY = os.path.join(os.path.dirname(__file__), 'test.pubkey')


def test_parsing():
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


def test_verify():
    pubkey = open(TEST_PUBKEY, 'rb').read()
    with MarReader(open(TEST_MAR, 'rb'), verify_key=pubkey) as m:
        assert m.verify()


def test_verify_nokey():
    with MarReader(open(TEST_MAR, 'rb')) as m:
        assert not m.verify()


def test_verify_wrongkey():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    private_key = rsa.generate_private_key(
             public_exponent=65537,
             key_size=2048,
             backend=default_backend()
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with MarReader(open(TEST_MAR, 'rb'), verify_key=public_key) as m:
        assert not m.verify()


def test_extract(tmpdir):
    with MarReader(open(TEST_MAR, 'rb')) as m:
        m.extract(str(tmpdir))
        assert sorted(tmpdir.listdir()) == [
            tmpdir.join(f) for f in [
                'Contents',
                'defaults',
                'update-settings.ini',
                'update.manifest',
            ]]
        # Check the contents. These should already be uncompressed
        assert (tmpdir.join('defaults/pref/channel-prefs.js').read('rb') ==
                b'pref("app.update.channel", "release");\n')


def test_extract_nodecompress(tmpdir):
    with MarReader(open(TEST_MAR, 'rb'), decompress=None) as m:
        m.extract(str(tmpdir))
        assert sorted(tmpdir.listdir()) == [
            tmpdir.join(f) for f in [
                'Contents',
                'defaults',
                'update-settings.ini',
                'update.manifest',
            ]]
        # Check the contents. These should already be uncompressed
        contents = tmpdir.join('defaults/pref/channel-prefs.js').read('rb')
        assert contents.startswith(b'BZh')
        assert (bz2.decompress(contents) ==
                b'pref("app.update.channel", "release");\n')
