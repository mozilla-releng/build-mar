import pytest

from mardor.signing import make_rsa_keypair
from mardor.writer import MarWriter


@pytest.fixture(scope='session')
def mar_cu(tmpdir_factory):
    """Compressed and unsigned MAR"""
    tmpdir = tmpdir_factory.mktemp('data')
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test_cu.mar')
    with mar_p.open('wb') as f:
        with MarWriter(f) as m:
            with tmpdir.as_cwd():
                m.add('message.txt', compress='bz2')
    return mar_p

@pytest.fixture(scope='session')
def mar_cue(tmpdir_factory):
    """Compressed and unsigned MAR with extra information"""
    tmpdir = tmpdir_factory.mktemp('data')
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test_cue.mar')
    with mar_p.open('w+b') as f:
        with MarWriter(f, productversion='99.0',
                      channel='1') as m:
            with tmpdir.as_cwd():
                m.add('message.txt', compress='bz2')
    return mar_p


@pytest.fixture(scope='session')
def mar_uu(tmpdir_factory):
    """Uncompressed and unsigned MAR"""
    tmpdir = tmpdir_factory.mktemp('data')
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test_uu.mar')
    with mar_p.open('wb') as f:
        with MarWriter(f) as m:
            with tmpdir.as_cwd():
                m.add('message.txt', compress=None)
    return mar_p


@pytest.fixture(scope='session')
def mar_sha384(tmpdir_factory):
    """MAR signed with SHA384"""
    tmpdir = tmpdir_factory.mktemp('data')
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test_sha384.mar')
    private_key, public_key = make_rsa_keypair(4096)
    with mar_p.open('w+b') as f:
        with MarWriter(f, signing_key=private_key, channel='release',
                       productversion='99.9', signing_algorithm='sha384') as m:
            with tmpdir.as_cwd():
                m.add('message.txt')
    return mar_p


@pytest.fixture(scope='session')
def test_keys():
    return {
        2048: make_rsa_keypair(2048),
        4096: make_rsa_keypair(4096),
    }
