import pytest

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
