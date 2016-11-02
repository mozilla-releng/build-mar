from mardor.writer import MarWriter
from mardor.reader import MarReader


def test_writer(tmpdir):
    message_p = tmpdir.join('message.txt')
    message_p.write('hello world')
    mar_p = tmpdir.join('test.mar')
    with mar_p.open('wb') as f:
        with MarWriter(f) as m:
            with tmpdir.as_cwd():
                m.add('message.txt')

    assert mar_p.size() > 0

    with mar_p.open('rb') as f:
        with MarReader(f) as m:
            assert len(m.mardata.index.entries) == 1
            assert m.mardata.index.entries[0].name == 'message.txt'
            m.extract(str(tmpdir.join('extracted')))
            assert (tmpdir.join('extracted', 'message.txt').read('rb') ==
                    b'hello world')