# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os

import pytest
from pytest import fixture
from pytest import raises

from mardor import cli
from mardor import mozilla
from mardor.reader import MarReader
from mardor.signing import make_rsa_keypair
from mardor.signing import sign_hash
from mardor.writer import add_signature_block

TEST_MAR_BZ2 = os.path.join(os.path.dirname(__file__), 'test-bz2.mar')
TEST_MAR_XZ = os.path.join(os.path.dirname(__file__), 'test-xz.mar')


@fixture
def parser():
    return cli.build_argparser()


def test_argparser(parser):
    args = ['-c', 'test.mar', 'file1', 'file2']
    args = parser.parse_args(args)
    assert args.create == 'test.mar'


def test_extract(tmpdir):
    cli.do_extract(TEST_MAR_BZ2, tmpdir, 'auto')
    assert (tmpdir.join('defaults/pref/channel-prefs.js').read('rb') ==
            b'pref("app.update.channel", "release");\n')


def test_create(tmpdir):
    test_mar = tmpdir.join('test.mar')

    tmpdir.join('hello.txt').write('hello world')
    files = [str(tmpdir.join('hello.txt'))]
    cli.do_create(str(test_mar), files, 'bz2')


def test_verify(tmpdir):
    assert cli.do_verify(TEST_MAR_BZ2, [':mozilla-release'])
    assert cli.do_verify(TEST_MAR_BZ2)

    with raises(SystemExit):
        assert not cli.do_verify(TEST_MAR_BZ2, [':mozilla-nightly'])
    with raises(SystemExit):
        assert not cli.do_verify(TEST_MAR_BZ2, [':mozilla-dep'])

    with raises(SystemExit):
        cli.do_verify(TEST_MAR_BZ2, [':mozilla-foo'])

    with raises(SystemExit):
        cli.do_verify(__file__)


    keyfile = tmpdir.join('release.pem')
    keyfile.write(mozilla.release1_sha1)
    assert cli.do_verify(TEST_MAR_BZ2, [str(keyfile)])


def test_list():
    text = "\n".join(cli.do_list(TEST_MAR_BZ2))
    assert "\n141     0664    update.manifest\n" in text


def test_list_detailed():
    text = "\n".join(cli.do_list(TEST_MAR_BZ2, detailed=True))
    assert "Product version: 100.0\n" in text
    assert "\n141     0664    update.manifest\n" in text


def test_list_noextra(tmpdir):
    test_mar = tmpdir.join('test.mar')

    tmpdir.join('hello.txt').write('hello world')
    tmpdir.join('hello.txt').chmod(0o666)
    with tmpdir.as_cwd():
        cli.do_create(str(test_mar), ['hello.txt'], None)

    lines = list(cli.do_list(str(test_mar)))
    assert lines == [
        'SIZE    MODE    NAME   ',
        '11      0666    hello.txt',
    ]


def test_main_verify():
    args = ['-v', TEST_MAR_BZ2, '-k', ':mozilla-release']
    assert cli.main(args) is None

    with raises(SystemExit):
        args = ['-v', TEST_MAR_BZ2, '-k', ':mozilla-nightly']
        cli.main(args)

    args = ['-v', TEST_MAR_BZ2]
    assert cli.main(args) is None


def test_main_list():
    cli.main(['-t', TEST_MAR_BZ2])


def test_main_list_detailed():
    cli.main(['-T', TEST_MAR_BZ2])


def test_main_noaction():
    with raises(SystemExit):
        cli.main([TEST_MAR_BZ2])

    with raises(SystemExit):
        cli.main(['-c', 'test.mar'])

    with raises(SystemExit):
        cli.main(['-t', '-v', TEST_MAR_BZ2])


def test_main_extract(tmpdir):
    with tmpdir.as_cwd():
        cli.main(['-x', TEST_MAR_BZ2])

    assert (tmpdir.join('defaults/pref/channel-prefs.js').read('rb')
            .startswith(b'BZh'))


def test_main_extract_bz2(tmpdir):
    with tmpdir.as_cwd():
        cli.main(['-x', TEST_MAR_BZ2, '-j'])

    assert (tmpdir.join('defaults/pref/channel-prefs.js').read('rb') ==
            b'pref("app.update.channel", "release");\n')


def test_main_extract_xz(tmpdir):
    with tmpdir.as_cwd():
        cli.main(['-x', TEST_MAR_XZ, '-J'])

    assert (tmpdir.join('defaults/pref/channel-prefs.js').read('rb') ==
            b'pref("app.update.channel", "release");\n')


def test_main_create(tmpdir):
    tmpdir.join('hello.txt').write('hello world')
    with tmpdir.as_cwd():
        cli.main(['-c', 'test.mar', 'hello.txt'])


@pytest.mark.parametrize('key_size', [2048, 4096])
def test_main_create_signed_v1(tmpdir, key_size, test_keys):
    priv, pub = test_keys[key_size]
    tmpdir.join('hello.txt').write('hello world')
    tmpdir.join('key.pem').write(priv)
    with tmpdir.as_cwd():
        cli.main(['--productversion', 'foo', '--channel', 'bar', '-k',
                  'key.pem', '-c', 'test.mar', 'hello.txt'])
        cli.main(['-v', 'test.mar', '-k', 'key.pem'])


def test_main_create_signed_badkeysize(tmpdir):
    priv, pub = make_rsa_keypair(1024)
    tmpdir.join('hello.txt').write('hello world')
    tmpdir.join('key.pem').write(priv)
    with tmpdir.as_cwd():
        with raises(SystemExit):
            cli.main(['--productversion', 'foo', '--channel', 'bar', '-k',
                      'key.pem', '-c', 'test.mar', 'hello.txt'])


def test_main_create_chdir(tmpdir):
    tmpdir.join('hello.txt').write('hello world')
    tmpmar = tmpdir.join('test.mar')
    cli.main(['-C', str(tmpdir), '-c', str(tmpmar), 'hello.txt'])

    with MarReader(tmpmar.open('rb')) as m:
        assert len(m.mardata.index.entries) == 1
        assert m.mardata.index.entries[0].name == 'hello.txt'


def test_main_extract_chdir(tmpdir):
    cli.main(['-C', str(tmpdir), '-x', TEST_MAR_BZ2])
    assert tmpdir.join('defaults/pref/channel-prefs.js').check()


def test_verify_malformed(mar_sha384, tmpdir):
    tmpmar = tmpdir.join('test.mar')
    mar_sha384.copy(tmpmar)
    with tmpmar.open('r+b') as f:
        # Mess with the mar's file offsets
        with MarReader(f) as m:
            offset = m.mardata.header.index_offset
            offset += 8

        f.seek(offset)
        f.write(b'\x12\x34\x56\x78')
        f.seek(0)

    with raises(SystemExit):
        assert not cli.do_verify(str(tmpmar))


def test_list_unknown_extra(mar_sha384, tmpdir):
    tmpmar = tmpdir.join('test.mar')
    mar_sha384.copy(tmpmar)
    with tmpmar.open('r+b') as f:
        with MarReader(f) as m:
            offset = m.mardata.additional.offset
            offset += 8

        f.seek(offset)
        f.write(b'\x12\x34\x56\x78')
        f.seek(0)

    text = "\n".join(cli.do_list(str(tmpmar), detailed=True))
    assert "Unknown additional data" in text

def test_hash(capsys):
    cli.do_hash('sha1', TEST_MAR_BZ2, False)
    cap = capsys.readouterr()
    assert cap.out == 'zSUOgnolN9uWtF4GM1pGVjj66Gs=\n'

    cli.do_hash('sha1', TEST_MAR_BZ2, True)
    cap = capsys.readouterr()
    assert cap.out == 'MCEwCQYFKw4DAhoFAAQUzSUOgnolN9uWtF4GM1pGVjj66Gs=\n'

    cli.do_hash('sha384', TEST_MAR_BZ2, True)
    cap = capsys.readouterr()
    assert cap.out == 'MEEwDQYJYIZIAWUDBAICBQAEMDASZm7fTyQ8YmHZUbTRgOIwzjjQ5AUY8LxwUm4euGUJk11WhHGf3PCpdNeVpGrvqg==\n'

def test_add_signature_sha1(tmpdir, test_keys):
    with MarReader(open(TEST_MAR_BZ2, 'rb')) as m:
        hashes = m.calculate_hashes()
    assert hashes == [(1, b'\xcd%\x0e\x82z%7\xdb\x96\xb4^\x063ZFV8\xfa\xe8k')]

    h = hashes[0][1]

    priv, pub = test_keys[2048]
    sig = sign_hash(priv, h, 'sha1')

    sigfile = tmpdir.join('signature')
    with sigfile.open('wb') as f:
        f.write(sig)

    tmpmar = tmpdir.join('output.mar')
    cli.do_add_signature(TEST_MAR_BZ2, str(tmpmar), str(sigfile))

    pubkey = tmpdir.join('pubkey')
    with pubkey.open('wb') as f:
        f.write(pub)
    assert cli.do_verify(str(tmpmar), [str(pubkey)])

def test_add_signature_sha384(tmpdir, test_keys):
    tmpmar = tmpdir.join('test.mar')
    with open(TEST_MAR_XZ, 'rb') as f:
        with tmpmar.open('wb') as dst:
            add_signature_block(f, dst, 'sha384')

    with MarReader(tmpmar.open('rb')) as m:
        hashes = m.calculate_hashes()
    assert hashes == [(2, b'\x08>\x82\x8d$\xbb\xa6Cg\xca\x15L\x9c\xf1\xde\x170\xbe\xeb8]\x17\xb9\xfdB\xa9\xd6\xf1(y\'\xf44\x1f\x01c%\xd4\x92\x1avm!\t\xd9\xc4\xfbv')]

    h = hashes[0][1]

    priv, pub = test_keys[4096]
    sig = sign_hash(priv, h, 'sha384')

    sigfile = tmpdir.join('signature')
    with sigfile.open('wb') as f:
        f.write(sig)

    tmpmar = tmpdir.join('output.mar')
    cli.do_add_signature(TEST_MAR_XZ, str(tmpmar), str(sigfile))

    pubkey = tmpdir.join('pubkey')
    with pubkey.open('wb') as f:
        f.write(pub)
    assert cli.do_verify(str(tmpmar), [str(pubkey)])

def test_add_signature_badsig(tmpdir):
    with tmpdir.join('sig').open('wb') as f:
        f.write(b"bad sig")

    with raises(ValueError):
        cli.do_add_signature(TEST_MAR_BZ2, str(tmpdir.join('test.mar')), str(tmpdir.join('sig')))

def test_main_hash():
    args = ['--hash', 'sha1', TEST_MAR_BZ2]
    assert cli.main(args) is None

    with raises(SystemExit):
        args = ['--hash', 'sha1']
        cli.main(args)

    with raises(SystemExit):
        args = ['--hash', 'sha1', TEST_MAR_BZ2, TEST_MAR_XZ]
        cli.main(args)

def test_main_add_signature(tmpdir):
    tmpmar = str(tmpdir.join('output.mar'))
    sigfile = tmpdir.join('sig')
    sigfile.write(b'0' * 256)
    args = ['--add-signature', TEST_MAR_BZ2, tmpmar, str(sigfile)]
    assert cli.main(args) is None
