# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os

import pytest
from pytest import fixture
from pytest import raises

from mardor import cli
from mardor import mozilla
from mardor.reader import Decompression
from mardor.reader import MarReader
from mardor.signing import make_rsa_keypair

TEST_MAR = os.path.join(os.path.dirname(__file__), 'test.mar')


@fixture
def parser():
    return cli.build_argparser()


def test_argparser(parser):
    args = ['-c', 'test.mar', 'file1', 'file2']
    args = parser.parse_args(args)
    assert args.create == 'test.mar'


def test_extract(tmpdir):
    cli.do_extract(TEST_MAR, tmpdir, Decompression.auto)
    assert (tmpdir.join('defaults/pref/channel-prefs.js').read('rb') ==
            b'pref("app.update.channel", "release");\n')


def test_create(tmpdir):
    test_mar = tmpdir.join('test.mar')

    tmpdir.join('hello.txt').write('hello world')
    files = [str(tmpdir.join('hello.txt'))]
    cli.do_create(str(test_mar), files, 'bz2')


def test_verify(tmpdir):
    assert cli.do_verify(TEST_MAR, [':mozilla-release'])
    assert not cli.do_verify(TEST_MAR, [':mozilla-nightly'])
    assert not cli.do_verify(TEST_MAR, [':mozilla-dep'])

    with raises(ValueError):
        cli.do_verify(TEST_MAR, [':mozilla-foo'])

    keyfile = tmpdir.join('release.pem')
    keyfile.write(mozilla.release1)
    assert cli.do_verify(TEST_MAR, [str(keyfile)])


def test_list():
    text = "\n".join(cli.do_list(TEST_MAR))
    assert "\n141     0664    update.manifest\n" in text


def test_list_detailed():
    text = "\n".join(cli.do_list(TEST_MAR, detailed=True))
    assert "Product version: 100.0\n" in text
    assert "\n141     0664    update.manifest\n" in text


def test_list_noextra(tmpdir):
    test_mar = tmpdir.join('test.mar')

    tmpdir.join('hello.txt').write('hello world')
    tmpdir.join('hello.txt').chmod(0o666)
    with tmpdir.as_cwd():
        cli.do_create(str(test_mar), ['hello.txt'], 'bz2')

    lines = list(cli.do_list(str(test_mar)))
    assert lines == [
        'SIZE    MODE    NAME   ',
        '11      0666    hello.txt',
    ]


def test_main_verify():
    args = ['-v', TEST_MAR, '-k', ':mozilla-release']
    cli.main(args)

    with raises(SystemExit):
        args = ['-v', TEST_MAR, '-k', ':mozilla-nightly']
        cli.main(args)

    with raises(SystemExit):
        args = ['-v', TEST_MAR]
        cli.main(args)


def test_main_list():
    cli.main(['-t', TEST_MAR])


def test_main_list_detailed():
    cli.main(['-T', TEST_MAR])


def test_main_noaction():
    with raises(SystemExit):
        cli.main([TEST_MAR])

    with raises(SystemExit):
        cli.main(['-c', 'test.mar'])

    with raises(SystemExit):
        cli.main(['-t', '-v', TEST_MAR])


def test_main_extract(tmpdir):
    with tmpdir.as_cwd():
        cli.main(['-x', TEST_MAR])

    assert (tmpdir.join('defaults/pref/channel-prefs.js').read('rb')
            .startswith(b'BZh'))


def test_main_extract_bz2(tmpdir):
    with tmpdir.as_cwd():
        cli.main(['-x', TEST_MAR, '-j'])

    assert (tmpdir.join('defaults/pref/channel-prefs.js').read('rb') ==
            b'pref("app.update.channel", "release");\n')


def test_main_create(tmpdir):
    tmpdir.join('hello.txt').write('hello world')
    with tmpdir.as_cwd():
        cli.main(['-c', 'test.mar', 'hello.txt'])


@pytest.mark.parametrize('key_size', [2048, 4096])
def test_main_create_signed_v1(tmpdir, key_size):
    priv, pub = make_rsa_keypair(key_size)
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
    cli.main(['-C', str(tmpdir), '-x', TEST_MAR])
    assert tmpdir.join('defaults/pref/channel-prefs.js').check()
