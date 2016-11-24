# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
from mardor import cli
from mardor.reader import Decompression


from pytest import fixture

TEST_MAR = os.path.join(os.path.dirname(__file__), 'test.mar')


@fixture
def parser():
    return cli.build_argparser()


def test_argparser(parser):
    args = ['-c', 'test.mar', 'file1', 'file2']
    args = parser.parse_args(args)
    assert args.action == 'create'


def test_extract(tmpdir):
    cli.do_extract(TEST_MAR, tmpdir, Decompression.auto)
    assert (tmpdir.join('defaults/pref/channel-prefs.js').read('rb') ==
            b'pref("app.update.channel", "release");\n')


def test_create(tmpdir):
    test_mar = tmpdir.join('test.mar')

    tmpdir.join('hello.txt').write('hello world')
    files = [str(tmpdir.join('hello.txt'))]
    cli.do_create(str(test_mar), files, 'bz2')
