import os
import re

from pkg_resources import get_distribution

import mardor


def test_version_in_setuppy():
    dist = get_distribution('mar')
    assert mardor.version_str == dist.version
    assert ".".join(str(_) for _ in mardor.version) == dist.version


def test_version_in_changelog():
    dist = get_distribution('mar')
    here = os.path.abspath(os.path.dirname(__file__))
    changelog_path = os.path.join(here, '..', 'CHANGELOG.rst')
    changelog = open(changelog_path).read()
    assert re.search('^{}'.format(re.escape(mardor.version_str)), changelog,
                     re.M)
