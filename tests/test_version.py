import os
import re
import warnings

try:
    from importlib.metadata import distribution
except ImportError:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from pkg_resources import get_distribution as distribution

import mardor


def test_version_in_setuppy():
    dist = distribution('mar')
    assert mardor.version_str == dist.version
    assert ".".join(str(_) for _ in mardor.version) == dist.version


def test_version_in_changelog():
    here = os.path.abspath(os.path.dirname(__file__))
    changelog_path = os.path.join(here, '..', 'CHANGELOG.rst')
    with open(changelog_path) as f:
        changelog = f.read()
    assert re.search('^{}'.format(re.escape(mardor.version_str)), changelog,
                     re.M)
