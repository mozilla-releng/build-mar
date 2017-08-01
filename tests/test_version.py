from pkg_resources import get_distribution

import mardor


def test_version():
    dist = get_distribution('mar')
    assert mardor.version_str == dist.version
    assert ".".join(str(_) for _ in mardor.version) == dist.version
