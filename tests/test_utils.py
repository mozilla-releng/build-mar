from mardor.utils import imaxsize

from hypothesis import given
from hypothesis.strategies import binary, streaming, integers

@given(streaming(binary()), integers(min_value=0))
def test_imaxsize(data, n):
    blocks = []
    for block in imaxsize(data, n):
        blocks.append(block)
    s = b"".join(blocks)
    assert len(s) <= n

