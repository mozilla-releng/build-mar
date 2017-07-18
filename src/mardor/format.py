# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""structures for reading and writing MAR data.

This relies on the construct module for specifying the data structures.

See also https://wiki.mozilla.org/Software_Update:MAR
"""

from construct import Array
from construct import Bytes
from construct import Computed
from construct import Const
from construct import CString
from construct import GreedyRange
from construct import If
from construct import Int32ub
from construct import Int64ub
from construct import Padding
from construct import Pointer
from construct import Rebuild
from construct import Select
from construct import Struct
from construct import len_
from construct import this

mar_header = "mar_header" / Struct(
    "magic" / Const(b"MAR1"),
    "index_offset" / Int32ub,
)

sig_entry = "sig_entry" / Struct(
    "algorithm_id" / Int32ub,
    "size" / Int32ub,
    "signature" / Bytes(this.size),
)

sigs_header = "sigs_header" / Struct(
    "filesize" / Int64ub,
    "count" / Int32ub,
    "sigs" / Array(this.count, sig_entry),
)

extra_entry = "extra_entry" / Struct(
    "size" / Int32ub,
    "id" / Int32ub,
    "data" / Bytes(this.size - 8),
)

productinfo_entry = "productinto_entry" / Struct(
    # TODO: Can we make this a Rebuild as well as have Padding calculated?
    "size" / Int32ub,
    "id" / Const(Int32ub, 1),
    "channel" / CString(encoding='ascii'),
    "productversion" / CString(encoding='ascii'),
    "padding" / Padding(this.size - len_(this.channel) -
                        len_(this.productversion) - 8),
)

extras_header = "extras_header" / Struct(
    "count" / Int32ub,
    "sections" / Array(this.count, Select(productinfo_entry, extra_entry)),
)

index_entry = "index_entry" / Struct(
    "offset" / Int32ub,
    "size" / Int32ub,
    "flags" / Int32ub,
    "name" / CString(encoding='ascii'),
)

index_header = "index_header" / Struct(
    "size" / Rebuild(Int32ub, len_(this.entries)),
    "entries" / GreedyRange(index_entry),
)


# Helper method to determine if a MAR file has signatures or not
def _has_sigs(ctx):
    """Helper method to determine if a MAR file has a signature section or not.

    It does this by looking at where file data starts in the file. If this
    starts immediately after the headers (at offset 8), then it's an old style
    MAR that has no signatures or addiontal information blocks.

    Args:
        ctx (context): construct parsing context

    Returns:
        True if the MAR file has a signature section
        False otherwise
    """
    return min(e.offset for e in ctx.index.entries) > 8


mar = "mar" / Struct(
    "header" / mar_header,

    "index" / Pointer(this.header.index_offset, index_header),

    # Pointer above restores our seek position to where it was before, i.e.
    # after the mar header. In modern MAR files, the mar header is followed by
    # the signatures and additional data sections. In older MAR files file data
    # follows immediately after.
    # These sections will not be present for older MAR files
    # that don't have signature / extra sections
    # Only add them if the earliest entry offset is greater than 8
    "signatures" / If(_has_sigs, sigs_header),
    "additional" / If(_has_sigs, extras_header),
    "data_offset" / Computed(lambda ctx: ctx.index.entries[0].offset),
    "data_length" / Computed(this.header.index_offset - this.data_offset),
    "data_header" / Pointer(this.data_offset, Bytes(6)),
    "is_compressed" / Computed(this.data_header == b'\xfd7zXZ\x00'),
)
