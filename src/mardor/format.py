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
from construct import Pointer
from construct import Prefixed
from construct import Select
from construct import Struct
from construct import Tell
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
    "offset" / Tell,
    "filesize" / Int64ub,
    "count" / Int32ub,
    "sigs" / Array(this.count, sig_entry),
    "offset_end" / Tell,
)

extra_entry = "extra_entry" / Struct(
    "size" / Int32ub,
    "id" / Int32ub,
    "data" / Bytes(this.size - 8),
)

productinfo_entry = "productinto_entry" / Struct(
    "size" / Int32ub,
    "id" / Const(value=1, subcon=Int32ub),
    "channel" / CString(encoding='ascii'),
    "productversion" / CString(encoding='ascii'),
    "padding" / Bytes(
                this.size - len_(this.channel) - len_(this.productversion) -
                # 8 bytes for size/id fields, and an
                # extra 2 bytes for the null terminator after
                # channel and productversion
                8 - 2,
    ),
)

extras_header = "extras_header" / Struct(
    "offset" / Tell,
    "count" / Int32ub,
    "sections" / Array(this.count, Select(productinfo_entry, extra_entry)),
    "offset_end" / Tell,
)

index_entry = "index_entry" / Struct(
    "offset" / Int32ub,
    "size" / Int32ub,
    "flags" / Int32ub,
    "name" / CString(encoding='ascii'),
)

index_header = "index_header" / Struct(
    "entries" / Prefixed(Int32ub, GreedyRange(index_entry)),
)


# Helper method to determine if a MAR file has signatures or not
def _has_sigs(ctx):
    """Determine if a MAR file has a signature section or not.

    It does this by looking at where file data starts in the file. If this
    starts immediately after the headers (at offset 8), then it's an old style
    MAR that has no signatures.

    Args:
        ctx (context): construct parsing context

    Returns:
        True if the MAR file has a signature section
        False otherwise

    """
    if not ctx.index.entries:
        return False
    return ctx.data_offset > 8


# Helper method to determine if a MAR file has additional sections or not
def _has_extras(ctx):
    """Determine if a MAR file has an additional section block or not.

    It does this by looking at where file data starts in the file. If this
    starts immediately after the signature data, then no additional sections are present.

    Args:
        ctx (context): construct parsing context

    Returns:
        True if the MAR file has an additional section block
        False otherwise

    """
    if not ctx.index.entries:
        return False

    return ctx.data_offset > 8 and ctx.data_offset > (ctx.signatures.offset_end + 8)


def _data_offset(ctx):
    if not ctx.index.entries:
        return ctx.header.index_offset
    else:
        # data offset can never be less than 8, which is the size of the MAR header
        return max(ctx.index.entries[0].offset, 8)


mar = "mar" / Struct(
    "header" / mar_header,

    "index" / Pointer(this.header.index_offset, index_header),

    # Helper attributes to assist with navigating the file
    "data_offset" / Computed(_data_offset),
    "data_length" / Computed(this.header.index_offset - this.data_offset),

    # Pointer above restores our seek position to where it was before, i.e.
    # after the mar header. In modern MAR files, the mar header is followed by
    # the signatures and additional data sections. In older MAR files file data
    # follows immediately after.
    # These sections will not be present for older MAR files
    # that don't have signature / extra sections
    # Only add them if the earliest entry offset is greater than 8
    "signatures" / If(_has_sigs, sigs_header),
    "additional" / If(_has_extras, extras_header),
)
