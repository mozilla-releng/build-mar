import struct


def packint(i):
    return struct.pack(">L", i)


def unpackint(s):
    return struct.unpack(">L", s)[0]


def unpacklongint(s):
    return struct.unpack(">Q", s)[0]
