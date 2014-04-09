# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

import ctypes, errno
from cpylmnl.linux import netlinkh as netlink

from . import _cproto
from ._libnetfilter_conntrackh import ATTR_MAX, ATTR_GRP_MAX, NFCT_FILTER_MAX, NFCT_FILTER_LOGIC_MAX


## nfct_new - allocate a new conntrack
def conntrack_new():
    ret = _cproto.c_nfct_new()
    if ret is None: _cproto.os_error()
    return ret

## nfct_destroy - release a conntrack object
conntrack_destroy = _cproto.c_nfct_destroy

## nfct_clone - clone a conntrack object
def conntrack_clone(ct):
    ret = _cproto.c_nfct_clone(ct)
    if ret is None: raise _cproto.os_error()
    return ret

## nfct_setobjopt - set a certain option for a conntrack object
def conntrack_setobjopt(ct, option):
    ret = _cproto.c_nfct_setobjopt(ct, option)
    if ret == -1: raise _cproto.os_error()

## nfct_getobjopt - get a certain option for a conntrack object
def conntrack_getobjopt(ct, option):
    ret = _cproto.c_nfct_getobjopt(ct, option)
    if ret == -1: raise _cproto.os_error()
    return ret

## nfct_set_attr_l - set the value of a certain conntrack attribute
def conntrack_set_attr_l(ct, attr_type, value):
    # value must be ctypes type, to check it
    # isinstance(value, _SimpleCData) is false in Structure, cannot access _ctypes._CData
    try:
        size = ctypes.sizeof(value)
    except TypeError:
        raise OSError(errno.EINVAL, "value must be ctypes type")
    if attr_type >= ATTR_MAX: raise OSError(errno.EINVAL, "not a valid ct attr type")
    _cproto.c_nfct_set_attr_l(ct, attr_type, ctypes.byref(value), size)

## nfct_set_attr - set the value of a certain conntrack attribute
def conntrack_set_attr(ct, attr_type, value):
    # XXX: assume value is ctypes data or c_void_p.value to handle Bitmask
    try:
        ref = ctypes.byref(value)
    except TypeError:
        ref = value
    if attr_type >= ATTR_MAX: raise OSError(errno.EINVAL, "not a valid ct attr type")
    _cproto.c_nfct_set_attr(ct, attr_type, ref)

## nfct_set_attr_u8 - set the value of a certain conntrack attribute
def conntrack_set_attr_u8(ct, attr_type, value):
    if attr_type >= ATTR_MAX: raise OSError(errno.EINVAL, "not a valid ct attr type")
    return _cproto.c_nfct_set_attr_u8(ct, attr_type, value)

## nfct_set_attr_u16 - set the value of a certain conntrack attribute
def conntrack_set_attr_u16(ct, attr_type, value):
    if attr_type >= ATTR_MAX: raise OSError(errno.EINVAL, "not a valid ct attr type")
    return _cproto.c_nfct_set_attr_u16(ct, attr_type, value)

## nfct_set_attr_u32 - set the value of a certain conntrack attribute
def conntrack_set_attr_u32(ct, attr_type, value):
    if attr_type >= ATTR_MAX: raise OSError(errno.EINVAL, "not a valid ct attr type")
    return _cproto.c_nfct_set_attr_u32(ct, attr_type, value)

## nfct_set_attr_u64 - set the value of a certain conntrack attribute
def conntrack_set_attr_u64(ct, attr_type, value):
    if attr_type >= ATTR_MAX: raise OSError(errno.EINVAL, "not a valid ct attr type")
    return _cproto.c_nfct_set_attr_u64(ct, attr_type, value)

## nfct_get_attr - get a conntrack attribute
def conntrack_get_attr(ct, attr_type):
    ret = _cproto.c_nfct_get_attr(ct, attr_type)
    if ret is None: raise _cproto.os_error()
    return ret

def conntrack_get_attr_as(ct, attr_type, cls):
    ret = _cproto.c_nfct_get_attr(ct, attr_type)
    if ret is None: raise _cproto.os_error()
    return ctypes.cast(ret, ctypes.POINTER(cls)).contents

## nfct_get_attr_u8 - get attribute of unsigned 8-bits long
def conntrack_get_attr_u8(ct, attr_type):
    ctypes.set_errno(0)
    ret = _cproto.c_nfct_get_attr_u8(ct, attr_type)
    if ret == 0: _cproto.c_raise_if_errno()
    return ret

## nfct_get_attr_u16 - get attribute of unsigned 16-bits long
# conntrack_get_attr_u16 = c_nfct_get_attr_u16
def conntrack_get_attr_u16(ct, attr_type):
    ctypes.set_errno(0)
    ret = _cproto.c_nfct_get_attr_u16(ct, attr_type)
    if ret == 0: _cproto.c_raise_if_errno()
    return ret

## nfct_get_attr_u32 - get attribute of unsigned 32-bits long
def conntrack_get_attr_u32(ct, attr_type):
    ctypes.set_errno(0)
    ret = _cproto.c_nfct_get_attr_u32(ct, attr_type)
    if ret == 0: _cproto.c_raise_if_errno()
    return ret

## nfct_get_attr_u64 - get attribute of unsigned 64-bits long
def conntrack_get_attr_u64(ct, attr_type):
    ctypes.set_errno(0)
    ret = _cproto.c_nfct_get_attr_u64(ct, attr_type)
    if ret == 0: _cproto.c_raise_if_errno()
    return ret

## nfct_attr_is_set - check if a certain attribute is set
def conntrack_attr_is_set(ct, attr_type):
    ret = _cproto.c_nfct_attr_is_set(ct, attr_type)
    if ret == -1: raise _cproto.os_error()
    return ret > 0

## nfct_attr_is_set_array - check if an array of attribute types is set
def conntrack_attr_is_set_array(ct, type_list):
    size = len(type_list)
    c_type_array = (ctypes.c_int * size)(*type_list)
    ret = _cproto.c_nfct_attr_is_set_array(ct, ctypes.cast(c_type_array, ctypes.c_void_p), size)
    if ret < 0: raise _cproto.os_error()
    return ret > 0

## nfct_attr_unset - unset a certain attribute
def conntrack_attr_unset(ct, attr_type):
    if _cproto.c_nfct_attr_unset(ct, attr_type) == -1: raise _cproto.os_error()

## nfct_set_attr_grp - set a group of attributes
def conntrack_set_attr_grp(ct, attr_type, data):
    try:
        ctypes.sizeof(data)
    except TypeError:
        raise OSError(errno.EINVAL, "data must be ctypes type")
    if attr_type >= ATTR_GRP_MAX: raise OSError(errno.EINVAL, "not a valid grp attr type")
    _cproto.c_nfct_set_attr_grp(ct, attr_type, ctypes.byref(data))

## nfct_get_attr_grp - get an attribute group
def conntrack_get_attr_grp(ct, attr_type, data):
    try:
        ctypes.sizeof(data)
    except TypeError:
        raise OSError(errno.EINVAL, "data must be ctypes type")
    ret = _cproto.c_nfct_get_attr_grp(ct, attr_type, ctypes.byref(data))
    if ret == -1: raise _cproto.os_error()
def conntrack_get_attr_grp_as(ct, attr_type, cls):
    data = cls.__new__(cls)
    conntrack_get_attr_grp(ct, attr_type, data)
    return data

## nfct_attr_grp_is_set - check if an attribute group is set
def conntrack_attr_grp_is_set(ct, attr_type):
    ret = _cproto.c_nfct_attr_grp_is_set(ct, attr_type)
    if ret < 0: raise _cproto.of_error()
    return ret > 0

## nfct_attr_grp_unset - unset an attribute group
def conntrack_attr_grp_unset(ct, attr_type):
    ret = _cproto.c_nfct_attr_grp_unset(ct, attr_type)
    if ret == -1: raise _cproto.os_error()

## nfct_snprintf - print a conntrack object to a buffer
def conntrack_snprintf(size, ct, msg_type, out_type, flags):
    c_buf = ctypes.create_string_buffer(size)
    ret = _cproto.c_nfct_snprintf(c_buf, size, ct, msg_type, out_type, flags)
    if ret == -1: raise _cproto.os_error()
    return c_buf.value

## nfct_snprintf_labels - print a bitmask object to a buffer including labels
def conntrack_snprintf_labels(size, ct, msg_type, out_type, flags, labelmap):
    c_buf = ctypes.create_string_buffer(size)
    if labelmap is not None:
        labelmaps = (ctypes.c_void_p * len(labelmap))
        # XXX: _labelmap attribute is introduced upper layer in __init__.py
        for i, e in enumerate(labelmap): labelmaps[i] = e._labelmap
        c_labelmap = byref(labelmaps)
    else:
        c_labelmap = None
    ret = _cproto.c_nfct_snprintf_labels(c_buf, size, ct, msg_type, out_type, flags, c_labelmap)
    if ret == -1: raise _cproto.os_error()
    return c_buf.value

## nfct_cmp - compare two conntrack objects
conntrack_cmp = _cproto.c_nfct_cmp

## nfct_copy - copy part of one source object to another
conntrack_copy = _cproto.c_nfct_copy

## nfct_copy_attr - copy an attribute of one source object to another
conntrack_copy_attr = _cproto.c_nfct_copy_attr

### Kernel-space filtering for events
## nfct_filter_create - create a filter
def filter_create():
    ret = _cproto.c_nfct_filter_create()
    if ret is None: raise _cproto.os_error()
    return ret

## nfct_filter_destroy - destroy a filter
filter_destroy = _cproto.c_nfct_filter_destroy

## nfct_filter_add_attr - add a filter attribute of the filter object
def filter_add_attr(f, attr_type, value):
    try:
        ctypes.sizeof(value)
    except TypeError:
        raise OSError(errno.EINVAL, "value must be ctypes type")
    if attr_type >= NFCT_FILTER_MAX: raise OSError(errno.EINVAL, "not a valid filter attr type")
    _cproto.c_nfct_filter_add_attr(f, attr_type, ctypes.byref(value))

## nfct_filter_add_attr_u32 - add an u32 filter attribute of the filter object
def filter_add_attr_u32(f, attr_type, value):
    if attr_type >= NFCT_FILTER_MAX: raise OSError(errno.EINVAL, "not a valid filter attr type")
    _cproto.c_nfct_filter_add_attr_u32(f, attr_type, value)

## nfct_filter_set_logic - set the filter logic for an attribute type
def filter_set_logic(f, attr_type, logic):
    if logic >= NFCT_FILTER_LOGIC_MAX: raise OSError(errno.EINVAL, "not a valid filter logic")
    ret = _cproto.c_nfct_filter_set_logic(f, attr_type, logic)
    if ret == -1: raise _cproto.os_error()

## nfct_filter_attach - attach a filter to a socket descriptor
def filter_attach(fd, f):
    ret = _cproto.c_nfct_filter_attach(fd, f)
    if ret == -1: raise _cproto.os_error()

## nfct_filter_detach - detach an existing filter
def filter_detach(fd):
    ret = _cproto.c_nfct_filter_detach(fd)
    if ret == -1: raise _cproto.os_error()


### Conntrack labels
## nfct_labelmap_get_name - get name of the label bit
def labelmap_get_name(m, bit):
    ret = _cproto.c_nfct_labelmap_get_name(m, bit)
    if ret is None: return None
    return ctypes.string_at(ret)

## nfct_labelmap_get_bit - get bit associated with the name
labelmap_get_bit = _cproto.c_nfct_labelmap_get_bit

## nfct_labelmap_new - create a new label map
def labelmap_new(mapfile):
    ret = _cproto.c_nfct_labelmap_new(mapfile)
    if ret is None: raise _cproto.os_error()
    return ret

## nfct_labelmap_destroy - destroy nfct_labelmap object
labelmap_destroy = _cproto.c_nfct_labelmap_destroy


### bitmask object
## nfct_bitmask_new - allocate a new bitmask
def bitmask_new(high):
    ret = _cproto.c_nfct_bitmask_new(high)
    if ret is None: raise _cproto.os_error()
    return ret

## nfct_bitmask_clone - duplicate a bitmask object
def bitmask_clone(b):
    ret = _cproto.c_nfct_bitmask_clone(b)
    if ret is None: raise _cproto.os_error()
    return ret

## nfct_bitmask_set_bit - set bit in the bitmask
bitmask_set_bit = _cproto.c_nfct_bitmask_set_bit

## nfct_bitmask_test_bit - test if a bit in the bitmask is set
def bitmask_test_bit(b, bit):
    return _cproto.c_nfct_bitmask_test_bit(b, bit) != 0

## nfct_bitmask_unset_bit - unset bit in the bitmask
bitmask_unset_bit = _cproto.c_nfct_bitmask_unset_bit

## nfct_bitmask_maxbit - return highest bit that may be set/unset
bitmask_maxbit = _cproto.c_nfct_bitmask_maxbit

## nfct_bitmask_destroy - destroy bitmask object
bitmask_destroy = _cproto.c_nfct_bitmask_destroy

##  nfct_nlmsg_build - build a netlink message from a conntrack object
def conntrack_nlmsg_build(nlh, ct):
    ret = _cproto.c_nfct_nlmsg_build(nlh, ct)
    if ret == -1: raise _cproto.os_error()

## nfct_nlmsg_parse - translate a netlink message to a conntrack object
def conntrack_nlmsg_parse(nlh, ct):
    ret = _cproto.c_nfct_nlmsg_parse(nlh, ct)
    if ret == -1: raise os_error()
    return ret

## nfct_payload_parse - translate a ... to a conntrack object
def conntrack_payload_parse(payload, l3num, ct):
    b = (ctypes.c_ubyte * len(payload)).from_buffer(payload)
    ret = _cproto.c_nfct_payload_parse(b, len(payload), l3num, ct)
    if ret == -1: raise _cproto.os_error()
