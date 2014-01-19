# -*- coding: utf-8 -*-

from __future__ import absolute_import

from ctypes import *
import errno
from cpylmnl.linux import netlinkh as netlink

from .cproto import *

## nfct_new - allocate a new conntrack
# conntrack_new = c_nfct_new
def conntrack_new():
    set_errno(0)
    ret = c_nfct_new()
    if ret is None: os_error()
    return ret

## nfct_destroy - release a conntrack object
conntrack_destroy = c_nfct_destroy

## nfct_clone - clone a conntrack object
# conntrack_clone = c_nfct_clone
def conntrack_clone(ct):
    set_errno(0)
    ret = c_nfct_clone(ct)
    if ret is None: raise os_error()
    return ret

## nfct_setobjopt - set a certain option for a conntrack object
# conntrack_setobjopt = c_nfct_setobjopt
def conntrack_setobjopt(ct, option):
    set_errno(0)
    if c_nfct_setobjopt(ct, option) == -1: raise os_error()

## nfct_getobjopt - get a certain option for a conntrack object
# conntrack_getobjopt = c_nfct_getobjopt
def conntrack_getobjopt(ct, option):
    set_errno(0)
    ret = c_nfct_getobjopt(ct, option)
    if ret == -1: c_raise_if_errno()
    return ret

## nfct_set_attr_l - set the value of a certain conntrack attribute
# conntrack_set_attr_l = c_nfct_set_attr_l
def conntrack_set_attr_l(ct, attr_type, value):
    # value must be ctypes type, to check it
    # isinstance(value, _SimpleCData) is false in Structure, cannot access _ctypes._CData
    try:
        size = sizeof(value)
    except TypeError:
        raise OSError(errno.EINVAL, "value must be ctypes type")
    c_nfct_set_attr_l(ct, attr_type, byref(value), size)

## nfct_set_attr - set the value of a certain conntrack attribute
# conntrack_set_attr = c_nfct_set_attr
def conntrack_set_attr(ct, attr_type, value):
    try:
        sizeof(value)
    except TypeError:
        raise OSError(errno.EINVAL, "value must be ctypes type")
    c_nfct_set_attr(ct, attr_type, value)

## nfct_set_attr_u8 - set the value of a certain conntrack attribute
conntrack_set_attr_u8 = c_nfct_set_attr_u8

## nfct_set_attr_u16 - set the value of a certain conntrack attribute
conntrack_set_attr_u16 = c_nfct_set_attr_u16

## nfct_set_attr_u32 - set the value of a certain conntrack attribute
conntrack_set_attr_u32 = c_nfct_set_attr_u32

## nfct_set_attr_u64 - set the value of a certain conntrack attribute
conntrack_set_attr_u64 = c_nfct_set_attr_u64

## nfct_get_attr - get a conntrack attribute
# conntrack_get_attr = c_nfct_get_attr
def conntrack_get_attr(ct, attr_type):
    set_errno(0)
    ret = c_nfct_get_attr(ct, option)
    if ret is None: raise os_error()
    return ret

def conntrack_get_attr_as(ct, attr_type, cls):
    set_errno(0)
    ret = c_nfct_get_attr(ct, option)
    if ret is None: raise os_error()
    return cast(ret, POINTER(cls)).contents

## nfct_get_attr_u8 - get attribute of unsigned 8-bits long
# conntrack_get_attr_u8 = c_nfct_get_attr_u8
def conntrack_get_attr_u8(ct, attr_type):
    set_errno(0)
    ret = c_nfct_get_attr_u8(ct, attr_type)
    if ret == 0: c_raise_if_errno()
    return ret

## nfct_get_attr_u16 - get attribute of unsigned 16-bits long
# conntrack_get_attr_u16 = c_nfct_get_attr_u16
def conntrack_get_attr_u16(ct, attr_type):
    set_errno(0)
    ret = c_nfct_get_attr_u16(ct, attr_type)
    if ret == 0: c_raise_if_errno()
    return ret

## nfct_get_attr_u32 - get attribute of unsigned 32-bits long
# conntrack_get_attr_u32 = c_nfct_get_attr_u32
def conntrack_get_attr_u32(ct, attr_type):
    set_errno(0)
    ret = c_nfct_get_attr_u32(ct, attr_type)
    if ret == 0: c_raise_if_errno()
    return ret

## nfct_get_attr_u64 - get attribute of unsigned 64-bits long
# conntrack_get_attr_u64 = c_nfct_get_attr_u64
def conntrack_get_attr_u64(ct, attr_type):
    set_errno(0)
    ret = c_nfct_get_attr_u64(ct, attr_type)
    if ret == 0: c_raise_if_errno()
    return ret

## nfct_attr_is_set - check if a certain attribute is set
# conntrack_attr_is_set = c_nfct_attr_is_set
def conntrack_attr_is_set(ct, attr_type):
    set_errno(0)
    ret = c_nfct_attr_is_set(ct, attr_type)
    if ret == -1: raise os_error()
    return ret > 0

## nfct_attr_is_set_array - check if an array of attribute types is set
# conntrack_attr_is_set_array = c_nfct_attr_is_set_array
def conntrack_attr_is_set_array(ct, type_list):
    set_errno(0)
    size = len(type_list)
    c_type_array = (c_int * size)
    for i, t in enumerate(type_list): c_type_array[i] = t
    ret = c_nfct_attr_is_set_array(ct, cast(c_type_array, c_void_p), size)
    if ret < 0: c_raise_if_errno()
    return ret > 0

## nfct_attr_unset - unset a certain attribute
#conntrack_attr_unset = c_nfct_attr_unset
def conntrack_attr_unset(ct, attr_type):
    set_errno(0)
    if c_nfct_attr_unset(ct, attr_type) == -1: raise os_error()

## nfct_set_attr_grp - set a group of attributes
# conntrack_set_attr_grp = c_nfct_set_attr_grp
def conntrack_set_attr_grp(ct, attr_type, data):
    try:
        sizeof(data)
    except TypeError:
        raise OSError(errno.EINVAL, "data must be ctypes type")
    c_nfct_set_attr_grp(ct, attr_type, byref(data))

## nfct_get_attr_grp - get an attribute group
# conntrack_get_attr_grp = c_nfct_get_attr_grp
def conntrack_get_attr_grp(ct, attr_type, data):
    set_errno(0)
    try:
        sizeof(data)
    except TypeError:
        raise OSError(errno.EINVAL, "data must be ctypes type")
    if nfct_get_attr_grp(ct, attr_type, byref(data)) < 0: raise os_error()
def conntrack_get_attr_grp_as(ct, attr_type, cls):
    data = cls.__new__(cls)
    conntrack_get_attr_grp(ct, attr_type, data)
    return data

## nfct_attr_grp_is_set - check if an attribute group is set
# conntrack_attr_grp_is_set = c_nfct_attr_grp_is_set
def conntrack_attr_grp_is_set(ct, attr_type):
    set_errno(0)
    ret = c_nfct_attr_grp_is_set(ct, attr_type)
    if ret < 0: c_raise_if_errno()
    return ret > 0

## nfct_attr_grp_unset - unset an attribute group
# conntrack_attr_grp_unset = c_nfct_attr_grp_unset
def conntrack_attr_grp_unset(ct, attr_type):
    set_errno(0)
    if c_nfct_attr_grp_unset(ct, attr_type) < 0: raise os_error()

## nfct_snprintf - print a conntrack object to a buffer
# conntrack_snprintf = c_nfct_snprintf
def conntrack_snprintf(size, ct, msg_type, out_type, flags):
    set_errno(0)
    c_buf = create_string_buffer(size)
    ret = c_nfct_snprintf(byref(c_buf), size, ct, msg_type, out_type, flags)
    if ret == -1: raise os_error()
    return str(c_buf)

## nfct_snprintf_labels - print a bitmask object to a buffer including labels
# conntrack_snprintf_labels = c_nfct_snprintf_labels
def conntrack_snprintf_labels(size, ct, msg_type, out_type, flags, labelmap):
    set_errno(0)
    c_buf = create_string_buffer(size)
    ret = c_nfct_snprintf_labels(byref(c_buf), size, ct, msg_type, out_type, flags, labelmap)
    if ret == -1: raise os_error()
    return str(c_buf)

## nfct_compare - compare two conntrack objects
conntrack_compare = c_nfct_compare

## nfct_cmp - compare two conntrack objects
conntrack_cmp = c_nfct_cmp

## nfct_copy - copy part of one source object to another
conntrack_copy = c_nfct_copy

## nfct_copy_attr - copy an attribute of one source object to another
conntrack_copy_attr = c_nfct_copy_attr

### Kernel-space filtering for events
## nfct_filter_create - create a filter
# filter_create = c_nfct_filter_create
def filter_create():
    set_errno(0)
    ret = c_nfct_filter_create()
    if ret == None: raise os_error()
    return ret

## nfct_filter_destroy - destroy a filter
filter_destroy = c_nfct_filter_destroy

## nfct_filter_add_attr - add a filter attribute of the filter object
# filter_add_attr = c_nfct_filter_add_attr
def filter_add_attr(f, attr_type, value):
    try:
        sizeof(value)
    except TypeError:
        raise OSError(errno.EINVAL, "value must be ctypes type")
    nfct_filter_add_attr(ct, attr_type, value)

## nfct_filter_add_attr_u32 - add an u32 filter attribute of the filter object
filter_add_attr_u32 = c_nfct_filter_add_attr_u32

## nfct_filter_set_logic - set the filter logic for an attribute type
# filter_set_logic = c_nfct_filter_set_logic
def filter_set_logic(f, attr_type, logic):
    set_errno(0)
    if c_nfct_filter_add_attr_u32(f, attr_type, logic) == -1: raise os_error()

## nfct_filter_attach - attach a filter to a socket descriptor
# filter_attach = c_nfct_filter_attach
def filter_attach(fd, f):
    set_errno(0)
    if c_nfct_filter_attach(fd, f) == -1: raise os_error()
    
## nfct_filter_detach - detach an existing filter
# filter_detach = c_nfct_filter_detach
def filter_detach(fd):
    set_errno(0)
    if c_nfct_filter_detach(fd) == -1: raise os_error()


### dump filtering
## nfct_filter_dump_create - create a dump filter
# filter_dump_create = c_nfct_filter_dump_create
def filter_dump_create():
    set_errno(0)
    ret = c_nfct_filter_dump()
    if ret == None: raise os_error()
    return ret

## nfct_filter_dump_destroy - destroy a dump filter
filter_dump_destroy = c_nfct_filter_dump_destroy

## nfct_filter_dump_set_attr - set filter attribute
# filter_dump_set_attr = c_nfct_filter_dump_attr_set
def filter_dump_set_attr(f, attr_type, value):
    try:
        sizeof(value)
    except TypeError:
        raise OSError(errno.EINVAL, "value must be ctypes type")
    c_nfct_filter_dump_set_attr(ct, attr_type, value)


## nfct_filter_dump_set_attr_u8 - set u8 dump filter attribute
filter_dump_set_attr_u8 = c_nfct_filter_dump_set_attr_u8


### Conntrack labels
## nfct_labelmap_get_name - get name of the label bit
# labelmap_get_name = c_nfct_labelmap_get_name
def labelmap_get_name(m, bit):
    ret = c_nfct_labelmap_get_name
    if ret == None: return None
    return string_at(ret)

## nfct_labelmap_get_bit - get bit associated with the name
# labelmap_get_bit = c_nfct_labelmap_get_bit
def labelmap_get_bit(m, name):
    return c_nfct_labelmap_get_bit(m, create_string_buffer(name))

## nfct_labelmap_new - create a new label map
# labelmap_new = c_nfct_labelmap_new
def labelmap_new():
    set_errno(0)
    ret = c_nfct_labelmap_new()
    if ret == None: raise os_error()
    return ret

## nfct_labelmap_destroy - destroy nfct_labelmap object
labelmap_destroy = c_nfct_labelmap_destroy


### bitmask object
## nfct_bitmask_new - allocate a new bitmask
# bitmask_new = c_nfct_bitmask_new
def bitmask_new(high):
    set_errno(0)
    ret = c_nfct_bitmask_new(high)
    if ret is None: raise os_error()
    return ret

## nfct_bitmask_clone - duplicate a bitmask object
# bitmask_clone = c_nfct_bitmask_clone
def bitmask_clone(b):
    set_errno(0)
    ret = c_nfct_bitmask_clone(b)
    if ret is None: raise os_error()
    return ret

## nfct_bitmask_set_bit - set bit in the bitmask
bitmask_set_bit = c_nfct_bitmask_set_bit

## nfct_bitmask_test_bit - test if a bit in the bitmask is set
# bitmask_test_bit = c_nfct_bitmask_test_bit
def bitmask_test_bit(b, bit):
    return c_nfct_bitmask_test_bit(b, bit) != 0

## nfct_bitmask_unset_bit - unset bit in the bitmask
bitmask_unset_bit = c_nfct_bitmask_unset_bit

## nfct_bitmask_maxbit - return highest bit that may be set/unset
bitmask_maxbit = c_nfct_bitmask_maxbit

## nfct_bitmask_destroy - destroy bitmask object
bitmask_destroy = c_nfct_bitmask_destroy

##  nfct_nlmsg_build - build a netlink message from a conntrack object
# conntrack_nlmsg_build = c_nfct_nlmsg_build
def conntrack_nlmsg_build(nlh, ct):
    set_errno(0)
    if c_nfct_nlmsg_build(nlh, ct) == -1: raise os_error()

## nfct_nlmsg_parse - translate a netlink message to a conntrack object
# conntrack_nlmsg_parse = c_nfct_nlmsg_parse
def conntrack_nlmsg_parse(nlh, ct):
    set_errno(0)
    ret = c_nfct_nlmsg_parse(nlh, ct)
    if ret == -1: raise os_error()
    return ret

## nfct_payload_parse - translate a ... to a conntrack object
# conntrack_payload_parse = c_nfct_payload_parse
def conntrack_payload_parse(payload, l3num, ct):
    b = (c_ubyte * len(payload)).from_buffer(payload)
    set_errno(0)
    ret = c_nfct_payload_parse(b, len(payload), l3num, ct)
    if ret == -1: raise os_error()
