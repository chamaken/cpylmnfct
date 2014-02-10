# -*- coding: utf-8 -*-

from __future__ import absolute_import

import ctypes, errno
from cpylmnl.linux import netlinkh as netlink

from . import cproto
from .libnetfilter_conntrackh import ATTR_EXP_MAX


### Expect object handling
## nfexp_new - allocate a new expectation
# expect_new = c_nfexp_new
def expect_new():
    ret = cproto.c_nfexp_new()
    if ret is None: raise cproto.os_error()
    return ret

## nfexp_destroy - release an expectation object
expect_destroy = cproto.c_nfexp_destroy

## nfexp_clone - clone a expectation object
def expect_clone(exp):
    ret = cproto.c_nfexp_clone(exp)
    if ret is None: raise cproto.os_error()
    return ret

## nfexp_cmp - compare two expectation objects
expect_cmp = cproto.c_nfexp_cmp


### NO LibrarySetup Library setup


### Expect object handling
## nfexp_set_attr - set the value of a certain expect attribute
def expect_set_attr(exp, attr_type, value):
    try:
        size = ctypes.sizeof(value)
    except TypeError:
        raise OSError(errno.EINVAL, "value must be ctypes type")
    if attr_type >= ATTR_EXP_MAX: raise OSError(errno.EINVAL, "not a valid expect attr type")
    cproto.c_nfexp_set_attr(exp, attr_type, ctypes.byref(value))

## nfexp_set_attr_u8 - set the value of a certain expect attribute
def expect_set_attr_u8(exp, attr_type, value):
    if attr_type >= ATTR_EXP_MAX: raise OSError(errno.EINVAL, "not a valid expect attr type")
    cproto.c_nfexp_set_attr_u8(exp, attr_type, value)

## nfexp_set_attr_u16 - set the value of a certain expect attribute
def expect_set_attr_u16(exp, attr_type, value):
    if attr_type >= ATTR_EXP_MAX: raise OSError(errno.EINVAL, "not a valid expect attr type")
    cproto.c_nfexp_set_attr_u16(exp, attr_type, value)

## nfexp_set_attr_u32 - set the value of a certain expect attribute
def expect_set_attr_u32(exp, attr_type, value):
    if attr_type >= ATTR_EXP_MAX: raise OSError(errno.EINVAL, "not a valid expect attr type")
    cproto.c_nfexp_set_attr_u32(exp, attr_type, value)

## nfexp_get_attr - get an expect attribute
def expect_get_attr(exp, attr_type):
    ret = cproto.c_nfexp_get_attr(exp, attr_type)
    if ret is None: raise cproto.os_error()
    return ret

def expect_get_attr_as(exp, attr_type, cls):
    ret = cproto.c_nfexp_get_attr(exp, attr_type)
    if ret is None: raise cproto.os_error()
    return ctypes.cast(ret, ctypes.POINTER(cls)).contents

## nfexp_get_attr_u8 - get attribute of unsigned 8-bits long
def expect_get_attr_u8(exp, attr_type):
    ctypes.set_errno(0)
    ret = cproto.c_nfexp_get_attr_u8(exp, attr_type)
    if ret == 0: cproto.c_raise_if_errno()
    return ret

## nfexp_get_attr_u16 - get attribute of unsigned 16-bits long
def expect_get_attr_u16(exp, attr_type):
    ctypes.set_errno(0)
    ret = cproto.c_nfexp_get_attr_u16(exp, attr_type)
    if ret == 0: cproto.c_raise_if_errno()
    return ret

## nfexp_get_attr_u32 - get attribute of unsigned 32-bits long
def expect_get_attr_u32(exp, attr_type):
    ctypes.set_errno(0)
    ret = cproto.c_nfexp_get_attr_u32(exp, attr_type)
    if ret == 0: cproto.c_raise_if_errno()
    return ret

## nfexp_attr_is_set - check if a certain attribute is set
def expect_attr_is_set(exp, attr_type):
    ret = cproto.c_nfexp_attr_is_set(exp, attr_type)
    if ret == -1: raise cproto.os_error()
    return ret > 0

## nfexp_attr_unset - unset a certain attribute
def expect_attr_unset(exp, attr_type):
    ret = cproto.c_nfexp_attr_unset(exp, attr_type)
    if ret == -1: raise cproto.os_error()

## nfexp_snprintf - print a conntrack object to a buffer
def expect_snprintf(size, exp, msg_type, out_flag, flags):
    c_buf = ctypes.create_string_buffer(size)
    ret = cproto.c_nfexp_snprintf(ctypes.byref(c_buf), size, exp, msg_type, out_type, flags)
    if ret == -1: raise cproto.os_error()
    return str(c_buf)

# expect_nlmsg_build = c_nfexp_nlmsg_build
def expect_nlmsg_build(nlh, exp):
    ret = cproto.c_nfexp_nlmsg_build(nlh, exp)
    if ret == -1: raise cproto.os_error()

# expect_nlmsg_parse = c_nfexp_nlmsg_parse
def expect_nlmsg_parse(nlh, ct):
    ret = cproto.c_nfexp_nlmsg_parse(nlh, exp)
    if ret == -1: raise cproto.os_error()
    return ret
