# -*- coding: utf-8 -*-

from __future__ import absolute_import

import errno

from . import _conntrack
from . import _expect
from ._libnetfilter_conntrackh import *

class Conntrack(object):
    def __init__(self, ct=None):
        if ct is None: ct = _conntrack.conntrack_new()
        self._ct = ct

    def destroy(self): # XXX: no lock
        _conntrack.conntrack_destroy(self._ct)
        del self._ct

    def __del__(self): # XXX: no lock
        if hasattr(self, "_ct"): self.destroy()

    def clone(self):
        return Conntrack(_conntrack.conntrack_clone(self._ct))

    def setobjopt(self, o):
        _conntrack.conntrack_setobjopt(self._ct, o)

    def getobjopt(self, o):
        return _conntrack.conntrack_getobjopt(self._ct, o)

    def set_attr_l(self, a, v):
        _conntrack.conntrack_set_attr_l(self._ct, a, v)

    def set_attr(self, a, v):
        _conntrack.conntrack_set_attr(self._ct, a, v)

    def set_attr_u8(self, a, v):
	_conntrack.conntrack_set_attr_u8(self._ct, a, v)

    def set_attr_u16(self, a, v):
	_conntrack.conntrack_set_attr_u16(self._ct, a, v)

    def set_attr_u32(self, a, v):
	_conntrack.conntrack_set_attr_u32(self._ct, a, v)

    def set_attr_u64(self, a, v):
	_conntrack.conntrack_set_attr_u64(self._ct, a, v)

    def get_attr(self, a):
        return _conntrack.conntrack_get_attr(self._ct, a)

    def get_attr_as(self, a, c):
	return _conntrack.conntrack_get_attr_as(self._ct, a, c)

    def get_attr_u8(self, a):
        return _conntrack.conntrack_get_attr_u8(self._ct, a)

    def get_attr_u16(self, a):
        return _conntrack.conntrack_get_attr_u16(self._ct, a)

    def get_attr_u32(self, a):
        return _conntrack.conntrack_get_attr_u32(self._ct, a)

    def get_attr_u64(self, a):
        return _conntrack.conntrack_get_attr_u64(self._ct, a)

    def attr_is_set(self, a):
        return _conntrack.conntrack_attr_is_set(self._ct, a)

    def attr_is_set_array(self, l):
	return _conntrack.conntrack_attr_is_set_array(self._ct, l)

    def attr_unset(self, a):
        return _conntrack.conntrack_attr_unset(self._ct, a)

    def set_attr_grp(self, a, d):
	_conntrack.conntrack_set_attr_grp(self._ct, a, d)

    def get_attr_grp(self, a, d):
	_conntrack.conntrack_get_attr_grp(self._ct, a, d)

    def get_attr_grp_as(self, a, c):
	return _conntrack.conntrack_get_attr_grp_as(self._ct, a, c)

    def attr_grp_is_set(self, a):
	return _conntrack.conntrack_attr_grp_is_set(self._ct, a)

    def attr_grp_unset(self, a):
	_conntrack.conntrack_attr_grp_unset(self._ct, a)

    def snprintf(self, s, m, o, f):
	return _conntrack.conntrack_snprintf(s, self._ct, m, o, f)

    def snprintf_labels(self, s, m, o, f, l):
        return _conntrack.conntrack_snprinf_labels(s, self._ct, m, o, f, l)

    def cmp(self, ct2, f):
        return _conntrack.conntrack_cmp(self._ct, ct2._ct, f)

    def copy(self, ct2, f):
        _conntrack.conntrack_copy(ct2._ct, self._ct, f)

    def copy_attr(self, ct2, t):
	_conntrack.conntrack_copy_attr(ct2._ct, self._ct, t)

    def nlmsg_build(self, nlh):
        _conntrack.conntrack_nlmsg_build(nlh, self._ct)

    def nlmsg_parse(self, nlh):
        _conntrack.conntrack_nlmsg_parse(nlh, self._ct)

    def payload_parse(self, p, l3):
	_conntrack.conntrack_payload_parse(p, l3, self._ct)

    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Filter(object):
    def __init__(self):			self._filter = _conntrack.filter_create()

    def destroy(self):
        _conntrack.filter_destroy(self._filter)
        del self._filter

    def __del__(self):
        hasattr(self, "_filter") and self.destroy()

    def add_attr(self, a, v):
        _conntrack.filter_add_attr(self._filter, a, v)

    def add_attr_u32(self, a, v):
	_conntrack.filter_add_attr_u32(self._filter, a, v)

    def set_logic(self, a, l):
        _conntrack.filter_set_logic(self._filter, a, l)

    def attach(self, fd):
        _conntrack.filter_attach(fd, self._filter)

    @staticmethod
    def detach(fd):
        _conntrack.filter_detach(fd)

    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class FilterDump(object):
    def __init__(self):			self._filter_dump = _conntrack.filter_dump_create()

    def destroy(self):
        _conntrack.filter_dump_destroy(self._filter_dump)
        del self._filter_dump

    def __del__(self):
        hasattr(self, "_filter_dump") and self.destroy()

    def set_attr(self, a, v):
        _conntrack.filter_dump_set_attr(self._filter_dump, a, v)

    def set_attr_u8(self, a, v):
	_conntrack.filter_dump_set_attr_u8(self._filter_dump, a, v)

    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Labelmap(object):
    def __init__(self, mapfile):	self._labelmap = _conntrack.labelmap_new(mapfile)

    def destroy(self):
        _conntrack.labelmap_destroy(self._labelmap)
        del self._labelmap

    def __del__(self):
        hasattr(self, "_labelmap") and self.destroy()

    def get_name(self, bit):
        return _conntrack.labelmap_get_name(self._labelmap, bit)

    def get_bit(self, name):
        return _conntrack.labelmap_get_bit(self._labelmap, name)

    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Bitmask(object):
    def __init__(self, high, bitmask=None):
        if bitmask is None:
            bitmask = _conntrack.bitmask_new(high)
        self._bitmask = bitmask

    def destroy(self):
        _conntrack.bitmask_destroy(self._bitmask)
        del self._bitmask

    def __del__(self):
        hasattr(self, "_bitmask") and self.destroy()

    def clone(self):
        return Bitmask(0, _conntrack.bitmask_clone(self._bitmask))

    def set_bit(self, bit):
        _conntrack.bitmask_set_bit(self._bitmask, bit)

    def test_bit(self, bit):
        return _conntrack.bitmask_test_bit(self._bitmask, bit)

    def unset_bit(self, bit):
        _conntrack.bitmask_unset_bit(self._bitmask, bit)

    def maxbit(self):
        return _conntrack.bitmask_maxbit(self._bitmask)

    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Expect(object):
    def __init__(self, exp=None):
        if exp is None: exp = _expect.expect_new()
        self._exp = exp

    def destroy(self):
        _expect.expect_destroy(self._exp)
        del self._exp

    def __del__(self):
        hasattr(self, "_exp") and self.destroy()

    def clone(self):
        return Expect(_expect.expect_clone(self._exp))

    def cmp(self, e2, f):
        return _expect.expect_cmp(self._exp, e2._exp, f)

    def set_attr(self, a, v):
        _expect.expect_set_attr(self._exp, a, v)

    def set_attr_u8(self, a, v):
	_expect.expect_set_attr_u8(self._exp, a, v)

    def set_attr_u16(self, a, v):
	_expect.expect_set_attr_u16(self._exp, a, v)

    def set_attr_u32(self, a, v):
	_expect.expect_set_attr_u32(self._exp, a, v)

    def get_attr(self, a):
        return _expect.expect_get_attr(self._exp, a)

    def get_attr_as(self, a, c):
	return _expect.expect_get_attr_as(self._exp, a, c)

    def get_attr_u8(self, a):
        return _expect.expect_get_attr_u8(self._exp, a)

    def get_attr_u16(self, a):
        return _expect.expect_get_attr_u16(self._exp, a)

    def get_attr_u32(self, a):
        return _expect.expect_get_attr_u32(self._exp, a)

    def attr_is_set(self, a):
        return _expect.expect_attr_is_set(self._exp, a)

    def attr_unset(self, a):
        _expect.expect_attr_unset(self._exp, a)

    def snprintf(self, s, m, o, f):
	return _expect.expect_snprintf(s, self._exp, m, o, f)

    def nlmsg_build(self, nlh):
        return _expect.expect_nlmsg_build(nlh, self._exp)

    def nlmsg_parse(self, nlh):
        return _expect.expect_nlmsg_parse(nlh, self._exp)

    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        self.destroy()
        return False
