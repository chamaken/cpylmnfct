# -*- coding: utf-8 -*-

from __future__ import absolute_import

import errno

from .conntrack import *
from .expect import *

class Conntrack(object):
    def __init__(self):			self._ct = conntrack_new()
    def destroy(self): # XXX: no lock	conntrack_destroy(self._ct)
    def clone(self):			return Conntrack(conntrack_clone(self._ct))
    def setobjopt(self, o):		conntrack_setobjopt(self._ct, o)
    def getobjopt(self, o):		return conntrack_getobjopt(self._ct, o)
    def set_attr_l(self, a, v):		conntrack_set_attr_l(self._ct, a, v)
    def set_attr(self, a, v):		conntrack_set_attr(self._ct, a, v)
    def set_attr_u8(self, a, v):	conntrack_set_attr_u8(self._ct, a, v)
    def set_attr_u16(self, a, v):	conntrack_set_attr_u16(self._ct, a, v)
    def set_attr_u32(self, a, v):	conntrack_set_attr_u32(self._ct, a, v)
    def set_attr_u64(self, a, v):	conntrack_set_attr_u64(self._ct, a, v)
    def get_attr(self, a):		return conntrack_get_attr(self._ct, a)
    def get_attr_as(self, a, c):	return conntrack_get_attr_as(self._ct, a, c)
    def get_attr_u8(self, a):		return conntrack_get_attr_u8(self._ct, a)
    def get_attr_u16(self, a):		return conntrack_get_attr_u16(self._ct, a)
    def get_attr_u32(self, a):		return conntrack_get_attr_u32(self._ct, a)
    def get_attr_u64(self, a):		return conntrack_get_attr_u64(self._ct, a)
    def attr_is_set(self, a):		return conntrack_attr_is_set(self._ct, a)
    def attr_is_set_array(self, l):	return conntrack_attr_is_set_array(self._ct, l)
    def attr_unset(self, a):		return conntrack_attr_unset(self._ct, a)
    def set_attr_grp(self, a, d):	conntrack_set_attr_grp(self._ct, a, d)
    def get_attr_grp(self, a, d):	conntrack_get_attr_grp(self._ct, a, d)
    def get_attr_grp_as(self, a, c):	return conntrack_get_attr_grp_as(self._ct, a, c)
    def attr_grp_is_set(self, a):	return conntrack_attr_grp_is_set(self._ct, a)
    def attr_grp_unset(self, a):	conntrack_attr_grp_unset(self._ct, a)
    def snprintf(self, s, m, o, f):	return conntrack_snprintf(s, self._ct, m, o, f)
    def snprintf_labels(self, s, m, o, f, l): return conntrack_snprinf_labels(s, self._ct, m, o, f, l)
    def compare(self, ct2):		return conntrack_compare(self._ct, ct2._ct)
    def cmp(self, ct2, f):		return conntrack_cmp(self._ct, ct2._ct, f)
    def copy(self, ct2, f):		conntrack_copy(ct2._ct, self._ct, f)
    def copy_attr(self, ct2, t):	conntrack_copy_attr(ct2._ct, self._ct, t)

    def nlmsg_build(self, nlh):		conntrack_nlmsg_build(nlh, self._ct)
    def nlmsg_parse(self, nlh):		conntrack_nlmsg_parse(nlh, self._ct)
    def payload_parse(self, p, l3):	conntrack_payload_parse(p, l3, self._ct)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Filter(object):
    def __init__(self):			self._filter = filter_create()
    def destroy(self):			filter_destroy(self._filter)
    def add_attr(self, a, v):		filter_add_attr(self._filter, a, v)
    def add_attr_u32(self, a, v):	filter_add_attr_u32(self._filter, a, v)
    def set_logic(self, a, l):		filter_set_logic(self._filter, a, l)
    def attach(self, fd):		filter_attach(fd, self._filter)
    @staticmethod
    def detatch(fd):			filter_detach(fd)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class FilterDump(object):
    def __init__(self):			self._filter_dump = filter_dump_create()
    def destroy(self):			filter_dump_destroy(self._filter_dump)
    def set_attr(self, a, v):		filter_dump_set_attr(self._filter.dump, a, v)
    def set_attr_u8(self, a, v):	filter_dump_set_attr_u8(self._filter.dump, a, v)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Labelmap(object):
    def __init__(self):			self._labelmap = labelmap_new()
    def destroy(self):			labelmap_destroy(self._labelmap)
    def get_name(self, bit):		return labelmap_get_name(self._labelmap, bit)
    def get_bit(self, name):		return labelmap_get_bit(self._labelmap, name)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Bitmask(object):
    def __init__(self, high):		self_bitmask = bitmask_new(high)
    def destroy(self):			bitmask_destroy(self._bitmask)
    def clone(self):			return Bitmask(0, bitmask_clone(self._bitmask))
    def set_bit(self, bit):		bitmask_set_bit(self._bitmask, bit)
    def test_bit(self, bit):		return bitmask_test_bit(self._bitmask, bit)
    def unset_bit(self, bit):		bitmask_unset_bit(self._bitmask, bit)
    def maxbit(self):			return bitmask_maxbit(self._bitmask)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Expect(object):
    def __init__(self):			self._exp = expect_new()
    def destroy(self):			expect_destroy(self._exp)
    def clone(self):			return Expect(expect_clone(self._exp))
    def cmp(self, e2, f):		return expect_cmp(self._exp, e2._exp, f)
    def set_attr(self, a, v):		expect_set_attr(self._exp, a, v)
    def set_attr_u8(self, a, v):	expect_set_attr_u8(self._exp, a, v)
    def set_attr_u16(self, a, v):	expect_set_attr_u16(self._exp, a, v)
    def set_attr_u32(self, a, v):	expect_set_attr_u32(self._exp, a, v)
    def get_attr(self, a):		return expect_get_attr(self._exp, a)
    def get_attr_as(self, a, c):	return expect_get_attr_as(self._exp, a, c)
    def get_attr_u8(self, a):		return expect_get_attr_u8(self._exp, a)
    def get_attr_u16(self, a):		return expect_get_attr_u16(self._exp, a)
    def get_attr_u32(self, a):		return expect_get_attr_u32(self._exp, a)
    def attr_is_set(self, a):		return expect_attr_is_set(self._exp, a)
    def attr_unset(self, a):		expect_attr_unset(self._exp, a)
    def snprintf(self, s, m, o, f):	return expect_snprintf(s, self._exp, m, o, f)

    def nlmsg_build(self, nlh):		return expect_nlmsg_build(nlh, self._exp)
    def nlmsg_parse(self, nlh):		return expect_nlmsg_parse(nlh, self._exp)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False
