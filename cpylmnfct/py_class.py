# -*- coding: utf-8 -*-

from __future__ import absolute_import

import errno

from . import conntrack
from . import expect

class Conntrack(object):
    def __init__(self, ct=None):
        if ct is None: ct = conntrack.conntrack_new()
        self._ct = ct

    def destroy(self): # XXX: no lock
        conntrack.conntrack_destroy(self._ct)
        del self._ct

    def __del__(self): # XXX: no lock
        if hasattr(self, "_ct"): self.destroy()

    def clone(self):			return Conntrack(conntrack.conntrack_clone(self._ct))
    def setobjopt(self, o):		conntrack.conntrack_setobjopt(self._ct, o)
    def getobjopt(self, o):		return conntrack.conntrack_getobjopt(self._ct, o)
    def set_attr_l(self, a, v):		conntrack.conntrack_set_attr_l(self._ct, a, v)
    def set_attr(self, a, v):		conntrack.conntrack_set_attr(self._ct, a, v)
    def set_attr_u8(self, a, v):	conntrack.conntrack_set_attr_u8(self._ct, a, v)
    def set_attr_u16(self, a, v):	conntrack.conntrack_set_attr_u16(self._ct, a, v)
    def set_attr_u32(self, a, v):	conntrack.conntrack_set_attr_u32(self._ct, a, v)
    def set_attr_u64(self, a, v):	conntrack.conntrack_set_attr_u64(self._ct, a, v)
    def get_attr(self, a):		return conntrack.conntrack_get_attr(self._ct, a)
    def get_attr_as(self, a, c):	return conntrack.conntrack_get_attr_as(self._ct, a, c)
    def get_attr_u8(self, a):		return conntrack.conntrack_get_attr_u8(self._ct, a)
    def get_attr_u16(self, a):		return conntrack.conntrack_get_attr_u16(self._ct, a)
    def get_attr_u32(self, a):		return conntrack.conntrack_get_attr_u32(self._ct, a)
    def get_attr_u64(self, a):		return conntrack.conntrack_get_attr_u64(self._ct, a)
    def attr_is_set(self, a):		return conntrack.conntrack_attr_is_set(self._ct, a)
    def attr_is_set_array(self, l):	return conntrack.conntrack_attr_is_set_array(self._ct, l)
    def attr_unset(self, a):		return conntrack.conntrack_attr_unset(self._ct, a)
    def set_attr_grp(self, a, d):	conntrack.conntrack_set_attr_grp(self._ct, a, d)
    def get_attr_grp(self, a, d):	conntrack.conntrack_get_attr_grp(self._ct, a, d)
    def get_attr_grp_as(self, a, c):	return conntrack.conntrack_get_attr_grp_as(self._ct, a, c)
    def attr_grp_is_set(self, a):	return conntrack.conntrack_attr_grp_is_set(self._ct, a)
    def attr_grp_unset(self, a):	conntrack.conntrack_attr_grp_unset(self._ct, a)
    def snprintf(self, s, m, o, f):	return conntrack.conntrack_snprintf(s, self._ct, m, o, f)
    def snprintf_labels(self, s, m, o, f, l): return conntrack.conntrack_snprinf_labels(s, self._ct, m, o, f, l)
    def cmp(self, ct2, f):		return conntrack.conntrack_cmp(self._ct, ct2._ct, f)
    def copy(self, ct2, f):		conntrack.conntrack_copy(ct2._ct, self._ct, f)
    def copy_attr(self, ct2, t):	conntrack.conntrack_copy_attr(ct2._ct, self._ct, t)

    def nlmsg_build(self, nlh):		conntrack.conntrack_nlmsg_build(nlh, self._ct)
    def nlmsg_parse(self, nlh):		conntrack.conntrack_nlmsg_parse(nlh, self._ct)
    def payload_parse(self, p, l3):	conntrack.conntrack_payload_parse(p, l3, self._ct)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Filter(object):
    def __init__(self, filter=None):
        if filter is None: filter = conntrack.filter_create()
        self._filter = filter

    def destroy(self):
        conntrack.filter_destroy(self._filter)
        del self._filter

    def __del__(self):
        if hasattr(self, "_filter"): self.destroy()

    def add_attr(self, a, v):		conntrack.filter_add_attr(self._filter, a, v)
    def add_attr_u32(self, a, v):	conntrack.filter_add_attr_u32(self._filter, a, v)
    def set_logic(self, a, l):		conntrack.filter_set_logic(self._filter, a, l)
    def attach(self, fd):		conntrack.filter_attach(fd, self._filter)
    @staticmethod
    def detatch(fd):			conntrack.filter_detach(fd)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class FilterDump(object):
    def __init__(self, filter_dump=None):
        if conntrack.filter_dump is None: conntrack.filter_dump = conntrack.filter_dump_create()
        self._conntrack.filter_dump = conntrack.filter_dump

    def destroy(self):
        conntrack.filter_dump_destroy(self._conntrack.filter_dump)
        del self._conntrack.filter_dump

    def __del__(self):
        if hasattr(self, "_conntrack.filter_dump"): self.destroy()

    def set_attr(self, a, v):		conntrack.filter_dump_set_attr(self._filter.dump, a, v)
    def set_attr_u8(self, a, v):	conntrack.filter_dump_set_attr_u8(self._filter.dump, a, v)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Labelmap(object):
    def __init__(self, labelmap=None):
        if labelmap is None: labelmap = conntrack.labelmap_new()
        self._labelmap = labelmap

    def destroy(self):
        conntrack.labelmap_destroy(self._labelmap)
        del self._labelmap

    def get_name(self, bit):		return conntrack.labelmap_get_name(self._labelmap, bit)
    def get_bit(self, name):		return conntrack.labelmap_get_bit(self._labelmap, name)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Bitmask(object):
    def __init__(self, high, bitmask=None):
        if bitmask is None:
            bitmask = conntrack.bitmask_new(high)
        self._bitmask = bitmask

    def destroy(self):
        conntrack.bitmask_destroy(self._bitmask)
        del self._bitmask

    def __del__(self):
        if hasattr(self, "_bitmask"): self.destroy()

    def clone(self):
        return Bitmask(0, conntrack.bitmask_clone(self._bitmask))

    def set_bit(self, bit):		conntrack.bitmask_set_bit(self._bitmask, bit)
    def test_bit(self, bit):		return conntrack.bitmask_test_bit(self._bitmask, bit)
    def unset_bit(self, bit):		conntrack.bitmask_unset_bit(self._bitmask, bit)
    def maxbit(self):			return conntrack.bitmask_maxbit(self._bitmask)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False


class Expect(object):
    def __init__(self, exp=None):
        if exp is None: exp = expect.expect_new()
        self._exp = exp

    def destroy(self):
        expect.expect_destroy(self._exp)
        del self._exp

    def __del__(self):
        if hasattr(self, "_exp"): self.destroy()

    def clone(self):			return Expect(expect.expect_clone(self._exp))
    def cmp(self, e2, f):		return expect.expect_cmp(self._exp, e2._exp, f)
    def set_attr(self, a, v):		expect.expect_set_attr(self._exp, a, v)
    def set_attr_u8(self, a, v):	expect.expect_set_attr_u8(self._exp, a, v)
    def set_attr_u16(self, a, v):	expect.expect_set_attr_u16(self._exp, a, v)
    def set_attr_u32(self, a, v):	expect.expect_set_attr_u32(self._exp, a, v)
    def get_attr(self, a):		return expect.expect_get_attr(self._exp, a)
    def get_attr_as(self, a, c):	return expect.expect_get_attr_as(self._exp, a, c)
    def get_attr_u8(self, a):		return expect.expect_get_attr_u8(self._exp, a)
    def get_attr_u16(self, a):		return expect.expect_get_attr_u16(self._exp, a)
    def get_attr_u32(self, a):		return expect.expect_get_attr_u32(self._exp, a)
    def attr_is_set(self, a):		return expect.expect_attr_is_set(self._exp, a)
    def attr_unset(self, a):		expect.expect_attr_unset(self._exp, a)
    def snprintf(self, s, m, o, f):	return expect.expect_snprintf(s, self._exp, m, o, f)

    def nlmsg_build(self, nlh):		return expect.expect_nlmsg_build(nlh, self._exp)
    def nlmsg_parse(self, nlh):		return expect.expect_nlmsg_parse(nlh, self._exp)

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.destroy()
        return False
