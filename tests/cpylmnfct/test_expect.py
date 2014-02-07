# -*- coding: utf-8 -*-

from __future__ import print_function

import sys, unittest
import socket, ctypes, errno

import cpylmnl as mnl
import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nf_conntrack_commonh as nfctcm
import cpylmnl.linux.netfilter.nfnetlink_conntrackh as nfnlct

import cpylmnfct as nfct

class TestSuite(unittest.TestCase):
    # almost just calling them
    def test_expect(self):
        try:
            exp = nfct.Expect()
            exp.destroy()
        except Exception as e:
            self.fail("could not create or destroy nf_expect: %s" % e)
        try:
            exp = nfct.Expect()
            del exp
        except Exception as e:
            self.fail("could not create or del nf_expect: %s" % e)
            
	# Expect.clone(self)
	# Expect.cmp(self, e2, f)
	# Expect.set_attr(self, a, v)
	# Expect.set_attr_u8(self, a, v)
	# Expect.set_attr_u16(self, a, v)
	# Expect.set_attr_u32(self, a, v)
	# Expect.get_attr(self, a)
	# Expect.get_attr_as(self, a, c)
	# Expect.get_attr_u8(self, a)
	# Expect.get_attr_u16(self, a)
	# Expect.get_attr_u32(self, a)
	# Expect.attr_is_set(self, a)
	# Expect.attr_unset(self, a)
	# Expect.snprintf(self, s, m, o, f)
	# Expect.nlmsg_build(self, nlh)
	# Expect.nlmsg_parse(self, nlh)
