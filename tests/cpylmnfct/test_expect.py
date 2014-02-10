# -*- coding: utf-8 -*-

from __future__ import print_function

import sys, unittest
import socket, ctypes, errno

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
            

    def test_clone(self):
        exp = nfct.Expect()
        exp.set_attr_u32(nfct.ATTR_EXP_TIMEOUT, 0x12345678)
        clone = exp.clone()
        self.assertNotEqual(exp._exp, clone._exp)
        self.assertEqual(clone.get_attr_u32(nfct.ATTR_EXP_TIMEOUT), 0x12345678)
        clone.destroy()
        exp.destroy()

    def test_cmp(self):
        exp1 = nfct.Expect()
        exp1.set_attr_u32(nfct.ATTR_EXP_TIMEOUT, 0x12345678)
        exp1.set_attr_u16(nfct.ATTR_EXP_ZONE, 0x4321)
        exp1.set_attr_u32(nfct.ATTR_EXP_FLAGS, 0x77777777)
        exp1.set_attr(nfct.ATTR_EXP_FN, ctypes.create_string_buffer(b"abcdefghijklmn"))

        exp2 = nfct.Expect()
        exp2.set_attr_u32(nfct.ATTR_EXP_TIMEOUT, 0x12345678)
        exp2.set_attr_u16(nfct.ATTR_EXP_ZONE, 0x4321)
        exp2.set_attr_u32(nfct.ATTR_EXP_FLAGS, 0x55555555)
        exp2.set_attr(nfct.ATTR_EXP_FN, ctypes.create_string_buffer(b"abcdefghijklmn"))
        self.assertEqual(exp1.cmp(exp2, nfct.NFCT_CMP_STRICT), 0)
        exp2.set_attr_u32(nfct.ATTR_EXP_FLAGS, 0x77777777)
        self.assertEqual(exp1.cmp(exp2, nfct.NFCT_CMP_STRICT), 1)

        # XXX: NFCT_CMP_MASK
        exp1.destroy()
        exp2.destroy()


    def test_attr(self):
        exp = nfct.Expect()
        exp.set_attr(nfct.ATTR_EXP_CLASS, ctypes.c_uint32(0x87654321))
        ret = exp.get_attr_as(nfct.ATTR_EXP_CLASS, ctypes.c_uint32)
        self.assertEqual(ret.value, 0x87654321)
        exp.set_attr(nfct.ATTR_EXP_HELPER_NAME, ctypes.create_string_buffer(b"attr_helper_nam"))
        ret = exp.get_attr(nfct.ATTR_EXP_HELPER_NAME)
        self.assertEqual(ctypes.cast(ret, ctypes.c_char_p).value, b"attr_helper_nam")

        try:
            exp.set_attr(nfct.ATTR_EXP_MAX, ctypes.c_int(1))
        except OSError as e:
            self.assertEquals(e.errno, errno.EINVAL)
        else:
            self.fail("no OSError raised")
        try:
            exp.get_attr(nfct.ATTR_EXP_MAX)
        except OSError as e:
            self.assertEquals(e.errno, errno.EINVAL)
        else:
            self.fail("no OSError raised")
        exp.destroy()


    def test_attr_u8(self):
        exp = nfct.Expect()
        exp.set_attr_u8(nfct.ATTR_EXP_NAT_DIR, 127)
        self.assertEqual(exp.get_attr_u8(nfct.ATTR_EXP_NAT_DIR), 127)
        try:
            exp.set_attr_u8(nfct.ATTR_EXP_MAX, 127)
        except OSError as e:
            self.assertEqual(e.errno, errno.EINVAL)
        else:
            self.fail("no OSError raised")
        try:
            exp.get_attr_u8(nfct.ATTR_EXP_MAX)
        except OSError as e:
            self.assertEqual(e.errno, errno.EINVAL)
        else:
            self.fail("no OSError raised")
        exp.destroy()


    def test_attr_u16(self):
        exp = nfct.Expect()
        exp.set_attr_u16(nfct.ATTR_EXP_ZONE, 0x3333)
        self.assertEqual(exp.get_attr_u16(nfct.ATTR_EXP_ZONE), 0x3333)
        try:
            exp.set_attr_u16(nfct.ATTR_EXP_MAX, 0x3333)
        except OSError as e:
            self.assertEqual(e.errno, errno.EINVAL)
        else:
            self.fail("no OSError raised")
        try:
            exp.get_attr_u16(nfct.ATTR_EXP_MAX)
        except OSError as e:
            self.assertEqual(e.errno, errno.EINVAL)
        else:
            self.fail("no OSError raised")
        exp.destroy()


    def test_attr_u32(self):
        exp = nfct.Expect()
        exp.set_attr_u32(nfct.ATTR_EXP_CLASS, 0x13135757)
        self.assertEqual(exp.get_attr_u32(nfct.ATTR_EXP_CLASS), 0x13135757)
        try:
            exp.set_attr_u32(nfct.ATTR_EXP_MAX, 0x13135757)
        except OSError as e:
            self.assertEqual(e.errno, errno.EINVAL)
        else:
            self.fail("no OSError raised")
        try:
            exp.get_attr_u32(nfct.ATTR_EXP_MAX)
        except OSError as e:
            self.assertEqual(e.errno, errno.EINVAL)
        else:
            self.fail("no OSError raised")
        exp.destroy()


    def test_attr_set(self):
        exp = nfct.Expect()
        exp.set_attr_u32(nfct.ATTR_EXP_TIMEOUT, 0x12345678)
        exp.set_attr_u16(nfct.ATTR_EXP_ZONE, 0x4321)
        self.assertTrue(exp.attr_is_set(nfct.ATTR_EXP_TIMEOUT))
        self.assertTrue(exp.attr_is_set(nfct.ATTR_EXP_ZONE))
        exp.attr_unset(nfct.ATTR_EXP_TIMEOUT)
        self.assertFalse(exp.attr_is_set(nfct.ATTR_EXP_TIMEOUT))
        self.assertTrue(exp.attr_is_set(nfct.ATTR_EXP_ZONE))

    # XXX: Expect.snprintf(self, s, m, o, f)
    # XXX: Expect.nlmsg_build(self, nlh)
    # XXX: Expect.nlmsg_parse(self, nlh)
