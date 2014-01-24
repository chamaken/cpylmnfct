# -*- coding: utf-8 -*-

from __future__ import absolute_import

from ctypes import *
import errno
from cpylmnl.linux import netlinkh as netlink

LIBNFCT = CDLL("libnetfilter_conntrack.so", use_errno=True)

### treat struct nf_conntrack, nfct_filter, nfct_filter_dump, nf_expect
### as opaque - c_void_p

## constructor / destructor
# struct nf_conntrack *nfct_new(void)
c_nfct_new = LIBNFCT.nfct_new
c_nfct_new.argtypes = None
c_nfct_new.restype = c_void_p

# void nfct_destroy(struct nf_conntrack *ct)
c_nfct_destroy = LIBNFCT.nfct_destroy
c_nfct_destroy.argtypes = [c_void_p]
c_nfct_destroy.restype = None

# int nfct_setobjopt(struct nf_conntrack *ct, unsigned int option)
c_nfct_setobjopt = LIBNFCT.nfct_setobjopt
c_nfct_setobjopt.argtypes = [c_void_p, c_uint]
c_nfct_setobjopt.restype = c_int

# int nfct_getobjopt(const struct nf_conntrack *ct, unsigned int option)
c_nfct_getobjopt = LIBNFCT.nfct_getobjopt
c_nfct_getobjopt.argtypes = [c_void_p, c_uint]
c_nfct_getobjopt.restype = c_int

# NO register / unregister callback
# NO register / unregister callback: extended version including netlink header

## clone
# struct nf_conntrack *nfct_clone(const struct nf_conntrack *ct)
c_nfct_clone = LIBNFCT.nfct_clone
c_nfct_clone.argtypes = [c_void_p]
c_nfct_clone.restype = c_void_p


## bitmask setter/getter
# struct nfct_bitmask *nfct_bitmask_new(unsigned int maxbit)
c_nfct_bitmask_new = LIBNFCT.nfct_bitmask_new
c_nfct_bitmask_new.argtypes = [c_uint]
c_nfct_bitmask_new.restype = c_void_p

# struct nfct_bitmask *nfct_bitmask_clone(const struct nfct_bitmask *)
c_nfct_bitmask_clone = LIBNFCT.nfct_bitmask_clone
c_nfct_bitmask_clone.argtypes = [c_void_p]
c_nfct_bitmask_clone.restype = c_void_p

# unsigned int nfct_bitmask_maxbit(const struct nfct_bitmask *)
c_nfct_bitmask_maxbit = LIBNFCT.nfct_bitmask_maxbit
c_nfct_bitmask_maxbit.argtypes = [c_void_p]
c_nfct_bitmask_maxbit.restype = c_uint

# void nfct_bitmask_set_bit(struct nfct_bitmask *, unsigned int bit)
c_nfct_bitmask_set_bit = LIBNFCT.nfct_bitmask_set_bit
c_nfct_bitmask_set_bit.argtype = [c_void_p, c_uint]
c_nfct_bitmask_set_bit.restype = None

# int nfct_bitmask_test_bit(const struct nfct_bitmask *, unsigned int bit)
c_nfct_bitmask_test_bit = LIBNFCT.nfct_bitmask_test_bit
c_nfct_bitmask_test_bit.argtype = [c_void_p, c_uint]
c_nfct_bitmask_test_bit.restype = c_int

# void nfct_bitmask_unset_bit(struct nfct_bitmask *, unsigned int bit)
c_nfct_bitmask_unset_bit = LIBNFCT.nfct_bitmask_unset_bit
c_nfct_bitmask_unset_bit.argtypes = [c_void_p, c_uint]
c_nfct_bitmask_unset_bit.restype = None

# void nfct_bitmask_destroy(struct nfct_bitmask *)
c_nfct_bitmask_destroy = LIBNFCT.nfct_bitmask_destroy
c_nfct_bitmask_destroy.argtypes = [c_void_p]
c_nfct_bitmask_destroy.restype = None


## connlabel name <-> bit translation mapping
# struct nfct_labelmap *nfct_labelmap_new(const char *mapfile)
c_nfct_labelmap_new = LIBNFCT.nfct_labelmap_new
c_nfct_labelmap_new.argtypes = [c_char_p]
c_nfct_labelmap_new.restype = c_void_p

# void nfct_labelmap_destroy(struct nfct_labelmap *map)
c_nfct_labelmap_destroy = LIBNFCT.nfct_labelmap_destroy
c_nfct_labelmap_destroy.argtypes = [c_void_p]
c_nfct_labelmap_destroy.restype = None

# const char *nfct_labelmap_get_name(struct nfct_labelmap *m, unsigned int bit)
c_nfct_labelmap_get_name = LIBNFCT.nfct_labelmap_get_name
c_nfct_labelmap_get_name.argtypes = [c_void_p, c_uint]
c_nfct_labelmap_get_name.restype = c_char_p

# int nfct_labelmap_get_bit(struct nfct_labelmap *m, const char *name)
c_nfct_labelmap_get_bit = LIBNFCT.nfct_labelmap_get_bit
c_nfct_labelmap_get_bit.argtypes = [c_void_p, c_char_p]
c_nfct_labelmap_get_bit.restype = c_int


## setter
# void nfct_set_attr(struct nf_conntrack *ct, const enum nf_conntrack_attr type, const void *value)
c_nfct_set_attr = LIBNFCT.nfct_set_attr
c_nfct_set_attr.argtypes = [c_void_p, c_int, c_void_p]
c_nfct_set_attr.restype = None

# void nfct_set_attr_u8(struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int8_t value)
c_nfct_set_attr_u8 = LIBNFCT.nfct_set_attr_u8
c_nfct_set_attr_u8.argtypes = [c_void_p, c_int, c_uint8]
c_nfct_set_attr_u8.restype = None

# void nfct_set_attr_u16(struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int16_t value)
c_nfct_set_attr_u16 = LIBNFCT.nfct_set_attr_u16
c_nfct_set_attr_u16.argtypes = [c_void_p, c_int, c_uint16]
c_nfct_set_attr_u16.restype = None

# void nfct_set_attr_u32(struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int32_t value)
c_nfct_set_attr_u32 = LIBNFCT.nfct_set_attr_u32
c_nfct_set_attr_u32.argtypes = [c_void_p, c_int, c_uint32]
c_nfct_set_attr_u32.restype = None

# void nfct_set_attr_u64(struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int64_t value)
c_nfct_set_attr_u64 = LIBNFCT.nfct_set_attr_u64
c_nfct_set_attr_u64.argtypes = [c_void_p, c_int, c_uint64]
c_nfct_set_attr_u64.restype = None

# void nfct_set_attr_l(struct nf_conntrack *ct, const enum nf_conntrack_attr type, const void *value, size_t len)
c_nfct_set_attr_l = LIBNFCT.nfct_set_attr_l
c_nfct_set_attr_l.argtypes = [c_void_p, c_int, c_void_p, c_size_t]
c_nfct_set_attr_l.restype = None


## getter
# const void *nfct_get_attr(const struct nf_conntrack *ct, const enum nf_conntrack_attr type)
c_nfct_get_attr = LIBNFCT.nfct_get_attr
c_nfct_get_attr.argtypes = [c_void_p, c_int]
c_nfct_get_attr.restype = c_void_p

# extern u_int8_t nfct_get_attr_u8(const struct nf_conntrack *ct, const enum nf_conntrack_attr type)
c_nfct_get_attr_u8 = LIBNFCT.nfct_get_attr_u8
c_nfct_get_attr_u8.argtypes = [c_void_p, c_int]
c_nfct_get_attr.restype = c_uint8

# u_int16_t nfct_get_attr_u16(const struct nf_conntrack *ct, const enum nf_conntrack_attr type)
c_nfct_get_attr_u16 = LIBNFCT.nfct_get_attr_u16
c_nfct_get_attr_u16.argtypes = [c_void_p, c_int]
c_nfct_get_attr.restype = c_uint16

# u_int32_t nfct_get_attr_u32(const struct nf_conntrack *ct, const enum nf_conntrack_attr type)
c_nfct_get_attr_u32 = LIBNFCT.nfct_get_attr_u32
c_nfct_get_attr_u32.argtypes = [c_void_p, c_int]
c_nfct_get_attr.restype = c_uint32

# u_int64_t nfct_get_attr_u64(const struct nf_conntrack *ct, const enum nf_conntrack_attr type)
c_nfct_get_attr_u64 = LIBNFCT.nfct_get_attr_u64
c_nfct_get_attr_u64.argtypes = [c_void_p, c_int]
c_nfct_get_attr.restype = c_uint64


## group setter
# void nfct_set_attr_grp(struct nf_conntrack *ct, const enum nf_conntrack_attr_grp type, const void *value)
c_nfct_set_attr_grp = LIBNFCT.nfct_set_attr_grp
c_nfct_set_attr_grp.argtypes = [c_void_p, c_int, c_void_p]
c_nfct_set_attr_grp.restype = None


## group getter
# extern int nfct_get_attr_grp(const struct nf_conntrack *ct, const enum nf_conntrack_attr_grp type, void *data)
c_nfct_get_attr_grp = LIBNFCT.nfct_get_attr_grp
c_nfct_get_attr_grp.argtypes = [c_void_p, c_int, c_void_p]
c_nfct_get_attr_grp.restype = c_int


## print
# int nfct_snprintf(char *buf, unsigned int size, const struct nf_conntrack *ct,
#		    const unsigned int msg_type, const unsigned int out_type, const unsigned int out_flags)
c_nfct_snprintf = LIBNFCT.nfct_snprintf
c_nfct_snprintf.argtypes = [c_char_p, c_uint, c_void_p, c_uint, c_uint, c_uint]
c_nfct_snprintf.restype = c_int

# int nfct_snprintf_labels(char *buf, unsigned int size, onst struct nf_conntrack *ct,
#			   const unsigned int msg_type, const unsigned int out_type, const unsigned int out_flags,
#			   struct nfct_labelmap *map)
c_nfct_snprintf_labels = LIBNFCT.nfct_snprintf_labels
c_nfct_snprintf_labels.argtypes = [c_char_p, c_uint, c_void_p, c_uint, c_uint, c_uint, c_void_p]
c_nfct_snprintf_labels.restype = c_int

## comparison
# int nfct_compare(const struct nf_conntrack *ct1, const struct nf_conntrack *ct2)
c_nfct_compare = LIBNFCT.nfct_compare
c_nfct_compare.argtypes = [c_void_p, c_void_p]
c_nfct_compare.restype = c_int

# int nfct_cmp(const struct nf_conntrack *ct1, const struct nf_conntrack *ct2, unsigned int flags)
c_nfct_cmp = LIBNFCT.nfct_cmp
c_nfct_cmp.argtypes = [c_void_p, c_void_p, c_uint]
c_nfct_cmp.restype = c_int

## copy
# void nfct_copy(struct nf_conntrack *dest, const struct nf_conntrack *source, unsigned int flags)
c_nfct_copy = LIBNFCT.nfct_copy
c_nfct_copy.argtypes = [c_void_p, c_void_p, c_uint]
c_nfct_copy.restype = None

# void nfct_copy_attr(struct nf_conntrack *ct1, const struct nf_conntrack *ct2, const enum nf_conntrack_attr type)
c_nfct_copy_attr = LIBNFCT.nfct_copy_attr
c_nfct_copy_attr.argtypes = [c_void_p, c_void_p, c_int]
c_nfct_copy_attr.restype = None


## event filtering
# struct nfct_filter *nfct_filter_create(void)
c_nfct_filter_create = LIBNFCT.nfct_filter_create
c_nfct_filter_create.argtypes = None
c_nfct_filter_create.restype = c_void_p

# void nfct_filter_destroy(struct nfct_filter *filter)
c_nfct_filter_destroy = LIBNFCT.nfct_filter_destroy
c_nfct_filter_destroy.argtypes = [c_void_p]
c_nfct_filter_destroy.restype = None

# void nfct_filter_add_attr(struct nfct_filter *filter, const enum nfct_filter_attr attr, const void *value)
c_nfct_filter_add_attr = LIBNFCT.nfct_filter_add_attr
c_nfct_filter_add_attr.argtypes = [c_void_p, c_int, c_void_p]
c_nfct_filter_add_attr.restype = None

# void nfct_filter_add_attr_u32(struct nfct_filter *filter, const enum nfct_filter_attr attr, const u_int32_t value)
c_nfct_filter_add_attr_u32 = LIBNFCT.nfct_filter_add_attr_u32
c_nfct_filter_add_attr_u32.argtypes = [c_void_p, c_int, c_uint32]
c_nfct_filter_add_attr_u32.restype = None

# int nfct_filter_set_logic(struct nfct_filter *filter, const enum nfct_filter_attr attr,
#                           const enum nfct_filter_logic logic);
c_nfct_filter_set_logic = LIBNFCT.nfct_filter_set_logic
c_nfct_filter_set_logic.argtypes = [c_void_p, c_int, c_int]
c_nfct_filter_set_logic.restype = c_int

# int nfct_filter_attach(int fd, struct nfct_filter *filter)
c_nfct_filter_attach = LIBNFCT.nfct_filter_attach
c_nfct_filter_attach.argtypes = [c_int, c_void_p]
c_nfct_filter_attach.restype = c_int

# int nfct_filter_detach(int fd)
c_nfct_filter_detach = LIBNFCT.nfct_filter_detach
c_nfct_filter_detach.argtypes = [c_int]
c_nfct_filter_detach.restype = c_int


## dump filtering
# struct nfct_filter_dump *nfct_filter_dump_create(void)
c_nfct_filter_dump_create = LIBNFCT.nfct_filter_dump_create
c_nfct_filter_dump_create.argtypes = None
c_nfct_filter_dump_create.restype = c_void_p

# void nfct_filter_dump_destroy(struct nfct_filter_dump *filter)
c_nfct_filter_dump_destroy = LIBNFCT.nfct_filter_dump_destroy
c_nfct_filter_dump_destroy.argtypes = [c_void_p]
c_nfct_filter_dump_destroy.restype = None

# void nfct_filter_dump_set_attr(struct nfct_filter_dump *filter_dump,
#			         const enum nfct_filter_dump_attr type,
#			         const void *data)
c_nfct_filter_dump_set_attr = LIBNFCT.nfct_filter_dump_set_attr
c_nfct_filter_dump_set_attr.argtypes = [c_void_p, c_int, c_void_p]
c_nfct_filter_dump_set_attr.restype = None

# void nfct_filter_dump_set_attr_u8(struct nfct_filter_dump *filter_dump,
#				    const enum nfct_filter_dump_attr type,
#				    u_int8_t data)
c_nfct_filter_dump_set_attr_u8 = LIBNFCT.nfct_filter_dump_set_attr_u8
c_nfct_filter_dump_set_attr_u8.argtypes = [c_void_p, c_int, c_uint8]
c_nfct_filter_dump_set_attr_u8.restype = None


## NO low level API: netlink functions

## New low level API: netlink functions
# int nfct_nlmsg_build(struct nlmsghdr *nlh, const struct nf_conntrack *ct)
c_nfct_nlmsg_build = LIBNFCT.nfct_nlmsg_build
c_nfct_nlmsg_build.argtypes = [POINTER(netlink.Nlmsghdr), c_void_p]
c_nfct_nlmsg_build.restype = c_int

# int nfct_nlmsg_parse(const struct nlmsghdr *nlh, struct nf_conntrack *ct)
c_nfct_nlmsg_parse = LIBNFCT.nfct_nlmsg_parse
c_nfct_nlmsg_parse.argtypes = [POINTER(netlink.Nlmsghdr), c_void_p]
c_nfct_nlmsg_parse.restype = c_int

# int nfct_payload_parse(const void *payload, size_t payload_len, uint16_t l3num, struct nf_conntrack *ct)
c_nfct_payload_parse = LIBNFCT.nfct_payload_parse
c_nfct_payload_parse.argtypes = [c_void_p, c_size_t, c_uint16, c_void_p]
c_nfct_payload_parse.restype = c_int


## NEW expectation API
## constructor / destructor */
# struct nf_expect *nfexp_new(void);
c_nfexp_new = LIBNFCT.nfexp_new
c_nfexp_new.argtypes = None
c_nfexp_new.restype = c_void_p

# void nfexp_destroy(struct nf_expect *exp)
c_nfexp_destroy = LIBNFCT.nfexp_destroy
c_nfexp_destroy.argtypes = [c_void_p]
c_nfexp_destroy.restype = None

## clone
# struct nf_expect *nfexp_clone(const struct nf_expect *exp)
c_nfexp_clone = LIBNFCT.nfexp_clone
c_nfexp_clone.argtypes = [c_void_p]
c_nfexp_clone.restype = c_void_p

## NO object size
## NO maximum object size
## NO register / unregister callback
## NO register / unregister callback: extended version including netlink header

## setter
# void nfexp_set_attr(struct nf_expect *exp, const enum nf_expect_attr type, const void *value)
c_nfexp_set_attr = LIBNFCT.nfexp_set_attr
c_nfexp_set_attr.argtypes = [c_void_p, c_int, c_void_p]
c_nfexp_argtype = None

# void nfexp_set_attr_u8(struct nf_expect *exp, const enum nf_expect_attr type, u_int8_t value)
c_nfexp_set_attr_u8 = LIBNFCT.nfexp_set_attr_u8
c_nfexp_set_attr_u8.argtypes = [c_void_p, c_int, c_uint8]
c_nfexp_set_attr_u8.restype = None

# void nfexp_set_attr_u16(struct nf_expect *exp, const enum nf_expect_attr type, u_int16_t value)
c_nfexp_set_attr_u16 = LIBNFCT.nfexp_set_attr_u16
c_nfexp_set_attr_u16.argtypes = [c_void_p, c_int, c_uint16]
c_nfexp_set_attr_u16.restype = None

# void nfexp_set_attr_u32(struct nf_expect *exp, const enum nf_expect_attr type, u_int32_t value)
c_nfexp_set_attr_u32 = LIBNFCT.nfexp_set_attr_u32
c_nfexp_set_attr_u32.argtypes = [c_void_p, c_int, c_uint32]
c_nfexp_set_attr_u32.restype = None

## getter
# const void *nfexp_get_attr(const struct nf_expect *exp, const enum nf_expect_attr type)
c_nfexp_get_attr = LIBNFCT.nfexp_get_attr
c_nfexp_get_attr.argtypes = [c_void_p, c_int]
c_nfexp_get_attr.restype = c_void_p

# u_int8_t nfexp_get_attr_u8(const struct nf_expect *exp, const enum nf_expect_attr type)
c_nfexp_get_attr_u8 = LIBNFCT.nfexp_get_attr_u8
c_nfexp_get_attr_u8.argtypes = [c_void_p, c_int]
c_nfexp_get_attr_u8.restype = c_uint8

# u_int16_t nfexp_get_attr_u16(const struct nf_expect *exp, const enum nf_expect_attr type)
c_nfexp_get_attr_u16 = LIBNFCT.nfexp_get_attr_u16
c_nfexp_get_attr_u16.argtypes = [c_void_p, c_int]
c_nfexp_get_attr_u16.restype = c_uint16

# u_int32_t nfexp_get_attr_u32(const struct nf_expect *exp, const enum nf_expect_attr type)
c_nfexp_get_attr_u32 = LIBNFCT.nfexp_get_attr_u32
c_nfexp_get_attr_u32.argtypes = [c_void_p, c_int]
c_nfexp_get_attr_u32.restype = c_uint32

## checker
# int nfexp_attr_is_set(const struct nf_expect *exp, const enum nf_expect_attr type)
c_nfexp_attr_is_set = LIBNFCT.nfexp_attr_is_set
c_nfexp_attr_is_set.argtypes = [c_void_p, c_int]
c_nfexp_attr_is_set.restype = c_int

## unsetter
# int nfexp_attr_unset(struct nf_expect *exp, const enum nf_expect_attr type)
c_nfexp_attr_unset = LIBNFCT.nfexp_attr_unset
c_nfexp_attr_unset.argtypes = [c_void_p, c_int]
c_nfexp_attr_unset.restype = c_int

## NO query

## print
# int nfexp_snprintf(char *buf, unsigned int size, const struct nf_expect *exp, const unsigned int msg_type,
# 		     const unsigned int out_type, const unsigned int out_flags)
c_nfexp_snprintf = LIBNFCT.nfexp_snprintf
c_nfexp_snprintf.argtypes = [c_char_p, c_uint, c_void_p, c_uint, c_uint, c_uint]
c_nfexp_snprintf.restype = c_int

## compare
# int nfexp_cmp(const struct nf_expect *exp1, const struct nf_expect *exp2, unsigned int flags)
c_nfexp_cmp = LIBNFCT.nfexp_cmp
c_nfexp_cmp.argtypes = [c_void_p, c_void_p]
c_nfexp_cmp.restype = c_int

## NO low level API

## New low level API: netlink functions
# int nfexp_nlmsg_build(struct nlmsghdr *nlh, const struct nf_expect *exp)
c_nfexp_nlmsg_build = LIBNFCT.nfexp_nlmsg_build
c_nfexp_nlmsg_build.argtypes = [POINTER(netlink.Nlmsghdr), c_void_p]
c_nfexp_nlmsg_build.restype = c_int

# int nfexp_nlmsg_parse(const struct nlmsghdr *nlh, struct nf_expect *exp)
c_nfexp_nlmsg_parse = LIBNFCT.nfexp_nlmsg_parse
c_nfexp_nlmsg_parse.argtypes = [POINTER(netlink.Nlmsghdr), c_void_p]
c_nfexp_nlmsg_parse.restype = c_int

## cpylmnl.linux.netfilter.nf_conntrack_commonh
# enum ip_conntrack_status 
# NF_CT_EXPECT_...

## cpylmnl.cpylmnl.linux.netfilter.nf_conntrack_tcph
# IP_CT_TCP_FLAG...


def c_raise_if_errno():
    en = get_errno()
    if en != 0:
        raise OSError(en, errno.errorcode[en])


def os_error():
    en = get_errno()
    return OSError(en, errno.errorcode[en])
