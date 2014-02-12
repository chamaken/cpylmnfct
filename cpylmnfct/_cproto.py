# -*- coding: utf-8 -*-

from __future__ import absolute_import

import ctypes, errno
from cpylmnl.linux import netlinkh as netlink

LIBNFCT = ctypes.CDLL("libnetfilter_conntrack.so", use_errno=True)

### treat struct nf_conntrack, nfct_filter, nfct_filter_dump, nf_expect
### as opaque - ctypes.c_void_p

## constructor / destructor
c_nfct_new = LIBNFCT.nfct_new
c_nfct_new.__doc__ = """\
struct nf_conntrack *nfct_new(void)"""
c_nfct_new.argtypes = None
c_nfct_new.restype = ctypes.c_void_p

c_nfct_destroy = LIBNFCT.nfct_destroy
c_nfct_destroy.__doc__ = """\
void nfct_destroy(struct nf_conntrack *ct)"""
c_nfct_destroy.argtypes = [ctypes.c_void_p]
c_nfct_destroy.restype = None

c_nfct_setobjopt = LIBNFCT.nfct_setobjopt
c_nfct_setobjopt.__doc__ = """\
int nfct_setobjopt(struct nf_conntrack *ct, unsigned int option)"""
c_nfct_setobjopt.argtypes = [ctypes.c_void_p, ctypes.c_uint]
c_nfct_setobjopt.restype = ctypes.c_int

c_nfct_getobjopt = LIBNFCT.nfct_getobjopt
c_nfct_getobjopt.__doc__ = """\
int nfct_getobjopt(const struct nf_conntrack *ct, unsigned int option)"""
c_nfct_getobjopt.argtypes = [ctypes.c_void_p, ctypes.c_uint]
c_nfct_getobjopt.restype = ctypes.c_int

# NO register / unregister callback
# NO register / unregister callback: extended version including netlink header

## clone
c_nfct_clone = LIBNFCT.nfct_clone
c_nfct_clone.__doc__ = """\
struct nf_conntrack *nfct_clone(const struct nf_conntrack *ct)"""
c_nfct_clone.argtypes = [ctypes.c_void_p]
c_nfct_clone.restype = ctypes.c_void_p


## bitmask setter/getter
c_nfct_bitmask_new = LIBNFCT.nfct_bitmask_new
c_nfct_bitmask_new.__doc__ = """\
struct nfct_bitmask *nfct_bitmask_new(unsigned int maxbit)"""
c_nfct_bitmask_new.argtypes = [ctypes.c_uint]
c_nfct_bitmask_new.restype = ctypes.c_void_p

c_nfct_bitmask_clone = LIBNFCT.nfct_bitmask_clone
c_nfct_bitmask_clone.__doc__ = """\
struct nfct_bitmask *nfct_bitmask_clone(const struct nfct_bitmask *)"""
c_nfct_bitmask_clone.argtypes = [ctypes.c_void_p]
c_nfct_bitmask_clone.restype = ctypes.c_void_p

c_nfct_bitmask_maxbit = LIBNFCT.nfct_bitmask_maxbit
c_nfct_bitmask_maxbit.__doc__ = """\
unsigned int nfct_bitmask_maxbit(const struct nfct_bitmask *)"""
c_nfct_bitmask_maxbit.argtypes = [ctypes.c_void_p]
c_nfct_bitmask_maxbit.restype = ctypes.c_uint

c_nfct_bitmask_set_bit = LIBNFCT.nfct_bitmask_set_bit
c_nfct_bitmask_set_bit.__doc__ = """\
void nfct_bitmask_set_bit(struct nfct_bitmask *, unsigned int bit)"""
c_nfct_bitmask_set_bit.argtype = [ctypes.c_void_p, ctypes.c_uint]
c_nfct_bitmask_set_bit.restype = None

c_nfct_bitmask_test_bit = LIBNFCT.nfct_bitmask_test_bit
c_nfct_bitmask_test_bit.__doc__ = """\
int nfct_bitmask_test_bit(const struct nfct_bitmask *, unsigned int bit)"""
c_nfct_bitmask_test_bit.argtype = [ctypes.c_void_p, ctypes.c_uint]
c_nfct_bitmask_test_bit.restype = ctypes.c_int

c_nfct_bitmask_unset_bit = LIBNFCT.nfct_bitmask_unset_bit
c_nfct_bitmask_unset_bit.__doc__ = """\
void nfct_bitmask_unset_bit(struct nfct_bitmask *, unsigned int bit)"""
c_nfct_bitmask_unset_bit.argtypes = [ctypes.c_void_p, ctypes.c_uint]
c_nfct_bitmask_unset_bit.restype = None

c_nfct_bitmask_destroy = LIBNFCT.nfct_bitmask_destroy
c_nfct_bitmask_destroy.__doc__ = """\
void nfct_bitmask_destroy(struct nfct_bitmask *)"""
c_nfct_bitmask_destroy.argtypes = [ctypes.c_void_p]
c_nfct_bitmask_destroy.restype = None


## connlabel name <-> bit translation mapping
c_nfct_labelmap_new = LIBNFCT.nfct_labelmap_new
c_nfct_labelmap_new.__doc__ = """\
struct nfct_labelmap *nfct_labelmap_new(const char *mapfile)"""
c_nfct_labelmap_new.argtypes = [ctypes.c_char_p]
c_nfct_labelmap_new.restype = ctypes.c_void_p

c_nfct_labelmap_destroy = LIBNFCT.nfct_labelmap_destroy
c_nfct_labelmap_destroy.__doc__ = """\
void nfct_labelmap_destroy(struct nfct_labelmap *map)"""
c_nfct_labelmap_destroy.argtypes = [ctypes.c_void_p]
c_nfct_labelmap_destroy.restype = None

c_nfct_labelmap_get_name = LIBNFCT.nfct_labelmap_get_name
c_nfct_labelmap_get_name.__doc__ = """\
const char *nfct_labelmap_get_name(struct nfct_labelmap *m, unsigned int bit)"""
c_nfct_labelmap_get_name.argtypes = [ctypes.c_void_p, ctypes.c_uint]
c_nfct_labelmap_get_name.restype = ctypes.c_char_p

c_nfct_labelmap_get_bit = LIBNFCT.nfct_labelmap_get_bit
c_nfct_labelmap_get_bit.__doc__ = """\
int nfct_labelmap_get_bit(struct nfct_labelmap *m, const char *name)"""
c_nfct_labelmap_get_bit.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
c_nfct_labelmap_get_bit.restype = ctypes.c_int


## setter
# void nfct_set_attr(struct nf_conntrack *ct, const enum nf_conntrack_attr type, const void *value)
c_nfct_set_attr = LIBNFCT.nfct_set_attr
c_nfct_set_attr.__doc__ = """\
void nfct_set_attr(struct nf_conntrack *ct, const enum nf_conntrack_attr type, const void *value)"""
c_nfct_set_attr.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
c_nfct_set_attr.restype = None

c_nfct_set_attr_u8 = LIBNFCT.nfct_set_attr_u8
c_nfct_set_attr_u8.__doc__ = """\
void nfct_set_attr_u8(struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int8_t value)"""
c_nfct_set_attr_u8.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint8]
c_nfct_set_attr_u8.restype = None

c_nfct_set_attr_u16 = LIBNFCT.nfct_set_attr_u16
c_nfct_set_attr_u16.__doc__ = """\
void nfct_set_attr_u16(struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int16_t value)"""
c_nfct_set_attr_u16.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint16]
c_nfct_set_attr_u16.restype = None

c_nfct_set_attr_u32 = LIBNFCT.nfct_set_attr_u32
c_nfct_set_attr_u32.__doc__ = """\
void nfct_set_attr_u32(struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int32_t value)"""
c_nfct_set_attr_u32.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
c_nfct_set_attr_u32.restype = None

c_nfct_set_attr_u64 = LIBNFCT.nfct_set_attr_u64
c_nfct_set_attr_u64.__doc__ = """\
void nfct_set_attr_u64(struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int64_t value)"""
c_nfct_set_attr_u64.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint64]
c_nfct_set_attr_u64.restype = None


c_nfct_set_attr_l = LIBNFCT.nfct_set_attr_l
c_nfct_set_attr_l.__doc__ = """\
void nfct_set_attr_l(struct nf_conntrack *ct, const enum nf_conntrack_attr type, const void *value, size_t len)"""
c_nfct_set_attr_l.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
c_nfct_set_attr_l.restype = None


## getter
c_nfct_get_attr = LIBNFCT.nfct_get_attr
c_nfct_get_attr.__doc__ = """\
const void *nfct_get_attr(const struct nf_conntrack *ct, const enum nf_conntrack_attr type)"""
c_nfct_get_attr.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfct_get_attr.restype = ctypes.c_void_p

c_nfct_get_attr_u8 = LIBNFCT.nfct_get_attr_u8
c_nfct_get_attr_u8.__doc__ = """\
u_int8_t nfct_get_attr_u8(const struct nf_conntrack *ct, const enum nf_conntrack_attr type)"""
c_nfct_get_attr_u8.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfct_get_attr_u8.restype = ctypes.c_uint8

c_nfct_get_attr_u16 = LIBNFCT.nfct_get_attr_u16
c_nfct_get_attr_u16.__doc__ = """\
u_int16_t nfct_get_attr_u16(const struct nf_conntrack *ct, const enum nf_conntrack_attr type)"""
c_nfct_get_attr_u16.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfct_get_attr_u16.restype = ctypes.c_uint16

c_nfct_get_attr_u32 = LIBNFCT.nfct_get_attr_u32
c_nfct_get_attr_u32.__doc__ = """\
u_int32_t nfct_get_attr_u32(const struct nf_conntrack *ct, const enum nf_conntrack_attr type)"""
c_nfct_get_attr_u32.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfct_get_attr_u32.restype = ctypes.c_uint32

c_nfct_get_attr_u64 = LIBNFCT.nfct_get_attr_u64
c_nfct_get_attr_u64.__doc__ = """\
u_int64_t nfct_get_attr_u64(const struct nf_conntrack *ct, const enum nf_conntrack_attr type)"""
c_nfct_get_attr_u64.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfct_get_attr_u64.restype = ctypes.c_uint64

## checker
c_nfct_attr_is_set = LIBNFCT.nfct_attr_is_set
c_nfct_attr_is_set.__doc__ = """\
int nfct_attr_is_set(const struct nf_conntrack *ct, const enum nf_conntrack_attr type)"""
c_nfct_attr_is_set.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfct_attr_is_set.restype = ctypes.c_int

c_nfct_attr_is_set_array = LIBNFCT.nfct_attr_is_set_array
c_nfct_attr_is_set_array.__doc__ = """\
int nfct_attr_is_set_array(const struct nf_conntrack *ct, const enum nf_conntrack_attr *type_array, int size)"""
c_nfct_attr_is_set_array.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
c_nfct_attr_is_set_array.restype = ctypes.c_int

## unsetter
c_nfct_attr_unset = LIBNFCT.nfct_attr_unset
c_nfct_attr_unset.__doc__ = """\
int nfct_attr_unset(struct nf_conntrack *ct, const enum nf_conntrack_attr type)"""
c_nfct_attr_unset.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfct_attr_unset.restype = ctypes.c_int

## group setter
c_nfct_set_attr_grp = LIBNFCT.nfct_set_attr_grp
c_nfct_set_attr_grp.__doc__ = """\
void nfct_set_attr_grp(struct nf_conntrack *ct, const enum nf_conntrack_attr_grp type, const void *value)"""
c_nfct_set_attr_grp.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
c_nfct_set_attr_grp.restype = None


## group getter
c_nfct_get_attr_grp = LIBNFCT.nfct_get_attr_grp
c_nfct_get_attr_grp.__doc__ = """\
int nfct_get_attr_grp(const struct nf_conntrack *ct, const enum nf_conntrack_attr_grp type, void *data)"""
c_nfct_get_attr_grp.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
c_nfct_get_attr_grp.restype = ctypes.c_int

## group checker
c_nfct_attr_grp_is_set = LIBNFCT.nfct_attr_grp_is_set
c_nfct_attr_grp_is_set.__doc__ = """\
int nfct_attr_grp_is_set(const struct nf_conntrack *ct, const enum nf_conntrack_attr_grp type)"""
c_nfct_attr_grp_is_set.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfct_attr_grp_is_set.restype = ctypes.c_int

## unsetter
c_nfct_attr_grp_unset = LIBNFCT.nfct_attr_grp_unset
c_nfct_attr_grp_unset.__doc__ = """\
int nfct_attr_grp_unset(struct nf_conntrack *ct, const enum nf_conntrack_attr_grp type)"""
c_nfct_attr_grp_unset.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfct_attr_grp_unset.restype = ctypes.c_int


## print
c_nfct_snprintf = LIBNFCT.nfct_snprintf
c_nfct_snprintf.__doc__ = """\
int nfct_snprintf(char *buf, unsigned int size, const struct nf_conntrack *ct,
                  const unsigned int msg_type, const unsigned int out_type, const unsigned int out_flags)"""
c_nfct_snprintf.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
c_nfct_snprintf.restype = ctypes.c_int

c_nfct_snprintf_labels = LIBNFCT.nfct_snprintf_labels
c_nfct_snprintf_labels.__doc__ = """\
int nfct_snprintf_labels(char *buf, unsigned int size, onst struct nf_conntrack *ct,
                         const unsigned int msg_type, const unsigned int out_type, const unsigned int out_flags,
                         struct nfct_labelmap *map)"""
c_nfct_snprintf_labels.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
c_nfct_snprintf_labels.restype = ctypes.c_int

## comparison
# NO int nfct_compare(const struct nf_conntrack *ct1, const struct nf_conntrack *ct2)

c_nfct_cmp = LIBNFCT.nfct_cmp
c_nfct_cmp.__doc__ = """\
int nfct_cmp(const struct nf_conntrack *ct1, const struct nf_conntrack *ct2, unsigned int flags)"""
c_nfct_cmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
c_nfct_cmp.restype = ctypes.c_int

## copy
c_nfct_copy = LIBNFCT.nfct_copy
c_nfct_copy.__doc__ = """\
void nfct_copy(struct nf_conntrack *dest, const struct nf_conntrack *source, unsigned int flags)"""
c_nfct_copy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
c_nfct_copy.restype = None

c_nfct_copy_attr = LIBNFCT.nfct_copy_attr
c_nfct_copy_attr.__doc__ = """\
void nfct_copy_attr(struct nf_conntrack *ct1, const struct nf_conntrack *ct2, const enum nf_conntrack_attr type)"""
c_nfct_copy_attr.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
c_nfct_copy_attr.restype = None


## event filtering
c_nfct_filter_create = LIBNFCT.nfct_filter_create
c_nfct_filter_create.__doc__ = """\
struct nfct_filter *nfct_filter_create(void)"""
c_nfct_filter_create.argtypes = None
c_nfct_filter_create.restype = ctypes.c_void_p

c_nfct_filter_destroy = LIBNFCT.nfct_filter_destroy
c_nfct_filter_destroy.__doc__ = """\
void nfct_filter_destroy(struct nfct_filter *filter)"""
c_nfct_filter_destroy.argtypes = [ctypes.c_void_p]
c_nfct_filter_destroy.restype = None

c_nfct_filter_add_attr = LIBNFCT.nfct_filter_add_attr
c_nfct_filter_add_attr.__doc__ = """\
void nfct_filter_add_attr(struct nfct_filter *filter, const enum nfct_filter_attr attr, const void *value)"""
c_nfct_filter_add_attr.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
c_nfct_filter_add_attr.restype = None

c_nfct_filter_add_attr_u32 = LIBNFCT.nfct_filter_add_attr_u32
c_nfct_filter_add_attr_u32.__doc__ = """\
void nfct_filter_add_attr_u32(struct nfct_filter *filter, const enum nfct_filter_attr attr, const u_int32_t value)"""
c_nfct_filter_add_attr_u32.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
c_nfct_filter_add_attr_u32.restype = None

c_nfct_filter_set_logic = LIBNFCT.nfct_filter_set_logic
c_nfct_filter_set_logic.__doc__ = """\
int nfct_filter_set_logic(struct nfct_filter *filter, const enum nfct_filter_attr attr,
                          const enum nfct_filter_logic logic)"""
c_nfct_filter_set_logic.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
c_nfct_filter_set_logic.restype = ctypes.c_int

c_nfct_filter_attach = LIBNFCT.nfct_filter_attach
c_nfct_filter_attach.__doc__ = """\
int nfct_filter_attach(int fd, struct nfct_filter *filter)"""
c_nfct_filter_attach.argtypes = [ctypes.c_int, ctypes.c_void_p]
c_nfct_filter_attach.restype = ctypes.c_int

c_nfct_filter_detach = LIBNFCT.nfct_filter_detach
c_nfct_filter_detach.__doc__ = """\
int nfct_filter_detach(int fd)"""
c_nfct_filter_detach.argtypes = [ctypes.c_int]
c_nfct_filter_detach.restype = ctypes.c_int


## dump filtering
c_nfct_filter_dump_create = LIBNFCT.nfct_filter_dump_create
c_nfct_filter_dump_create.__doc__ = """\
struct nfct_filter_dump *nfct_filter_dump_create(void)"""
c_nfct_filter_dump_create.argtypes = None
c_nfct_filter_dump_create.restype = ctypes.c_void_p

c_nfct_filter_dump_destroy = LIBNFCT.nfct_filter_dump_destroy
c_nfct_filter_dump_destroy.__doc__ = """\
void nfct_filter_dump_destroy(struct nfct_filter_dump *filter)"""
c_nfct_filter_dump_destroy.argtypes = [ctypes.c_void_p]
c_nfct_filter_dump_destroy.restype = None

c_nfct_filter_dump_set_attr = LIBNFCT.nfct_filter_dump_set_attr
c_nfct_filter_dump_set_attr.__doc__ = """\
void nfct_filter_dump_set_attr(struct nfct_filter_dump *filter_dump,
                               const enum nfct_filter_dump_attr type,
                               const void *data)"""
c_nfct_filter_dump_set_attr.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
c_nfct_filter_dump_set_attr.restype = None

c_nfct_filter_dump_set_attr_u8 = LIBNFCT.nfct_filter_dump_set_attr_u8
c_nfct_filter_dump_set_attr_u8.__doc__ = """\
void nfct_filter_dump_set_attr_u8(struct nfct_filter_dump *filter_dump,
                                  const enum nfct_filter_dump_attr type,
                                  u_int8_t data)"""
c_nfct_filter_dump_set_attr_u8.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint8]
c_nfct_filter_dump_set_attr_u8.restype = None


## NO low level API: netlink functions

## New low level API: netlink functions
c_nfct_nlmsg_build = LIBNFCT.nfct_nlmsg_build
c_nfct_nlmsg_build.__doc__ = """\ 
int nfct_nlmsg_build(struct nlmsghdr *nlh, const struct nf_conntrack *ct)"""
c_nfct_nlmsg_build.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_void_p]
c_nfct_nlmsg_build.restype = ctypes.c_int

c_nfct_nlmsg_parse = LIBNFCT.nfct_nlmsg_parse
c_nfct_nlmsg_parse.__doc__ = """\
int nfct_nlmsg_parse(const struct nlmsghdr *nlh, struct nf_conntrack *ct)"""
c_nfct_nlmsg_parse.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_void_p]
c_nfct_nlmsg_parse.restype = ctypes.c_int

c_nfct_payload_parse = LIBNFCT.nfct_payload_parse
c_nfct_payload_parse.__doc__ = """\
int nfct_payload_parse(const void *payload, size_t payload_len, uint16_t l3num, struct nf_conntrack *ct)"""
c_nfct_payload_parse.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint16, ctypes.c_void_p]
c_nfct_payload_parse.restype = ctypes.c_int


## NEW expectation API
## constructor / destructor */
c_nfexp_new = LIBNFCT.nfexp_new
c_nfexp_new.__doc__ = """\
struct nf_expect *nfexp_new(void)"""
c_nfexp_new.argtypes = None
c_nfexp_new.restype = ctypes.c_void_p

c_nfexp_destroy = LIBNFCT.nfexp_destroy
c_nfexp_destroy.__doc__ = """\
void nfexp_destroy(struct nf_expect *exp)"""
c_nfexp_destroy.argtypes = [ctypes.c_void_p]
c_nfexp_destroy.restype = None

## clone
c_nfexp_clone = LIBNFCT.nfexp_clone
c_nfexp_clone.__doc__ = """\
struct nf_expect *nfexp_clone(const struct nf_expect *exp)"""
c_nfexp_clone.argtypes = [ctypes.c_void_p]
c_nfexp_clone.restype = ctypes.c_void_p

## NO object size
## NO maximum object size
## NO register / unregister callback
## NO register / unregister callback: extended version including netlink header

## setter
c_nfexp_set_attr = LIBNFCT.nfexp_set_attr
c_nfexp_set_attr.__doc__ = """\
void nfexp_set_attr(struct nf_expect *exp, const enum nf_expect_attr type, const void *value)"""
c_nfexp_set_attr.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
c_nfexp_argtype = None

c_nfexp_set_attr_u8 = LIBNFCT.nfexp_set_attr_u8
c_nfexp_set_attr_u8.__doc__ = """\
void nfexp_set_attr_u8(struct nf_expect *exp, const enum nf_expect_attr type, u_int8_t value)"""
c_nfexp_set_attr_u8.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint8]
c_nfexp_set_attr_u8.restype = None

c_nfexp_set_attr_u16 = LIBNFCT.nfexp_set_attr_u16
c_nfexp_set_attr_u16.__doc__ = """\
void nfexp_set_attr_u16(struct nf_expect *exp, const enum nf_expect_attr type, u_int16_t value)"""
c_nfexp_set_attr_u16.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint16]
c_nfexp_set_attr_u16.restype = None

c_nfexp_set_attr_u32 = LIBNFCT.nfexp_set_attr_u32
c_nfexp_set_attr_u32.__doc__ = """\
void nfexp_set_attr_u32(struct nf_expect *exp, const enum nf_expect_attr type, u_int32_t value)"""
c_nfexp_set_attr_u32.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
c_nfexp_set_attr_u32.restype = None

## getter
c_nfexp_get_attr = LIBNFCT.nfexp_get_attr
c_nfexp_get_attr.__doc__ = """\
const void *nfexp_get_attr(const struct nf_expect *exp, const enum nf_expect_attr type)"""
c_nfexp_get_attr.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfexp_get_attr.restype = ctypes.c_void_p

c_nfexp_get_attr_u8 = LIBNFCT.nfexp_get_attr_u8
c_nfexp_get_attr_u8.__doc__ = """\
u_int8_t nfexp_get_attr_u8(const struct nf_expect *exp, const enum nf_expect_attr type)"""
c_nfexp_get_attr_u8.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfexp_get_attr_u8.restype = ctypes.c_uint8

c_nfexp_get_attr_u16 = LIBNFCT.nfexp_get_attr_u16
c_nfexp_get_attr_u16.__doc__ = """\
u_int16_t nfexp_get_attr_u16(const struct nf_expect *exp, const enum nf_expect_attr type)"""
c_nfexp_get_attr_u16.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfexp_get_attr_u16.restype = ctypes.c_uint16

c_nfexp_get_attr_u32 = LIBNFCT.nfexp_get_attr_u32
c_nfexp_get_attr_u32.__doc__ = """\
u_int32_t nfexp_get_attr_u32(const struct nf_expect *exp, const enum nf_expect_attr type)"""
c_nfexp_get_attr_u32.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfexp_get_attr_u32.restype = ctypes.c_uint32

## checker
c_nfexp_attr_is_set = LIBNFCT.nfexp_attr_is_set
c_nfexp_attr_is_set.__doc__ = """\
int nfexp_attr_is_set(const struct nf_expect *exp, const enum nf_expect_attr type)"""
c_nfexp_attr_is_set.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfexp_attr_is_set.restype = ctypes.c_int

## unsetter
c_nfexp_attr_unset = LIBNFCT.nfexp_attr_unset
c_nfexp_attr_unset.__doc__ = """\
int nfexp_attr_unset(struct nf_expect *exp, const enum nf_expect_attr type)"""
c_nfexp_attr_unset.argtypes = [ctypes.c_void_p, ctypes.c_int]
c_nfexp_attr_unset.restype = ctypes.c_int

## NO query

## print
c_nfexp_snprintf = LIBNFCT.nfexp_snprintf
c_nfexp_snprintf.__doc__ = """\
int nfexp_snprintf(char *buf, unsigned int size, const struct nf_expect *exp, const unsigned int msg_type,
                   const unsigned int out_type, const unsigned int out_flags)"""
c_nfexp_snprintf.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
c_nfexp_snprintf.restype = ctypes.c_int

## compare
c_nfexp_cmp = LIBNFCT.nfexp_cmp
c_nfexp_cmp.__doc__ = """\
int nfexp_cmp(const struct nf_expect *exp1, const struct nf_expect *exp2, unsigned int flags)"""
c_nfexp_cmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
c_nfexp_cmp.restype = ctypes.c_int

## NO low level API

## New low level API: netlink functions
c_nfexp_nlmsg_build = LIBNFCT.nfexp_nlmsg_build
c_nfexp_nlmsg_build.__doc__ = """\
int nfexp_nlmsg_build(struct nlmsghdr *nlh, const struct nf_expect *exp)"""
c_nfexp_nlmsg_build.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_void_p]
c_nfexp_nlmsg_build.restype = ctypes.c_int

c_nfexp_nlmsg_parse = LIBNFCT.nfexp_nlmsg_parse
c_nfexp_nlmsg_parse.__doc__ = """\
int nfexp_nlmsg_parse(const struct nlmsghdr *nlh, struct nf_expect *exp)"""
c_nfexp_nlmsg_parse.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_void_p]
c_nfexp_nlmsg_parse.restype = ctypes.c_int

## cpylmnl.linux.netfilter.nf_conntrack_commonh
# enum ip_conntrack_status
# NF_CT_EXPECT_...

## cpylmnl.cpylmnl.linux.netfilter.nf_conntrack_tcph
# IP_CT_TCP_FLAG...


def c_raise_if_errno():
    """raise OSError is C errno != 0"""
    en = ctypes.get_errno()
    if en != 0:
        raise OSError(en, errno.errorcode[en])


def os_error():
    """create OSError from C errno. And clear C errno"""
    en = ctypes.get_errno()
    ctypes.set_errno(0)
    if en == 0:
        return OSError(en, "(no errno found)")
    else:
        return OSError(en, errno.errorcode[en])
