# -*- coding: utf-8 -*-

import ctypes
from cpylmnl.linux.netfilter import nfnetlinkh as nfnl
from cpylmnl.linux.netfilter import nfnetlink_compath as nfnlcm
try:
    from enum import Enum
except ImportError:
    Enum = object


# enum
CONNTRACK = nfnl.NFNL_SUBSYS_CTNETLINK
EXPECT = nfnl.NFNL_SUBSYS_CTNETLINK_EXP

# Subscribe to all possible conntrack event groups. Use this
# flag in case that you want to catch up all the possible
# events. Do not use this flag for dumping or any other
# similar operation.
NFCT_ALL_CT_GROUPS = (nfnlcm.NF_NETLINK_CONNTRACK_NEW
                      |nfnlcm.NF_NETLINK_CONNTRACK_UPDATE
                      |nfnlcm.NF_NETLINK_CONNTRACK_DESTROY)

## conntrack attributes
class ConntrackAttr(Enum):
	ATTR_ORIG_IPV4_SRC = 0,			# u32 bits
	ATTR_IPV4_SRC = ATTR_ORIG_IPV4_SRC	# alias
	ATTR_ORIG_IPV4_DST = 1			# u32 bits
	ATTR_IPV4_DST = ATTR_ORIG_IPV4_DST	# alias
	ATTR_REPL_IPV4_SRC = 2			# u32 bits
	ATTR_REPL_IPV4_DST = 3			# u32 bits
	ATTR_ORIG_IPV6_SRC = 4			# u128 bits
	ATTR_IPV6_SRC = ATTR_ORIG_IPV6_SRC	# alias
	ATTR_ORIG_IPV6_DST = 5			# u128 bits
	ATTR_IPV6_DST = ATTR_ORIG_IPV6_DST	# alias
	ATTR_REPL_IPV6_SRC = 6			# u128 bits
	ATTR_REPL_IPV6_DST = 7			# u128 bits
	ATTR_ORIG_PORT_SRC = 8			# u16 bits
	ATTR_PORT_SRC = ATTR_ORIG_PORT_SRC	# alias
	ATTR_ORIG_PORT_DST = 9			# u16 bits
	ATTR_PORT_DST = ATTR_ORIG_PORT_DST	# alias
	ATTR_REPL_PORT_SRC = 10			# u16 bits
	ATTR_REPL_PORT_DST = 11			# u16 bits
	ATTR_ICMP_TYPE = 12			# u8 bits
	ATTR_ICMP_CODE = 13			# u8 bits
	ATTR_ICMP_ID = 14			# u16 bits
	ATTR_ORIG_L3PROTO = 15			# u8 bits
	ATTR_L3PROTO = ATTR_ORIG_L3PROTO	# alias
	ATTR_REPL_L3PROTO = 16			# u8 bits
	ATTR_ORIG_L4PROTO = 17			# u8 bits
	ATTR_L4PROTO = ATTR_ORIG_L4PROTO	# alias
	ATTR_REPL_L4PROTO = 18			# u8 bits
	ATTR_TCP_STATE = 19			# u8 bits
	ATTR_SNAT_IPV4 = 20			# u32 bits
	ATTR_DNAT_IPV4 = 21			# u32 bits
	ATTR_SNAT_PORT = 22			# u16 bits
	ATTR_DNAT_PORT = 23			# u16 bits
	ATTR_TIMEOUT = 24			# u32 bits
	ATTR_MARK = 25				# u32 bits
	ATTR_ORIG_COUNTER_PACKETS = 26		# u64 bits
	ATTR_REPL_COUNTER_PACKETS = 27		# u64 bits
	ATTR_ORIG_COUNTER_BYTES = 28		# u64 bits
	ATTR_REPL_COUNTER_BYTES = 29		# u64 bits
	ATTR_USE = 30				# u32 bits
	ATTR_ID = 31				# u32 bits
	ATTR_STATUS = 32			# u32 bits
	ATTR_TCP_FLAGS_ORIG = 33		# u8 bits
	ATTR_TCP_FLAGS_REPL = 34		# u8 bits
	ATTR_TCP_MASK_ORIG = 35			# u8 bits
	ATTR_TCP_MASK_REPL = 36			# u8 bits
	ATTR_MASTER_IPV4_SRC = 37		# u32 bits
	ATTR_MASTER_IPV4_DST = 38		# u32 bits
	ATTR_MASTER_IPV6_SRC = 39		# u128 bits
	ATTR_MASTER_IPV6_DST = 40		# u128 bits
	ATTR_MASTER_PORT_SRC = 41		# u16 bits
	ATTR_MASTER_PORT_DST = 42		# u16 bits
	ATTR_MASTER_L3PROTO = 43		# u8 bits
	ATTR_MASTER_L4PROTO = 44		# u8 bits
	ATTR_SECMARK = 45			# u32 bits
	ATTR_ORIG_NAT_SEQ_CORRECTION_POS = 46	# u32 bits
	ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE = 47	# u32 bits
	ATTR_ORIG_NAT_SEQ_OFFSET_AFTER = 48	# u32 bits
	ATTR_REPL_NAT_SEQ_CORRECTION_POS = 49	# u32 bits
	ATTR_REPL_NAT_SEQ_OFFSET_BEFORE = 50	# u32 bits
	ATTR_REPL_NAT_SEQ_OFFSET_AFTER = 51	# u32 bits
	ATTR_SCTP_STATE = 52			# u8 bits
	ATTR_SCTP_VTAG_ORIG = 53		# u32 bits
	ATTR_SCTP_VTAG_REPL = 54		# u32 bits
	ATTR_HELPER_NAME = 55			# string (30 bytes max)
	ATTR_DCCP_STATE = 56			# u8 bits
	ATTR_DCCP_ROLE = 57			# u8 bits
	ATTR_DCCP_HANDSHAKE_SEQ = 58		# u64 bits
	ATTR_TCP_WSCALE_ORIG = 59		# u8 bits
	ATTR_TCP_WSCALE_REPL = 60		# u8 bits
	ATTR_ZONE = 61				# u16 bits
	ATTR_SECCTX = 62			# string
	ATTR_TIMESTAMP_START = 63		# u64 bits, linux >= 2.6.38
	ATTR_TIMESTAMP_STOP = 64		# u64 bits, linux >= 2.6.38
	ATTR_HELPER_INFO = 65			# variable length
	ATTR_CONNLABELS = 66			# variable length
	ATTR_CONNLABELS_MASK = 67		# variable length
	ATTR_MAX = 68
ATTR_ORIG_IPV4_SRC = 0
ATTR_IPV4_SRC = ATTR_ORIG_IPV4_SRC
ATTR_ORIG_IPV4_DST = 1
ATTR_IPV4_DST = ATTR_ORIG_IPV4_DST
ATTR_REPL_IPV4_SRC = 2
ATTR_REPL_IPV4_DST = 3
ATTR_ORIG_IPV6_SRC = 4
ATTR_IPV6_SRC = ATTR_ORIG_IPV6_SRC
ATTR_ORIG_IPV6_DST = 5
ATTR_IPV6_DST = ATTR_ORIG_IPV6_DST
ATTR_REPL_IPV6_SRC = 6
ATTR_REPL_IPV6_DST = 7
ATTR_ORIG_PORT_SRC = 8
ATTR_PORT_SRC = ATTR_ORIG_PORT_SRC
ATTR_ORIG_PORT_DST = 9
ATTR_PORT_DST = ATTR_ORIG_PORT_DST
ATTR_REPL_PORT_SRC = 10
ATTR_REPL_PORT_DST = 11
ATTR_ICMP_TYPE = 12
ATTR_ICMP_CODE = 13
ATTR_ICMP_ID = 14
ATTR_ORIG_L3PROTO = 15
ATTR_L3PROTO = ATTR_ORIG_L3PROTO
ATTR_REPL_L3PROTO = 16
ATTR_ORIG_L4PROTO = 17
ATTR_L4PROTO = ATTR_ORIG_L4PROTO
ATTR_REPL_L4PROTO = 18
ATTR_TCP_STATE = 19
ATTR_SNAT_IPV4 = 20
ATTR_DNAT_IPV4 = 21
ATTR_SNAT_PORT = 22
ATTR_DNAT_PORT = 23
ATTR_TIMEOUT = 24
ATTR_MARK = 25
ATTR_ORIG_COUNTER_PACKETS = 26
ATTR_REPL_COUNTER_PACKETS = 27
ATTR_ORIG_COUNTER_BYTES = 28
ATTR_REPL_COUNTER_BYTES = 29
ATTR_USE = 30
ATTR_ID = 31
ATTR_STATUS = 32
ATTR_TCP_FLAGS_ORIG = 33
ATTR_TCP_FLAGS_REPL = 34
ATTR_TCP_MASK_ORIG = 35
ATTR_TCP_MASK_REPL = 36
ATTR_MASTER_IPV4_SRC = 37
ATTR_MASTER_IPV4_DST = 38
ATTR_MASTER_IPV6_SRC = 39
ATTR_MASTER_IPV6_DST = 40
ATTR_MASTER_PORT_SRC = 41
ATTR_MASTER_PORT_DST = 42
ATTR_MASTER_L3PROTO = 43
ATTR_MASTER_L4PROTO = 44
ATTR_SECMARK = 45
ATTR_ORIG_NAT_SEQ_CORRECTION_POS = 46
ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE = 47
ATTR_ORIG_NAT_SEQ_OFFSET_AFTER = 48
ATTR_REPL_NAT_SEQ_CORRECTION_POS = 49
ATTR_REPL_NAT_SEQ_OFFSET_BEFORE = 50
ATTR_REPL_NAT_SEQ_OFFSET_AFTER = 51
ATTR_SCTP_STATE = 52
ATTR_SCTP_VTAG_ORIG = 53
ATTR_SCTP_VTAG_REPL = 54
ATTR_HELPER_NAME = 55
ATTR_DCCP_STATE = 56
ATTR_DCCP_ROLE = 57
ATTR_DCCP_HANDSHAKE_SEQ = 58
ATTR_TCP_WSCALE_ORIG = 59
ATTR_TCP_WSCALE_REPL = 60
ATTR_ZONE = 61
ATTR_SECCTX = 62
ATTR_TIMESTAMP_START = 63
ATTR_TIMESTAMP_STOP = 64
ATTR_HELPER_INFO = 65
ATTR_CONNLABELS = 66
ATTR_CONNLABELS_MASK = 67
ATTR_MAX = 68

## conntrack attribute groups
class ConntrackAttrGrp(Enum):
	ATTR_GRP_ORIG_IPV4 = 0			# struct nfct_attr_grp_ipv4
	ATTR_GRP_REPL_IPV4 = 1			# struct nfct_attr_grp_ipv4
	ATTR_GRP_ORIG_IPV6 = 2			# struct nfct_attr_grp_ipv6
	ATTR_GRP_REPL_IPV6 = 3			# struct nfct_attr_grp_ipv6
	ATTR_GRP_ORIG_PORT = 4			# struct nfct_attr_grp_port
	ATTR_GRP_REPL_PORT = 5			# struct nfct_attr_grp_port
	ATTR_GRP_ICMP = 6			# struct nfct_attr_grp_icmp
	ATTR_GRP_MASTER_IPV4 = 7		# struct nfct_attr_grp_ipv4
	ATTR_GRP_MASTER_IPV6 = 8		# struct nfct_attr_grp_ipv6
	ATTR_GRP_MASTER_PORT = 9		# struct nfct_attr_grp_port
	ATTR_GRP_ORIG_COUNTERS = 10		# struct nfct_attr_grp_ctrs
	ATTR_GRP_REPL_COUNTERS = 11		# struct nfct_attr_grp_ctrs
	ATTR_GRP_ORIG_ADDR_SRC = 12		# union nfct_attr_grp_addr
	ATTR_GRP_ORIG_ADDR_DST = 13		# union nfct_attr_grp_addr
	ATTR_GRP_REPL_ADDR_SRC = 14		# union nfct_attr_grp_addr
	ATTR_GRP_REPL_ADDR_DST = 15		# union nfct_attr_grp_addr
	ATTR_GRP_MAX = 16
ATTR_GRP_ORIG_IPV4 = 0
ATTR_GRP_REPL_IPV4 = 1
ATTR_GRP_ORIG_IPV6 = 2
ATTR_GRP_REPL_IPV6 = 3
ATTR_GRP_ORIG_PORT = 4
ATTR_GRP_REPL_PORT = 5
ATTR_GRP_ICMP = 6
ATTR_GRP_MASTER_IPV4 = 7
ATTR_GRP_MASTER_IPV6 = 8
ATTR_GRP_MASTER_PORT = 9
ATTR_GRP_ORIG_COUNTERS = 10
ATTR_GRP_REPL_COUNTERS = 11
ATTR_GRP_ORIG_ADDR_SRC = 12
ATTR_GRP_ORIG_ADDR_DST = 13
ATTR_GRP_REPL_ADDR_SRC = 14
ATTR_GRP_REPL_ADDR_DST = 15
ATTR_GRP_MAX = 16

class AttrGrpIpv4(ctypes.Structure):
    """struct nfct_attr_grp_ipv4
	uint32_t src, dst
    """
    _fields_ = [("src",		ctypes.c_uint32),
                ("dst",		ctypes.c_uint32)]

class AttrGrpIpv6(ctypes.Structure):
    """struct nfct_attr_grp_ipv6
        uint32_t src[4], dst[4]
    """
    _fields_ = [("src", 	(ctypes.c_uint32 * 4)),
                ("dst",		(ctypes.c_uint32 * 4))]

class AttrGrpPort(ctypes.Structure):
    """struct nfct_attr_grp_port
	uint16_t sport, dport
    """
    _fields_ = [("sport", 	ctypes.c_uint16),
                ("dport", 	ctypes.c_uint16)]

class AttrGrpIcmp(ctypes.Structure):
    """struct nfct_attr_grp_icmp
    """
    _fields_ = [("id", 		ctypes.c_uint16), # uint16_t id
                ("code", 	ctypes.c_uint8),  # uint8_t code, type
                ("type", 	ctypes.c_uint8)]

class AttrGrpCtrs(ctypes.Structure):
    """struct nfct_attr_grp_ctrs
    """
    _fields_ = [("packets",	ctypes.c_uint64), # uint64_t packets
                ("bytes", 	ctypes.c_uint64)] # uint64_t bytes

class AttrGrpAddr(ctypes.Union):
    """union nfct_attr_grp_addr
    """
    _fields_ = [("ip",		ctypes.c_uint32),       # uint32_t ip
                ("ip6",		(ctypes.c_uint32 * 4)), # uint32_t ip6[4]
                ("addr",	(ctypes.c_uint32 * 4))] # uint32_t addr[4]

## message type
# enum nf_conntrack_msg_type
class ConntrackMsgType(Enum):
    NFCT_T_UNKNOWN = 0

    NFCT_T_NEW_BIT = 0
    NFCT_T_NEW = (1 << NFCT_T_NEW_BIT)

    NFCT_T_UPDATE_BIT = 1
    NFCT_T_UPDATE = (1 << NFCT_T_UPDATE_BIT)

    NFCT_T_DESTROY_BIT = 2
    NFCT_T_DESTROY = (1 << NFCT_T_DESTROY_BIT)

    NFCT_T_ALL = NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY

    NFCT_T_ERROR_BIT = 31
    NFCT_T_ERROR = (1 << NFCT_T_ERROR_BIT)
NFCT_T_UNKNOWN = 0
NFCT_T_NEW_BIT = 0
NFCT_T_NEW = (1 << NFCT_T_NEW_BIT)
NFCT_T_UPDATE_BIT = 1
NFCT_T_UPDATE = (1 << NFCT_T_UPDATE_BIT)
NFCT_T_DESTROY_BIT = 2
NFCT_T_DESTROY = (1 << NFCT_T_DESTROY_BIT)
NFCT_T_ALL = NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY
NFCT_T_ERROR_BIT = 31
NFCT_T_ERROR = (1 << NFCT_T_ERROR_BIT)


## set option
# enum
NFCT_SOPT_UNDO_SNAT		= 0
NFCT_SOPT_UNDO_DNAT		= 1
NFCT_SOPT_UNDO_SPAT		= 2
NFCT_SOPT_UNDO_DPAT		= 3
NFCT_SOPT_SETUP_ORIGINAL	= 4
NFCT_SOPT_SETUP_REPLY		= 5
__NFCT_SOPT_MAX			= 6
NFCT_SOPT_MAX 			= (__NFCT_SOPT_MAX - 1)


## get option
# enum
NFCT_GOPT_IS_SNAT	= 0
NFCT_GOPT_IS_DNAT	= 1
NFCT_GOPT_IS_SPAT	= 2
NFCT_GOPT_IS_DPAT	= 3
__NFCT_GOPT_MAX		= 4
NFCT_GOPT_MAX		= (__NFCT_GOPT_MAX - 1)


## print
## output type
# enum
NFCT_O_PLAIN	= 0
NFCT_O_DEFAULT	= NFCT_O_PLAIN
NFCT_O_XML	= 1
NFCT_O_MAX	= 2

## output flags
# enum
NFCT_OF_SHOW_LAYER3_BIT = 0
NFCT_OF_SHOW_LAYER3 = (1 << NFCT_OF_SHOW_LAYER3_BIT)
NFCT_OF_TIME_BIT = 1
NFCT_OF_TIME = (1 << NFCT_OF_TIME_BIT)
NFCT_OF_ID_BIT = 2
NFCT_OF_ID = (1 << NFCT_OF_ID_BIT)
NFCT_OF_TIMESTAMP_BIT = 3
NFCT_OF_TIMESTAMP = (1 << NFCT_OF_TIMESTAMP_BIT)


## comparison
# enum
NFCT_CMP_ALL = 0
NFCT_CMP_ORIG = (1 << 0)
NFCT_CMP_REPL = (1 << 1)
NFCT_CMP_TIMEOUT_EQ = (1 << 2)
NFCT_CMP_TIMEOUT_GT = (1 << 3)
NFCT_CMP_TIMEOUT_GE = (NFCT_CMP_TIMEOUT_EQ | NFCT_CMP_TIMEOUT_GT)
NFCT_CMP_TIMEOUT_LT = (1 << 4)
NFCT_CMP_TIMEOUT_LE = (NFCT_CMP_TIMEOUT_EQ | NFCT_CMP_TIMEOUT_LT)
NFCT_CMP_MASK = (1 << 5)
NFCT_CMP_STRICT = (1 << 6)


## copy
# enum
NFCT_CP_ALL = 0
NFCT_CP_ORIG = (1 << 0)
NFCT_CP_REPL = (1 << 1)
NFCT_CP_META = (1 << 2)
NFCT_CP_OVERRIDE = (1 << 3)


## event filtering
class FilterProto(ctypes.Structure):
    """struct nfct_filter_proto
    """
    _fields_ = [("proto",	ctypes.c_uint16), # uint16_t proto
                ("state",	ctypes.c_uint16)] # uint16_t state

class FilterIpv4(ctypes.Structure):
    """struct nfct_filter_ipv4
    """
    _fields_ = [("addr", 	ctypes.c_uint32), # uint32_t addr
                ("mask", 	ctypes.c_uint32)] # uint32_t mask

class FilterIpv6(ctypes.Structure):
    """struct nfct_filter_ipv6
    """
    _fields_ = [("addr",	(ctypes.c_uint32 * 4)), # uint32_t addr[4]
                ("mask",	(ctypes.c_uint32 * 4))] # uint32_t mask[4]

class FilterAttr(Enum):
    NFCT_FILTER_L4PROTO = 0		# uint32_t
    NFCT_FILTER_L4PROTO_STATE = 1	# struct nfct_filter_proto
    NFCT_FILTER_SRC_IPV4 = 2		# struct nfct_filter_ipv4
    NFCT_FILTER_DST_IPV4 = 3		# struct nfct_filter_ipv4
    NFCT_FILTER_SRC_IPV6 = 4		# struct nfct_filter_ipv6
    NFCT_FILTER_DST_IPV6 = 5		# struct nfct_filter_ipv6
    NFCT_FILTER_MARK = 6		# struct nfct_filter_dump_mark
    NFCT_FILTER_MAX = 7
NFCT_FILTER_L4PROTO = 0
NFCT_FILTER_L4PROTO_STATE = 1
NFCT_FILTER_SRC_IPV4 = 2
NFCT_FILTER_DST_IPV4 = 3
NFCT_FILTER_SRC_IPV6 = 4
NFCT_FILTER_DST_IPV6 = 5
NFCT_FILTER_MARK = 6
NFCT_FILTER_MAX = 7

class FilterLogic(Enum):
    NFCT_FILTER_LOGIC_POSITIVE = 0
    NFCT_FILTER_LOGIC_NEGATIVE = 1
    NFCT_FILTER_LOGIC_MAX = 2
NFCT_FILTER_LOGIC_POSITIVE = 0
NFCT_FILTER_LOGIC_NEGATIVE = 1
NFCT_FILTER_LOGIC_MAX = 2


## dump filtering
class FilterDumpMark(ctypes.Structure):
    """struct nfct_filter_dump_mark
    """
    _fields_ = [("val",		ctypes.c_uint32), # uint32_t val
                ("mask",	ctypes.c_uint32)] # uint32_t mask

class FilterDumpAttr(Enum):
    NFCT_FILTER_DUMP_MARK = 0	# struct nfct_filter_dump_mark
    NFCT_FILTER_DUMP_L3NUM = 1	# uint8_t
    NFCT_FILTER_DUMP_MAX = 2
NFCT_FILTER_DUMP_MARK = 0
NFCT_FILTER_DUMP_L3NUM = 1
NFCT_FILTER_DUMP_MAX = 2

## expect attributes
class ExpectAttr(Enum):
    ATTR_EXP_MASTER = 0		# pointer to conntrack object
    ATTR_EXP_EXPECTED = 1	# pointer to conntrack object
    ATTR_EXP_MASK = 2		# pointer to conntrack object
    ATTR_EXP_TIMEOUT = 3	# u32 bits
    ATTR_EXP_ZONE = 4		# u16 bits
    ATTR_EXP_FLAGS = 5		# u32 bits
    ATTR_EXP_HELPER_NAME = 6	# string (16 bytes max)
    ATTR_EXP_CLASS = 7		# u32 bits
    ATTR_EXP_NAT_TUPLE = 8	# pointer to conntrack object
    ATTR_EXP_NAT_DIR = 9	# u8 bits
    ATTR_EXP_FN = 10		# string
    ATTR_EXP_MAX = 11
ATTR_EXP_MASTER = 0
ATTR_EXP_EXPECTED = 1
ATTR_EXP_MASK = 2
ATTR_EXP_TIMEOUT = 3
ATTR_EXP_ZONE = 4
ATTR_EXP_FLAGS = 5
ATTR_EXP_HELPER_NAME = 6
ATTR_EXP_CLASS = 7
ATTR_EXP_NAT_TUPLE = 8
ATTR_EXP_NAT_DIR = 9
ATTR_EXP_FN = 10
ATTR_EXP_MAX = 11
