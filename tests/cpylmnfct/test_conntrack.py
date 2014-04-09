# -*- coding: utf-8 -*-

from __future__ import print_function

import sys, os, unittest
import socket, ctypes, errno

import cpylmnl as mnl
import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nf_conntrack_commonh as nfctcm
import cpylmnl.linux.netfilter.nfnetlink_conntrackh as nfnlct

import cpylmnfct as nfct

class TestSuite(unittest.TestCase):
    def setUp(self):
        self.nlmsgbuf10 = bytearray([ # len: 196 + 16
					# ----------------	------------------
                0xc4, 0x00, 0x00, 0x00,	# |  0000000196  |	| message length |
                0x02, 0x01, 0x00, 0x00,	# | 00258 | ---- |	|  type | flags  |	IPCTNL_MSG_CT_DELETE
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	|     port ID    |
					# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0x01, 0x02, 0x03, 0x04,	# | 01 02 03 04  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0xff, 0xfe, 0xfd, 0xfc,	# | ff fe fd fc  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0xf8, 0x8f, 0x00, 0x00,	# | f8 8f 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0x00, 0x35, 0x00, 0x00,	# | 00 35 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|	+ CTA_TUPLE_REPLY
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0xff, 0xfe, 0xfd, 0xfc,	# | ff fe fd fc  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0x01, 0x02, 0x03, 0x04,	# | 01 02 03 04  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0x00, 0x35, 0x00, 0x00,	# | 00 35 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0xf8, 0x8f, 0x00, 0x00,	# | f8 8f 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|	CTA_ID *
                0x17, 0x6d, 0x0d, 0x78,	# | 17 6d 0d 78  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|	CTA_STATUS
                0x00, 0x00, 0x00, 0x08,	# | 00 00 00 08  |	|      data      |	  IPS_CONFIRMED
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|	+ CTA_COUNTERS_ORIG *
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|	  CTA_CONTERS_BYTES
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|	+ CTA_COUNTERS_REPLY *
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|	  CTA_CONTERS_BYTES
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                                        # ----------------	------------------
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
                ])

        self.nlmsgbuf11 = bytearray([ # len: 132 + 16
					# ----------------	------------------
                0x84, 0x00, 0x00, 0x00,	# |  0000000132  |	| message length |
                0x02, 0x01, 0x00, 0x00,	# | 00258 | ---- |	|  type | flags  |	IPCTNL_MSG_CT_DELETE
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	|     port ID    |
					# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0x01, 0x02, 0x03, 0x04,	# | 01 02 03 04  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0xff, 0xfe, 0xfd, 0xfc,	# | ff fe fd fc  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0xf8, 0x8f, 0x00, 0x00,	# | f8 8f 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0x00, 0x35, 0x00, 0x00,	# | 00 35 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|	+ CTA_TUPLE_REPLY
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0xff, 0xfe, 0xfd, 0xfc,	# | ff fe fd fc  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0x01, 0x02, 0x03, 0x04,	# | 01 02 03 04  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0x00, 0x35, 0x00, 0x00,	# | 00 35 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0xf8, 0x8f, 0x00, 0x00,	# | f8 8f 00 00  |	|      data      |	  - CTA_TUPLE_PROTO
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|	CTA_STATUS
                0x00, 0x00, 0x00, 0x08,	# | 00 00 00 08  |	|      data      |	  IPS_CONFIRMED
                                        # ----------------	------------------
                ])

        self.nlmsgbuf20 = bytearray([ # len: 708 + 16
					# ----------------	------------------
                0xdc, 0x00, 0x00, 0x00,	# |  0000000220  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
					# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0x01, 0x01, 0x01, 0x01,	# | 01 01 01 01  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0x02, 0x02, 0x02, 0x02,	# | 02 02 02 02  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PTOTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|	+ CTA_TUPLE_REPLY
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_TUPLE_V4_SRC
                0x01, 0x01, 0x01, 0x01,	# | 01 01 01 01  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_TUP+E_V4_DST
                0x02, 0x02, 0x02, 0x02,	# | 02 02 02 02  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_TUPLE_SRC_PORT
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_TUPLE_DST_PORT
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |	  IPS_EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
                0x00, 0x00, 0x00, 0x99,	# | 00 00 00 99  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|	+ CTA_COUNTERS_ORIG *
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|	  CTA_COUNTERS_BYTES
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|	+ CTA_COUNTERS_REPLY *
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|	  CTA_COUNTERS_BYTES
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|	CTA_MARK
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|	CTA_ID *
                0x15, 0x50, 0xb8, 0xb8,	# | 15 50 b8 b8  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|	CTA_USE
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                			# ----------------	------------------
					#
					# ----------------	------------------
                0x0c, 0x01, 0x00, 0x00,	# |  0000000268  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
                			# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0x03, 0x05, 0x05, 0x05,	# | 03 03 03 03  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0x06, 0x06, 0x06, 0x06,	# | 04 04 04 04  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0xc1, 0x79, 0x00, 0x00,	# | c1 79 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0x01, 0xbd, 0x00, 0x00,	# | 01 bd 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|	  + CTA_TUPLE_REPLY
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	    + CTA_TUPLE_IP
                0x06, 0x06, 0x06, 0x06,	# |00008|--|00001|	|len |flags| type|	      CTA_IP_V4_SRC
                0x04, 0x04, 0x04, 0x04,	# | 04 04 04 04  |	|      data      |
                0x05, 0x05, 0x05, 0x05,	# |00008|--|00002|	|len |flags| type|	      CTA_IP_V4_DST
                0x03, 0x03, 0x03, 0x03,	# | 03 03 03 03  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	    + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	      CTA_PROTO_NUM
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	      CTA_PROTO_SRC_PORT
                0x01, 0xbd, 0x00, 0x00,	# | 01 bd 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	      CTA_PROTO_DST_PORT
                0xc1, 0x79, 0x00, 0x00,	# | c1 79 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |	  IPS_EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
                0x00, 0x06, 0x97, 0x65,	# | 00 06 97 65  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|	+ CTA_COUNTERS_ORIG *
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|	  CTA_COUNTERS_BYTES
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|	+ CTA_COUNTERS_REPLY *
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|	  CTA_COUNTERS_BYTES
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x30, 0x00, 0x04, 0x80,	# |00048|N-|00004|	|len |flags| type|	+ CTA_PROTOINFO
                0x2c, 0x00, 0x01, 0x80,	# |00044|N-|00001|	|len |flags| type|	  + CTA_PROTOINFO_TCP
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTOINFO_TCP_STATE
                0x03, 0x00, 0x00, 0x00,	# | 03 00 00 00  |	|      data      |
                0x05, 0x00, 0x02, 0x00,	# |00005|--|00002|	|len |flags| type|	    CTA_PROTOINFO_TCP_WSCALE_ORIGINAL
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|      data      |
                0x05, 0x00, 0x03, 0x00,	# |00005|--|00003|	|len |flags| type|	    CTA_PROTOINFO_TCP_WSCALE_REPLY
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x06, 0x00, 0x04, 0x00,	# |00006|--|00004|	|len |flags| type|	    CTA_PROTOINFO_TCP_FLAGS_ORIGINAL
                0x23, 0x00, 0x00, 0x00,	# | 23 00 00 00  |	|      data      |
                0x06, 0x00, 0x05, 0x00,	# |00006|--|00005|	|len |flags| type|	    CTA_PROTOINFO_TCP_FLAGS_REPLY
                0x23, 0x00, 0x00, 0x00,	# | 23 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|	CTA_MARK
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|	CTA_ID *
                0x14, 0xcc, 0x56, 0x58,	# | 14 cc 56 58  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|	CTA_USE
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                			# ----------------	------------------
					#
                			# ----------------	------------------
		0xdc, 0x00, 0x00, 0x00,	# |  0000000220  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
                                        # ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0x55, 0x55, 0x55, 0x55,	# | 55 55 55 55  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0x66, 0x66, 0x66, 0x66,	# | 66 66 66 66  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0xca, 0xda, 0x00, 0x00,	# | ca da 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0x02, 0x02, 0x00, 0x00,	# | 02 02 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|	  + CTA_TUPLE_REPLY
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	    + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	      CTA_IP_V4_SRC
                0x66, 0x66, 0x66, 0x66,	# | 66 66 66 66  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	      CTA_IP_V4_DST
                0x55, 0x55, 0x55, 0x55,	# | 55 55 55 55  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	    + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	      CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	      CTA_PROTO_SRC_PORT
                0x02, 0x02, 0x00, 0x00,	# | 02 02 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	      CTA_PROTO_DST_PORT
                0xca, 0xda, 0x00, 0x00,	# | ca da 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
                0x00, 0x00, 0x00, 0x08,	# | 00 00 00 08  |	|      data      |	  IPS_CONFIRMED
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
                0x00, 0x00, 0x00, 0x13,	# | 00 00 00 13  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|	+ CTA_COUNTERS_ORIG *
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|	  CTA_COUNTERS_BYTES
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|	+ CTA_COUNTERS_REPLY *
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |	  CTA_COUNTERS_BYTES
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|	CTA_MARK
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|	CTA_ID *
                0x12, 0xd5, 0x69, 0xe8,	# | 12 d5 69 e8  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|	CTA_USE
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                			# ----------------	------------------
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
                ])

        self.nlmsgbuf21 = bytearray([ # len: 660 + 16
					# ----------------	------------------
                0x9c, 0x00, 0x00, 0x00,	# |  0000000156  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
					# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0x01, 0x01, 0x01, 0x01,	# | 01 01 01 01  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0x02, 0x02, 0x02, 0x02,	# | 02 02 02 02  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PTOTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|	+ CTA_TUPLE_REPLY
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_TUPLE_V4_SRC
                0x01, 0x01, 0x01, 0x01,	# | 01 01 01 01  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_TUP+E_V4_DST
                0x02, 0x02, 0x02, 0x02,	# | 02 02 02 02  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_TUPLE_SRC_PORT
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_TUPLE_DST_PORT
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |	  IPS_EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
                0x00, 0x00, 0x00, 0x99,	# | 00 00 00 99  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|	CTA_MARK
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|	CTA_USE
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                			# ----------------	------------------
					#
					# ----------------	------------------
                0xcc, 0x00, 0x00, 0x00,	# |  0000000204  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
                			# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0x03, 0x05, 0x05, 0x05,	# | 03 03 03 03  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0x06, 0x06, 0x06, 0x06,	# | 04 04 04 04  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0xc1, 0x79, 0x00, 0x00,	# | c1 79 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0x01, 0xbd, 0x00, 0x00,	# | 01 bd 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|	  + CTA_TUPLE_REPLY
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	    + CTA_TUPLE_IP
                0x06, 0x06, 0x06, 0x06,	# |00008|--|00001|	|len |flags| type|	      CTA_IP_V4_SRC
                0x04, 0x04, 0x04, 0x04,	# | 04 04 04 04  |	|      data      |
                0x05, 0x05, 0x05, 0x05,	# |00008|--|00002|	|len |flags| type|	      CTA_IP_V4_DST
                0x03, 0x03, 0x03, 0x03,	# | 03 03 03 03  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	    + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	      CTA_PROTO_NUM
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	      CTA_PROTO_SRC_PORT
                0x01, 0xbd, 0x00, 0x00,	# | 01 bd 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	      CTA_PROTO_DST_PORT
                0xc1, 0x79, 0x00, 0x00,	# | c1 79 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |	  IPS_EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
                0x00, 0x06, 0x97, 0x65,	# | 00 06 97 65  |	|      data      |
                0x30, 0x00, 0x04, 0x80,	# |00048|N-|00004|	|len |flags| type|	+ CTA_PROTOINFO
                0x2c, 0x00, 0x01, 0x80,	# |00044|N-|00001|	|len |flags| type|	  + CTA_PROTOINFO_TCP
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTOINFO_TCP_STATE
                0x03, 0x00, 0x00, 0x00,	# | 03 00 00 00  |	|      data      |
                0x05, 0x00, 0x02, 0x00,	# |00005|--|00002|	|len |flags| type|	    CTA_PROTOINFO_TCP_WSCALE_ORIGINAL
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|      data      |
                0x05, 0x00, 0x03, 0x00,	# |00005|--|00003|	|len |flags| type|	    CTA_PROTOINFO_TCP_WSCALE_REPLY
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x06, 0x00, 0x04, 0x00,	# |00006|--|00004|	|len |flags| type|	    CTA_PROTOINFO_TCP_FLAGS_ORIGINAL
                0x23, 0x00, 0x00, 0x00,	# | 23 00 00 00  |	|      data      |
                0x06, 0x00, 0x05, 0x00,	# |00006|--|00005|	|len |flags| type|	    CTA_PROTOINFO_TCP_FLAGS_REPLY
                0x23, 0x00, 0x00, 0x00,	# | 23 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|	CTA_MARK
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|	CTA_USE
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                			# ----------------	------------------
					#
                			# ----------------	------------------
		0x9c, 0x00, 0x00, 0x00,	# |  0000000156  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
                                        # ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0x55, 0x55, 0x55, 0x55,	# | 55 55 55 55  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0x66, 0x66, 0x66, 0x66,	# | 66 66 66 66  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0xca, 0xda, 0x00, 0x00,	# | ca da 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0x02, 0x02, 0x00, 0x00,	# | 02 02 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|	  + CTA_TUPLE_REPLY
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	    + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	      CTA_IP_V4_SRC
                0x66, 0x66, 0x66, 0x66,	# | 66 66 66 66  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	      CTA_IP_V4_DST
                0x55, 0x55, 0x55, 0x55,	# | 55 55 55 55  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	    + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	      CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	      CTA_PROTO_SRC_PORT
                0x02, 0x02, 0x00, 0x00,	# | 02 02 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	      CTA_PROTO_DST_PORT
                0xca, 0xda, 0x00, 0x00,	# | ca da 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
                0x00, 0x00, 0x00, 0x08,	# | 00 00 00 08  |	|      data      |	  IPS_CONFIRMED
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
                0x00, 0x00, 0x00, 0x13,	# | 00 00 00 13  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|	CTA_MARK
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|	CTA_USE
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                			# ----------------	------------------
                ])


    # almost just calling them
    def test_conntrack(self):
        try:
            ct = nfct.Conntrack()
            ct.destroy()
        except Exception as e:
            self.fail("could not create or destroy nf_conntrack: %s" % e)
        try:
            ct = nfct.Conntrack()
            del ct
        except Exception as e:
            self.fail("could not create or del nf_conntrack: %s" % e)

    def test_clone(self):
        ct = nfct.Conntrack()
        ct.set_attr_u8(nfct.ATTR_ORIG_L3PROTO, 11)
        clone = ct.clone()
        self.assertNotEqual(ct._ct, clone._ct)
        self.assertEqual(clone.get_attr_u8(nfct.ATTR_ORIG_L3PROTO), 11)
        clone.destroy()
        ct.destroy()


    def test_objopt(self):
        ct = nfct.Conntrack()
        # ct.set_attr_u32(nfct.ATTR_STATUS, nfctcm.IPS_SRC_NAT_DONE)
        ct.set_attr_u32(nfct.ATTR_REPL_IPV4_DST, 1)
        self.assertEqual(ct.getobjopt(nfct.NFCT_GOPT_IS_SNAT), 1)
        ct.setobjopt(nfct.NFCT_SOPT_UNDO_SNAT)
        self.assertEqual(ct.getobjopt(nfct.NFCT_GOPT_IS_SNAT), 0)
        ct.destroy()


    def test_set_attr_l(self):
        ct = nfct.Conntrack()
        a1 = ctypes.c_uint32(0x12345678)
        ct.set_attr_l(nfct.ATTR_ORIG_IPV4_SRC, a1)
        a2 = ct.get_attr_as(nfct.ATTR_ORIG_IPV4_SRC, ctypes.c_uint32)
        self.assertEqual(a1.value, a2.value)
        ct.destroy()


    def test_attr(self):
        ct = nfct.Conntrack()
        a1 = ctypes.c_uint32(0x12345678)
        ct.set_attr(nfct.ATTR_ORIG_IPV4_SRC, a1)
        a2 = ct.get_attr_as(nfct.ATTR_ORIG_IPV4_SRC, ctypes.c_uint32)
        self.assertEqual(a1.value, a2.value)
        ct.destroy()


    def test_attr_u8(self):
        ct = nfct.Conntrack()
        ct.set_attr_u8(nfct.ATTR_ORIG_L3PROTO, 123)
        self.assertEqual(ct.get_attr_u8(nfct.ATTR_ORIG_L3PROTO), 123)
        ct.destroy()


    def test_attr_u16(self):
        ct = nfct.Conntrack()
        ct.set_attr_u16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
        self.assertEqual(ct.get_attr_u16(nfct.ATTR_ORIG_PORT_SRC), 0x1234)
        ct.destroy()

    def test_attr_u32(self):
        ct = nfct.Conntrack()
        ct.set_attr_u32(nfct.ATTR_ORIG_IPV4_DST, 0x12345678)
        self.assertEqual(ct.get_attr_u32(nfct.ATTR_ORIG_IPV4_DST), 0x12345678)
        ct.destroy()

    def test_attr_u64(self):
        ct = nfct.Conntrack()
        # ct.set_attr_u64(nfct.ATTR_ORIG_COUNTER_PACKETS, 0x123456789abcdef)
        # ... is set_attr_do_nothing
        ct.set_attr_u64(nfct.ATTR_DCCP_HANDSHAKE_SEQ, 0x123456789abcdef)
        self.assertEqual(ct.get_attr_u64(nfct.ATTR_DCCP_HANDSHAKE_SEQ), 0x123456789abcdef)
        ct.destroy()


    def test_attr_is_set(self):
        ct = nfct.Conntrack()
        ct.set_attr_u64(nfct.ATTR_DCCP_HANDSHAKE_SEQ, 0x123456789abcdef)
        self.assertTrue(ct.attr_is_set(nfct.ATTR_DCCP_HANDSHAKE_SEQ))
        self.assertFalse(ct.attr_is_set(nfct.ATTR_ORIG_COUNTER_PACKETS))
        ct.destroy()


    def test_attr_is_set_array(self):
        ct = nfct.Conntrack()
        ct.set_attr_u8(nfct.ATTR_ORIG_L3PROTO, 123)
        ct.set_attr_u16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
        ct.set_attr_u32(nfct.ATTR_ORIG_IPV4_DST, 0x12345678)
        a = [nfct.ATTR_ORIG_L3PROTO, nfct.ATTR_ORIG_L3PROTO, nfct.ATTR_ORIG_IPV4_DST]
        self.assertTrue(ct.attr_is_set_array(a))
        a = [nfct.ATTR_ORIG_L3PROTO, nfct.ATTR_ORIG_L3PROTO, nfct.ATTR_ORIG_IPV4_DST, nfct.ATTR_ORIG_COUNTER_PACKETS]
        self.assertFalse(ct.attr_is_set_array(a))
        ct.destroy()


    def test_attr_unset(self):
        ct = nfct.Conntrack()
        ct.set_attr_u8(nfct.ATTR_ORIG_L3PROTO, 123)
        ct.attr_unset(nfct.ATTR_ORIG_L3PROTO)
        self.assertFalse(ct.attr_is_set(nfct.ATTR_ORIG_L3PROTO))
        ct.destroy()


    def test_attr_grp(self):
        ct = nfct.Conntrack()
        grp1 = nfct.AttrGrpIpv4(0x12345678, 0x9abcdef0)
        ct.set_attr_grp(nfct.ATTR_GRP_ORIG_IPV4, grp1)
        grp2 = nfct.AttrGrpIpv4(0, 0)
        ct.get_attr_grp(nfct.ATTR_GRP_ORIG_IPV4, grp2)
        self.assertEquals(grp2.src, grp1.src)
        self.assertEquals(grp2.dst, grp1.dst)

        grp3 = ct.get_attr_grp_as(nfct.ATTR_GRP_ORIG_IPV4, nfct.AttrGrpIpv4)
        self.assertEquals(grp3.src, grp1.src)
        self.assertEquals(grp3.dst, grp1.dst)

        self.assertTrue(ct.attr_grp_is_set(nfct.ATTR_GRP_ORIG_IPV4))
        ct.attr_grp_unset(nfct.ATTR_GRP_ORIG_IPV4)
        self.assertFalse(ct.attr_grp_is_set(nfct.ATTR_GRP_ORIG_IPV4))


    # Conntrack.snprintf(self, s, m, o, f)
    # Conntrack.snprintf_labels(self, s, m, o, f, l)


    def test_cmp(self):
        ct1 = nfct.Conntrack()
        grp = nfct.AttrGrpIpv4(0x12345678, 0x9abcdef0)
        ct1.set_attr_grp(nfct.ATTR_GRP_ORIG_IPV4, grp)
        ct1.set_attr_u8(nfct.ATTR_ORIG_L3PROTO, 123)
        ct1.set_attr_u16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
        ct1.set_attr_u32(nfct.ATTR_ORIG_IPV4_DST, 0x12345678)
        ct1.set_attr_u64(nfct.ATTR_ID, 0xabcdef)

        ct2 = nfct.Conntrack()
        ct2.set_attr_grp(nfct.ATTR_GRP_ORIG_IPV4, grp)
        ct2.set_attr_u8(nfct.ATTR_ORIG_L3PROTO, 123)
        ct2.set_attr_u16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
        ct2.set_attr_u32(nfct.ATTR_ORIG_IPV4_DST, 0x87654321)

        self.assertEqual(ct1.cmp(ct2, nfct.NFCT_CMP_ALL), 0)
        ct2.set_attr_u32(nfct.ATTR_ORIG_IPV4_DST, 0x12345678)
        self.assertEqual(ct1.cmp(ct2, nfct.NFCT_CMP_ALL), 1)

        self.assertEqual(ct1.cmp(ct2, nfct.NFCT_CMP_STRICT), 0)
        # not literaly strict but meta
        ct2.set_attr_u64(nfct.ATTR_ID, 0xabcdef)
        self.assertEqual(ct1.cmp(ct2, nfct.NFCT_CMP_STRICT), 1)

        ct1.destroy()
        ct2.destroy()


    def test_copy(self):
        ct1 = nfct.Conntrack()
        ct1.set_attr_u8(nfct.ATTR_ORIG_L3PROTO, 123)
        ct1.set_attr_u16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
        ct2 = nfct.Conntrack()
        ct1.copy(ct2, nfct.NFCT_CP_ALL)
        self.assertEqual(ct2.get_attr_u8(nfct.ATTR_ORIG_L3PROTO), 123)
        self.assertEqual(ct2.get_attr_u16(nfct.ATTR_ORIG_PORT_SRC), 0x1234)
        ct1.destroy()
        ct2.destroy()


    def test_copy_attr(self):
        ct1 = nfct.Conntrack()
        ct1.set_attr_u8(nfct.ATTR_ORIG_L3PROTO, 123)
        ct1.set_attr_u16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
        ct2 = nfct.Conntrack()
        ct1.copy_attr(ct2, nfct.ATTR_ORIG_L3PROTO)
        self.assertEqual(ct2.get_attr_u8(nfct.ATTR_ORIG_L3PROTO), 123)
        try:
            ct2.get_attr_u16(nfct.ATTR_ORIG_PORT_SRC)
        except OSError as e:
            self.assertEqual(e.errno, errno.ENODATA)
        else:
            self.fail("no OSError raise")
        ct1.destroy()
        ct2.destroy()


    def test_parse_build(self):
        ct = nfct.Conntrack()
        nlh = netlink.Nlmsghdr(self.nlmsgbuf10)
        ct.nlmsg_parse(nlh)
        nlh = mnl.Header.put_new_header(1024)
        nlh.type = (nfnl.NFNL_SUBSYS_CTNETLINK << 8) | nfnlct.IPCTNL_MSG_CT_DELETE
        nlh.flags = 0
        nlh.seq = 0
        nlh.portid = 0
        nfh = nlh.put_extra_header_as(nfnl.Nfgenmsg)
        nfh.family = socket.AF_INET
        nfh.version = nfnl.NFNETLINK_V0
        nfh.res_id = 0

        ct.nlmsg_build(nlh)
        self.assertEqual(nlh.marshal_binary(), self.nlmsgbuf11)

    # Conntrack.payload_parse(self, p, l3)


    def test_filter(self):
        try:
            fl = nfct.Filter()
            fl.destroy()
        except Exceptio as e:
            self.fail("could not create or destroy filter: %s" % e)

        try:
            fl = nfct.Filter()
            del fl
        except Exception as e:
            self.fail("could not create or del filter: %s" % e)


    def test_filter_add_attr(self):
        fl = nfct.Filter()
        src4 = nfct.FilterIpv4(addr=0x12345678, mask=0xffff0000)
        try:
            fl.add_attr(nfct.NFCT_FILTER_SRC_IPV4, src4)
        except Exception as e:
            raise
            self.fail("could not add attr to filter: %s" % e)
        try:
            fl.add_attr(nfct.NFCT_FILTER_MAX, src4)
        except OSError as e:
            self.assertEqual(e.errno, errno.EINVAL)
        else:
            self.fail("not raise OSError")


    def test_filter_add_attr_u32(self):
        fl = nfct.Filter()
        try:
            fl.add_attr_u32(nfct.NFCT_FILTER_L4PROTO, 1)
        except Exception as e:
            self.fail("could not add attr to filter: %s" % e)
        try:
            fl.add_attr_u32(nfct.NFCT_FILTER_MAX, 1)
        except OSError as e:
            self.assertEqual(e.errno, errno.EINVAL)
        else:
            self.fail("not raise OSError")


    def test_filter_set_logic(self):
        fl = nfct.Filter()
        try:
            fl.set_logic(nfct.NFCT_FILTER_SRC_IPV4, nfct.NFCT_FILTER_LOGIC_NEGATIVE)
        except Exception as e:
            raise
            self.fail("could not set logic to filter: %s" % e)
        try:
            fl.set_logic(nfct.NFCT_FILTER_DST_IPV4, nfct.NFCT_FILTER_LOGIC_MAX)
        except OSError as e:
            self.assertEqual(e.errno, errno.EINVAL)
        else:
            self.fail("not raise OSError")
        fl.destroy()


    def test_filter_attach(self):
        fl = nfct.Filter()
        with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
            try:
                fl.attach(nl.get_fd())
            except Exception as e:
                self.fail("could not attach filter to fd: %s" % e)
        fl.destroy()


    def test_filter_detach(self):
        with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
            try:
                nfct.Filter.detach(nl.get_fd())
            except OSError as e:
                self.assertEqual(e.errno, errno.ENOENT)
            else:
                self.fail("not raise OSError")
            fl = nfct.Filter()
            fl.attach(nl.get_fd())
            try:
                # nfct.Filter.detach(nl.get_fd())
                fl.detach(nl.get_fd())
            except Exception as e:
                self.fail("could not detatch filter to fd: %s" % e)
            fl.destroy()


    def test_labelmap(self):
        mapfname = os.path.join(os.path.dirname(__file__), "connlabel.conf")
        try:
            lm = nfct.Labelmap(bytes(mapfname.encode("utf-8")))
            lm.destroy()
        except Exception as e:
            raise
            self.fail("could not create or destroy filter dump: %s" % e)
        try:
            lm = nfct.Labelmap(bytes(mapfname.encode("utf-8")))
            del lm
        except Exception as e:
            self.fail("could not create or del filter dump: %s" % e)


    def test_labelmap_get_name(self):
        mapfname = os.path.join(os.path.dirname(__file__), "connlabel.conf")
        lm = nfct.Labelmap(bytes(mapfname.encode("utf-8")))
        self.assertEquals(lm.get_name(3), b"ppp-out")
        self.assertEquals(lm.get_name(11), None)
        lm.destroy()


    def test_label_get_bit(self):
        mapfname = os.path.join(os.path.dirname(__file__), "connlabel.conf")
        lm = nfct.Labelmap(bytes(mapfname.encode("utf-8")))
        self.assertEquals(lm.get_bit(b"ppp-out"), 3)
        self.assertEquals(lm.get_bit(b"abcdefg"), -1)
        lm.destroy()


    def test_bitmask(self):
        try:
            bm = nfct.Bitmask(192)
            bm.destroy()
        except Exception as e:
            self.fail("could not create or destroy filter dump: %s" % e)
        try:
            bm = nfct.Bitmask(192)
            del bm
        except Exception as e:
            self.fail("could not create or del filter dump: %s" % e)


    def test_bitmask_clone(self):
        bm = nfct.Bitmask(192)
        bm.set_bit(1)
        bm.set_bit(11)
        bm.set_bit(111)
        clone = bm.clone()
        self.assertTrue(clone.test_bit(1))
        self.assertTrue(clone.test_bit(11))
        self.assertTrue(clone.test_bit(111))
        self.assertFalse(clone.test_bit(0))
        self.assertFalse(clone.test_bit(10))
        self.assertFalse(clone.test_bit(100))
        bm.destroy()
        

    def test_bitmask_bit(self):
        bm = nfct.Bitmask(8)
        bm.set_bit(7)
        self.assertTrue(bm.test_bit(7))
        self.assertFalse(bm.test_bit(6))
        bm.unset_bit(7)
        self.assertFalse(bm.test_bit(7))
        bm.destroy()


    def test_bitmask_maxbit(self):
        bm = nfct.Bitmask(192)
        self.assertEqual(bm.maxbit(), 192 + 32 - 1)
        bm.destroy()
