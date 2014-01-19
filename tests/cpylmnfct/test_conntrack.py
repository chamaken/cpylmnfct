# -*- coding: utf-8 -*-

from __future__ import print_function

import sys, unittest
import struct, socket, ipaddr

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl as mnl

import cpylmnfct as nfct

class TestSuite(unittest.TestCase):
    def setUp(self):
        self.nlmsgbuf1 = bytearray([
					# ----------------	------------------
                0xc4, 0x00, 0x00, 0x00,	# |  0000000196  |	| message length |
                0x02, 0x01, 0x00, 0x00,	# | 00258 | ---- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	|     port ID    |
					# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0x01, 0x02, 0x03, 0x04,	# | 01 02 03 04  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0xff, 0xfe, 0xfd, 0xfc,	# | ff fe fd fc  |	|      data      |	  - CTA_TUPLE_IP
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0xf8, 0x8f, 0x00, 0x00,	# | f8 8f 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0x00, 0x35, 0x00, 0x00,	# | 00 35 00 00  |	|      data      |	  - CTA_TUPLE_PROTO
					#						- CTA_TUPLE_ORIG
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|	+ CTA_TUPLE_REPLY
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
                0xff, 0xfe, 0xfd, 0xfc,	# | ff fe fd fc  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
                0x01, 0x02, 0x03, 0x04,	# | 01 02 03 04  |	|      data      |	  - CTA_TUPLE_IP
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
                0x00, 0x35, 0x00, 0x00,	# | 00 35 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
                0xf8, 0x8f, 0x00, 0x00,	# | f8 8f 00 00  |	|      data      |	  - CTA_TUPLE_PROTO
					#						- CTA_TUPLE_REPLY
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|	CTA_ID
                0x17, 0x6d, 0x0d, 0x78,	# | 17 6d 0d 78  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|	CTA_STATUS
                0x00, 0x00, 0x00, 0x08,	# | 00 00 00 08  |	|      data      |	  IPS_CONFIRMED
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|	+ CTA_COUNTERS_ORIG
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|	  CTA_CONTERS_BYTES
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |	- CTA_CONTERS_ORIG
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|	+ CTA_COUNTERS_REPLY
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|	  CTA_CONTERS_BYTES
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                ])                      # ----------------	------------------

        self.nlmsgbuf2 = bytearray([
					# ----------------	------------------
                0xdc, 0x00, 0x00, 0x00,	# |  0000000220  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
					# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|	  + 
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x85, 0x9a, 0xb2, 0xf7,	# | 85 9a b2 f7  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x85, 0x9a, 0xb2, 0xf7,	# | 85 9a b2 f7  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x99,	# | 00 00 00 99  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x15, 0x50, 0xb8, 0xb8,	# | 15 50 b8 b8  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
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
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x86,	# | 0a 60 fe 86  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x00, 0x33, 0x85,	# | 0a 00 33 85  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0xc1, 0x79, 0x00, 0x00,	# | c1 79 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x01, 0xbd, 0x00, 0x00,	# | 01 bd 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x00, 0x33, 0x85,	# | 0a 00 33 85  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x86,	# | 0a 60 fe 86  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x01, 0xbd, 0x00, 0x00,	# | 01 bd 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0xc1, 0x79, 0x00, 0x00,	# | c1 79 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x06, 0x97, 0x65,	# | 00 06 97 65  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x30, 0x00, 0x04, 0x80,	# |00048|N-|00004|	|len |flags| type|
                0x2c, 0x00, 0x01, 0x80,	# |00044|N-|00001|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x03, 0x00, 0x00, 0x00,	# | 03 00 00 00  |	|      data      |
                0x05, 0x00, 0x02, 0x00,	# |00005|--|00002|	|len |flags| type|
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|      data      |
                0x05, 0x00, 0x03, 0x00,	# |00005|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x06, 0x00, 0x04, 0x00,	# |00006|--|00004|	|len |flags| type|
                0x23, 0x00, 0x00, 0x00,	# | 23 00 00 00  |	|      data      |
                0x06, 0x00, 0x05, 0x00,	# |00006|--|00005|	|len |flags| type|
                0x23, 0x00, 0x00, 0x00,	# | 23 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x14, 0xcc, 0x56, 0x58,	# | 14 cc 56 58  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
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
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x05, 0x35, 0x1d,	# | 0a 05 35 1d  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0xc1,	# | 0a 60 fe c1  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0xca, 0xda, 0x00, 0x00,	# | ca da 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x02, 0x02, 0x00, 0x00,	# | 02 02 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0xc1,	# | 0a 60 fe c1  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x05, 0x35, 0x1d,	# | 0a 05 35 1d  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x02, 0x02, 0x00, 0x00,	# | 02 02 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0xca, 0xda, 0x00, 0x00,	# | ca da 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x08,	# | 00 00 00 08  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x13,	# | 00 00 00 13  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x12, 0xd5, 0x69, 0xe8,	# | 12 d5 69 e8  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
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
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|                
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x85, 0x9a, 0xa6, 0xf2,	# | 85 9a a6 f2  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x85, 0x9a, 0xa6, 0xf2,	# | 85 9a a6 f2  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0a,	# | 00 00 00 0a  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x09,	# | 00 00 00 09  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x17, 0x30, 0x10, 0x68,	# | 17 30 10 68  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
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
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|                
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xc8, 0x9e,	# | 0a 60 c8 9e  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xc8, 0x9e,	# | 0a 60 c8 9e  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x06,	# | 00 00 00 06  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x17, 0x20, 0xb0, 0x68,	# | 17 20 b0 68  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
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
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x89,	# | 0a 60 fe 89  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0xac, 0x11, 0x24, 0xc8,	# | ac 11 24 c8  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0xc6, 0x35, 0x00, 0x00,	# | c6 35 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x00, 0x50, 0x00, 0x00,	# | 00 50 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0xac, 0x11, 0x24, 0xc8,	# | ac 11 24 c8  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x89,	# | 0a 60 fe 89  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x00, 0x50, 0x00, 0x00,	# | 00 50 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0xc6, 0x35, 0x00, 0x00,	# | c6 35 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x08,	# | 00 00 00 08  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x62,	# | 00 00 00 62  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x30, 0x00, 0x04, 0x80,	# |00048|N-|00004|	|len |flags| type|
                0x2c, 0x00, 0x01, 0x80,	# |00044|N-|00001|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x01, 0x00, 0x00, 0x00,	# | 01 00 00 00  |	|      data      |
                0x05, 0x00, 0x02, 0x00,	# |00005|--|00002|	|len |flags| type|
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|      data      |
                0x05, 0x00, 0x03, 0x00,	# |00005|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x06, 0x00, 0x04, 0x00,	# |00006|--|00004|	|len |flags| type|
                0x03, 0x00, 0x00, 0x00,	# | 03 00 00 00  |	|      data      |
                0x06, 0x00, 0x05, 0x00,	# |00006|--|00005|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x17, 0x1f, 0xa9, 0xe8,	# | 17 1f a9 e8  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
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
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x85, 0x9a, 0x4b, 0xf1,	# | 85 9a 4b f1  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0xa1,	# | 0a 60 fe a1  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x0f, 0x49, 0x00, 0x00,	# | 0f 49 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x01, 0x01, 0x00, 0x00,	# | 01 01 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0xa1,	# | 0a 60 fe a1  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x85, 0x9a, 0x4b, 0xf1,	# | 85 9a 4b f1  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x01, 0x01, 0x00, 0x00,	# | 01 01 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x0f, 0x49, 0x00, 0x00,	# | 0f 49 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x52,	# | 00 00 00 52  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x30, 0x00, 0x04, 0x80,	# |00048|N-|00004|	|len |flags| type|
                0x2c, 0x00, 0x01, 0x80,	# |00044|N-|00001|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x07, 0x00, 0x00, 0x00,	# | 07 00 00 00  |	|      data      |
                0x05, 0x00, 0x02, 0x00,	# |00005|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x05, 0x00, 0x03, 0x00,	# |00005|--|00003|	|len |flags| type|
                0x07, 0x00, 0x00, 0x00,	# | 07 00 00 00  |	|      data      |
                0x06, 0x00, 0x04, 0x00,	# |00006|--|00004|	|len |flags| type|
                0x21, 0x00, 0x00, 0x00,	# | 21 00 00 00  |	|      data      |
                0x06, 0x00, 0x05, 0x00,	# |00006|--|00005|	|len |flags| type|
                0x25, 0x00, 0x00, 0x00,	# | 25 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x17, 0x1f, 0xa0, 0x68,	# | 17 1f a0 68  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                			# ----------------	------------------
                			#
                			# ----------------	------------------
                0xec, 0x00, 0x00, 0x00,	# |  0000000236  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
					# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x3c, 0x00, 0x01, 0x80,	# |00060|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0x65, 0x01,	# | 0a 60 65 01  |	|      data      |
                0x24, 0x00, 0x02, 0x80,	# |00036|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x01, 0x00, 0x00, 0x00,	# | 01 00 00 00  |	|      data      |
                0x06, 0x00, 0x04, 0x00,	# |00006|--|00004|	|len |flags| type|
                0xd2, 0x04, 0x00, 0x00,	# | d2 04 00 00  |	|      data      |
                0x05, 0x00, 0x05, 0x00,	# |00005|--|00005|	|len |flags| type|
                0x08, 0x00, 0x00, 0x00,	# | 08 00 00 00  |	|      data      |
                0x05, 0x00, 0x06, 0x00,	# |00005|--|00006|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x3c, 0x00, 0x02, 0x80,	# |00060|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0x65, 0x01,	# | 0a 60 65 01  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x24, 0x00, 0x02, 0x80,	# |00036|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x01, 0x00, 0x00, 0x00,	# | 01 00 00 00  |	|      data      |
                0x06, 0x00, 0x04, 0x00,	# |00006|--|00004|	|len |flags| type|
                0xd2, 0x04, 0x00, 0x00,	# | d2 04 00 00  |	|      data      |
                0x05, 0x00, 0x05, 0x00,	# |00005|--|00005|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x05, 0x00, 0x06, 0x00,	# |00005|--|00006|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0a,	# | 00 00 00 0a  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x17, 0x23, 0xc1, 0x98,	# | 17 23 c1 98  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                			# ----------------	------------------
					#
					# ----------------	------------------
                0xec, 0x00, 0x00, 0x00,	# |  0000000236  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
 					# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x3c, 0x00, 0x01, 0x80,	# |00060|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x08, 0xfb, 0x05,	# | 0a 08 fb 05  |	|      data      |
                0x24, 0x00, 0x02, 0x80,	# |00036|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x01, 0x00, 0x00, 0x00,	# | 01 00 00 00  |	|      data      |
                0x06, 0x00, 0x04, 0x00,	# |00006|--|00004|	|len |flags| type|
                0xd2, 0x04, 0x00, 0x00,	# | d2 04 00 00  |	|      data      |
                0x05, 0x00, 0x05, 0x00,	# |00005|--|00005|	|len |flags| type|
                0x08, 0x00, 0x00, 0x00,	# | 08 00 00 00  |	|      data      |
                0x05, 0x00, 0x06, 0x00,	# |00005|--|00006|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x3c, 0x00, 0x02, 0x80,	# |00060|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x08, 0xfb, 0x05,	# | 0a 08 fb 05  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x24, 0x00, 0x02, 0x80,	# |00036|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x01, 0x00, 0x00, 0x00,	# | 01 00 00 00  |	|      data      |
                0x06, 0x00, 0x04, 0x00,	# |00006|--|00004|	|len |flags| type|
                0xd2, 0x04, 0x00, 0x00,	# | d2 04 00 00  |	|      data      |
                0x05, 0x00, 0x05, 0x00,	# |00005|--|00005|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x05, 0x00, 0x06, 0x00,	# |00005|--|00006|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0a,	# | 00 00 00 0a  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x05,	# | 00 00 00 05  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x17, 0x20, 0xb1, 0x98,	# | 17 20 b1 98  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
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
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x84,	# | 0a 60 fe 84  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x00, 0x33, 0x14,	# | 0a 00 33 14  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x0f, 0xaa, 0x00, 0x00,	# | 0f aa 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0xe8, 0xcb, 0x00, 0x00,	# | e8 cb 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x00, 0x33, 0x14,	# | 0a 00 33 14  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x84,	# | 0a 60 fe 84  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0xe8, 0xcb, 0x00, 0x00,	# | e8 cb 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x0f, 0xaa, 0x00, 0x00,	# | 0f aa 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x06, 0x97, 0x45,	# | 00 06 97 45  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x30, 0x00, 0x04, 0x80,	# |00048|N-|00004|	|len |flags| type|
                0x2c, 0x00, 0x01, 0x80,	# |00044|N-|00001|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x03, 0x00, 0x00, 0x00,	# | 03 00 00 00  |	|      data      |
                0x05, 0x00, 0x02, 0x00,	# |00005|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x05, 0x00, 0x03, 0x00,	# |00005|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x06, 0x00, 0x04, 0x00,	# |00006|--|00004|	|len |flags| type|
                0x22, 0x00, 0x00, 0x00,	# | 22 00 00 00  |	|      data      |
                0x06, 0x00, 0x05, 0x00,	# |00006|--|00005|	|len |flags| type|
                0x22, 0x00, 0x00, 0x00,	# | 22 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x17, 0x70, 0x55, 0x28,	# | 17 70 55 28  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                			# ----------------	------------------
                			# 
                			# ---------------	------------------ 
                0xdc, 0x00, 0x00, 0x00,	# |  0000000220  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
					# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xc8, 0x71,	# | 0a 60 c8 71  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xc8, 0x71,	# | 0a 60 c8 71  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x34,	# | 00 00 00 34  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x12, 0xc8, 0xb7, 0x88,	# | 12 c8 b7 88  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                			# ----------------	------------------
                			#
					# 
                			# 
                			# ----------------	------------------
                0xdc, 0x00, 0x00, 0x00,	# |  0000000220  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
                			# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x85, 0x9a, 0xb0, 0xf5,	# | 85 9a b0 f5  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x85, 0x9a, 0xb0, 0xf5,	# | 85 9a b0 f5  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0a,	# | 00 00 00 0a  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0a,	# | 00 00 00 0a  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x17, 0x40, 0xf2, 0xc8,	# | 17 40 f2 c8  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
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
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xc8, 0x70,	# | 0a 60 c8 70  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xc8, 0x70,	# | 0a 60 c8 70  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x3b,	# | 00 00 00 3b  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x00, 0x18, 0x29, 0xe8,	# | 00 18 29 e8  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                			# ----------------	------------------
                			#
                			# ----------------	------------------
                0x0c, 0x01, 0x00, 0x00, # |  0000000268  |	| message length |
                0x00, 0x01, 0x02, 0x00,	# | 00256 | -M-- |	|  type | flags  |
                0x00, 0x00, 0x00, 0x00,	# |  0000000000  |	| sequence number|
                0xca, 0x24, 0x00, 0x00,	# |  0000009418  |	|     port ID    |
					# ----------------	------------------
                0x02, 0x00, 0x00, 0x00,	# | 02 00 00 00  |	|  extra header  |
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0xac, 0x10, 0x51, 0x13,	# | ac 10 51 13  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0xc1,	# | 0a 60 fe c1  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0xea, 0xf6, 0x00, 0x00,	# | ea f6 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x00, 0x50, 0x00, 0x00,	# | 00 50 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0xc1,	# | 0a 60 fe c1  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0xac, 0x10, 0x51, 0x13,	# | ac 10 51 13  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x06, 0x00, 0x00, 0x00,	# | 06 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x00, 0x50, 0x00, 0x00,	# | 00 50 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0xea, 0xf6, 0x00, 0x00,	# | ea f6 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0x6f,	# | 00 00 00 6f  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x30, 0x00, 0x04, 0x80,	# |00048|N-|00004|	|len |flags| type|
                0x2c, 0x00, 0x01, 0x80,	# |00044|N-|00001|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x07, 0x00, 0x00, 0x00,	# | 07 00 00 00  |	|      data      |
                0x05, 0x00, 0x02, 0x00,	# |00005|--|00002|	|len |flags| type|
                0x08, 0x00, 0x00, 0x00,	# | 08 00 00 00  |	|      data      |
                0x05, 0x00, 0x03, 0x00,	# |00005|--|00003|	|len |flags| type|
                0x07, 0x00, 0x00, 0x00,	# | 07 00 00 00  |	|      data      |
                0x06, 0x00, 0x04, 0x00,	# |00006|--|00004|	|len |flags| type|
                0x27, 0x00, 0x00, 0x00,	# | 27 00 00 00  |	|      data      |
                0x06, 0x00, 0x05, 0x00,	# |00006|--|00005|	|len |flags| type|
                0x23, 0x00, 0x00, 0x00,	# | 23 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x17, 0x44, 0xfe, 0xa8,	# | 17 44 fe a8  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
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
                0x34, 0x00, 0x01, 0x80,	# |00052|N-|00001|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xc8, 0xd8,	# | 0a 60 c8 d8  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x34, 0x00, 0x02, 0x80,	# |00052|N-|00002|	|len |flags| type|
                0x14, 0x00, 0x01, 0x80,	# |00020|N-|00001|	|len |flags| type|
                0x08, 0x00, 0x01, 0x00,	# |00008|--|00001|	|len |flags| type|
                0x0a, 0x60, 0xc8, 0xd8,	# | 0a 60 c8 d8  |	|      data      |
                0x08, 0x00, 0x02, 0x00,	# |00008|--|00002|	|len |flags| type|
                0x0a, 0x60, 0xfe, 0x92,	# | 0a 60 fe 92  |	|      data      |
                0x1c, 0x00, 0x02, 0x80,	# |00028|N-|00002|	|len |flags| type|
                0x05, 0x00, 0x01, 0x00,	# |00005|--|00001|	|len |flags| type|
                0x11, 0x00, 0x00, 0x00,	# | 11 00 00 00  |	|      data      |
                0x06, 0x00, 0x02, 0x00,	# |00006|--|00002|	|len |flags| type|
                0x00, 0xa1, 0x00, 0x00,	# | 00 a1 00 00  |	|      data      |
                0x06, 0x00, 0x03, 0x00,	# |00006|--|00003|	|len |flags| type|
                0x04, 0x64, 0x00, 0x00,	# | 04 64 00 00  |	|      data      |
                0x08, 0x00, 0x03, 0x00,	# |00008|--|00003|	|len |flags| type|
                0x00, 0x00, 0x00, 0x0e,	# | 00 00 00 0e  |	|      data      |
                0x08, 0x00, 0x07, 0x00,	# |00008|--|00007|	|len |flags| type|
                0x00, 0x00, 0x00, 0xa4,	# | 00 00 00 a4  |	|      data      |
                0x1c, 0x00, 0x09, 0x80,	# |00028|N-|00009|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x1c, 0x00, 0x0a, 0x80,	# |00028|N-|00010|	|len |flags| type|
                0x0c, 0x00, 0x01, 0x00,	# |00012|--|00001|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x0c, 0x00, 0x02, 0x00,	# |00012|--|00002|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x08, 0x00,	# |00008|--|00008|	|len |flags| type|
                0x00, 0x00, 0x00, 0x00,	# | 00 00 00 00  |	|      data      |
                0x08, 0x00, 0x0c, 0x00,	# |00008|--|00012|	|len |flags| type|
                0x15, 0x96, 0xd7, 0x88,	# | 15 96 d7 88  |	|      data      |
                0x08, 0x00, 0x0b, 0x00,	# |00008|--|00011|	|len |flags| type|
                0x00, 0x00, 0x00, 0x01,	# | 00 00 00 01  |	|      data      |
                ])                      # ----------------	------------------
                
    def test_conntrack_nlmsg_parse(self):
        nlh1 = netlink.Nlmsghdr(self.nlmsgbuf1)
        ct1 = nfct.conntrack_new()
        nfct.conntrack_nlmsg_parse(nlh1, ct1)
        orig_ipv4_src = socket.inet_ntoa(struct.pack("i", nfct.conntrack_get_attr_u32(ct1, nfct.ATTR_ORIG_IPV4_SRC)))
        orig_ipv4_dst = socket.inet_ntoa(struct.pack("i", nfct.conntrack_get_attr_u32(ct1, nfct.ATTR_ORIG_IPV4_DST)))
        orig_port_src = nfct.conntrack_get_attr_u16(ct1, nfct.ATTR_ORIG_PORT_SRC)
        orig_port_dst = nfct.conntrack_get_attr_u16(ct1, nfct.ATTR_ORIG_PORT_DST)
        orig_proto = nfct.conntrack_get_attr_u8(ct1, nfct.ATTR_ORIG_L4PROTO)
        print("%s:%04x > (%d) > %s:%04x" % (orig_ipv4_src, orig_port_src, orig_proto,
                                            orig_ipv4_dst, orig_port_dst), file=sys.stderr)

        repl_ipv4_src = socket.inet_ntoa(struct.pack("i", nfct.conntrack_get_attr_u32(ct1, nfct.ATTR_REPL_IPV4_SRC)))
        repl_ipv4_dst = socket.inet_ntoa(struct.pack("i", nfct.conntrack_get_attr_u32(ct1, nfct.ATTR_REPL_IPV4_DST)))
        repl_port_src = nfct.conntrack_get_attr_u16(ct1, nfct.ATTR_REPL_PORT_SRC)
        repl_port_dst = nfct.conntrack_get_attr_u16(ct1, nfct.ATTR_REPL_PORT_DST)
        repl_proto = nfct.conntrack_get_attr_u8(ct1, nfct.ATTR_REPL_L4PROTO)
        print("%s:%04x > (%d) < %s:%04x" % (repl_ipv4_src, repl_port_src, repl_proto,
                                            repl_ipv4_dst, repl_port_dst), file=sys.stderr)


        nlh2 = netlink.Nlmsghdr(self.nlmsgbuf2)
        ct2 = nfct.conntrack_new()
        mnl.nlmsg_fprint(self.nlmsgbuf2, nfnl.Nfgenmsg.sizeof(), out=sys.stderr)



        # Conntrack.__init__(ct=None)
        # Conntrack.destroy(self)
        # Conntrack.__del__(self)
        # Conntrack.clone(self)
        # Conntrack.setobjopt(self, o)
        # Conntrack.getobjopt(self, o)
        # Conntrack.set_attr_l(self, a, v)
        # Conntrack.set_attr(self, a, v)
        # Conntrack.set_attr_u8(self, a, v)
        # Conntrack.set_attr_u16(self, a, v)
        # Conntrack.set_attr_u32(self, a, v)
        # Conntrack.set_attr_u64(self, a, v)
        # Conntrack.get_attr(self, a)
        # Conntrack.get_attr_as(self, a, c)
        # Conntrack.get_attr_u8(self, a)
        # Conntrack.get_attr_u16(self, a)
        # Conntrack.get_attr_u32(self, a)
        # Conntrack.get_attr_u64(self, a)
        # Conntrack.attr_is_set(self, a)
        # Conntrack.attr_is_set_array(self, l)
        # Conntrack.attr_unset(self, a)
        # Conntrack.set_attr_grp(self, a, d)
        # Conntrack.get_attr_grp(self, a, d)
        # Conntrack.get_attr_grp_as(self, a, c)
        # Conntrack.attr_grp_is_set(self, a)
        # Conntrack.attr_grp_unset(self, a)
        # Conntrack.snprintf(self, s, m, o, f)
        # Conntrack.snprintf_labels(self, s, m, o, f, l)
        # Conntrack.compare(self, ct2)
        # Conntrack.cmp(self, ct2, f)
        # Conntrack.copy(self, ct2, f)
        # Conntrack.copy_attr(self, ct2, t)

        # Conntrack.nlmsg_build(self, nlh)
        # Conntrack.nlmsg_parse(self, nlh)
        # Conntrack.payload_parse(self, p, l3)


        # Filter.__init__(self, filter=None)
	# Filter.destroy(self)
        # Filter.__del__(self)
        # Filter.add_attr(self, a, v)
        # Filter.add_attr_u32(self, a, v)
        # Filter.set_logic(self, a, l)
        # Filter.attach(self, fd)
        # Filter.detatch(fd)


	# FilterDump.__init__(self, filter_dump=None)
	# FilterDump.destroy(self)
	# FilterDump.__del__(self)
	# FilterDump.set_attr(self, a, v)
	# FilterDump.set_attr_u8(self, a, v)


	# Labelmap.__init__(self, labelmap=None)
	# Labelmap.destroy(self)
	# Labelmap.get_name(self, bit)
	# Labelmap.get_bit(self, name)


	# Bitmask.__init__(self, high, bitmask=None)
	# Bitmask.destroy(self)
	# Bitmask.__del__(self)
	# Bitmask.clone(self)
	# Bitmask.set_bit(self, bit)
	# Bitmask.test_bit(self, bit)
	# Bitmask.unset_bit(self, bit)
	# Bitmask.maxbit(self)


	# Expect.__init__(self, exp=None)
	# Expect.destroy(self)
	# Expect.__del__(self)
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
