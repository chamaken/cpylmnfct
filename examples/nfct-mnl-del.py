#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, socket, logging
import time, ipaddr

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_conntrackh as nfnlct
import cpylmnl.linux.netfilter.nf_conntrack_tcph as nfct_tcp
import cpylmnl as mnl
import cpylmnfct as nfct


log = logging.getLogger(__name__)


def main():
    nl = mnl.Socket(netlink.NETLINK_NETFILTER)
    nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
    portid = nl.get_portid()

    nlh = mnl.Header.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh.type = (nfnl.NFNL_SUBSYS_CTNETLINK << 8) | nfnlct.IPCTNL_MSG_CT_DELETE
    nlh.flags = netlink.NLM_F_REQUEST|netlink.NLM_F_CREATE|netlink.NLM_F_EXCL|netlink.NLM_F_ACK
    seq = int(time.time())
    nlh.seq = seq

    nfh = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfh.family = socket.AF_INET
    nfh.version = nfnl.NFNETLINK_V0
    nfh.res_id = 0

    ct = nfct.Conntrack()
    ct.set_attr_u8(nfct.ATTR_L3PROTO, socket.AF_INET)
    ct.set_attr_u32(nfct.ATTR_IPV4_SRC, int(ipaddr.IPv4Address("1.1.1.1")))
    ct.set_attr_u32(nfct.ATTR_IPV4_DST, int(ipaddr.IPv4Address("2.2.2.2")))

    ct.set_attr_u8(nfct.ATTR_L4PROTO, socket.IPPROTO_TCP)
    ct.set_attr_u16(nfct.ATTR_PORT_SRC, socket.htons(20))
    ct.set_attr_u16(nfct.ATTR_PORT_DST, socket.htons(10))

    ct.nlmsg_build(nlh)

    nl.send_nlmsg(nlh)
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    ret = nl.recv_into(buf)
    while ret > 0:
        ret = mnl.cb_run(buf[:ret], seq, portid, None, None)
        if ret <= mnl.MNL_CB_STOP:
            break
        ret = nl.recv_into(buf)

    # if ret == mnl.MNL_CB_ERROR - not needed, cb_run raise OSError in the case
    nl.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        # format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
                        format='%(asctime)s %(levelname)s: %(message)s')
    main()
