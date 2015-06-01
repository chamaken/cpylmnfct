#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, socket, logging, time

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_conntrackh as nfnlct
import cpylmnl as mnl
import cpylmnfct as nfct


log = logging.getLogger(__name__)


def main():
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)

    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()

        nlh = mnl.Nlmsg.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
        nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_CTNETLINK << 8) | nfnlct.IPCTNL_MSG_CT_DELETE
        nlh.nlmsg_flags = netlink.NLM_F_REQUEST|netlink.NLM_F_ACK
        seq = int(time.time())
        nlh.nlmsg_seq = seq

        nfh = nlh.put_extra_header_as(nfnl.Nfgenmsg)
        nfh.nfgen_family = socket.AF_INET
        nfh.version = nfnl.NFNETLINK_V0
        nfh.res_id = 0

        nl.send_nlmsg(nlh)

        ret = nl.recv_into(buf)
        while ret > 0:
            ret = mnl.cb_run(buf[:ret], seq, portid, None, None)
            if ret <= mnl.MNL_CB_STOP:
                break
            ret = nl.recv_into(buf)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        # format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
                        format='%(asctime)s %(levelname)s: %(message)s')
    main()
