#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, socket, logging, time

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_compath as nfnl_compat
import cpylmnl.linux.netfilter.nfnetlink_conntrackh as nfnlct
import cpylmnl as mnl
import cpylmnfct as nfct


log = logging.getLogger(__name__)


@mnl.header_cb
def data_cb(nlh, data):
    mtype = nfct.NFCT_T_UNKNOWN
    htype = nlh.type & 0xFF

    if htype == nfnlct.IPCTNL_MSG_CT_NEW:
        if nlh.flags & (netlink.NLM_F_CREATE|netlink.NLM_F_EXCL) != 0:
            mtype = nfct.NFCT_T_NEW
        else:
            mtype = nfct.NFCT_T_UPDATE
    elif htype == nfnlct.IPCTNL_MSG_CT_DELETE:
        mtype = nfct.NFCT_T_DESTROY

    with nfct.Conntrack() as ct:
        ct.nlmsg_parse(nlh)
        print(ct.snprintf(4096, mtype, nfct.NFCT_O_DEFAULT, 0))

    return mnl.MNL_CB_OK


def main():
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)

    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        nl.bind(nfnl_compat.NF_NETLINK_CONNTRACK_NEW |\
                    nfnl_compat.NF_NETLINK_CONNTRACK_UPDATE |\
                    nfnl_compat.NF_NETLINK_CONNTRACK_DESTROY,
                mnl.MNL_SOCKET_AUTOPID)
        while True:
            ret = nl.recv_into(buf)
            ret = mnl.cb_run(buf[:ret], 0, 0, data_cb, None)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        # format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
                        format='%(asctime)s %(levelname)s: %(message)s')
    main()
