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
mapfname = "../tests/cpylmnfct/connlabel.conf"


def print_label(ct, labelmap):
    try:
        b = nfct.Bitmask(0, ct.get_attr(nfct.ATTR_CONNLABELS))
    except OSError as e:
        return

    print("labels:")
    maxbit = b.maxbit()
    for i in range(maxbit):
        if b.test_bit(i):
            if labelmap is None:
                name = ""
            else:
                name = labelmap.get_name(i)
            print("\t'%s' (%d)" % (name, i))


@mnl.header_cb
def data_cb(nlh, data):
    ct = nfct.Conntrack()
    ct.nlmsg_parse(nlh)

    buf = ct.snprintf(4096, nfct.NFCT_T_UNKNOWN, nfct.NFCT_O_DEFAULT, 0)

    print("%s" % buf)
    print_label(ct, data)

    ct.destroy()
    return mnl.MNL_CB_OK


def main():
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    l = nfct.Labelmap(mapfname)

    nl = mnl.Socket(netlink.NETLINK_NETFILTER)
    nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
    portid = nl.get_portid()

    nlh = mnl.Header.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh.type = (nfnl.NFNL_SUBSYS_CTNETLINK << 8) | nfnlct.IPCTNL_MSG_CT_GET
    nlh.flags = netlink.NLM_F_REQUEST|netlink.NLM_F_DUMP
    seq = int(time.time())
    nlh.seq = seq

    nfh = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfh.family = socket.AF_UNSPEC
    nfh.version = nfnl.NFNETLINK_V0
    nfh.res_id = 0

    nl.send_nlmsg(nlh)

    ret = nl.recv_into(buf)
    while ret > 0:
        ret = mnl.cb_run(buf[:ret], seq, portid, data_cb, l)
        if ret <= mnl.MNL_CB_STOP:
            break
        ret = nl.recv_into(buf)

    l.destroy()
    nl.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        # format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
                        format='%(asctime)s %(levelname)s: %(message)s')
    main()
