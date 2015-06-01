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


@mnl.nlmsg_cb
def data_cb(nlh, data):
    with nfct.Conntrack() as ct:
        ct.nlmsg_parse(nlh)
        print(ct.snprintf(4096, nfct.NFCT_T_UNKNOWN, nfct.NFCT_O_DEFAULT, 0))

    return mnl.MNL_CB_OK


def main():
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    try:
        l = nfct.Labelmap(mapfname)
    except Exception as e:
        log.warn("no labelmap: %s" % e)
        l = None
    cbargs = CbArgs()

    if len(sys.argv) < 2:
        show_labels(l) # not return

    if l is None:
        try:
            cbargs.bit = int(sys.argv[1])
        except Exception as e:
            show_labels(l) # not return
    else:
        cbargs.bit = l.get_bit(sys.argv[1])


    if cbargs.bit < 0:
        print("will clear all labels")
    else:
        print("will set label bit %d" % cbargs.bit)

    nl = sock_nl_create()
    portid = nl.get_portid()

    nlh = mnl.Nlmsg.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_CTNETLINK << 8) | nfnlct.IPCTNL_MSG_CT_GET
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST|netlink.NLM_F_DUMP
    seq = int(time.time())
    nlh.nlmsg_seq = seq

    nfh = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfh.nfgen_family = socket.AF_UNSPEC
    nfh.version = nfnl.NFNETLINK_V0
    nfh.res_id = 0

    nl.send_nlmsg(nlh)

    ret = nl.recv_into(buf)

    cbargs.nl = sock_nl_create()
    cbargs.seq = seq

    while ret > 0:
        ret = mnl.cb_run(buf[:ret], seq, portid, data_cb, cbargs)
        if ret <= mnl.MNL_CB_STOP:
            break
        ret = nl.recv_into(buf)

    # if ret == -1 ... is not needed because cb_run raises OSError in the case

    if l is not None:
        l.destroy()
    nl.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        # format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
                        format='%(asctime)s %(levelname)s: %(message)s')
    main()
