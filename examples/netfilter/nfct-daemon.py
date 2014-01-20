#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, logging, socket, time, struct, select
import ipaddr, ctypes, errno, signal
import cPickle as pickle

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_conntrackh as nfnlct
import cpylmnl.linux.netfilter.nfnetlink_compath as nfnlcm
import cpylmnl as mnl
import cpylmnfct as nfct


log = logging.getLogger(__name__)
CARBON_SERVER = '192.168.1.1'
CARBON_PORT = 2004
nl_sock = None
send_nlh = None
send_sock = None


class Tuple(object):
    def __init__(self, l3, server, client, l4, port=0):
        self.l3proto = l3
        self.server = server	# big endian byte[4 or 16]
        self.client = client	# big endian byte[4 or 16]
        self.l4proto = l4
        self.port = port


class Counter(object):
    def __init__(self, pkts, b):
        self.pkts = pkts
        self.bytes = b
        self.deleting = False

nstats = dict() # {Tuple: Counter}


def make_tuple(ct):
    l3proto = ct.get_attr_u8(nfct.ATTR_L3PROTO)
    l4proto = ct.get_attr_u8(nfct.ATTR_L4PROTO)

    if l3proto == socket.AF_INET:
        # I don't know why bytearray needed (*1)
        server = bytearray(ct.get_attr_as(nfct.ATTR_IPV4_DST, (ctypes.c_ubyte * 4)))
        client = bytearray(ct.get_attr_as(nfct.ATTR_IPV4_SRC, (ctypes.c_ubyte * 4)))
        # (*1) get addresses properly
    elif l3proto == socket.AF_INET6:
        server = bytearray(ct.get_attr_as(nfct.ATTR_IPV6_DST, (ctypes.c_ubyte * 16)))
        client = bytearray(ct.get_attr_as(nfct.ATTR_IPV6_SRC, (ctypes.c_ubyte * 16)))
    else:
        return nil, errno.EPROTONOSUPPORT

    if l4proto == socket.IPPROTO_ICMP:
        port = ct.get_attr_u8(nfct.ATTR_ICMP_TYPE)
    elif l4proto in (socket.IPPROTO_TCP, socket.IPPROTO_UDP,
                     # socket.IPPROTO_DCCP, socket.IPPROTO_SCTP, socket.IPPROTO_UDPLITE
                     ):
        port = ct.get_attr_u16(nfct.ATTR_PORT_DST)
    else:
        port = 0

    return Tuple(l3proto, server, client, l4proto, port)


@mnl.header_cb
def data_cb(nlh, data):
    ct = nfct.Conntrack()
    ct.nlmsg_parse(nlh)

    orig_packets = ct.get_attr_u64(nfct.ATTR_ORIG_COUNTER_PACKETS)
    repl_packets = ct.get_attr_u64(nfct.ATTR_REPL_COUNTER_PACKETS)
    orig_bytes = ct.get_attr_u64(nfct.ATTR_ORIG_COUNTER_BYTES)
    repl_bytes = ct.get_attr_u64(nfct.ATTR_REPL_COUNTER_BYTES)

    if orig_packets + repl_packets == 0:
        return mnl.MNL_CB_OK

    t = make_tuple(ct)
    counter = nstats.setdefault(t, Counter(0, 0))
    counter.pkts += orig_packets + repl_packets
    counter.bytes += orig_bytes + repl_bytes

    if nlh.type & 0xff == nfnlct.IPCTNL_MSG_CT_DELETE:
        counter.deleting = True

    # (*1) get addresses properly
    # print("server: %s, client: %s" % (".".join(["%d" % i for i in t.server]), ".".join(["%d" % i for i in t.client])))
    return mnl.MNL_CB_OK


def handle(nl):
    try:
        buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
    except OSError as e:
        if e.errno == ENOBUFS:
            print("The daemon has hit ENOBUFS, you can " \
                      + "increase the size of your receiver " \
                      + "buffer to mitigate this or enable " \
                      + "reliable delivery.",
                  file=sys.stderr)
        else:
            print("mnl_socket_recvfrom: %s" % e)
        return -1

    try:
        ret = mnl.cb_run(buf, 0, 0, data_cb, None)
    except OSError as e:
        print("mnl_cb_run: %s" % e, file=sys.stderr)
        return -1
    if ret <= mnl.MNL_CB_STOP:
        return 0

    return 0


def alarm_handler(signum, frame):
    global nl_sock
    global send_nlh
    global send_sock

    # ... request a fresh dump of the table from kernel
    nl_sock.send_nlmsg(send_nlh)

    deleting_keys = []
    now = int(time.time())
    listOfMetricTuples = []

    for k, v in nstats.iteritems():
        # (*1) can not get proper addresses
        # print("server: %s, client: %s" % (".".join(["%d" % i for i in k.server]), ".".join(["%d" % i for i in k.client])))
        if v.pkts == 0: continue

        if k.l4proto == socket.IPPROTO_ICMP:
            l4 = "ICMP.%d" % k.port
        elif k.l4proto == socket.IPPROTO_TCP:
            l4 = "TCP.%d" % socket.ntohs(k.port)
        elif k.l4proto == socket.IPPROTO_UDP:
            l4 = "UDP.%d" % socket.ntohs(k.port)
        else:
            l4 = "unknown.%d" % k.l4proto

        if k.l3proto == socket.AF_INET:
            path = ".".join([":".join(["%d" % i for i in k.server]),
                             "%s" % l4,
                             ":".join(["%d" % i for i in k.client])])
        elif k.l4proto == socket.AF_INET6:
            path = ".".join([":".join(["%x%x" % (k.server[i], k.server[i + 1]) for i in range(0, len(k.server), 2)]),
                             "%s" % l4,
                             ":".join(["%x%x" % (k.client[i], k.client[i + 1]) for i in range(0, len(k.client), 2)])])
            
        t = (path, (now, v.bytes))
        listOfMetricTuples.append(t)
        v.pkts = 0
        v.bytes = 0
        if v.deleting:
            deleting_keys.append(k)

    payload = pickle.dumps(listOfMetricTuples)
    header = struct.pack("!L", len(payload))
    message = header + payload
    # should catch EINTR?
    send_sock.sendall(message)

    for k in deleting_keys: del nstats[k]



def main():
    global nl_sock
    global send_nlh
    global send_sock

    if len(sys.argv) != 2:
        print("Usage: %s <poll-secs>" % sys.argv[0])
        sys.exit(-1)

    # prepare for sending to carbon
    send_sock = socket.socket()
    try:
        send_sock.connect((CARBON_SERVER, CARBON_PORT))
    except Exception as e:
        log.fatal("could not connect to carbon server %d@%s" % (CARBON_PORT, CARBON_SERVER))
        sys.exit(-1)

    secs = int(sys.argv[1])
    print("Polling every %s seconds from kernel..." % secs)

    # Set high priority for this process, less chances to overrun
    # the netlink receiver buffer since the scheduler gives this process
    # more chances to run
    os.nice(-20)

    # Open netlink socket to operate with netfilter
    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl_sock:
        # Subscribe to destroy events to avoid leaking counters. The same
        # socket is used to periodically atomically dump and reset counters.
        nl_sock.bind(nfnlcm.NF_NETLINK_CONNTRACK_DESTROY, mnl.MNL_SOCKET_AUTOPID)

        # Set netlink receiver buffer to 16 MBytes, to avoid packet drops
        # XXX: has to use python's. socket.fromfd() is available only in Unix
        buffersize = 1 << 22
        sock = socket.fromfd(nl_sock.get_fd(), socket.AF_NETLINK, socket.SOCK_RAW)
        sock.setsockopt(socket.SOL_SOCKET, 33, buffersize) # SO_RCVBUFFORCE

        # The two tweaks below enable reliable event delivery, packets may
        # be dropped if the netlink receiver buffer overruns. This happens...
        #
        # a) if ther kernel spams this user-space process until the receiver
        #    is filled
        #
        # or:
        #
        # b) if the user-space process does not pull message from the
        #    receiver buffer so often.
        on = struct.pack("i", 1)[0]
        nl_sock.setsockopt(netlink.NETLINK_BROADCAST_ERROR, on)
        nl_sock.setsockopt(netlink.NETLINK_NO_ENOBUFS, on)

        buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
        send_nlh = mnl.nlmsg_put_header(buf, mnl.Header)

        # Counters are atomically zerod in each dump
        send_nlh.type = (nfnl.NFNL_SUBSYS_CTNETLINK << 8) | nfnlct.IPCTNL_MSG_CT_GET_CTRZERO
        send_nlh.flags = netlink.NLM_F_REQUEST|netlink.NLM_F_DUMP

        nfh = send_nlh.put_extra_header_as(nfnl.Nfgenmsg)
        nfh.family = socket.AF_INET
        nfh.version = nfnl.NFNETLINK_V0
        nfh.res_id = 0

        # Filter by mark: We only want to dump entries whose mark is zefo
        send_nlh.put_u32(nfnlct.CTA_MARK, socket.htonl(0))
        send_nlh.put_u32(nfnlct.CTA_MARK_MASK, socket.htonl(0xffffffff))

        # Every N seconds ...
        signal.setitimer(signal.ITIMER_REAL, secs, secs)
        signal.signal(signal.SIGALRM, alarm_handler)

        fd = nl_sock.get_fd()
        while True:
            try:
                rlist, wlist, xlist = select.select([fd], [], [])
            except select.error as e:
                if e[0] == errno.EINTR: continue
                raise
            # Handled event and periodic atomic-dump-and-reset messages
            if fd in rlist:
                if handle(nl_sock) < 0:
                    return -1


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
