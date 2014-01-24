#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, logging, socket, time, struct, select
import ctypes, errno, signal, threading, multiprocessing
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
CARBON_PREFIX = "myrouter"

nstats = dict() # {Tuple: Counter}
nstats_lock = threading.Lock()
nl_socket = None
sending_nlmsghdr = None
sending_queue = None


class Tuple(object):
    def __init__(self, l3, server, client, l4, port=0):
        self.l3proto = l3
        self.server = server	# big endian byte[4 or 16]
        self.client = client	# big endian byte[4 or 16]
        self.l4proto = l4
        self.port = port

    def __hash__(self):
        return self.l3proto + hash(str(self.server)) + hash(str(self.client)) \
            + self.l4proto + self.port

    def __eq__(self, other):
        return self.l3proto == other.l3proto \
            and self.server == other.server \
            and self.client == other.client \
            and self.l4proto == other.l4proto \
            and self.port == other.port

    def __str__(self): # carbon path
        if self.l4proto == socket.IPPROTO_ICMP:
            l4 = "ICMP.%d" % self.port
        elif self.l4proto == socket.IPPROTO_TCP:
            l4 = "TCP.%d" % socket.ntohs(self.port)
        elif self.l4proto == socket.IPPROTO_UDP:
            l4 = "UDP.%d" % socket.ntohs(self.port)
        else:
            l4 = "unknown.%d" % self.l4proto

        if self.l3proto == socket.AF_INET:
            # address is not dotted quad, colon quad
            path = ".".join([CARBON_PREFIX,
                             ":".join(["%d" % i for i in self.server]),
                             "%s" % l4,
                             ":".join(["%d" % i for i in self.client])])
        elif self.l3proto == socket.AF_INET6:
            path = ".".join([CARBON_PREFIX,
                             ":".join(["%x%x" % (self.server[i], self.server[i + 1])
                                       for i in range(0, len(self.server), 2)]),
                             "%s" % l4,
                             ":".join(["%x%x" % (self.client[i], self.client[i + 1])
                                       for i in range(0, len(self.client), 2)])])
        return path


class Counter(object):
    def __init__(self, pkts, b):
        self.pkts = pkts
        self.bytes = b
        self.deleting = False


def make_tuple(ct):
    try:
        l3proto = ct.get_attr_u8(nfct.ATTR_L3PROTO)
    except Exception as e:
        log.error("could not get L3PROTO: %s" % e)
        return None

    try:
        l4proto = ct.get_attr_u8(nfct.ATTR_L4PROTO)
    except Exception as e:
        # cannot get DST on IGMP?
        log.warn("ignore because could not get L4PROTO: %s, L3PROTO: %d" % (e, l3proto))
        return None

    if l3proto == socket.AF_INET:
        server = bytearray(struct.pack("i", ct.get_attr_u32(nfct.ATTR_IPV4_DST)))
        client = bytearray(struct.pack("i", ct.get_attr_u32(nfct.ATTR_IPV4_SRC)))
    elif l3proto == socket.AF_INET6:
        # I don't know why bytearray needed (*1)
        server = bytearray(ct.get_attr_as(nfct.ATTR_IPV6_DST, (ctypes.c_ubyte * 16)))
        client = bytearray(ct.get_attr_as(nfct.ATTR_IPV6_SRC, (ctypes.c_ubyte * 16)))
        # (*1) get addresses properly here
    else:
        log.warn("unknow L3 proto: %d" % l3proto)
        return None

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
    try:
        ct.nlmsg_parse(nlh)
    except Exception as e:
        log.error("nlmsg_parse: %s" % e)
        return mnl.MNL_CB_OK

    t = make_tuple(ct)
    if t is None: return mnl.MNL_CB_OK

    counter = nstats.setdefault(t, Counter(0, 0))
    if nlh.type & 0xff == nfnlct.IPCTNL_MSG_CT_DELETE:
        counter.deleting = True

    try:
        orig_packets = ct.get_attr_u64(nfct.ATTR_ORIG_COUNTER_PACKETS)
    except Exception as e:
        log.error("could not get ORIG_COUNTER_PACKETS: %s" % e)
        return mnl.MNL_CB_OK
    try:
        repl_packets = ct.get_attr_u64(nfct.ATTR_REPL_COUNTER_PACKETS)
    except Exception as e:
        log.error("could not get REPL_COUNTER_PACKETS: %s" % e)
        return mnl.MNL_CB_OK

    if orig_packets + repl_packets == 0:
        return mnl.MNL_CB_OK

    try:
        orig_bytes = ct.get_attr_u64(nfct.ATTR_ORIG_COUNTER_BYTES)
    except Exception as e:
        log.error("could not get ORIG_COUNTER_BYTES: %s" % e)
        return mnl.MNL_CB_OK
    try:
        repl_bytes = ct.get_attr_u64(nfct.ATTR_REPL_COUNTER_BYTES)
    except Exception as e:
        log.error("could not get REPL_COUNTER_BYTES: %s" % e)
        return mnl.MNL_CB_OK

    counter.pkts += orig_packets + repl_packets
    counter.bytes += orig_bytes + repl_bytes

    return mnl.MNL_CB_OK


def handle(buf):
    nstats_lock.acquire(True)
    try:
        ret = mnl.cb_run(buf, 0, 0, data_cb, None)
    finally:
        nstats_lock.release()

    return 0


def alarm_handler(signum, frame):
    global nl_socket
    global sending_queue
    global sending_nlmsghdr

    # ... request a fresh dump of the table from kernel
    nl_socket.send_nlmsg(sending_nlmsghdr)

    if not nstats_lock.acquire(False):
        log.warn("nstats is being handled by another")
        return

    now = int(time.time())
    listOfMetricTuples = []
    deleting_keys = []
    for k, v in nstats.iteritems():
        if v.deleting:  deleting_keys.append(k)
        if v.pkts == 0: continue
        listOfMetricTuples.append((str(k), (now, v.bytes)))
        v.pkts = 0
        v.bytes = 0
    for k in deleting_keys: del nstats[k]

    nstats_lock.release()

    log.info("deleting       #: %d" % len(deleting_keys))
    log.info("current nstats #: %d" % len(nstats))

    sending_queue.put(listOfMetricTuples)


def send_process(sk):
    global sending_queue
    while True:
        l = sending_queue.get() # listOfMetricTuples
        if len(l) is None: return
        if len(l) == 0: continue

        payload = pickle.dumps(l)
        header = struct.pack("!L", len(payload))
        message = header + payload
        # should catch EINTR?
        sk.sendall(message)
        log.info("sent entries #: %d, size: %d" % (len(l), len(message)))


def set_sending_nlh():
    global sending_nlmsghdr

    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    sending_nlmsghdr = mnl.nlmsg_put_header(buf, mnl.Header)

    # Counters are atomically zerod in each dump
    sending_nlmsghdr.type = (nfnl.NFNL_SUBSYS_CTNETLINK << 8) | nfnlct.IPCTNL_MSG_CT_GET_CTRZERO
    sending_nlmsghdr.flags = netlink.NLM_F_REQUEST|netlink.NLM_F_DUMP

    nfh = sending_nlmsghdr.put_extra_header_as(nfnl.Nfgenmsg)
    nfh.family = socket.AF_INET
    nfh.version = nfnl.NFNETLINK_V0
    nfh.res_id = 0

    # Filter by mark: We only want to dump entries whose mark is zefo
    sending_nlmsghdr.put_u32(nfnlct.CTA_MARK, socket.htonl(0))
    sending_nlmsghdr.put_u32(nfnlct.CTA_MARK_MASK, socket.htonl(0xffffffff))


def mnl_socket_poll(nl):
    fd = nl.get_fd()
    p = select.poll()
    while True:
        p.register(fd, select.POLLIN | select.POLLERR)
        try:
            events = p.poll(-1)
        except select.error as e: # by SIGALRM
            if e[0] == errno.EINTR:
                continue
            raise
        for efd, event in events:
            if efd == fd:
                if event == select.POLLIN:
                    return 0
                if event == select.POLLERR:
                    return -1


def main():
    global nl_socket
    global sending_queue

    if len(sys.argv) != 2:
        print("Usage: %s <poll-secs>" % sys.argv[0], file=sys.stderr)
        sys.exit(-1)
    secs = int(sys.argv[1])
    print("Polling every %s seconds from kernel..." % secs)


    # Set high priority for this process, less chances to overrun
    # the netlink receiver buffer since the scheduler gives this process
    # more chances to run
    os.nice(-20)

    # Open socket for sending to carbon
    carbon_socket = socket.socket()
    try:
        carbon_socket.connect((CARBON_SERVER, CARBON_PORT))
    except Exception as e:
        log.fatal("could not connect to carbon server %d@%s" % (CARBON_PORT, CARBON_SERVER))
        sys.exit(-1)

    frame_size = 4096
    # Open netlink socket to operate with netfilter
    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl_socket:
        # use ring rx only
        nl_socket.set_ringopt(mnl.MNL_RING_RX, mnl.MNL_SOCKET_BUFFER_SIZE * 4, 64, mnl.MNL_SOCKET_BUFFER_SIZE, 4 * 64)
        nl_socket.map_ring()
        rxring = nl_socket.get_ring(mnl.MNL_RING_RX)

        # Subscribe to destroy events to avoid leaking counters. The same
        # socket is used to periodically atomically dump and reset counters.
        nl_socket.bind(nfnlcm.NF_NETLINK_CONNTRACK_DESTROY, mnl.MNL_SOCKET_AUTOPID)

        # tweak nl socket buffer
        buffersize = 1 << 22
        sock = socket.fromfd(nl_socket.get_fd(), socket.AF_NETLINK, socket.SOCK_RAW)
        sock.setsockopt(socket.SOL_SOCKET, 33, buffersize) # SO_RCVBUFFORCE

        # The two tweaks below enable reliable event delivery, packets may
        # be dropped if the netlink receiver buffer overruns. This happens ...
        # a) if the kernel spams this user-space process until the receiver
        #    is filled.
        # or:
        # b) if the user-space process does not pull messages from the
        #    receiver buffer so often.
        on = struct.pack("i", 1)[0]
        nl_socket.setsockopt(netlink.NETLINK_BROADCAST_ERROR, on)
        nl_socket.setsockopt(netlink.NETLINK_NO_ENOBUFS, on)

        set_sending_nlh()

        sending_queue = multiprocessing.Queue(16)
        p = multiprocessing.Process(target=send_process, args=(carbon_socket,))
        p.start()

        # Every N seconds ...
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.setitimer(signal.ITIMER_REAL, 0.1, secs)

        recvbuf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
        while True:
            frame = rxring.get_frame()
            if frame.status == netlink.NL_MMAP_STATUS_VALID:
                buf = mnl.MNL_FRAME_PAYLOAD(frame)
            elif frame.status == netlink.NL_MMAP_STATUS_COPY:
                rsize = nl_socket.recv_into(recvbuf)
                buf = recvbuf[:rsize]
            else:
                # XXX: ignore error return value -1
                mnl_socket_poll(nl_socket)
                continue
            ret = handle(buf)
            frame.status = netlink.NL_MMAP_STATUS_UNUSED
            rxring.advance()
            if ret < 0: return -1


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        # format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
                        format='%(asctime)s %(levelname)s: %(message)s')
    main()