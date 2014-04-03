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
# write: set True in data_cb if NLM_F_MULTI set in nlmsg_flgas and
#        set False if cb_run returns MNL_CB_STOP. e.g. nlmsg_type is NLMSG_DONE
# read:  in periodic task, not send dump request if True
# Or not using dump, catch EBUSY on send_nlmsg()
dumping = False


"""
This program send data to carbon sever specified by CARBON_ prefix
above. The carbon path in the data is:

    <CARBON_PREFIX>.<src addr>.<dst addr>.<L4 proto>.<port>

Supported L4 protos are only TCP, UDP and ICMP. <port> will be
type in case of ICMP. And value is converted from bytes to bit per
second. iptables setup is done by:

    iptables -t nat -I PREROUTING -m connbytes \
        --connbytes 0 --connbytes-dir both --connbytes-mode bytes


* Working with another network equipment's monitor port
  # adversaria for me

  ASCII art:
                 +---------------------+   +------------------+
  <--- uplink ---+ <Network switch>    |   | <This box>       |
                 |                     |   |                  |
                 | communication port  +---+ eth0             |
                 |                     |   |                  |
                 | uplink monitor port +---+ eth1             |
                 +---------------------+   +------------------+

  eth0 is normal connection to login by ssh or stuff like that and
  has IP address. eth1 is connected to the monitorport which mirrors
  both tx/rx of network switch's uplink port. I need to collect
  conntrack data from eth1 and send carbon data through eth0. Before
  setting iptables I need to:

  1. set route from eth1 to network /dev/null
     * enable ip forwarding
       # echo 1 > /proc/sys/net/ipv4/ip_forwarding

     * prepare dummy0
       # ip link add null0 type dummy
       # ip link set null0 up

     * create route to null0 in a new table
       # ip route add default dev null0 table 200

     * create routing rule for packets from eth1
       # ip rule add iif eth1 table 200

  2. setup bridge
     * create bridg and add eth1 to it
       # brctl addbr br0
       # ip link set br0 up
       # brctl addif br0 eth1

     * tossing up L2 frame to L3
       # ebtables -t broute -I BROUTING -i eth1 \
       #     -j redirect --redirect-target DROP

  3. set eth1 promisc mode
     # ip link set eth1 promisc on

  At this time, I can see packets from eth1 on null0 without
  promisc mode. e.g. tcpdump -npi null0. And ``can not see on eth0.''

  For so you know through, packets generaged in the box and sending
  through the network switch uplink will doubly count. Use connmark
  target to avoid it,

    iptables -t mangle -I PREROUTING -i eth1 -j CONNMARK --set-mark 1

  and uncomment CTA_MARK lines below appropriately.
"""

class Tuple(object):
    """simple flow representation"""

    def __init__(self, l3, server, client, l4, port=0):
        self.l3proto = l3
        self.server = server	# big endian byte[4 or 16]
        self.client = client	# big endian byte[4 or 16]
        self.l4proto = l4
        self.port = port        # dst port or icmp type

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
    """create tuple from nf_conntrack """
    try:
        l3proto = ct.get_attr_u8(nfct.ATTR_L3PROTO)
    except Exception as e:
        log.error("could not get L3PROTO: %s" % e)
        return None

    try:
        l4proto = ct.get_attr_u8(nfct.ATTR_L4PROTO)
    except Exception as e:
        log.warn("could not get L4PROTO: %s, L3PROTO: %d" % (e, l3proto))
        return None

    if l3proto == socket.AF_INET:
        server = bytearray(struct.pack("I", ct.get_attr_u32(nfct.ATTR_IPV4_DST)))
        client = bytearray(struct.pack("I", ct.get_attr_u32(nfct.ATTR_IPV4_SRC)))
    elif l3proto == socket.AF_INET6:
        # I don't know why bytearray cast is needed
        server = bytearray(ct.get_attr_as(nfct.ATTR_IPV6_DST, (ctypes.c_ubyte * 16)))
        client = bytearray(ct.get_attr_as(nfct.ATTR_IPV6_SRC, (ctypes.c_ubyte * 16)))
    else:
        log.warn("unknow L3 proto: %d" % l3proto)
        return None

    if l4proto == socket.IPPROTO_ICMP:
        port = ct.get_attr_u8(nfct.ATTR_ICMP_TYPE)
    elif l4proto in (socket.IPPROTO_TCP, socket.IPPROTO_UDP):
        port = ct.get_attr_u16(nfct.ATTR_PORT_DST)
    else:
        port = 0

    return Tuple(l3proto, server, client, l4proto, port)


def mark_cmp(ct, value, mask):
    return ct.attr_is_set(nfct.ATTR_MARK) \
        and ct.get_attr_u32(nfct.ATTR_MARK) & mask == value


@mnl.header_cb
def data_cb(nlh, data):
    """mnl callback which update tuple's counter """
    global nstats
    global dumping

    if nlh.flags & netlink.NLM_F_MULTI == netlink.NLM_F_MULTI:
        dumping = True

    msgtype = nlh.type & 0xFF
    if msgtype == nfnlct.IPCTNL_MSG_CT_NEW:
        if nlh.flags & (netlink.NLM_F_CREATE|netlink.NLM_F_EXCL):
            print("NFCT_T_NEW")
        else:
            print("NFCT_T_UPDATE")
    elif msgtype == nfnlct.IPCTNL_MSG_CT_DELETE:
        print("NFCT_T_DESTROY")
    else:
        print("NFCT_T_UNKNOWN")


    with nfct.Conntrack() as ct:
        try:
            ct.nlmsg_parse(nlh)
        except Exception as e:
            log.error("nlmsg_parse: %s" % e)
            return mnl.MNL_CB_OK

        # CTA_MARK:
        # if you want to filter by mark - only want event entries whose mark is one
        # if not mark_cmp(ct, 1, 0xffffffff):
        #     return mnl.MNL_CB_OK

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


def start_periodic_task(secs, nl, q):
    """Executing periodic actions in Python
    http://stackoverflow.com/questions/8600161/executing-periodic-actions-in-python

    Unfortunately we could not acquire remainded time from Python's select
    """
    nlh = mnl.Header.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    # Counters are atomically zerod in each dump
    nlh.type = (nfnl.NFNL_SUBSYS_CTNETLINK << 8) | nfnlct.IPCTNL_MSG_CT_GET_CTRZERO
    nlh.flags = netlink.NLM_F_REQUEST|netlink.NLM_F_DUMP

    nfh = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfh.family = socket.AF_INET
    nfh.version = nfnl.NFNETLINK_V0
    nfh.res_id = 0

    # if you want to filter by mark - only want to dump entries whose mark is one
    # nlh.put_u32(nfnlct.CTA_MARK, socket.htonl(1))
    # nlh.put_u32(nfnlct.CTA_MARK_MASK, socket.htonl(0xffffffff))

    args = (secs, nl, nlh, q)
    next_call = [time.time()]
    def _doit(secs, nl, nlh, q):
        global nstats
        global nstats_lock
        global dumping

        if dumping:
            log.warn("dump takes more than interval secs, increasing it is recommended")
        else:
            nl.send_nlmsg(nlh) # XXX: no exception check

        with nstats_lock:
            now = int(next_call[0])
            listOfMetricTuples = []
            deleting_keys = []

            for k, v in nstats.iteritems():
                if v.deleting: deleting_keys.append(k)
                if v.pkts == 0: continue
                listOfMetricTuples.append((str(k), (now, v.bytes * 8 / secs))) # bit per sec
                v.pkts = 0
                v.bytes = 0

            for k in deleting_keys:
                del nstats[k]

        log.info("deletig        #: %d" % len(deleting_keys))
        log.info("current nstats #: %d" % len(nstats))
        q.put(listOfMetricTuples)

        next_call[0] += secs
        # it seems negative first param is allowed
        t = threading.Timer(next_call[0] - time.time(), _doit, args)
        t.daemon = True
        t.start()

    _doit(*args)


def send_process(sk, q):
    """sending list of metrics to carbon """
    while True:
        listOfMetricTuples = q.get()
        if listOfMetricTuples is None: return
        if len(listOfMetricTuples) == 0: continue

        payload = pickle.dumps(listOfMetricTuples)
        header = struct.pack("!L", len(payload))
        message = header + payload
        # sk.sendall(message)

        log.info("sent entries #: %d, size: %d" % (len(listOfMetricTuples), len(message)))


def main():
    global nstats
    global nstats_lock
    global dumping

    if len(sys.argv) != 2:
        print("Usage: %s <poll-secs>" % sys.argv[0])
        sys.exit(1)
    secs = int(sys.argv[1])

    print("Polling every %s seconds from kernel..." % secs)

    # Set high priority for this process, less chances to overrun
    # the netlink receiver buffer since the scheduler gives this process
    # more chances to run
    os.nice(-20)

    # setup netlink socket - see examples/netfilter/nfct-daemon in libmnl
    nl = mnl.Socket(netlink.NETLINK_NETFILTER)
    nl.bind(nfnlcm.NF_NETLINK_CONNTRACK_DESTROY, mnl.MNL_SOCKET_AUTOPID)
    sock = socket.fromfd(nl.get_fd(), socket.AF_NETLINK, socket.SOCK_RAW)
    sock.setsockopt(socket.SOL_SOCKET, 33, 1 << 22) # 33 == SO_RCVBUFFORCE
    on = struct.pack("i", 1)
    nl.setsockopt(netlink.NETLINK_BROADCAST_ERROR, on)
    nl.setsockopt(netlink.NETLINK_NO_ENOBUFS, on)

    # start sending process
    q = multiprocessing.Queue(8) # from periodic task to carbon sender
    carbon_socket = socket.socket()
    carbon_socket.connect((CARBON_SERVER, CARBON_PORT))
    p = multiprocessing.Process(target=send_process, args=(carbon_socket, q))
    p.start()

    # start periodic task
    start_periodic_task(secs, nl, q)

    # receive and aggregate loop
    rcvbuf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    while True:
        rsize = nl.recv_into(rcvbuf) # XXX: no exception check
        with nstats_lock:
            ret = mnl.cb_run(rcvbuf[:rsize], 0, 0, data_cb, None)
        if ret == mnl.MNL_CB_STOP:
            dumping = False
        elif ret < 0:
            q.put(None) # let sending process finish
            sys.exit(-1)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        # format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
                        format='%(asctime)s %(levelname)s: %(message)s')
    main()
