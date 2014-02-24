# -*- coding: utf-8 -*-
"""Python wrapper of libnetfilter_conntrack using ctypes

---- Citing the original libnetfilter_conntrack

libnetfilter_conntrack is a userspace library providing a programming
interface (API) to the in-kernel connection tracking state table. The
library libnetfilter_conntrack has been previously known as
libnfnetlink_conntrack and libctnetlink. This library is currently used by
conntrack-tools among many other applications.

libnetfilter_conntrack homepage is:
     http://netfilter.org/projects/libnetfilter_conntrack/

Dependencies
  libnetfilter_conntrack requires libnfnetlink and a kernel that includes the
  nf_conntrack_netlink subsystem (i.e. 2.6.14 or later, >= 2.6.18 recommended).

Main Features
 - listing/retrieving entries from the kernel connection tracking table.
 - inserting/modifying/deleting entries from the kernel connection tracking
   table.
 - listing/retrieving entries from the kernel expect table.
 - inserting/modifying/deleting entries from the kernel expect table.

Git Tree
  The current development version of libnetfilter_conntrack can be accessed at
  https://git.netfilter.org/cgi-bin/gitweb.cgi?p=libnetfilter_conntrack.git

Privileges
  You need the CAP_NET_ADMIN capability in order to allow your application
  to receive events from and to send commands to kernel-space, excepting
  the conntrack table dumping operation.

Using libnetfilter_conntrack
  To write your own program using libnetfilter_conntrack, you should start by
  reading the doxygen documentation (start by \link LibrarySetup \endlink page)
  and check examples available under utils/ in the libnetfilter_conntrack
  source code tree. You can compile these examples by invoking `make check'.

Authors
  libnetfilter_conntrack has been almost entirely written by Pablo Neira Ayuso.

Python Binding
  pynetfilter_conntrack is a Python binding of libnetfilter_conntrack written
  by Victor Stinner. You can visit his official web site at
  http://software.inl.fr/trac/trac.cgi/wiki/pynetfilter_conntrack.
"""

from __future__ import absolute_import

import errno

from . import _conntrack
from . import _expect
from ._libnetfilter_conntrackh import *

class Conntrack(object):
    """Conntrack object handling
    """
    def __init__(self, ct=None):
        """allocate a new conntrack

        In case of success, this function returns a valid pointer to a memory blob,
        otherwise raise OSError.
        """
        if ct is None: ct = _conntrack.conntrack_new()
        self._ct = ct

    def destroy(self): # XXX: no lock
        """release a conntrack object
        """
        _conntrack.conntrack_destroy(self._ct)
        del self._ct

    def __del__(self): # XXX: no lock
        """This function wraps destroy() if underlay _ct has exist.
        """
        if hasattr(self, "_ct"): self.destroy()

    def clone(self):
        """clone a conntrack object

        On error, OSError raised. Otherwise,
        a valid Conntrack object is returned.
        """
        return Conntrack(_conntrack.conntrack_clone(self._ct))

    def setobjopt(self, o):
        """set a certain option for a conntrack object

        In case of error, OSError is raised.

        @type o: number (NFCT_SOPT_)
        @param o: option parameter
        """
        _conntrack.conntrack_setobjopt(self._ct, o)

    def getobjopt(self, o):
        """get a certain option for a conntrack object

        In case of error, OSError is raised. On success,
        1 is returned if option is set, otherwise 0 is returned.

        @type o: number (NFCT_GOPT_)
        @param o: option parameter
        """
        return _conntrack.conntrack_getobjopt(self._ct, o)

    def set_attr_l(self, a, v):
        """set the value of a certain conntrack attribute

        This function and another setters are different from original, raises
        OSError if attribute type is bigger than ATTR_MAX.

        @type a: number (ATTR_)
        @param a: attribute type
        @type v: ctypes data type
        @param v: attribute value
        """
        _conntrack.conntrack_set_attr_l(self._ct, a, v)

    def set_attr(self, a, v):
        """set the value of a certain conntrack attribute

        Note that certain attributes are unsettable:
          - ATTR_USE
          - ATTR_ID
          - ATTR_*_COUNTER_*
          - ATTR_SECCTX
          - ATTR_TIMESTAMP_*
        The call of this function for such attributes do nothing.

        @type a: number (ATTR_)
        @param a: attribute type
        @type v: ctypes data type
        @param v: attribute value
        """
        _conntrack.conntrack_set_attr(self._ct, a, v)

    def set_attr_u8(self, a, v):
        """set the value of a certain conntrack attribute

        @type a: number (ATTR_)
        @param a: attribute type
        @type v: number
        @param v: unsigned 8 bits attribute value
        """
        _conntrack.conntrack_set_attr_u8(self._ct, a, v)

    def set_attr_u16(self, a, v):
        """set the value of a certain conntrack attribute

        @type a: number (ATTR_)
        @param a: attribute type
        @type v: number
        @param v: unsigned 16 bits attribute value
        """
        _conntrack.conntrack_set_attr_u16(self._ct, a, v)

    def set_attr_u32(self, a, v):
        """set the value of a certain conntrack attribute

        @type a: number (ATTR_)
        @param a: attribute type
        @type v: number
        @param v: unsigned 32 bits attribute value
        """
        _conntrack.conntrack_set_attr_u32(self._ct, a, v)

    def set_attr_u64(self, a, v):
        """set the value of a certain conntrack attribute

        @type a: number (ATTR_)
        @param a: attribute type
        @type v: number
        @param v: unsigned 64 bits attribute value
        """
        _conntrack.conntrack_set_attr_u64(self._ct, a, v)

    def get_attr(self, a):
        """get a conntrack attribute

        In case of success a valid pointer to the attribute requested is returned,
        on error OSError is raised.

        @type a: number (ATTR_)
        @param a: attribute type

        @rtype: ctypes.c_void_p
        @return: pointer to the attribute
        """
        return _conntrack.conntrack_get_attr(self._ct, a)

    def get_attr_as(self, a, c):
        """get a conntrack attribute

        This function wraps get_attr().

        @type a: number (ATTR_)
        @param a: attribute type
        @type c: class of subclass of ctypes data type
        @param c: casting class

        @rtype: specified by c param
        @return: attribute object, contents
        """
        return _conntrack.conntrack_get_attr_as(self._ct, a, c)

    def get_attr_u8(self, a):
        """get attribute of unsigned 8-bits long

        Returns the value of the requested attribute, if the attribute is not
        set, OSError is raised. In order to check if the attribute is set or not,
        use attr_is_set.

        @type a: number (ATTR_)
        @param a: attribute type

        @rtype: number
        @return: the value of the requested attribute
        """
        return _conntrack.conntrack_get_attr_u8(self._ct, a)

    def get_attr_u16(self, a):
        """get attribute of unsigned 16-bits long

        Returns the value of the requested attribute, if the attribute is not
        set, OSError is raised. In order to check if the attribute is set or not,
        use attr_is_set.

        @type a: number (ATTR_)
        @param a: attribute type

        @rtype: number
        @return: the value of the requested attribute
        """
        return _conntrack.conntrack_get_attr_u16(self._ct, a)

    def get_attr_u32(self, a):
        """get attribute of unsigned 32-bits long

        Returns the value of the requested attribute, if the attribute is not
        set, OSError is raised. In order to check if the attribute is set or not,
        use attr_is_set.

        @type a: number (ATTR_)
        @param a: attribute type

        @rtype: number
        @return: the value of the requested attribute
        """
        return _conntrack.conntrack_get_attr_u32(self._ct, a)

    def get_attr_u64(self, a):
        """get attribute of unsigned 64-bits long


        Returns the value of the requested attribute, if the attribute is not
        set, OSError is raised. In order to check if the attribute is set or not,
        use attr_is_set.

        @type a: number (ATTR_)
        @param a: attribute type

        @rtype: number
        @return: the value of the requested attribute
        """
        return _conntrack.conntrack_get_attr_u64(self._ct, a)

    def attr_is_set(self, a):
        """check if a certain attribute is set

        On error, OSError is raised. Otherwise
        true is returned if the attribute is set or false if it is not set.

        @type a: number (ATTR_)
        @param a: attribute type

        @rtype: bool
        @return: if a certain attribute is set or not
        """
        return _conntrack.conntrack_attr_is_set(self._ct, a)

    def attr_is_set_array(self, l):
        """check if an array of attribute types is set

        On error, -1 is returned and errno is set appropiately, otherwise
        1 is returned if the all attributes are set or 0 if not set.

        @type l: list of number (ATTR_)
        @param l: attribute type array

        @rtype: bool
        @return: if an array of attribute types is set
        """
        return _conntrack.conntrack_attr_is_set_array(self._ct, l)

    def attr_unset(self, a):
        """unset a certain attribute

        On error, OSError is raised, otherwise 0 is returned.

        @type a: number (ATTR_)
        @param a: attribute type
        """
        return _conntrack.conntrack_attr_unset(self._ct, a)

    def set_attr_grp(self, a, d):
        """set a group of attributes

        Note that calling this function for ATTR_GRP_COUNTER_* and ATTR_GRP_ADDR_*
        have no effect. This function is different from original, raises OSError
        if a param is greater than ATTR_GRP_MAX.

        @type a: number (ATTR_GRP_)
        @param a: attribute group
        @type d: ctypes data type
        @param d: NfctAttrGrp_ object
        """
        _conntrack.conntrack_set_attr_grp(self._ct, a, d)

    def get_attr_grp(self, a, d):
        """get an attribute group

        On error, it raises OSError. On success, the
        d param contains the attribute group object.

        @type a: number (ATTR_GRP_)
        @param a: attribute group
        @type d: ctypes data type
        @param d: NfctAttrGrp_ object
        """
        _conntrack.conntrack_get_attr_grp(self._ct, a, d)

    def get_attr_grp_as(self, a, c):
        """get an attribute group

        On error, it raises OSError. Otherwise attribute group object is
        returned.

        @type a: number (ATTR_GRP_)
        @param a: attribute group
        @type c: class of ctypes data type
        @param c: NfctAttrGrp_ class

        @rtype: specified by c param
        @return: attribute group object
        """
        return _conntrack.conntrack_get_attr_grp_as(self._ct, a, c)

    def attr_grp_is_set(self, a):
        """check if an attribute group is set

        If the attribute group is set, this function returns 1, otherwise 0.
        On error, it raises OSError.

        @type a: number (ATTR_GRP_)
        @param a: attribute group

        @rtype: bool
        @return: if an attribute group is set
        """
        return _conntrack.conntrack_attr_grp_is_set(self._ct, a)

    def attr_grp_unset(self, a):
        """unset an attribute group

        On error, it raises OSError.

        @type a: number (ATTR_GRP_)
        @param a: attribute group
        """
        _conntrack.conntrack_attr_grp_unset(self._ct, a)

    def snprintf(self, s, m, o, f):
        """print a conntrack object to a buffer

        If you are listening to events, probably you want to display the message
        type as well. In that case, set the message type parameter to any of the
        known existing types, ie. NFCT_T_NEW, NFCT_T_UPDATE, NFCT_T_DESTROY.
        If you pass NFCT_T_UNKNOWN, the message type will not be output.

        Currently, the output available are:
          - NFCT_O_DEFAULT: default /proc-like output
          - NFCT_O_XML: XML output

        The output flags are:
          - NFCT_OF_SHOW_LAYER3: include layer 3 information in the output,
            this is *only* required by NFCT_O_DEFAULT.
          - NFCT_OF_TIME: display current time.
          - NFCT_OF_ID: display the ID number.
          - NFCT_OF_TIMESTAMP: display creation and (if exists) deletion time.

        To use NFCT_OF_TIMESTAMP, you have to:

            $ echo 1 > /proc/sys/net/netfilter/nf_conntrack_timestamp

        This requires a Linux kernel >= 2.6.38.

        Note that NFCT_OF_TIME displays the current time when snprintf() has
        been called. Thus, it can be used to know when a flow was destroy if you
        print the message just after you receive the destroy event. If you want
        more accurate timestamping, use NFCT_OF_TIMESTAMP.

        This function returns the size of the information that _would_ have been
        written to the buffer, even if there was no room for it. Thus, the
        behaviour is similar to snprintf. On error, OSError is raised.

        @type s: number
        @param s: size of the buffer
        @type m: number (NFCT_T_UNKNOWN, NFCT_T_NEW,...)
        @param m: print message type
        @type o: number (NFCT_O_DEFAULT, NFCT_O_XML, ...)
        @param o: print type
        @type f: number (NFCT_OF_LAYER3)
        @param f: extra flags for the output type

        @rtype: string
        @return: Conntrack string representation
        """
        return _conntrack.conntrack_snprintf(s, self._ct, m, o, f)

    def snprintf_labels(self, s, m, o, f, l):
        """print a bitmask object to a buffer including labels

        When map is NULL, the function is equal to snprintf().
        Otherwise, if the conntrack object has a connlabel attribute, the active
        labels are translated using the label map and added to the buffer.

        @type s: number
        @param s: size of the buffer
        @type m: number (NFCT_T_UNKNOWN, NFCT_T_NEW,...)
        @param m: print message type
        @type o: number (NFCT_O_DEFAULT, NFCT_O_XML, ...)
        @param o: print type
        @type f: number (NFCT_OF_LAYER3)
        @param f: extra flags for the output type
        @type l: list of Labelmap
        @param l: describing the connlabel translation, or None
        """
        return _conntrack.conntrack_snprinf_labels(s, self._ct, m, o, f, l)

    def cmp(self, ct2, f):
        """compare two conntrack objects

        This function only compare attribute set in both objects, by default
        the comparison is not strict, ie. if a certain attribute is not set in one
        of the objects, then such attribute is not used in the comparison.
        If you want more strict comparisons, you can use the appropriate flags
        to modify this behaviour (see NFCT_CMP_STRICT and NFCT_CMP_MASK).

        The available flags are:

        - NFCT_CMP_STRICT: the compared objects must have the same attributes
          and the same values, otherwise it returns that the objects are
          different.
        - NFCT_CMP_MASK: the first object is used as mask, this means that
          if an attribute is present in ct1 but not in ct2, this function
          returns that the objects are different.
        - NFCT_CMP_ALL: full comparison of both objects
        - NFCT_CMP_ORIG: it only compares the source and destination address;
          source and destination ports; the layer 3 and 4 protocol numbers
          of the original direction; and the id (if present).
        - NFCT_CMP_REPL: like NFCT_CMP_REPL but it compares the flow
          information that goes in the reply direction.
        - NFCT_CMP_TIMEOUT_EQ: timeout(ct1) == timeout(ct2)
        - NFCT_CMP_TIMEOUT_GT: timeout(ct1) > timeout(ct2)
        - NFCT_CMP_TIMEOUT_LT: timeout(ct1) < timeout(ct2)
        - NFCT_CMP_TIMEOUT_GE: timeout(ct1) >= timeout(ct2)
        - NFCT_CMP_TIMEOUT_LE: timeout(ct1) <= timeout(ct2)

        The status bits comparison is status(ct1) & status(ct2) == status(ct1).

        If both conntrack object are equal, this function returns 1, otherwise
        0 is returned.

        @type ct2: Conntrack
        @param ct2: a valid conntrack object
        @type f: number (NFCT_CMP_)
        @param f: flags
        """
        return _conntrack.conntrack_cmp(self._ct, ct2._ct, f)

    def copy(self, ct2, f):
        """copy part of one source object to another

        This function copies one part of the source object to the target.
        It behaves like clone but:

        1) You have to pass an already allocated space for the target object
        2) You can copy only a part of the source object to the target

        The current supported flags are:
        - NFCT_CP_ALL: that copies the object entirely.
        - NFCT_CP_ORIG and NFCT_CP_REPL: that can be used to copy the
          information that identifies a flow in the original and the reply
          direction. This information is usually composed of: source and
          destination IP address; source and destination ports; layer 3
          and 4 protocol number.
        - NFCT_CP_META: that copies the metainformation
          (all the attributes >= ATTR_TCP_STATE)
        - NFCT_CP_OVERRIDE: changes the default behaviour of nfct_copy() since
          it overrides the destination object. After the copy, the destination
          is a clone of the origin. This flag provides faster copying.

        @type ct2: Conntrack
        @param ct2: destination object
        @type f: number (NFCT_CP_)
        @param f: flags
        """
        _conntrack.conntrack_copy(ct2._ct, self._ct, f)

    def copy_attr(self, ct2, t):
        """copy an attribute of one source object to another

        This function copies one attribute (if present) to another object.

        @type ct2: Conntrack
        @param ct2: destination object
        @type t: number (ATTR_)
        @param t: attribute type
        """
        _conntrack.conntrack_copy_attr(ct2._ct, self._ct, t)

    def nlmsg_build(self, nlh):
        """build a netlink message from a conntrack object

        @type nlh: mnl.Nlmsghdr or its subclass
        @param nlh: the netlink message
        """
        _conntrack.conntrack_nlmsg_build(nlh, self._ct)

    def nlmsg_parse(self, nlh):
        """translate a netlink message to a conntrack object

        @type nlh: mnl.Nlmsghdr or its subclass
        @param nlh: the netlink message
        """
        _conntrack.conntrack_nlmsg_parse(nlh, self._ct)

    def payload_parse(self, p, l3):
        """
        """
        _conntrack.conntrack_payload_parse(p, l3, self._ct)

    def __enter__(self):
        """
        """
        return self

    def __exit__(self, t, v, tb):
        """
        """
        self.destroy()
        return False


class Filter(object):
    """Kernel-space filtering for events
    """
    def __init__(self):
        """create a filter

        This function returns a valid pointer on success, otherwise OSError is
        raised.
        """
        self._filter = _conntrack.filter_create()

    def destroy(self):
        """destroy a filter

        This function releases the memory that is used by the filter object.
        However, please note that this function does *not* detach an already
        attached filter.
        """
        _conntrack.filter_destroy(self._filter)
        del self._filter

    def __del__(self):
        """This function wraps destroy() if underlay _filter has exist.
        """
        hasattr(self, "_filter") and self.destroy()

    def add_attr(self, a, v):
        """add a filter attribute of the filter object

        Limitations: You can add up to 127 IPv4 addresses and masks for
        NFCT_FILTER_SRC_IPV4 and, similarly, 127 for NFCT_FILTER_DST_IPV4.

        This function raises OSError is a is greater than NFCT_FILTER_MAX.

        @type a: number (NFCT_FILTER_)
        @param a: attribute type
        @type v: ctypes data type (FilterProto, FilterIpv...)
        @param v: the value of the filter attribute
        """
        _conntrack.filter_add_attr(self._filter, a, v)

    def add_attr_u32(self, a, v):
        """add an u32 filter attribute of the filter object

        Limitations: You can add up to 255 protocols which is a reasonable
        limit. This function raises OSError is a is greater than NFCT_FILTER_MAX.

        @type a: number
        @param a: filter attribute type
        @type v: number
        @param v: value of the filter attribute using unsigned int (32 bits)
        """
        _conntrack.filter_add_attr_u32(self._filter, a, v)

    def set_logic(self, a, l):
        """set the filter logic for an attribute type

        You can only use this function once to set the filtering logic for
        one attribute. You can define two logics: NFCT_FILTER_POSITIVE_LOGIC
        that accept events that match the filter, and NFCT_FILTER_NEGATIVE_LOGIC
        that rejects events that match the filter. Default filtering logic is
        NFCT_FILTER_POSITIVE_LOGIC.

        On error, it returns -1 and errno is appropriately set. On success, it
        returns 0.

        @type a: number (NFCT_FILTER_)
        @param a: filter attribute type
        @type l: number (NFCT_FILTER_LOGIC_)
        @param l: filter logic that we want to use
        """
        _conntrack.filter_set_logic(self._filter, a, l)

    def attach(self, fd):
        """attach a filter to a socket descriptor

        This function raises OSError on error. If the
        errno is EINVAL probably you have found a bug in it. Please,
        report this.

        @type fd: number
        @param fd: socket descriptor
        """
        _conntrack.filter_attach(fd, self._filter)

    @staticmethod
    def detach(fd):
        """detach an existing filter

        This function raises OSError on error.

        @type fd: number
        @param fd: socket descriptor
        """
        _conntrack.filter_detach(fd)

    def __enter__(self):
        """
        """
        return self

    def __exit__(self, t, v, tb):
        """
        """
        self.destroy()
        return False


class FilterDump(object):
    """Kernel-space filtering for dumping
    """
    def __init__(self):
        """create a dump filter

        This function returns a valid pointer on success, otherwise OSError
        is raised.
        """
        self._filter_dump = _conntrack.filter_dump_create()

    def destroy(self):
        """destroy a dump filter

        This function releases the memory that is used by the filter object.
        """
        _conntrack.filter_dump_destroy(self._filter_dump)
        del self._filter_dump

    def __del__(self):
        """This function wraps destroy() if underlay _filter_dump has exist.
        """
        hasattr(self, "_filter_dump") and self.destroy()

    def set_attr(self, a, v):
        """set filter attribute

        @type a: number (NFCT_FILTER_DUMP_)
        @param a: filter dump filter object that we want to modify
        @type v: FilterDumpMark
        @param v: the value of the filter attribute
        """
        _conntrack.filter_dump_set_attr(self._filter_dump, a, v)

    def set_attr_u8(self, a, v):
        """set u8 dump filter attribute

        @type a: number (NFCT_FILTER_DUMP_)
        @param a: filter attribute type
        @type v: number
        @param v: value of the filter attribute using unsigned int (32 bits).
        """
        _conntrack.filter_dump_set_attr_u8(self._filter_dump, a, v)

    def __enter__(self):
        """
        """
        return self

    def __exit__(self, t, v, tb):
        """
        """
        self.destroy()
        return False


class Labelmap(object):
    """Conntrack labels
    """
    def __init__(self, mapfile=None):
        """create a new label map

        If mapfile is NULL, the default mapping file is used.
        returns a new label map, or raises OSError on error.
        """
        self._labelmap = _conntrack.labelmap_new(mapfile)

    def destroy(self):
        """destroy nfct_labelmap object

        This function releases the memory that is used by the labelmap object.
        """
        _conntrack.labelmap_destroy(self._labelmap)
        del self._labelmap

    def __del__(self):
        """This function wraps destroy() if underlay _labelmap has exist.
        """
        hasattr(self, "_labelmap") and self.destroy()

    def get_name(self, bit):
        """get name of the label bit

        returns a string of the name associated with the label.
        If no name has been configured, the empty string is returned.
        If bit is out of range, None is returned.

        @type bit: number
        @param bit: whose name should be returned

        @rtype: string
        @return: a string of the name associated with the label
        """
        return _conntrack.labelmap_get_name(self._labelmap, bit)

    def get_bit(self, name):
        """get bit associated with the name

        returns the bit associated with the name, or negative value on error.

        @type name: string
        @param name: name of the label

        @rtype: number
        @return: the bit associated with the name
        """
        return _conntrack.labelmap_get_bit(self._labelmap, name)

    def __enter__(self):
        """
        """
        return self

    def __exit__(self, t, v, tb):
        """
        """
        self.destroy()
        return False


class Bitmask(object):
    """bitmask object

    This object may be set as connlabels or connlabels_mask in nf_conntrack.
    And will be destroyed when nfct_destroy() is called. This means that
    it should not be freed independently if set by nfct_set_attr() then
    __del__ is not implemented. Needs explicit calling destroy() if not set
    in nf_conntrack.

    Becoming nfct_set_attr() params means there is a way to implement this
    class as ctypes.Structures subclass. But this might be freed implicitly
    by nfct_destroy() so that this has messy "raw" property.
    """
    def __init__(self, high, bitmask=None):
        """allocate a new bitmask

        In case of success, this function returns a valid pointer to a memory blob,
        otherwise OSError is raised.
        """
        if bitmask is None:
            bitmask = _conntrack.bitmask_new(high)
        self._bitmask = bitmask

    @property
    def raw(self):
        return self._bitmask

    def destroy(self):
        """destroy bitmask object

        This function releases the memory that is used by the bitmask object.
        """
        _conntrack.bitmask_destroy(self._bitmask)
        del self._bitmask

    def clone(self):
        """duplicate a bitmask object

        @rtype: Bitmask
        @return: an identical copy of the bitmask
        """
        return Bitmask(0, _conntrack.bitmask_clone(self._bitmask))

    def set_bit(self, bit):
        """set bit in the bitmask

        @type bit: number
        @param bit: the bit to set
        """
        _conntrack.bitmask_set_bit(self._bitmask, bit)

    def test_bit(self, bit):
        """test if a bit in the bitmask is set

        @type bit: number
        @param bit: the bit to test

        @rtype: bool
        @return: if a bit in the bitmask is set or not
        """
        return _conntrack.bitmask_test_bit(self._bitmask, bit)

    def unset_bit(self, bit):
        """unset bit in the bitmask

        @type bit: number
        @param bit: the bit to clear
        """
        _conntrack.bitmask_unset_bit(self._bitmask, bit)

    def maxbit(self):
        """return highest bit that may be set/unset

        @rtype: number
        @return: highest bit that may be set/unset
        """
        return _conntrack.bitmask_maxbit(self._bitmask)

    def __enter__(self):
        """
        """
        return self

    def __exit__(self, t, v, tb):
        """
        """
        self.destroy()
        return False


class Expect(object):
    """Expect object handling
    """
    def __init__(self, exp=None):
        """allocate a new expectation

        In case of success, this function returns a valid Expect object,
        otherwise OSError is raised.
        """
        if exp is None: exp = _expect.expect_new()
        self._exp = exp

    def destroy(self):
        """release an expectation object
        """
        _expect.expect_destroy(self._exp)
        del self._exp

    def __del__(self):
        """This function wraps destroy() if underlay _exp has exist.
        """
        hasattr(self, "_exp") and self.destroy()

    def clone(self):
        """clone a expectation object

        On error, OSError is raised. Otherwise,
        a valid cloned Expect object is returned.

        @rtype: Expect
        @return: cloned Expect object
        """
        return Expect(_expect.expect_clone(self._exp))

    def cmp(self, e2, f):
        """compare two expectation objects

        This function only compare attribute set in both objects, by default
        the comparison is not strict, ie. if a certain attribute is not set in one
        of the objects, then such attribute is not used in the comparison.
        If you want more strict comparisons, you can use the appropriate flags
        to modify this behaviour (see NFCT_CMP_STRICT and NFCT_CMP_MASK).

        The available flags are:
        - NFCT_CMP_STRICT: the compared objects must have the same attributes
          and the same values, otherwise it returns that the objects are
          different.
        - NFCT_CMP_MASK: the first object is used as mask, this means that
          if an attribute is present in exp1 but not in exp2, this function
          returns that the objects are different.

        Other existing flags that are used by Conntrack.cmp() are ignored.

        If both conntrack object are equal, this function returns 1, otherwise
        0 is returned.

        @type e2: Expect
        @param e2: valid expectation object
        @type f: number
        @param f: flags

        @rtype: number
        @return: 1 if both conntrack object are equal, or 0
        """
        return _expect.expect_cmp(self._exp, e2._exp, f)

    def set_attr(self, a, v):
        """set the value of a certain expect attribute

        Note that certain attributes are unsettable:
        - ATTR_EXP_USE
        - ATTR_EXP_ID
        - ATTR_EXP_*_COUNTER_*
        The call of this function for such attributes do nothing.

        @type a: number (ATTR_EXP_)
        @param a: attribute type
        @type v: ctypes data type
        @param v: the attribute value
        """
        _expect.expect_set_attr(self._exp, a, v)

    def set_attr_u8(self, a, v):
        """set the value of a certain expect attribute

        @type a: number (ATTR_EXP_)
        @param a: attribute type
        @type v: number
        @param v: unsigned 8 bits attribute value
        """
        _expect.expect_set_attr_u8(self._exp, a, v)

    def set_attr_u16(self, a, v):
        """set the value of a certain expect attribute

        @type a: number (ATTR_EXP_)
        @param a: attribute type
        @type v: number
        @param v: unsigned 16 bits attribute value
        """
        _expect.expect_set_attr_u16(self._exp, a, v)

    def set_attr_u32(self, a, v):
        """set the value of a certain expect attribute

        @type a: number (ATTR_EXP_)
        @param a: attribute type
        @type v: number
        @param v: unsigned 32 bits attribute value
        """
        _expect.expect_set_attr_u32(self._exp, a, v)

    def get_attr(self, a):
        """get an expect attribute

        In case of success a valid pointer to the attribute requested is returned,
        on error OSError is raised.

        @type a: number (ATTR_EXP_)
        @param a: attribute type

        @rtype: ctypes.c_void_p
        @return: pointer to the attribute requested
        """
        return _expect.expect_get_attr(self._exp, a)

    def get_attr_as(self, a, c):
        """get an expect attribute

        This function wraps get_attr().

        @type a: number (ATTR_EXP_)
        @param a: attribute type
        @type c: of ctypes data type
        @param c: casting class

        @rtype: specified by c param
        @return: attribute
        """
        return _expect.expect_get_attr_as(self._exp, a, c)

    def get_attr_u8(self, a):
        """get attribute of unsigned 8-bits long

        Returns the value of the requested attribute, if the attribute is not
        set, OSError is raised. In order to check if the attribute is set or not,
        use nfexp_attr_is_set.

        @type a: number (ATTR_EXP_)
        @param a: attribute type

        @rtype: number
        @return value of the requested attribute
        """
        return _expect.expect_get_attr_u8(self._exp, a)

    def get_attr_u16(self, a):
        """get attribute of unsigned 16-bits long

        Returns the value of the requested attribute, if the attribute is not
        set, OSError is raised. In order to check if the attribute is set or not,
        use nfexp_attr_is_set.

        @type a: number (ATTR_EXP_)
        @param a: attribute type

        @rtype: number
        @return value of the requested attribute
        """
        return _expect.expect_get_attr_u16(self._exp, a)

    def get_attr_u32(self, a):
        """get attribute of unsigned 32-bits long

        Returns the value of the requested attribute, if the attribute is not
        set, OSError is raised. In order to check if the attribute is set or not,
        use nfexp_attr_is_set.

        @type a: number (ATTR_EXP_)
        @param a: attribute type

        @rtype: number
        @return value of the requested attribute
        """
        return _expect.expect_get_attr_u32(self._exp, a)

    def attr_is_set(self, a):
        """check if a certain attribute is set

        On error, OSError is raised, otherwise
        it returns if the attribute is set or not.

        @type a: number (ATTR_EXP_)
        @param a: attribute type

        @rtype: bool
        @return: if the attribute is set or not
        """
        return _expect.expect_attr_is_set(self._exp, a)

    def attr_unset(self, a):
        """unset a certain attribute

        On error, OSError is raised.

        @type a: number (ATTR_EXP_)
        @param a: attribute type
        """
        _expect.expect_attr_unset(self._exp, a)

    def snprintf(self, s, m, o, f):
        """print a conntrack object to a buffer

        If you are listening to events, probably you want to display the message
        type as well. In that case, set the message type parameter to any of the
        known existing types, ie. NFEXP_T_NEW, NFEXP_T_UPDATE, NFEXP_T_DESTROY.
        If you pass NFEXP_T_UNKNOWN, the message type will not be output.

        Currently, the output available are:
        - NFEXP_O_DEFAULT: default /proc-like output
        - NFEXP_O_XML: XML output

        The output flags are:
        - NFEXP_O_LAYER: include layer 3 information in the output, this is
                        *only* required by NFEXP_O_DEFAULT.

        On error, OSError is raised. Otherwise, string is returned.

        @type s: number
        @param s: size of the buffer
        @type m: number (NFEXP_T_UNKNOWN, NFEXP_T_NEW,...)
        @param m: print message type
        @type o: number (NFEXP_O_DEFAULT, NFEXP_O_XML, ...)
        @param o: type
        @type f: number (NFEXP_OF_LAYER3)
        @param f: extra flags for the output type
        """
        return _expect.expect_snprintf(s, self._exp, m, o, f)

    def nlmsg_build(self, nlh):
        """build a netlink message from a conntrack object
        """
        return _expect.expect_nlmsg_build(nlh, self._exp)

    def nlmsg_parse(self, nlh):
        """translate a netlink message to a conntrack object
        """
        return _expect.expect_nlmsg_parse(nlh, self._exp)

    def __enter__(self):
        """
        """
        return self

    def __exit__(self, t, v, tb):
        """
        """
        self.destroy()
        return False
