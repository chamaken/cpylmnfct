cpylmnfct
=========

Python wrapper of libnetfilter_conntrack using ctypes, under heavy development

sample
------

see examples


installation
------------

not prepared yet


requires
--------

* libnetfilter_conntrack
* Python >= 2.6
* cpylmnl (https://github.com/chamaken/cpylmnl)
* test reqs (optional): **python-coverage**, **python-nose**


links
-----

* libnetfilter_conntrack: http://www.netfilter.org/projects/libnetfilter_conntrack/
* pynetfilter_conntrack: https://pypi.python.org/pypi/pynetfilter_conntrack


comparison
----------

| original				| cpylmnfct			| remarks			|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| nfct_open				| (Not implemented)		|				|
| nfct_open_nfnl			| (Not implemented)		|				|
| nfct_close				| (Not implemented)		|				|
| nfct_fd				| (Not implemented)		|				|
| nfct_nfnlh				| (Not implemented)		|				|
| nfct_new				| Conntrack()			|				|
| nfct_destroy				| Conntrack.destroy		|				|
| nfct_clone				| Conntrack.clone		|				|
| nfct_sizeof				| (Not implemented)		|				|
| nfct_maxsize				| (Not implemented)		|				|
| nfct_setobjopt			| Conntrack.setobjopt		|				|
| nfct_getobjopt			| Conntrack.getobjopt		|				|
| nfct_callback_register		| (Not implemented)		|				|
| nfct_callback_unregister		| (Not implemented)		|				|
| nfct_callback_register2		| (Not implemented)		|				|
| nfct_callback_unregister2		| (Not implemented)		|				|
| nfct_bitmask_new			| Bitmask()			|				|
| nfct_bitmask_clone			| Bitmask.clone			|				|
| nfct_bitmask_maxbit			| Bitmask.maxbit		|				|
| nfct_bitmask_test_bit			| Bitmask.test_bit		|				|
| nfct_bitmask_unset_bit		| Bitmask.unset_bit		|				|
| nfct_bitmask_clear			| Bitmask.destroy		|				|
| nfct_bitmask_equal			| Bitmask.__eq__		|				|
| nfct_bitmask_destroy			| Bitmask.destroy		|				|
| nfct_labelmap.new			| Labelmap()			|				|
| nfct_labelmap.destroy			| Labelmap.destroy		|				|
| nfct_labelmap.get_name		| Labelmap.get_name		|				|
| nfct_labelmap.get_bit			| Labelmap.get_bit		|				|
| nfct_set_attr				| Conntrack.set_attr		| value must be a _CData	|
| nfct_set_attr_u8			| Conntrack.set_attr_u8		|				|
| nfct_set_attr_u16			| Conntrack.set_attr_u16	|				|
| nfct_set_attr_u32			| Conntrack.set_attr_u32	|				|
| nfct_set_attr_u64			| Conntrack.set_attr_u64	|				|
| nfct_set_attr_l			| Conntrack.set_attr_l		|				|
| nfct_get_attr				| Conntrack.get_attr		|				|
| (add)					| Conntrack.get_attr_as		| casting c_void_p		|
| nfct_get_attr_u8			| Conntrack.get_attr_u8		|				|
| nfct_get_attr_u16			| Conntrack.get_attr_u16	|				|
| nfct_get_attr_u32			| Conntrack.get_attr_u32	|				|
| nfct_get_attr_u64			| Conntrack.get_attr_u64	|				|
| nfct_attr_is_set			| Conntrack.attr_is_set		| return boolean		|
| nfct_attr_is_set_array		| Conntrack.attr_is_set_array	| return boolean		|
| nfct_attr_unset			| Conntrack.attr_unset		|				|
| nfct_set_attr_grp			| Conntrack.set_attr_grp	|				|
| nfct_attr_get_attr_grp		| Conntrack.attr_get_attr_grp	|				|
| (add)					| Conntrack.attr_get_attr_grp_as|				|
| nfct_attr_grp_is_set			| Conntrack.attr_grp_is_set	|				|
| nfct_attr_grp_unset			| Conntrack.attr_grp_unset	|				|
| nfct_snprintf				| Conntrack.snprintf		|				|
| nfct_snprintf_labels			| Conntrack.snprintf_labels	|				|
| nfct_compare				| Conntrack.compare		|				|
| nfct_cmp				| Conntrack.cmp			|				|
| nfct_query				| (Not implemented)		|				|
| nfct_send				| (Not implemented)		|				|
| nfct_catch				| (Not implemented)		|				|
| nfct_copy				| Conntrack.copy		|				|
| nfct_copy_attr			| Conntrack.copy_attr		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_filter_create			| Filter()			|				|
| nfct_filter_destroy			| Filter.destroy		|				|
| nfct_filter_add_attr			| Filter.add_attr		|				|
| nfct_filter_add_attr_u32		| Filter.add_attr_u32		|				|
| nfct_filter_set_logic			| Filter.set_logic		|				|
| nfct_filter_attach			| Filter.attach			|				|
| nfct_filter_detach			| Filter.detach			|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_filter_dump_create		| FilterDump()			|				|
| nfct_filter_dump_destroy		| FilterDump.destroy		|				|
| nfct_filter_dump_set_attr		| FilterDump.set_attr		|				|
| nfct_filter_dump_set_attr_u8		| FilterDump.set_attr_U8	|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_build_conntrack			| (Not implemented)		|				|
| nfct_parse_conntrack			| (Not implemented)		|				|
| nfct_build_query			| (Not implemented)		|				|
| nfct_nlmsg_build			| Conntrack.nlmsg_build		|				|
| nfct_nlmsg_parse			| Conntrack.nlmsg_parse		|				|
| nfct_payload_parse			| Conntrack.payload_parse	|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfexp_new				| Expect()			|				|
| nfexp_destroy				| Expect.destroy		|				|
| nfexp_clone				| Expect.clone			|				|
| nfexp_sizeof				| (Not implemented)		|				|
| nfexp_maxsize				| (Not implemented)		|				|
| nfexp_callback_register		| (Not implemented)		|				|
| nfexp_callback_unregister		| (Not implemented)		|				|
| nfexp_callback_register2		| (Not implemented)		|				|
| nfexp_callback_unregister2		| (Not implemented)		|				|
| nfexp_set_attr			| Expect.set_attr		|				|
| nfexp_set_attr_u8			| Expect.set_attr_u8		|				|
| nfexp_set_attr_u16			| Expect.set_attr_u16		|				|
| nfexp_set_attr_u32			| Expect.set_attr_u32		|				|
| nfexp_get_attr			| Expect.get_attr		|				|
| (add)					| Expect.get_attr_as		|				|
| nfexp_get_attr_u8			| Expect.get_attr_u8		|				|
| nfexp_get_attr_u16			| Expect.get_attr_u16		|				|
| nfexp_get_attr_u32			| Expect.get_attr_u32		|				|
| nfexp_attr_is_set			| Expect.attr_is_set		|				|
| nfexp_attr_unset			| Expect.attr_unset		|				|
| nfexp_query				| (Not implemented)		|				|
| nfexp_snprintf			| Expect.snprintf		|				|
| nfexp_cmp				| Expect.cmp			|				|
| nfexp_send				| (Not implemented)		|				|
| nfexp_catch				| (Not implemented)		|				|
| nfexp_build_expect			| (Not implemented)		|				|
| nfexp_parse_expect			| (Not implemented)		|				|
| nfexp_build_query			| (Not implemented)		|				|
| nfexp_nlmsg_build			| Expect.nlmsg_build		|				|
| nfexp_nlmsg_parse			| Expect.nlmsg_parse		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
