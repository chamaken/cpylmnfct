cpylmnfct
=========

python wrapper of libnetfilter_conntrack using ctypes, under heavy development

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

| original				| cgolmnfct			| remarks			|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| nfct_open				| (Not implemented)		|				|
| nfct_open_nfnl			| (Not implemented)		|				|
| nfct_close				| (Not implemented)		|				|
| nfct_fd				| (Not implemented)		|				|
| nfct_nfnlh				| (Not implemented)		|				|
| nfct_new				| conntrack_new			|				|
| nfct_destroy				| conntrack_destroy		|				|
| nfct_clone				| conntrack_clone		|				|
| nfct_sizeof				| (Not implemented)		|				|
| nfct_maxsize				| (Not implemented)		|				|
| nfct_setobjopt			| conntrack_setobjopt		|				|
| nfct_getobjopt			| conntrack_getobjopt		|				|
| nfct_callback_register		| (Not implemented)		|				|
| nfct_callback_unregister		| (Not implemented)		|				|
| nfct_callback_register2		| (Not implemented)		|				|
| nfct_callback_unregister2		| (Not implemented)		|				|
| nfct_bitmask_new			| bitmask_New			|				|
| nfct_bitmask_clone			| bitmask_clone			|				|
| nfct_bitmask_maxbit			| bitmask_maxbit		|				|
| nfct_bitmask_test_bit			| bitmask_test_bit		|				|
| nfct_bitmask_unset_bit		| bitmask_unset_bit		|				|
| nfct_bitmask_destroy			| bitmask_destroy		|				|
| nfct_labelmap_new			| labelmap_new			|				|
| nfct_labelmap_destroy			| labelmap_destroy		|				|
| nfct_labelmap_get_name		| labelmap_get_name		|				|
| nfct_labelmap_get_bit			| labelmap_get_bit		|				|
| nfct_set_attr				| conntrack_set_attr		| value must be a _CData	|
| nfct_set_attr_u8			| conntrack_set_attr_u8		|				|
| nfct_set_attr_u16			| conntrack_set_attr_u16	|				|
| nfct_set_attr_u32			| conntrack_set_attr_u32	|				|
| nfct_set_attr_u64			| conntrack_set_attr_u64	|				|
| nfct_set_attr_l			| conntrack_set_attr_l		|				|
| nfct_get_attr				| conntrack_get_attr		|				|
| (add)					| conntrack_get_attr_as		| casting c_void_p		|
| nfct_get_attr_u8			| conntrack_get_attr_u8		|				|
| nfct_get_attr_u16			| conntrack_get_attr_u16	|				|
| nfct_get_attr_u32			| conntrack_get_attr_u32	|				|
| nfct_get_attr_u64			| conntrack_get_attr_u64	|				|
| nfct_attr_is_set			| conntrack_attr_is_set		| return boolean		|
| nfct_attr_is_set_array		| conntrack_attr_is_set_array	| return boolean		|
| nfct_attr_unset			| conntrack_attr_unset		|				|
| nfct_set_attr_grp			| conntrack_set_attr_grp	|				|
| nfct_attr_get_attr_grp		| conntrack_attr_get_attr_grp	|				|
| (add)					| conntrack_attr_get_attr_grp_as|				|
| nfct_attr_grp_is_set			| conntrack_attr_grp_is_set	|				|
| nfct_attr_grp_unset			| conntrack_attr_grp_unset	|				|
| nfct_snprintf				| conntrack_snprintf		|				|
| nfct_snprintf_labels			| conntrack_snprintf_labels	|				|
| nfct_compare				| conntrack_compare		|				|
| nfct_cmp				| conntrack_cmp			|				|
| nfct_query				| (Not implemented)		|				|
| nfct_send				| (Not implemented)		|				|
| nfct_catch				| (Not implemented)		|				|
| nfct_copy				| conntrack_copy		|				|
| nfct_copy_attr			| conntrack_copy_attr		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_filter_create			| filter_create			|				|
| nfct_filter_destroy			| filter_destroy		|				|
| nfct_filter_add_attr			| filter_add_attr		|				|
| nfct_filter_add_attr_u32		| filter_add_attr_u32		|				|
| nfct_filter_set_logic			| filter_set_logic		|				|
| nfct_filter_attach			| filter_attach			|				|
| nfct_filter_detach			| filter_detach			|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_filter_dump_create		| filter_dump_create		|				|
| nfct_filter_dump_destroy		| filter_dump_destroy		|				|
| nfct_filter_dump_set_attr		| filter_dump_set_attr		|				|
| nfct_filter_dump_set_attr_u8		| filter_dump_set_attr_U8	|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_build_conntrack			| (Not implemented)		|				|
| nfct_parse_conntrack			| (Not implemented)		|				|
| nfct_build_query			| (Not implemented)		|				|
| nfct_nlmsg_build			| conntrack_nlmsg_build		|				|
| nfct_nlmsg_parse			| conntrack_nlmsg_parse		|				|
| nfct_payload_parse			| conntrack_payload_parse	|				|
| (add)					| conntrack_PayloadParseBytes	|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfexp_new				| expect_new			|				|
| nfexp_destroy				| expect_destroy		|				|
| nfexp_clone				| expect_clone			|				|
| nfexp_sizeof				| (Not implemented)		|				|
| nfexp_maxsize				| (Not implemented)		|				|
| nfexp_callback_register		| (Not implemented)		|				|
| nfexp_callback_unregister		| (Not implemented)		|				|
| nfexp_callback_register2		| (Not implemented)		|				|
| nfexp_callback_unregister2		| (Not implemented)		|				|
| nfexp_set_attr			| expect_set_attr		|				|
| nfexp_set_attr_u8			| expect_set_attr_u8		|				|
| nfexp_set_attr_u16			| expect_set_attr_u16		|				|
| nfexp_set_attr_u32			| expect_set_attr_u32		|				|
| nfexp_get_attr			| expect_get_attr		|				|
| (add)					| expect_get_attr_as		|				|
| nfexp_get_attr_u8			| expect_get_attr_u8		|				|
| nfexp_get_attr_u16			| expect_get_attr_u16		|				|
| nfexp_get_attr_u32			| expect_get_attr_u32		|				|
| nfexp_attr_is_set			| expect_attr_is_set		|				|
| nfexp_attr_unset			| expect_attr_unset		|				|
| nfexp_query				| (Not implemented)		|				|
| nfexp_snprintf			| expect_snprintf		|				|
| nfexp_cmp				| expect_cmp			|				|
| nfexp_send				| (Not implemented)		|				|
| nfexp_catch				| (Not implemented)		|				|
| nfexp_build_expect			| (Not implemented)		|				|
| nfexp_parse_expect			| (Not implemented)		|				|
| nfexp_build_query			| (Not implemented)		|				|
| nfexp_nlmsg_build			| expect_nlmsg_build		|				|
| nfexp_nlmsg_parse			| expect_nlmsg_parse		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
