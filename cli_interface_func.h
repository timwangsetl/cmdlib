#ifndef __FUNC_INTERFACE__
#define __FUNC_INTERFACE__


#define IF_FAST_PORT	    0x01000000
#define IF_GIGA_PORT	    0x02000000
#define IF_XE_PORT	        0x04000000
#define IF_TRUNK_PORT	    0x10000000
#define IF_VLAN_PORT	    0x20000000
#define IF_RANGE_PORT	    0x40000000
#define IF_LOOPBACK_PORT    0x80000000

int func_if_port(struct users *u);
int func_if_range_port(struct users *u);

int func_if_trunk_port(struct users *u);
int func_if_vlan(struct users *u);

int nfunc_if_trunk_port(struct users *u);
int nfunc_if_vlan(struct users *u);


#endif

