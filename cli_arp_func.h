#ifndef __FUNC_ARP__
#define __FUNC_ARP__

#define ARP_IF_FAST_PORT	0x08000000
#define ARP_IF_GIGA_PORT	0x10000000
#define ARP_IF_XE_PORT	    0x20000000

int func_static_arp(struct users *u);
int nfunc_static_arp(struct users *u);




#endif

