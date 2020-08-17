#ifndef __DO_ARP__
#define __DO_ARP__


/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* arp commands parse function */
static int do_arp(int argc, char *argv[], struct users *u);
static int do_arp_ip(int argc, char *argv[], struct users *u);
static int do_arp_ip_mac(int argc, char *argv[], struct users *u);
static int do_arp_vlan(int argc, char *argv[], struct users *u);
static int do_arp_vlan_intf(int argc, char *argv[], struct users *u);
static int do_arp_vlan_type_interface(int argc, char *argv[], struct users *u);
static int do_arp_vlan_interfac_ethernet(int argc, char *argv[], struct users *u);
static int do_arp_vlan_interface_num(int argc, char *argv[], struct users *u);
static int do_arp_vlan_interface_slash(int argc, char *argv[], struct users *u);
static int do_arp_interface_port(int argc, char *argv[], struct users *u);

static int no_arp_ip(int argc, char *argv[], struct users *u);

#endif

