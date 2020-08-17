#ifndef __DO_INTERFANCE__
#define __DO_INTERFANCE__

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* interface */
static int do_interface(int argc, char *argv[], struct users *u);

static int do_interface_range(int argc, char *argv[], struct users *u);

/* interface port */
static int do_interface_ethernet(int argc, char *argv[], struct users *u);
static int do_interface_num(int argc, char *argv[], struct users *u);
static int do_interface_slash(int argc, char *argv[], struct users *u);
static int do_interface_port(int argc, char *argv[], struct users *u);

/* interface port-aggregator and vlan */
static int do_interface_trunk(int argc, char *argv[], struct users *u);
static int do_interface_trunk_port(int argc, char *argv[], struct users *u);

static int do_interface_vlan(int argc, char *argv[], struct users *u);
static int do_interface_vlan_id(int argc, char *argv[], struct users *u);

/* interface loopback added by kim 20160630*/
static int do_interface_lo(int argc, char *argv[], struct users *u);
static int do_interface_lo_id(int argc, char *argv[], struct users *u);
static int do_interface_lo_ipaddr(int argc, char *argv[], struct users *u);
static int do_interface_lo_ipmask(int argc, char *argv[], struct users *u);
static int no_interface_lo_id(int argc, char *argv[], struct users *u);

/* interface range port */
static int do_interface_range_port(int argc, char *argv[], struct users *u);
static int do_interface_range_num(int argc, char *argv[], struct users *u);
static int do_interface_range_slash(int argc, char *argv[], struct users *u);
static int do_interface_range_port_start(int argc, char *argv[], struct users *u);
static int do_interface_range_hyphen(int argc, char *argv[], struct users *u);
static int do_interface_range_comma(int argc, char *argv[], struct users *u);
static int do_interface_range_port_end(int argc, char *argv[], struct users *u);
static int do_interface_range_comma_end(int argc, char *argv[], struct users *u);

/* no interface */
static int no_interface(int argc, char *argv[], struct users *u);

/* interface port-aggregator and vlan */
static int no_interface_trunk_port(int argc, char *argv[], struct users *u);

static int no_interface_vlan_id(int argc, char *argv[], struct users *u);

#endif

