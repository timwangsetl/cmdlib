#ifndef __DO_MAC__
#define __DO_MAC__

#define MAC_IF_FAST_PORT_MSK	0x08000000
#define MAC_IF_GIGA_PORT_MSK	0x10000000
#define MAC_IF_XE_PORT_MSK	0x20000000

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* mac commands parse function */
static int do_mac(int argc, char *argv[], struct users *u);
static int do_mac_add_aging(int argc, char *argv[], struct users *u);
static int do_mac_add_agSt(int argc, char *argv[], struct users *u);
static int do_mac_add_st(int argc, char *argv[], struct users *u);
static int do_mac_add_st_m(int argc, char *argv[], struct users *u);
static int do_mac_add_st_m_v(int argc, char *argv[], struct users *u);

static int do_mac_add_st_m_vid(int argc, char *argv[], struct users *u);
static int no_mac_add_st_m_vid(int argc, char *argv[], struct users *u);

static int do_mac_add_st_m_v_int(int argc, char *argv[], struct users *u);

/* interface range fast-port */
static int do_mac_interface_range_port(int argc, char *argv[], struct users *u);
static int do_mac_interface_range_num(int argc, char *argv[], struct users *u);
static int do_mac_interface_range_slash(int argc, char *argv[], struct users *u);
static int do_mac_interface_range_port_start(int argc, char *argv[], struct users *u);
static int do_mac_interface_range_hyphen(int argc, char *argv[], struct users *u);
static int do_mac_interface_range_comma(int argc, char *argv[], struct users *u);
static int do_mac_interface_range_port_end(int argc, char *argv[], struct users *u);
static int do_mac_interface_range_comma_end(int argc, char *argv[], struct users *u);

static int do_accl(int argc, char *argv[], struct users *u);
static int do_accl_name(int argc, char *argv[], struct users *u);
static int no_accl_name(int argc, char *argv[], struct users *u);
static int no_mac_add_aging(int argc, char *argv[], struct users *u);
//static int no_mac_add(int argc, char *argv[], struct users *u);

static int do_mac_blackhole(int argc, char *argv[], struct users *u);
static int no_mac_blackhole(int argc, char *argv[], struct users *u);
static int do_mac_add_blackhole(int argc, char *argv[], struct users *u);
static int no_mac_add_blackhole(int argc, char *argv[], struct users *u);
static int do_mac_add_blackhole_v(int argc, char *argv[], struct users *u);
static int no_mac_add_blackhole_v(int argc, char *argv[], struct users *u);
static int do_mac_blackhole_vid(int argc, char *argv[], struct users *u);
static int no_mac_blackhole_vid(int argc, char *argv[], struct users *u);

#endif

