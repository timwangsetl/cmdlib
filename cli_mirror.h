#ifndef __DO_MIRROR__
#define __DO_MIRROR__

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* mirror commands parse function */
static int do_mirror(int argc, char *argv[], struct users *u);
static int do_session(int argc, char *argv[], struct users *u);
static int do_session_num(int argc, char *argv[], struct users *u);
static int do_session_type(int argc, char *argv[], struct users *u);
static int do_session_type_interface(int argc, char *argv[], struct users *u);
static int do_session_type_vlan(int argc, char *argv[], struct users *u);

/* interface port */
static int do_mirror_interface_ethernet(int argc, char *argv[], struct users *u);
static int do_mirror_interface_num(int argc, char *argv[], struct users *u);
static int do_mirror_interface_slash(int argc, char *argv[], struct users *u);
static int do_mirror_interface_port(int argc, char *argv[], struct users *u);

/* interface range port */
static int do_mirror_interface_range_port(int argc, char *argv[], struct users *u);
static int do_mirror_interface_range_num(int argc, char *argv[], struct users *u);
static int do_mirror_interface_range_slash(int argc, char *argv[], struct users *u);
static int do_mirror_interface_range_port_start(int argc, char *argv[], struct users *u);
static int do_mirror_interface_range_hyphen(int argc, char *argv[], struct users *u);
static int do_mirror_interface_range_comma(int argc, char *argv[], struct users *u);
static int do_mirror_interface_range_port_end(int argc, char *argv[], struct users *u);
static int do_mirror_interface_range_comma_end(int argc, char *argv[], struct users *u);

static int do_mirror_interface_opt(int argc, char *argv[], struct users *u);

/* Negative func */
static int no_session_num(int argc, char *argv[], struct users *u);
static int no_mirror_interface_range_port_start(int argc, char *argv[], struct users *u);
static int no_mirror_interface_opt(int argc, char *argv[], struct users *u);

static int do_mirror_vlan_range_num(int argc, char *argv[], struct users *u);


static int do_session_vlan_num(int argc, char *argv[], struct users *u);
static int do_session_vlan(int argc, char *argv[], struct users *u);
static int do_session_vlan_type_interface(int argc, char *argv[], struct users *u);
static int do_mirror_vlan_interface_ethernet(int argc, char *argv[], struct users *u);
static int do_mirror_vlan_interface_num(int argc, char *argv[], struct users *u);
static int do_mirror_vlan_interface_slash(int argc, char *argv[], struct users *u);
static int do_mirror_vlan_interface_port(int argc, char *argv[], struct users *u);
static int do_session_vlan_type_vlan(int argc, char *argv[], struct users *u);
static int do_mirror_vlan_vlan_range_num(int argc, char *argv[], struct users *u);
static int do_session_vlan_des_type(int argc, char *argv[], struct users *u);
static int do_session_vlan_src_type(int argc, char *argv[], struct users *u);
static int no_session_vlan(int argc, char *argv[], struct users *u);


#endif
