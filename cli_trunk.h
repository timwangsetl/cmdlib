#ifndef __DO_TRUNK__
#define __DO_TRUNK__

/* option subcmds maskbit */
#define TRUNK_OPT_LOAD_BALANCE			0x00000001



/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* trunk commands parse function */
static int do_trunk(int argc, char *argv[], struct users *u);
static int no_trunk(int argc, char *argv[], struct users *u);
static int do_trunk_load_balance(int argc, char *argv[], struct users *u);
static int no_trunk_load_balance(int argc, char *argv[], struct users *u);
static int do_trunk_load_balance_src_mac(int argc, char *argv[], struct users *u);
static int do_trunk_load_balance_dst_mac(int argc, char *argv[], struct users *u);
static int do_trunk_load_balance_both_mac(int argc, char *argv[], struct users *u);
static int do_trunk_load_balance_src_ip(int argc, char *argv[], struct users *u);
static int do_trunk_load_balance_dst_ip(int argc, char *argv[], struct users *u);
static int do_trunk_load_balance_both_ip(int argc, char *argv[], struct users *u);
static int do_trunk_load_balance_src_port(int argc, char *argv[], struct users *u);
static int do_trunk_load_balance_dst_port(int argc, char *argv[], struct users *u);
static int do_trunk_load_balance_both_port(int argc, char *argv[], struct users *u);

/* lacp commands parse function */
static int do_lacp(int argc, char *argv[], struct users *u);
static int do_lacp_interval_mode(int argc, char *argv[], struct users *u);
static int do_lacp_interval_mode_fast(int argc, char *argv[], struct users *u);
static int do_lacp_interval_mode_normal(int argc, char *argv[], struct users *u);
static int no_lacp_interval_mode(int argc, char *argv[], struct users *u);

int init_cli_trunk(void);

#endif
