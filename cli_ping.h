#ifndef __DO_PING__
#define __DO_PING__

/* option subcmds maskbit */
#define PING_OPT_ALL_TIME			0x00000001
#define PING_OPT_PKT_LEN			0x00000002
#define PING_OPT_PKT_CNT			0x00000004
#define PING_OPT_WAIT_TIME			0x00000008
#define PING_OPT_INTERVAL_TIME		0x00000010
#define PING_OPT_TTL				0x00000020
#define PING_OPT_TOS				0x00000040

/* option value in postion of u->x_param */
#define PING_PKT_LEN_POS			1
#define PING_PKT_CNT_POS			2
#define PING_WAIT_TIME_POS			3
#define PING_INTERVAL_TIME_POS		4
#define PING_TTL_POS				5
#define PING_TOS_POS				6

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* ping commands parse function */
static int do_ping(int argc, char *argv[], struct users *u);

static int do_ping_ip(int argc, char *argv[], struct users *u);
static int do_ping_host(int argc, char *argv[], struct users *u);
static int do_ping_ipv6(int argc, char *argv[], struct users *u);
static int do_v6(int argc, char *argv[], struct users *u);

static int do_ping_opt_a(int argc, char *argv[], struct users *u);
static int do_ping_opt_l(int argc, char *argv[], struct users *u);
static int do_ping_opt_n(int argc, char *argv[], struct users *u);
static int do_ping_opt_w(int argc, char *argv[], struct users *u);
static int do_ping_opt_b(int argc, char *argv[], struct users *u);
static int do_ping_opt_t(int argc, char *argv[], struct users *u);
static int do_ping_opt_s(int argc, char *argv[], struct users *u);

#endif
