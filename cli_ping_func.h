#ifndef __FUNC_PING__
#define __FUNC_PING__



/* option subcmds maskbit */
#define PING_OPT_ALL_TIME			0x00000001
#define PING_OPT_PKT_LEN			0x00000002
#define PING_OPT_PKT_CNT			0x00000004
#define PING_OPT_WAIT_TIME			0x00000008
#define PING_OPT_INTERVAL_TIME		0x00000010
#define PING_OPT_TTL				0x00000020
#define PING_OPT_TOS				0x00000040
#define PING_HOST					0x00000080
#define PING_IPV4					0x00000100

/* option value in postion of u->x_param */
#define PING_PKT_LEN_POS			1
#define PING_PKT_CNT_POS			2
#define PING_WAIT_TIME_POS			3
#define PING_INTERVAL_TIME_POS		4
#define PING_TTL_POS				5
#define PING_TOS_POS				6

int func_ping(struct users *u);
int func_v6(struct users *u);

#endif

