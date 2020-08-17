#ifndef __FUNC_CLOCK__
#define __FUNC_CLOCK__
/* extern functions */
int func_clock(struct users *u);
int func_timezone(struct users *u);
int nfunc_timezone(struct users *u);
int func_ntp_server(struct users *u);
int func_ntp_time(struct users *u);
int nfunc_ntp(struct users *u);
int nfunc_ntp_query(struct users *u);
static int check_ipaddr(char *ip_buf);

/*----------------------------------------------------------------------------------------------------------------*/
#if 0
int func_config_dot1q(struct users *u);
int nfunc_config_dot1q(struct users *u);
#endif

/*----------------------------------------------------------------------------------------------------------------*/

#endif

