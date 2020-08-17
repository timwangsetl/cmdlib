#ifndef __FUNC_RADIUS_SERVER__
#define __FUNC_RADIUS_SERVER__

int create_user_cfg();
int create_hostapd_conf();
int create_hostapd_maxuser_cfg();
int cli_start_dot1x();
int cli_stop_dot1x();
int func_set_radius_ip_port(char *ip, char *port1, char *port2);
int func_set_radius_key(char *key);
int nfunc_radius_host();
int nfunc_radius_key();
#define	db_ra(fmt,arg...)		//printf("%s %d "fmt,__FUNCTION__,__LINE__,##arg)	

#endif


