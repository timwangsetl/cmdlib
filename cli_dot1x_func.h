#ifndef __FUNC_DOT1X__
#define __FUNC_DOT1X__

int func_set_dot1x_enable();
int check_hostapd_conf(void);
int cli_start_dot1x();
int cli_stop_dot1x();
int create_hostapd_conf();
int create_user_cfg();
int create_hostapd_maxuser_cfg();
int func_set_dot1x_reauth_enable();
int func_set_dot1x_reauth_time(char *time);
int func_set_dot1x_quietperiod(char *time);
int func_set_dot1x_txperiod(char *time);
int func_applicate_authentication_list();
int check_is_local();


int nfunc_set_dot1x_disable();
int nfunc_set_dot1x_timeout_default();
int nfunc_set_dot1x_quietperiod_default();
int nfunc_set_dot1x_timeout_default();


extern int cli_stop_dot1x();
extern int cli_start_dot1x();

int func_do_guest_vlan_enable();
int func_no_guest_vlan_enable();
#endif

