#ifndef __FUNC_OTHERS__
#define __FUNC_OTHERS__

int func_traceroute(struct users *u);
int func_anti_dos_ena(struct users *u);
//int func_exec_timeout(struct users *u);
//int nfunc_exec_timeout(struct users *u);

int nfunc_config_dot1q(struct users *u);
int func_config_dot1q(struct users *u);

int nfunc_config_dot1q_tpid(struct users *u);
int func_config_dot1q_tpid(struct users *u);

int func_error_disable_recover_enable(u);
int func_error_disable_recover_timeout(u);
int nfunc_error_disable_recover(u);


























#endif
