#ifndef __FUNC_SYSLOG__
#define __FUNC_SYSLOG__



int nfunc_log_on(struct users *u);
int func_log_on(struct users *u);



int nfunc_log_host(struct users *u);
int func_log_host_ip(struct users *u);


int nfunc_log_buff(struct users *u);
int func_log_buf_default(struct users *u);
int func_log_buff_value(struct users *u);
int func_log_buff_alerts(struct users *u);
int func_log_buff_crit(struct users *u);
int func_log_buff_debug(struct users *u);
int func_log_buff_emerg(struct users *u);
int func_log_buff_erro(struct users *u);
int func_log_buff_infor(struct users *u);
int func_log_buff_notif(struct users *u);
int func_log_buff_warni(struct users *u);

int nfunc_log_console(struct users *u);
int func_log_con_default(struct users *u);
int func_log_cons_alerts(struct users *u);
int func_log_cons_crit(struct users *u);
int func_log_cons_debug(struct users *u);
int func_log_cons_emerg(struct users *u);
int func_log_cons_erro(struct users *u);
int func_log_cons_infor(struct users *u);
int func_log_cons_notif(struct users *u);
int func_log_cons_warni(struct users *u);
int nfunc_log_console(struct users *u);

int nfunc_log_trap(struct users *u);
int func_log_trap_default(struct users *u);
int func_log_trap_alerts(struct users *u);
int func_log_trap_crit(struct users *u);
int func_log_trap_debug(struct users *u);
int func_log_trap_emerg(struct users *u);
int func_log_trap_erro(struct users *u);
int func_log_trap_infor(struct users *u);
int func_log_trap_notif(struct users *u);
int func_log_trap_warni(struct users *u);



#endif

