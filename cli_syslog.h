#ifndef __DO_SYSLOG__
#define __DO_SYSLOG__


/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* logging commands parse function */
static int do_syslog(int argc, char *argv[], struct users *u);

/* logging buffered commands parse function */
static int do_log_buff(int argc, char *argv[], struct users *u);
static int do_log_buff_value(int argc, char *argv[], struct users *u);
static int do_log_buff_alerts(int argc, char *argv[], struct users *u);
static int do_log_buff_crit(int argc, char *argv[], struct users *u);
static int do_log_buff_debug(int argc, char *argv[], struct users *u);
static int do_log_buff_emerg(int argc, char *argv[], struct users *u);
static int do_log_buff_erro(int argc, char *argv[], struct users *u);
static int do_log_buff_infor(int argc, char *argv[], struct users *u);
static int do_log_buff_notif(int argc, char *argv[], struct users *u);
static int do_log_buff_warni(int argc, char *argv[], struct users *u);

/* logging host commands parse function */
static int do_log_host(int argc, char *argv[], struct users *u);
static int do_log_host_ip(int argc, char *argv[], struct users *u);

/* logging on commands parse function */
static int do_log_on(int argc, char *argv[], struct users *u);

/* logging console commands parse function */
static int do_log_console(int argc, char *argv[], struct users *u);
static int do_log_cons_alerts(int argc, char *argv[], struct users *u);
static int do_log_cons_crit(int argc, char *argv[], struct users *u);
static int do_log_cons_debug(int argc, char *argv[], struct users *u);
static int do_log_cons_emerg(int argc, char *argv[], struct users *u);
static int do_log_cons_erro(int argc, char *argv[], struct users *u);
static int do_log_cons_infor(int argc, char *argv[], struct users *u);
static int do_log_cons_notif(int argc, char *argv[], struct users *u);
static int do_log_cons_warni(int argc, char *argv[], struct users *u);

/*wuchunli 2012-2-27 13:54:48 begin*/
static int do_log_count(int argc, char *argv[], struct users *u);
static int no_do_log_count(int argc, char *argv[], struct users *u);
static int do_log_facility_value(int argc, char *argv[], struct users *u);
static int no_do_log_facility(int argc, char *argv[], struct users *u);
static int do_log_rate(int argc, char *argv[], struct users *u);
static int no_do_log_rate(int argc, char *argv[], struct users *u);
static int do_log_rate_value(int argc, char *argv[], struct users *u);
static int do_log_facility(int argc, char *argv[], struct users *u);
static int do_log_userinfo(int argc, char *argv[], struct users *u);
static int no_do_log_userinfo(int argc, char *argv[], struct users *u);
static int do_log_command(int argc, char *argv[], struct users *u);
static int no_do_log_command(int argc, char *argv[], struct users *u);
static int do_service(int argc, char *argv[], struct users *u);
static int do_service_time(int argc, char *argv[], struct users *u);
static int do_service_time_debug(int argc, char *argv[], struct users *u);
static int do_service_time_log(int argc, char *argv[], struct users *u);
static int do_service_time_debug_date(int argc, char *argv[], struct users *u);
static int do_service_time_debug_up(int argc, char *argv[], struct users *u);
static int do_service_time_log_date(int argc, char *argv[], struct users *u);
static int do_service_time_log_up(int argc, char *argv[], struct users *u);
static int do_service_sysname(int argc, char *argv[], struct users *u);
static int do_service_number(int argc, char *argv[], struct users *u);
static int no_do_service_time(int argc, char *argv[], struct users *u);
static int no_do_service_time_debug(int argc, char *argv[], struct users *u);
static int no_do_service_time_log(int argc, char *argv[], struct users *u);
static int no_do_service_sysname(int argc, char *argv[], struct users *u);
static int no_do_service_number(int argc, char *argv[], struct users *u);
/*wuchunli 2012-2-27 13:54:57 end*/

/* logging trap commands parse function */
static int do_log_trap(int argc, char *argv[], struct users *u);
static int do_log_trap_alerts(int argc, char *argv[], struct users *u);
static int do_log_trap_crit(int argc, char *argv[], struct users *u);
static int do_log_trap_debug(int argc, char *argv[], struct users *u);
static int do_log_trap_emerg(int argc, char *argv[], struct users *u);
static int do_log_trap_erro(int argc, char *argv[], struct users *u);
static int do_log_trap_infor(int argc, char *argv[], struct users *u);
static int do_log_trap_notif(int argc, char *argv[], struct users *u);
static int do_log_trap_warni(int argc, char *argv[], struct users *u);

/* no logging commands parse function */
static int no_do_log_buff(int argc, char *argv[], struct users *u);
static int no_do_log_host(int argc, char *argv[], struct users *u);
static int no_do_log_on(int argc, char *argv[], struct users *u);
static int no_do_log_console(int argc, char *argv[], struct users *u);
static int no_do_log_trap(int argc, char *argv[], struct users *u);

#endif
