#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/stat.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/file.h>
#include <syslog.h>
#include <termios.h>

#include <arpa/inet.h>

#include "if_info.h"
#include "console.h"
#include "cmdparse.h"
#include "parameter.h"

#include "cli_syslog_func.h"

#define SYSLOG_CONF "/etc/syslog.conf"

/*added by wuchunli 2012-3-22 10:22:02*/
static void cli_set_logging_buf_size_default(char *buf_size)
{
	char *cur_cfg_def = nvram_safe_get_def(buf_size);
	nvram_set(buf_size, cur_cfg_def);
	free(cur_cfg_def);
	return;
}

/* cli set logging level default
   modified by wuchunli 2012-3-27 12:31:12*/
static void cli_set_logging_level_default(char *type)
{
	char *cur_cfg_def = nvram_safe_get_def(type);
	nvram_set(type, cur_cfg_def);
	free(cur_cfg_def);
	return;
}

/*modified by wuchunli 2012-3-21 12:23:34*/
int nfunc_log_buff(struct users *u)
{
	/* logging buffer disable */
	char *log_buf_enable = nvram_safe_get("log_buf_enable");
	if (atoi(log_buf_enable) != 0) {
		nvram_set("log_buf_enable", "0");
		nvram_set("log_buf_size", "");
		SYSTEM("/bin/rm /var/log/messages > /dev/null 2>&1");
		cli_set_logging_level_default("log_buf_type");
		system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	}
  	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Clear buffer and disabled the buffer log,%s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(log_buf_enable);
 	 return 0;
}

/*modified by wuchunli 2012-3-21 12:26:43*/
int nfunc_log_on(struct users *u)
{
	/*log_enable:logging global enable*/
	char *log_enable = nvram_safe_get("log_enable");
	if (atoi(log_enable) !=0) {
		nvram_set("log_enable", "0");
		system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	}
  	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Disable logging to all supported destinations,%s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(log_enable);
  	return 0;
}

/*modified by wuchunli 2012-3-21 12:33:26*/
int nfunc_log_console(struct users *u)
{
	char *log_con_enable = nvram_safe_get("log_con_enable");
	if (atoi(log_con_enable) != 0) {
		nvram_set("log_con_enable", "0");
		cli_set_logging_level_default("log_con_type");
		system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	}
  	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Disable logging to console,%s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(log_con_enable);
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:26:14 
  no logging trap:disable logging to host
  no logging host:delete host ip
  */
int nfunc_log_trap(struct users *u)
{
	char *log_host_enable = nvram_safe_get("log_host_enable");
	if (atoi(log_host_enable) != 0) {
		nvram_set("log_host_enable", "0");
		cli_set_logging_level_default("log_host_type");
		system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	}
  	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Disable logging to host,%s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(log_host_enable);
  	return 0;
}

/*modified by wuchunli 2012-3-22 13:52:14*/
int nfunc_log_host(struct users *u)
{
  	nvram_set("log_host", "");
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Delete the logging host IP, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

int func_log_host_ip(struct users *u)
{
  	struct in_addr s;
  	char ip_addr[MAX_ARGV_LEN] = {'0'};
  	cli_param_get_ipv4(STATIC_PARAM, 0, &s, ip_addr, sizeof(ip_addr), u);
  	nvram_set("log_host", ip_addr);
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed logging host IP, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-21 11:05:29*/
int func_log_on(struct users *u)
{
	/*logging global enable*/
	nvram_set("log_enable", "1");
    system("/usr/bin/killall -SIGUSR2 syslogd > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Enable logging to all supported destinations, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	
  	return 0;
}

/*modified by wuchunli 2012-3-21 11:05:29*/
int func_log_buff_value(struct users *u)
{
	int buffer_size = 0;
	char buff[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_int(STATIC_PARAM, 0, &buffer_size, u);
	char *log_buf_size = nvram_safe_get("log_buf_size");
	/* log_buf_enable:logging buffer enable*/
	char *log_buf_enable = nvram_safe_get("log_buf_enable"); 
	sprintf(buff, "%d", buffer_size);
	if (0 == atoi(log_buf_enable)) {
		nvram_set("log_buf_enable","1");
		cli_set_logging_level_default("log_con_type");
	}
	nvram_set("log_buf_size", buff);	
	system("/usr/bin/killall -SIGUSR2 syslogd > /dev/null 2>&1");	
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Open the buffer log and set the size of buffer to %s bytes, %s\n", buff, getenv("LOGIN_LOG_MESSAGE"));
	free(log_buf_size);
	free(log_buf_enable);
	return 0;
}	

/*added by wuchunli 2012-3-22 10:14:59*/
int func_log_buf_default(struct users *u)
{
	nvram_set("log_buf_enable","1");
	cli_set_logging_level_default("log_buf_type");
	cli_set_logging_buf_size_default("log_buf_size");
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Open the buffer log and set the logging buffer to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-26 13:58:11*/
int func_log_buff_alerts(struct users *u)
{
	nvram_set("log_buf_enable","1");
  	nvram_set("log_buf_type", "1"); //alerts
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Configed the type of buffer to alerts, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-26 13:59:51*/
int func_log_buff_crit(struct users *u)
{
	nvram_set("log_buf_enable","1");
  	nvram_set("log_buf_type", "2"); //critical
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Configed the type of buffer to critical, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-26 13:59:59*/
int func_log_buff_debug(struct users *u)
{
	nvram_set("log_buf_enable","1");
  	nvram_set("log_buf_type", "7"); //debugging
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of buffer to debugging, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-26 14:00:38*/
int func_log_buff_emerg(struct users *u)
{
	nvram_set("log_buf_enable","1");
  	nvram_set("log_buf_type", "0"); //emergencies
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of buffer to emergencies, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

/*modified by wuchunli 2012-3-26 14:01:02*/
int func_log_buff_erro(struct users *u)
{
	nvram_set("log_buf_enable","1");
  	nvram_set("log_buf_type", "3"); //errors
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of buffer to errors, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-26 14:01:31*/
int func_log_buff_infor(struct users *u)
{
	nvram_set("log_buf_enable","1");
  	nvram_set("log_buf_type", "6"); //informational
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of buffer to informational, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-26 14:02:10*/
int func_log_buff_notif(struct users *u)
{
	nvram_set("log_buf_enable","1");
  	nvram_set("log_buf_type", "5"); //notifications
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of buffer to notifications, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 9:48:21*/
int func_log_buff_warni(struct users *u)
{
	nvram_set("log_buf_enable","1");
  	nvram_set("log_buf_type", "4"); //warnings
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of buffer to warnings, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*added by wuchunli 2012-3-22 9:47:32 
 logging console <cr>
  */
int func_log_con_default(struct users *u)
{
	nvram_set("log_con_enable","1");
	cli_set_logging_level_default("log_con_type");
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Open the console log and set the logging console level to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 9:49:58*/
int func_log_cons_alerts(struct users *u)
{
	nvram_set("log_con_enable","1");
  	nvram_set("log_con_type", "1"); //alerts
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set the logging console level to alerts, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 9:52:01*/
int func_log_cons_crit(struct users *u)
{
	nvram_set("log_con_enable","1");
  	nvram_set("log_con_type", "2"); //critical
  	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set the logging console level to critical, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 9:58:58*/
int func_log_cons_debug(struct users *u)
{
	nvram_set("log_con_enable","1");
  	nvram_set("log_con_type", "7"); //debugging
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of console to debugging, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:01:46*/
int func_log_cons_emerg(struct users *u)
{
	nvram_set("log_con_enable","1");
  	nvram_set("log_con_type", "0"); //emergencies
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of console to emergencies, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:01:09*/
int func_log_cons_erro(struct users *u)
{
	nvram_set("log_con_enable","1");
  	nvram_set("log_con_type", "3"); //errors
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of console to errors, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:08:48*/
int func_log_cons_infor(struct users *u)
{
	nvram_set("log_con_enable","1");
    nvram_set("log_con_type", "6"); //informational
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of console to informational, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return 0;
}

/*modified by wuchunli 2012-3-22 10:03:32*/
int func_log_cons_notif(struct users *u)
{
	nvram_set("log_con_enable","1");
  	nvram_set("log_con_type", "5"); //notifications
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
 	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of console to notifications, %s\n", getenv("LOGIN_LOG_MESSAGE"));
 	return 0;
}		

/*modified by wuchunli 2012-3-22 10:08:36*/
int func_log_cons_warni(struct users *u)
{
	nvram_set("log_con_enable","1");
  	nvram_set("log_con_type", "4"); //warnings
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of console to warnings, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*added by wuchunli 2012-3-22 10:11:35 
  logging trap <cr>*/
int func_log_trap_default(struct users *u)
{
	nvram_set("log_host_enable","1");
	cli_set_logging_level_default("log_host_type");
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Open the host log and set the logging host level to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:04:55*/
int func_log_trap_alerts(struct users *u)
{
	nvram_set("log_host_enable","1");
  	nvram_set("log_host_type", "1"); //alerts
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of host to alerts, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:05:26*/
int func_log_trap_crit(struct users *u)
{
	nvram_set("log_host_enable","1");
  	nvram_set("log_host_type", "2"); //critical
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of host to critical, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:05:31*/
int func_log_trap_debug(struct users *u)
{
	nvram_set("log_host_enable","1");
  	nvram_set("log_host_type", "7"); //debugging
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of host to debugging, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:06:03*/
int func_log_trap_emerg(struct users *u)
{
	nvram_set("log_host_enable","1");
  	nvram_set("log_host_type", "0"); //emergencies
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of host to emergencies, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:07:01*/
int func_log_trap_erro(struct users *u)
{
	nvram_set("log_host_enable","1");
  	nvram_set("log_host_type", "3"); //errors
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of host to errors, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:07:11*/
int func_log_trap_infor(struct users *u)
{
	nvram_set("log_host_enable","1");
  	nvram_set("log_host_type", "6"); //informational
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of host to informational, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:07:39*/
int func_log_trap_notif(struct users *u)
{
	nvram_set("log_host_enable","1");
  	nvram_set("log_host_type", "5"); //notifications
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of host to notifications, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

/*modified by wuchunli 2012-3-22 10:08:11*/
int func_log_trap_warni(struct users *u)
{
	nvram_set("log_host_enable","1");
  	nvram_set("log_host_type", "4"); 
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
  	syslog(LOG_NOTICE, "[CONFIG-5-LOGGING]: Configed the type of host to warnings, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}


