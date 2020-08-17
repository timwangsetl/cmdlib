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

#include "console.h"
#include "cmdparse.h"
#include "parameter.h"

#include "cli_lldp_func.h"

int func_lldp_run(struct users *u)
{
	char *lldp_enable = nvram_safe_get("lldp_enable");
	
	if(*lldp_enable != '1'){
		nvram_set("lldp_enable", "1");
		SYSTEM("/usr/sbin/lldpd");
	}
	free(lldp_enable);
	return 0;
}

int func_set_lldp_holdtime(struct users *u)
{
	char hold_time[10] = {'\0'};
	int i_holdtime;
	cli_param_get_int(DYNAMIC_PARAM, LLDP_1_POS, &i_holdtime, u);
	sprintf(hold_time, "%d", i_holdtime);
	char *lldp_holdtime = nvram_safe_get("lldp_holdtime");
	nvram_set("lldp_holdtime", hold_time);
	system("killall -SIGUSR2 lldpd");
	free(lldp_holdtime);
	return 0;
}

int func_set_lldp_interval_time(struct users *u)
{
	char i_time[10] = {'\0'};
	int i_interval_time;
	cli_param_get_int(DYNAMIC_PARAM, LLDP_2_POS, &i_interval_time, u);
	sprintf(i_time, "%d", i_interval_time);
	char *lldp_interval_time = nvram_safe_get("lldp_interval_time");
	nvram_set("lldp_interval_time", i_time);
	system("killall -SIGUSR2 lldpd");
	free(lldp_interval_time);
	return 0;
}

int nfunc_lldp_run(struct users *u)
{
	/*shut down lldp*/
	char *lldp_enable = nvram_safe_get("lldp_enable");
	if('0' != *lldp_enable){
		nvram_set("lldp_enable", "0");
		SYSTEM("killall lldpd > /dev/null 2>&1");
		free(lldp_enable);
		return 0;
	}
	free(lldp_enable);
	return 0;
}

int nfunc_set_lldp_holdtime(struct users *u)
{
	/*set lldp holdtime to default*/
	char *lldp_holdtime = nvram_safe_get_def("lldp_holdtime");
	nvram_set("lldp_holdtime", lldp_holdtime);
	system("killall -SIGUSR2 lldpd >/dev/null 2>&1");
	free(lldp_holdtime);
	return 0;
}

int nfunc_set_lldp_interval_time(struct users *u)
{
	/*set lldp interval_time to default*/
	char *lldp_interval_time = nvram_safe_get_def("lldp_interval_time");
	nvram_set("lldp_interval_time",lldp_interval_time);
	system("killall -SIGUSR2 lldpd >/dev/null 2>&1");
	free(lldp_interval_time);
	return 0;
}



















