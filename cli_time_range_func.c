/*
 * Copyright 2011 by FeiXun Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_clock_func.c
 * Function   : show command function
 * Auther     : dawei.hu
 * Version    : 1.0
 * Date       : 2011/11/21
 *                                         
*/

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

#include "cli_time_range_func.h"
#include "bcmutils.h"

static int cli_delete_time_range_list(char *name)
{
	//int res, i, flag=0;
	//char *time_range_name, *time_range_cfg, *port_acl, *buff, *p, *ptr;
	//char temp[ACL_NAME_LEN+3], port_acl_name[1024];	

	/* following is to modify nvram value */	
	//time_range_name = nvram_safe_get("time_range_name");
	//time_range_cfg  = nvram_safe_get("time_range_cfg");


	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Deleted the MAC address by name %s, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int cli_set_time_range_nvram(char *name_str)
{
	char *time_range_cfg  = nvram_safe_get("time_range_cfg");
	char *str;
		
	/* name is not exist */
	str = malloc(strlen(time_range_cfg) + 64);
	if(NULL == str)
	{
		free(time_range_cfg);
		return -1;
	}
	memset(str, '\0', strlen(time_range_cfg) + 64);
	strcpy(str, time_range_cfg);
	strcat(str, name_str);
	strcat(str, "|;");
	
	nvram_set("time_range_cfg", str);
	
	free(str);
	free(time_range_cfg);
	return CLI_SUCCESS;
}
	
int func_time_range_name(struct users *u)
{
	char time_range_name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(STATIC_PARAM, 0, time_range_name, u);

	//cli_set_acl_nvram(acl_name);
	if(cli_set_time_range_nvram(time_range_name) == -2)
		return -1;
	
	nvram_set("time_range_name", time_range_name);
	syslog(LOG_NOTICE, "[CONFIG-5-MAC]: The access list name was set to %s, %s\n", time_range_name, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

int nfunc_time_range_name(struct users *u)
{
	char time_range_name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(STATIC_PARAM, 0, time_range_name, u);

	cli_delete_time_range_list(time_range_name);
	
	return 0;
}

int func_time_range_set(struct users *u)
{
	char command[35]; 
	//char *time_range_cfg = nvram_safe_get("time_range_cfg");
	int offset;	
	struct timeval tv;
	struct timezone tz;	
	char buff[MAX_ARGV_LEN] = {'\0'};
	int day = 0, month = 0, year = 0;
	
	cli_param_get_string(STATIC_PARAM, 0, buff, u); 
	cli_param_get_int(STATIC_PARAM, 0, &day, u);
	cli_param_get_int(STATIC_PARAM, 1, &month, u);
	cli_param_get_int(STATIC_PARAM, 2, &year, u);
	
	/*wuchunli 2012-4-16 9:31:16 begin 
	  modify format*/
	switch (month) {
		case 2:
			if (0 == year % 4) {
				if (day > 29) {
					vty_output("Invalid day format!\n");
					return 0;	
				}
			} else {
				if (day > 28) {
					vty_output("Invalid day format!\n");
					return 0;	
				}
			}
			break;
		case 4:
		case 6:
		case 9:
		case 11:
			if (day > 30) {
				vty_output("Invalid day format!\n");
				return 0;	
			}
			break;
		default:
			break;
	}	
	
//	sprintf(command, "/bin/date -s %d.%d.%d-%s |cd", year, month, day, buff);
//	system(command);

//	//fix the timezone bug 2011/1/12
//	offset=atoi(timeoffset);
//	gettimeofday (&tv , &tz);
//	tv.tv_sec -= offset*3600;
//	settimeofday(&tv, &tz);
//	free(timeoffset);
	return 0;
	/*wuchunli 2012-4-16 9:31:49 end*/
}  

