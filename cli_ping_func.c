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
#include <netdb.h>

#include <arpa/inet.h>

#include "console.h"
#include "cmdparse.h"
#include "parameter.h"
#include "nvram.h"

#include "cli_ping_func.h"

/*
 *  Function: func_ping
 *  Purpose:   ping host
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   jialong.chu and dawei.hu
 *  modifier: gujiajie   01/30/2012
 *  Date:    2011/12/8
 */

int func_ping(struct users *u)
{	
	char ip_str[32];
	char *lan_ipaddr = nvram_safe_get("lan_ipaddr");
	char *ip_staticip_enable = nvram_safe_get("ip_staticip_enable");

	if(strlen(lan_ipaddr) == 0 && *ip_staticip_enable == '1') {
		free(lan_ipaddr);
		free(ip_staticip_enable);
		printf("Please set ip address first\n");
		return -1;
	}
	free(lan_ipaddr);
	free(ip_staticip_enable);

	if(ISSET_CMD_MSKBIT(u, PING_IPV4))
	{
		struct in_addr s;
		char ip_addr[MAX_ARGV_LEN] = {'\0'};	
		cli_param_get_ipv4(STATIC_PARAM, 0, &s, ip_addr, sizeof(ip_addr), u);
		strcpy(ip_str, ip_addr);
	}
	
	if(ISSET_CMD_MSKBIT(u, PING_HOST))
	{
		struct in_addr s;
		struct hostent *hptr;
		char host[MAX_ARGV_LEN] = {'\0'};	
		cli_param_get_string(STATIC_PARAM, 0, host, u);

		/* check ip_addr*/
		if(inet_pton(AF_INET, host, (void *)&s) !=	1)	
		{
			if((hptr = gethostbyname(host)) == NULL)
			{
				vty_output("  Unknow host\n");
				return -1 ;
			}
			else
			{
				if(hptr->h_addrtype != AF_INET)
				{
					vty_output("  unknown address type; only AF_INET is supported.\n");
					return -1 ;
				}
				else
					inet_ntop(hptr->h_addrtype, hptr->h_addr, ip_str, sizeof(ip_str));
			}
		}
		else
			strcpy(ip_str, host);
	}

	int var = 0;
	char command[128] = {'\0'}, buffer[MAX_ARGV_LEN] = {'\0'};
  	if(ISSET_CMD_MSKBIT(u, PING_OPT_PKT_LEN))
 	{
  	 	cli_param_get_int(DYNAMIC_PARAM, PING_PKT_LEN_POS, &var, u);
  	 	snprintf(buffer, sizeof(buffer), "-s %d ", (var-8/*ICMP_MINLEN*/));  
		strcat(command, buffer);
  	}
  	if(ISSET_CMD_MSKBIT(u, PING_OPT_PKT_CNT))
  	{
  	 	cli_param_get_int(DYNAMIC_PARAM, PING_PKT_CNT_POS, &var, u);
  	 	snprintf(buffer, sizeof(buffer), "-c %d ", var); 

		if(var != 0)
			strcat(command, buffer);
  	}
  	if(ISSET_CMD_MSKBIT(u, PING_OPT_WAIT_TIME))
  	{
  	 	cli_param_get_int(DYNAMIC_PARAM, PING_WAIT_TIME_POS, &var, u);
  	 	snprintf(buffer, sizeof(buffer), "-w %d ", var); 
		strcat(command, buffer);
  	}
  	if(ISSET_CMD_MSKBIT(u, PING_OPT_INTERVAL_TIME))
  	{
  	 	cli_param_get_int(DYNAMIC_PARAM, PING_INTERVAL_TIME_POS, &var, u);
  	 	snprintf(buffer, sizeof(buffer), "-b %d ", var);  
		strcat(command, buffer);
  	}
  	if(ISSET_CMD_MSKBIT(u, PING_OPT_TTL))
  	{
  	 	cli_param_get_int(DYNAMIC_PARAM, PING_TTL_POS, &var, u);
  	 	snprintf(buffer, sizeof(buffer), "-t %d ", var); 
		strcat(command, buffer);
  	}
  	if(ISSET_CMD_MSKBIT(u, PING_OPT_TOS))
  	{
  	 	cli_param_get_int(DYNAMIC_PARAM, PING_TOS_POS, &var, u);
  	 	snprintf(buffer, sizeof(buffer), "-s %d ", var); 
		strcat(command, buffer);
  	}

    if(strstr(command, "-n") == NULL
		&& ISSET_CMD_MSKBIT(u, PING_OPT_ALL_TIME))
    {
		snprintf(buffer, sizeof(buffer), "-a ");
		strcat(command, buffer);
    }
    
    if(strstr(command, "-c") == NULL)
		strcat(command, " -c 4");
   
    SYSTEM("/bin/ping %s %s", command, ip_str);

	return 0;
}

/*
 *  Function: func_v6
 *  Purpose:   ping ipv6 host
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:    2011/12/8
 */


int func_v6(struct users *u)
{
	char buffer[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(STATIC_PARAM, 0, buffer, u);
	SYSTEM("/bin/ping6 -c 5 %s", buffer);

	return 0;
}

