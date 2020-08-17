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

#include "cli_login_func.h"
/*
 *  Function: func_clock
 *  Purpose:   open telnet
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/25
 */

int func_telnet_host(struct users *u)
{
	char cmd_str[32];
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
				inet_ntop(hptr->h_addrtype, hptr->h_addr, cmd_str, sizeof(cmd_str));
		}
	}
	else strcpy(cmd_str, host);
		
	SYSTEM("/usr/bin/telnet %s",cmd_str);
			
	return 0;		   
}

int func_telnet_ip(struct users *u)
{
	struct in_addr s;
	char ip_addr[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_ipv4(STATIC_PARAM, 0, &s, ip_addr, sizeof(ip_addr), u);
	SYSTEM("/usr/bin/telnet %s",ip_addr);

	return 0;
}


int func_telnet_ipv6(struct users *u)
{
  char ipv6_str[MAX_ARGV_LEN] = {'\0'};
  struct in6_addr s;

  cli_param_get_ipv6(STATIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);

  SYSTEM("/usr/bin/telnet %s",ipv6_str);
}
/*
 * Function: ssh function 
 * Author: gujiajie  01/19/2012
 */
int func_ssh(struct users *u)
{
	struct in_addr s;
	int num = 0;
	char ip_addr[MAX_ARGV_LEN] = {'\0'};
	char name[MAX_ARGV_LEN] = {'\0'};
	char buffer1[MAX_ARGV_LEN] = {'\0'};
	char buffer2[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_ipv4(DYNAMIC_PARAM, 0, &s, ip_addr, sizeof(ip_addr), u);
	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);
	if(ISSET_CMD_MSKBIT(u, SSH_P))
 	{
		cli_param_get_int(STATIC_PARAM, 0, &num, u);
  	 	sprintf(buffer1,"-p %d", num);  
  	}
	if(ISSET_CMD_MSKBIT(u, SSH_C))
 	{
		if (ISSET_CMD_MSKBIT(u, CIPHER_DES))
			sprintf(buffer2,"-c %s", "3des");  
		else
			sprintf(buffer2,"-c %s", "blowfish");  
  	}
	SYSTEM("/usr/sbin/ssh -l %s %s %s %s", name, ip_addr, buffer1, buffer2);

	return 0;
}

int func_ssh_enable(struct users *u)
{
	char *ssh_enable = NULL;
	/* enable ssh */
	ssh_enable = nvram_safe_get("ssh_enable");
	if('1' != *ssh_enable) {
		SYSTEM("/usr/sbin/sshd -f /etc/sshd_config -g 180");
		nvram_set("ssh_enable", "1");
	}
	syslog(LOG_NOTICE, "[CONFIG-5-SSH]: Enabled the ssh function, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(ssh_enable);
	return 0;
}

int nfunc_ssh_enable(struct users *u)
{
	char *ssh_enable = NULL;
	
	ssh_enable = nvram_safe_get("ssh_enable");
	if('0' != *ssh_enable) {
		SYSTEM("/usr/bin/killall sshd > /dev/null 2>&1");
		nvram_set("ssh_enable", "0");
	}
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Remove IP address from the access list, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(ssh_enable);

	return 0;
}

