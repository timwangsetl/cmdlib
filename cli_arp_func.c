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

#include "cli_arp_func.h"
#include "bcmutils.h"
#include <net/if_arp.h>

//add static arp
static int cli_set_static_arp(char *lan_staip,char *lan_stamac, int vlan, int port)
{
	return 1;
}

static int cli_no_arp(char *lan_staip)
{
	return 1;
}

int func_static_arp(struct users *u)
{
    int vlan, port, num; 
    char port_str[MAX_ARGV_LEN] = {0};
	struct in_addr s;
	char ip_addr[MAX_ARGV_LEN] = {'\0'}, mac_addr[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_ipv4(STATIC_PARAM, 0, &s, ip_addr, sizeof(ip_addr), u);
	cli_param_get_string(STATIC_PARAM, 0, mac_addr, u);
	cli_param_get_int(STATIC_PARAM, 0, &vlan, u);
	cli_param_get_int(STATIC_PARAM, 1, &num, u);
    
    if(ISSET_CMD_MSKBIT(u, ARP_IF_FAST_PORT))
		port = num;
	else if(ISSET_CMD_MSKBIT(u, ARP_IF_GIGA_PORT))
		port = num+FNUM;
 
	if(cli_set_static_arp(ip_addr, mac_addr, vlan, port) != 1)
		return -1;

	return 0;
}

int nfunc_static_arp(struct users *u)
{
	struct in_addr s;
	char ip_addr[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_ipv4(STATIC_PARAM, 0, &s, ip_addr, sizeof(ip_addr), u);
	
	if(cli_no_arp(ip_addr) != 1)
		return -1;

	return 0;
}



