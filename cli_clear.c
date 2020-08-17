/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_clear.c
 * Function   : show command function
 * Auther     : dawei.hu
 * Version    : 1.0
 * Date       : 2011/12/8
 *
 *********************Revision History****************
 Date       Version     Modifier            Command
 
                                            
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

#include "cli_clear.h"
#include "cli_clear_func.h"

/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/12/8  1.0       dawei.hu    clear_topcmds[]

 */

static struct topcmds clear_topcmds[] = {
	{ "clear", 0, ENA_TREE, do_clear, NULL, NULL, 0, 0, 0,
	 	"Clear something", "�� ��" },
	{ TOPCMDS_END }
};

/*
*  sub command struct
*
****************Revision History****************
Date       Version    Modifier         Modifications
2011/12/8  1.0       dawei.hu   
*/


static struct cmds clear_cmds[] = {
	{ "arp-cache",CLI_CMD, 0, 0, do_arp, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Clear ARP cache", "���ARP����" },
	{ "logging",CLI_CMD, 0, 0, do_logging, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Clear logging buffer", "�����־��Ϣ" },
	{ "mac",CLI_CMD, 0, 0, do_mac, NULL, NULL, CLI_END_NONE, 0, 0,
		"MAC forwarding table", "MAC��ַ��" },

	{ "telnet",CLI_CMD, 0, 0, do_telnet_clear, NULL, NULL, CLI_END_NONE|CLI_END_FLAG, 0, 0,
		"Clear incoming telnet connection", "��������telnet����" },
	{ "ssh", CLI_CMD, 0, 0, do_ssh_clear, NULL, NULL, CLI_END_NONE|CLI_END_FLAG, 0, 0,
		"Clear incoming ssh connection", "��������ssh����" },

	{ "access-list",CLI_CMD, 0, 0, do_access, NULL, NULL, CLI_END_NONE, 0, 0,
		"Clear access list statistical information", "��������б�" },
	{ "counters",CLI_CMD, 0, 0, do_counters, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Clear ports flow statistics", "���ͳ����Ϣ" },
	{ "ip",CLI_CMD, 0, 0, do_ip, NULL, NULL, CLI_END_NONE, 0, 0,
		"Clear ip dhcp binding information", "���IP DHCP ���б�" },
	{ "ipv6",CLI_CMD, 0, 0, do_ipv6, NULL, NULL, CLI_END_NONE, 0, 0,
		"Clear ipv6 dhcp binding information", "���IPv6 DHCP ���б�" },
	{ CMDS_END }
};

static struct cmds mac_cmds[] = {
	{ "address-table",CLI_CMD, 0, 0, do_mac_add, NULL, NULL, CLI_END_FLAG, 0, 0,
		"MAC forwarding table", "MAC��ַ��" },
	{ CMDS_END }
};

static struct cmds telnet_cmds[] = {
	{ "<1 - 16>",CLI_INT, 0, 0, do_telnet_index, NULL, NULL, CLI_END_FLAG, 1, 16,
		"telnet index", "telnet���" },
	{ CMDS_END }
};

static struct cmds ssh_cmds[] = {
	{ "<1 - 16>", CLI_INT, 0, 0, do_ssh_index, NULL, NULL, CLI_END_FLAG, 1, 16,
		"ssh index", "ssh���" },
	{ CMDS_END }
};

static struct cmds access_cmds[] = {
	{ "counters",CLI_CMD, 0, 0, do_access_counters, NULL, NULL, CLI_END_FLAG|CLI_END_NONE, 0, 0,
 		"Clear access list counters", "��������б��ͳ����Ϣ" },
	{ CMDS_END }
};

static struct cmds access_counters_cmds[] = {
	{ "WORD",CLI_WORD, 0, 0, do_access_counters_name, NULL, NULL, CLI_END_FLAG, 0, 0,
 		"Access list name", "�����б������" },
	{ CMDS_END }
};

static struct cmds ip_cmds[] = {
	{ "dhcp",CLI_CMD, 0, 0, do_ip_dhcp, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ip dhcp binging", "���IP DHCP ���б�" },
 	{ "igmp",CLI_CMD, 0, 0, do_ip_igmp, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ip igmp", "���IP IGMP �б�" },
 	{ "mroute",CLI_CMD, 0, 0, do_ip_mroute, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ip mroute", "���IP mroute �б�" },
 	{ "pim-sm",CLI_CMD, 0, 0, do_ip_pim, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ip pim-sm", "���IP pim-sm �б�" },
	{ CMDS_END }
};

static struct cmds ip_dhcp_cmds[] = {
	{ "bindding",CLI_CMD, 0, 0, do_ip_dhcp_binding, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ip dhcp binging", "���IP DHCP ���б�" },
	{ CMDS_END }
};

static struct cmds ip_dhcp_binding_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_dhcp_binding_addr, NULL, NULL, CLI_END_FLAG, 0, 0,
		"special IP address", "�ض�IP ��ַ" },
	{ "all",CLI_CMD, 0, 0, do_ip_dhcp_binding_all, NULL, NULL, CLI_END_FLAG, 0, 0,
 		"All binding information", "���а��б�" },
	{ CMDS_END }
};

static struct cmds ip_igmp_cmds[] = {
	{ "group",CLI_CMD, 0, 0, do_ip_igmp_group, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ip igmp group", "���IP IGMP ��" },
	{ CMDS_END }
};

static struct cmds ip_igmp_group_cmds[] = {
	{ "WORD",CLI_WORD, 0, 0, do_ip_igmp_group_int, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ip igmp group", "���IP IGMP ��" },
	{ CMDS_END }
};

static struct cmds ip_igmp_group_int_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_igmp_group_int_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"special IP address", "�ض�IP ��ַ" },
	{ CMDS_END }
};

static struct cmds ipv6_cmds[] = {
	{ "dhcp",CLI_CMD, 0, 0, do_ipv6_dhcp, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ipv6 dhcp binging", "���IPv6 DHCP ���б�" },
 	{ "mld",CLI_CMD, 0, 0, do_ipv6_mld, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ipv6 mld", "���IPv6 mld" },
 	{ "mroute",CLI_CMD, 0, 0, do_ipv6_mroute, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ipv6 mroute", "���IPv6 mroute �б�" },
 	{ "pim",CLI_CMD, 0, 0, do_ipv6_pim, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ipv6 pim", "���IPv6 pim ӳ��" },
	{ CMDS_END }
};

static struct cmds ipv6_dhcp_cmds[] = {
	{ "bindding",CLI_CMD, 0, 0, do_ipv6_dhcp_binding, NULL, NULL, CLI_END_FLAG, 0, 0,
 		"Clear ipv6 dhcp binging", "���IPv6 DHCP ���б�" },
	{ CMDS_END }
};

static struct cmds ipv6_dhcp_binding_cmds[] = {
	{ "X:X:X:X::X/<0-128>", CLI_IPV6, 0, 0, do_ipv6_dhcp_binding_addr, NULL, NULL, CLI_END_FLAG, 0, 0 ,
		"IPv6 binding address", "IPV6 �󶨵�ַ" } ,
	{ CMDS_END }
};

static struct cmds ipv6_mld_cmds[] = {
	{ "group",CLI_CMD, 0, 0, do_ipv6_mld_group, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ipv6 mld group", "���IPv6 mld ��" },
	{ CMDS_END }
};

static struct cmds ipv6_mld_group_cmds[] = {
	{ "WORD",CLI_WORD, 0, 0, do_ipv6_mld_group_int, NULL, NULL, CLI_END_FLAG, 0, 0,
 		"Clear ipv6 mld group interface", "���IPv6 mld ��ӿ�" },
	{ CMDS_END }
};

static struct cmds ipv6_mld_group_int_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ipv6_mld_group_int_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Clear ipv6 mld group address", "���IPv6 mld ���ַ" },
	{ CMDS_END }
};

static struct cmds ipv6_mroute_cmds[] = {
	{ "pim",CLI_CMD, 0, 0, do_ipv6_mroute_pim, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ipv6 mroute table", "���IPv6 mroute ��" },
	{ CMDS_END }
};

static struct cmds ipv6_mroute_pim_cmds[] = {
	{ "all",CLI_CMD, 0, 0, do_ipv6_mroute_pim_all, NULL, NULL, CLI_END_FLAG, 0, 0,
 		"Clear all ipv6 mroute table", "������� IP mroute ��" },
 	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ipv6_mroute_pim_group, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IPv6 group", "IPv6 ��" },
	{ CMDS_END }
};

static struct cmds ipv6_mroute_pim_group_cmds[] = {
 	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ipv6_mroute_pim_group_src, NULL, NULL, CLI_END_FLAG, 0, 0,
		"source IPv6 address", "ԴIPv6 ��ַ" },
	{ CMDS_END }
};

static struct cmds ipv6_pim_cmds[] = {
	{ "rp-mapping",CLI_CMD, 0, 0, do_ipv6_pim_rp, NULL, NULL, CLI_END_FLAG, 0, 0,
 		"Clear ipv6 pim-sm rp-mapping", "���IPv6 pim mapping��" },
	{ CMDS_END }
};

static struct cmds ipv6_pim_rp_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ipv6_pim_rp_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"rp IPv6 address", "rp IPv6 ��ַ" },
	{ CMDS_END }
};

static struct cmds ip_mroute_cmds[] = {
	{ "pim-sm",CLI_CMD, 0, 0, do_ip_mroute_pim_sm, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ip mroute table", "���IP mroute ��" },
	{ "pim-dm",CLI_CMD, 0, 0, do_ip_mroute_pim, NULL, NULL, CLI_END_NONE, 0, 0,
 		"Clear ip mroute table", "���IP mroute ��" },
	{ CMDS_END }
};

static struct cmds ip_mroute_pim_cmds[] = {
	{ "all",CLI_CMD, 0, 0, do_ip_mroute_pim_all, NULL, NULL, CLI_END_FLAG, 0, 0,
 		"Clear all ip mroute table", "������� IP mroute ��" },
 	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_mroute_pim_group, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP group", "IP ��" },
	{ CMDS_END }
};

static struct cmds ip_mroute_pim_group_cmds[] = {
 	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_mroute_pim_group_src, NULL, NULL, CLI_END_FLAG, 0, 0,
		"source IP address", "ԴIP ��ַ" },
	{ CMDS_END }
};

static struct cmds ip_pim_cmds[] = {
	{ "rp-mapping",CLI_CMD, 0, 0, do_ip_pim_rp, NULL, NULL, CLI_END_FLAG, 0, 0,
 		"Clear ip pim-sm rp-mapping", "���IP pim mapping��" },
	{ CMDS_END }
};

static struct cmds ip_pim_rp_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_pim_rp_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"rp IP address", "rp IP ��ַ" },
	{ CMDS_END }
};

/*
*  Function:	do_clear
*  Purpose:	clear topcmd parse function
*  Parameters:
* 	argc  -  Param count
* 	argv  -  Param value
*  Returns:
*  
*  Author:  dawei.hu
*  Date:	  2011/12/8
*/

static int do_clear(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(clear_cmds, argc, argv, u);

	return retval;
}


/*
*  Function:	do_arp
*  Purpose:	clear topcmd parse function
*  Parameters:
* 	argc  -  Param count
* 	argv  -  Param value
*  Returns:
*  
*  Author:  dawei.hu
*  Date:	  2011/12/8
*/
static int do_arp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_arp(u);
	}
	return retval;
}

/*
*	Function:	 do_logging
*	Purpose: clear topcmd parse function
*	Parameters:
*	 argc  -  Param count
*	 argv  -  Param value
*	Returns:
*	
*	Author:  dawei.hu
*	Date:	   2011/12/8
*/
static int do_logging(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
	 	/* Do application function */
		func_clear_logging(u);
	}
	return retval;
}

/*
*	 Function:	  do_counters
*	 Purpose: clear topcmd parse function
*	 Parameters:
*	  argc	-  Param count
*	  argv	-  Param value
*	 Returns:
*	 
*	 Author:  dawei.hu
*	 Date:		2011/12/8
*/
static int do_counters(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_counters(u);
	}
	return retval;
}

/*
*	 Function:	  do_mac
*	 Purpose: clear topcmd parse function
*	 Parameters:
*	  argc	-  Param count
*	  argv	-  Param value
*	 Returns:
*	 
*	 Author:  dawei.hu
*	 Date:		2011/12/8
*/

static int do_mac(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_cmds, argc, argv, u);

	return retval;

}

/*
*	  Function:    do_telnet_clear
*	  Purpose: clear topcmd parse function
*	  Parameters:
*	   argc  -	Param count
*	   argv  -	Param value
*	  Returns:
*	  
*	  Author:  dawei.hu
*	  Date: 	 2011/12/8
*/

static int do_telnet_clear(int argc, char *argv[], struct users *u)
{
	int retval = -1;



	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_clear_telnet(u, 0);
		return retval;
	}
	
	retval = sub_cmdparse(telnet_cmds, argc, argv, u);

	return retval;

}

/*
*	  Function:    do_ssh_clear
*	  Purpose: clear topcmd parse function
*	  Parameters:
*	   argc  -	Param count
*	   argv  -	Param value
*	  Returns:
*	  
*	  Author:  wei.zhang
*	  Date: 	 2012/4/24
*/
static int do_ssh_clear(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if ( (retval = cmdend2(argc, argv, u)) == 0){
		
		func_clear_ssh(u, 0);
		return retval;
	}
	retval = sub_cmdparse( ssh_cmds, argc, argv, u );
	
	return retval;
}


/*
*	   Function:	do_access
*	   Purpose: clear topcmd parse function
*	   Parameters:
*		argc  -  Param count
*		argv  -  Param value
*	   Returns:
*	   
*	   Author:	dawei.hu
*	   Date:	  2011/12/8
*/

static int do_access(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(access_cmds, argc, argv, u);

	return retval;
}

/*
*	 Function:	  do_mac_add
*	 Purpose: mac subcmd parse function
*	 Parameters:
*	  argc	-  Param count
*	  argv	-  Param value
*	 Returns:
*	 
*	 Author:  dawei.hu
*	 Date:		2011/12/8
*/
static int do_mac_add(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_mac(u);
	}
	return retval;
}

 /*
 *	  Function:    do_telnet_index
 *	  Purpose: telnet subcmd parse function
 *	  Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	  Returns:
 *	  
 *	  Author:  dawei.hu
 *	  Date: 	 2011/12/8
 */
static int do_telnet_index(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_telnet(u, 0);
	}
	return retval;
}

 /*
 *	  Function:    do_ssh_index
 *	  Purpose: telnet subcmd parse function
 *	  Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	  Returns:
 *	  
 *	  Author:  wei.zhang
 *	  Date: 	 2012/4/24
 */
static int do_ssh_index(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = cmdend2(argc, argv, u);
	
	if (retval == 0){
		func_clear_ssh(u, 0);	
	}
	
	return retval;
}

/*
*    Function:	do_access_counters
*    Purpose: access subcmd parse function
*    Parameters:
* 	argc  -  Param count
* 	argv  -  Param value
*    Returns:
*    
*    Author:	dawei.hu
*    Date:	  2011/12/8
*/
static int do_access_counters(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_access(u);
	} else
		retval = sub_cmdparse(access_counters_cmds, argc, argv, u);
	
	return retval;
}

/*
*    Function:	do_access_counter_name
*    Purpose: access_counters subcmd parse function
*    Parameters:
* 	argc  -  Param count
* 	argv  -  Param value
*    Returns:
*    
*    Author:	dawei.hu
*    Date:	  2011/12/8
*/
static int do_access_counters_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_name(u);
	}
	return retval;
}

/*
*	   Function:	do_ip
*	   Purpose: clear topcmd parse function
*	   Parameters:
*		argc  -  Param count
*		argv  -  Param value
*	   Returns:
*	   
*	   Author:	dawei.hu
*	   Date:	  2011/12/8
*/

static int do_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_cmds, argc, argv, u);

	return retval;
}

static int do_ip_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_dhcp_cmds, argc, argv, u);

	return retval;
}

static int do_ip_dhcp_binding(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_dhcp_binding_cmds, argc, argv, u);

	return retval;
}

static int do_ip_dhcp_binding_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ip_dhcp_binding_addr(u);
	}
	return retval;
}

static int do_ip_dhcp_binding_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ip_dhcp_binding_all(u);
	}
	return retval;
}

/*
*	   Function:	do_ipv6
*	   Purpose: clear topcmd parse function
*	   Parameters:
*		argc  -  Param count
*		argv  -  Param value
*	   Returns:
*	   
*	   Author:	dawei.hu
*	   Date:	  2011/12/8
*/

static int do_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_dhcp_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_dhcp_binding(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ipv6_dhcp_binding_all(u);
	} else
		retval = sub_cmdparse(ipv6_dhcp_binding_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_dhcp_binding_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ipv6_dhcp_binding_addr(u);
	}
	return retval;
}

static int do_ipv6_mld(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_mld_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_mld_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_mld_group_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_mld_group_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ipv6_mld_group_int(u);
	} else
		retval = sub_cmdparse(ipv6_mld_group_int_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_mld_group_int_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ipv6_mld_group_int_ip(u);
	}
	return retval;
}

/*
*	   Function:	do_ipv6_mroute
*	   Purpose: clear topcmd parse function
*	   Parameters:
*		argc  -  Param count
*		argv  -  Param value
*	   Returns:
*	   
*	   Author:	xi.chen
*	   Date:	  2011/12/8
*/
static int do_ipv6_mroute(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_mroute_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_mroute_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_mroute_pim_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_mroute_pim_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ipv6_mroute_pim_all(u);
	}
	return retval;
}

static int do_ipv6_mroute_pim_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ipv6_mroute_pim_group(u);
	} else
		retval = sub_cmdparse(ipv6_mroute_pim_group_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_mroute_pim_group_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ipv6_mroute_pim_group_src(u);
	}
	return retval;
}

/*
*	   Function:	do_ip_igmp
*	   Purpose: clear topcmd parse function
*	   Parameters:
*		argc  -  Param count
*		argv  -  Param value
*	   Returns:
*	   
*	   Author:	dawei.hu
*	   Date:	  2011/12/8
*/

static int do_ip_igmp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_igmp_cmds, argc, argv, u);

	return retval;
}

static int do_ip_igmp_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_igmp_group_cmds, argc, argv, u);

	return retval;
}

static int do_ip_igmp_group_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_igmp_group_int_cmds, argc, argv, u);

	return retval;
}

static int do_ip_igmp_group_int_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ip_igmp_group(u);
	}
	return retval;
}

/*
*	   Function:	do_ip_mroute
*	   Purpose: clear topcmd parse function
*	   Parameters:
*		argc  -  Param count
*		argv  -  Param value
*	   Returns:
*	   
*	   Author:	xi.chen
*	   Date:	  2011/12/8
*/
static int do_ip_mroute(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_mroute_cmds, argc, argv, u);

	return retval;
}

static int do_ip_mroute_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_mroute_pim_cmds, argc, argv, u);

	return retval;
}

static int do_ip_mroute_pim_sm(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ip_mroute_pim_all(u);
	}
	return retval;
}

static int do_ip_mroute_pim_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ip_mroute_pim_all(u);
	}
	return retval;
}

static int do_ip_mroute_pim_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ip_mroute_pim_group(u);
	} else
		retval = sub_cmdparse(ip_mroute_pim_group_cmds, argc, argv, u);

	return retval;
}

static int do_ip_mroute_pim_group_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ip_mroute_pim_group_src(u);
	}
	return retval;
}

/*
 *	   Function:	do_ip_pim
 *	   Purpose: clear topcmd parse function
 *	   Parameters:
 *		argc  -  Param count
 *		argv  -  Param value
 *	   Returns:
 *	   
 *	   Author:	xi.chen
 *	   Date:	  2011/12/8
 */

static int do_ip_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_cmds, argc, argv, u);

	return retval;
}

static int do_ip_pim_rp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ip_pim_rp(u);
	} else
		retval = sub_cmdparse(ip_pim_rp_cmds, argc, argv, u);

	return retval;
}

static int do_ip_pim_rp_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ip_pim_rp_ip(u);
	}
	return retval;
}

/*
 *	   Function:	do_ipv6_pim
 *	   Purpose: clear topcmd parse function
 *	   Parameters:
 *		argc  -  Param count
 *		argv  -  Param value
 *	   Returns:
 *	   
 *	   Author:	xi.chen
 *	   Date:	  2011/12/8
 */

static int do_ipv6_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_pim_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_pim_rp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ipv6_pim_rp(u);
	} else
		retval = sub_cmdparse(ipv6_pim_rp_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_pim_rp_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clear_ipv6_pim_rp_ip(u);
	}
	return retval;
}

 /*
  *  Function:	init_cli_clear
  *  Purpose:  Register clear function command
  *  Parameters:
  * 	void
  *  Returns:
  * 	retval	-  The number of registered successfully
  *  Author:   dawei.hu
  *  Date:	  2011/12/8
  */
  
int init_cli_clear(void)
{
	int retval = -1;
	retval = registerncmd(clear_topcmds, (sizeof(clear_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1,"init_cli_clear retval = %d\n", retval);

	return retval;
}

