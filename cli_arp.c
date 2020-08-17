/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_arp.c
 * Function   : arp command function
 * Auther     : yunchang.xuan
 * Version    : 1.0
 * Date       : 2011/11/7
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
 2011/11/7  1.01        yunchangxuan    arp  A.B.C.D        H.H.H.H.H.H    
                                                                          alias     
                                             pending-time     <2-15>      
                                             max-incomplate   <0-1024>                                                                                                      
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

#include "cli_arp.h"
#include "cli_arp_func.h"

/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/4  1.01       yunchang.xuan    add the arp_topcmds[]
                                            interface_arp_topcmds[]
 */
static struct topcmds arp_topcmds[] = {
	{ "arp", 0, CONFIG_TREE, do_arp, NULL, NULL, 0, 0, 0,
		"Config ARP", "配置ARP" },
	{ TOPCMDS_END }
};

/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       yunchang.xuan    add arp_cmds
                                            arp_ip_cmds[]
                                            arp_alias_cmds[]
 */
static struct cmds arp_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_arp_ip, no_arp_ip, NULL, CLI_END_NO, 0, 0,
		"IP address", "IP地址" },
//	{ "pending-time", CLI_CMD, 0, 0, do_arp_pending_time, NULL, NULL, 0, 0, 0,
//		"Set the ARP pending-time", "配置ARP记录的解析等待时间" },
//	{ "max-incomplate", CLI_CMD, 0, 0, do_arp_max_incomplate, NULL, NULL, 0, 0, 0,
//		"Maximum count of incomplate ARP entries ", "配置可缓存的最大未解析ARP条目数" },	
	{ CMDS_END }
};


static struct cmds arp_ip_cmds[] = {
	{ "HH:HH:HH:HH:HH:HH", CLI_MAC, 0, 0, do_arp_ip_mac, NULL, NULL, CLI_END_NO, 0, 0,
		"48 bit hardware address of ARP entry", "ARP记录的48比特的硬件地址" },	
	{ CMDS_END }
};

//static struct cmds arp_alias_cmds[] = {
//	{ "alias", CLI_CMD, 0, 0, do_arp_alias, NULL, NULL, 1, 0, 0,
//		"Seconds to be kept for an incomplete ARP entry ", "回答对这个IP的ARP请求" },
//	{ CMDS_END }
//};


//static struct cmds arp_pending_time_cmds[] = {
//	{ "<2-15>", CLI_INT, 0, 0, do_pending_time, NULL, NULL, 1, 2, 15,
//		"Seconds to be kept for an incomplete ARP entry", "ARP记录的解析等待时间" },
//	{ CMDS_END }
//};
//
//static struct cmds arp_max_incomplete_cmds[] = {
//	{ "<0-1024>", CLI_INT, 0, 0, do_max_incomplate, NULL, NULL, 1, 0, 1024,
//		"Maximum count of incomplete ARP entries", "可缓存的最大未解析ARP条目数" },
//	{ CMDS_END }
//};

static struct cmds arp_vlan[] = {
    { "vlan", CLI_CMD, 0, 0, do_arp_vlan, NULL, NULL, CLI_END_NONE, 0, 0,
        "SPAN VLAN interface", "VLAN" },
    { CMDS_END }
};

static struct cmds arp_vlan_num_cmds[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_arp_vlan_intf, NULL, NULL, CLI_END_NO, 1, 4094,
		"VLAN interface number", "VLAN 序号" },
	{ CMDS_END }
};

static struct cmds arp_vlan_interface[] = {
    { "interface", CLI_CMD, 0, 0, do_arp_vlan_type_interface, NULL, NULL, CLI_END_NONE, 0, 0,
        "port interface", "端口" },
    { CMDS_END }
};

/* interface fast port */
static struct cmds arp_vlan_interface_dst[] = {
#if (XPORT==0)
    { "FastEthernet", CLI_CMD_UNUSAL, 0, ARP_IF_FAST_PORT, do_arp_vlan_interfac_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
        "FastEthernet interface", "快速以太网接口" },
#endif
    { "GigaEthernet", CLI_CMD_UNUSAL, 0, ARP_IF_GIGA_PORT, do_arp_vlan_interfac_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
        "GigaEthernet interface", "千兆以太网端口" },
#if (XPORT==1)
    { "TenGigaEthernet", CLI_CMD_UNUSAL, 0, ARP_IF_XE_PORT, do_arp_vlan_interfac_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
        "TenGigaEthernet interface", "万兆以太网端口" },
#endif
    { CMDS_END }
};

static struct cmds arp_vlan_interface_num_cmds[] = {
    { "<0-0>", CLI_CHAR_NO_BLANK, 0, 0, do_arp_vlan_interface_num, NULL, NULL, CLI_END_NONE, 0x30, 0x30,
        "Interface number", "槽号" },
    { CMDS_END }
};

static struct cmds arp_vlan_interface_slash_cmds[] = {
    { "/", CLI_CHAR_NO_BLANK, 0, 0, do_arp_vlan_interface_slash, NULL, NULL, CLI_END_NONE, 0, 0,
        "Slash", "斜杠" },
    { CMDS_END }
};

static struct cmds arp_vlan_interface_port_cmds[] = {
    { "<x-x>", CLI_INT, 0, 0, do_arp_interface_port, NULL, NULL, CLI_END_FLAG, 0, 0,
        "Port number", "端口号" },
    { CMDS_END }
};

/*
 *  Function:  do_arp
 *  Purpose:   arp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yunchangxuan
 *  Date:     2011/11/7
 */
static int do_arp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(arp_cmds, argc, argv, u);

	return retval;
}



/*
 *  Function:  do_arp_ip
 *  Purpose:   arp_ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_arp_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(arp_ip_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_arp_ip
 *  Purpose:   arp_ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_arp_ip_mac(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(arp_vlan, argc, argv, u);

	return retval;
}

///*
// *  Function:  do_arp_alias
// *  Purpose:   arp_alias subcmd parse function
// *  Parameters:
// *     argc  -  Param count
// *     argv  -  Param value
// *  Returns:
// *  
// *  Author:   yunchang.xuan
// *  Date:    2011/11/7
// */
//static int do_arp_alias(int argc, char *argv[], struct users *u)
//{
//	int retval = -1;
//
//	retval = cmdend2(argc, argv, u);
//	if(retval == 0) 
//	{
//		/* Do application function */
//		do_test_param(argc, argv, u);
//
//	}
//
//	return retval;
//}


static int do_arp_vlan(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(arp_vlan_num_cmds, argc, argv, u);
    
    return retval;
}

static int do_arp_vlan_intf(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(arp_vlan_interface, argc, argv, u);
    
    return retval;
}

static int do_arp_vlan_type_interface(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(arp_vlan_interface_dst, argc, argv, u);
    
    return retval;
}

/* interface fast port */
static int do_arp_vlan_interfac_ethernet(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(arp_vlan_interface_num_cmds, argc, argv, u);

    return retval;
}


static int do_arp_vlan_interface_num(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(arp_vlan_interface_slash_cmds, argc, argv, u);

    return retval;
}

static char port_num_start[MAX_ARGV_LEN] = {'\0'};
static char port_num_end[MAX_ARGV_LEN] = {'\0'};

static int do_arp_vlan_interface_slash(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    struct cmds *cmds_ptr = arp_vlan_interface_port_cmds;

    memset(port_num_start, '\0', sizeof(port_num_start));

    /* Change argcmin and argcmax according to interface type */
    if(ISSET_CMD_MSKBIT(u, ARP_IF_FAST_PORT))
    {
        sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
        cmds_ptr->argcmin = 1;
        cmds_ptr->argcmax = (PNUM-GNUM);
    }
    else if(ISSET_CMD_MSKBIT(u, ARP_IF_GIGA_PORT))
    {
        sprintf(port_num_start, "<%d-%d>", 1, GNUM);
        cmds_ptr->argcmin = 1;
        cmds_ptr->argcmax = GNUM;
    }
    else
        sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

    /* Change name */
    cmds_ptr->name = port_num_start;
    
    retval = sub_cmdparse(arp_vlan_interface_port_cmds, argc, argv, u);

    return retval;
}

static int do_arp_interface_port(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application */
//        func_mirror_interface_dst(u);
		func_static_arp(u);
    }
    
    return retval;
}

/*
 *  Function:  no_arp_ip
 *  Purpose:   no arp_ip parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int no_arp_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_static_arp(u);
	}

	return retval;	
}


/*
 *  Function:  init_cli_arp
 *  Purpose:  Register arp function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
int init_cli_arp(void)
{
	int retval = -1;

	/* Register ping_topcmds[] */
//	retval = registerncmd(arp_topcmds, (sizeof(arp_topcmds)/sizeof(struct topcmds) - 1));
//	
//	DEBUG_MSG(1, "init_cli_arp retval = %d\n", retval);

	return retval;
}
