/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_interface.c
 * Function   : interface command function
 * Auther     : limin.hua
 * Version    : 1.0
 * Date       : 2011/11/9
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

#include "cli_interface.h"
#include "cli_interface_func.h"
#include "bcmutils.h"



static struct topcmds interface_topcmds[] = {
	{ "interface", 0, CONFIG_TREE|IF_SUMMARY_TREE, do_interface, no_interface, NULL, CLI_END_NONE, 0, 0,
		"Interface configuration", "配置接口" },
	{ TOPCMDS_END }
};

static struct cmds interface_cmds[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0, IF_FAST_PORT, do_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0, IF_GIGA_PORT, do_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口" },
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, IF_XE_PORT, do_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网接口" },
#endif
	{ "port-aggregator", CLI_CMD_UNUSAL, 0, IF_TRUNK_PORT, do_interface_trunk, NULL, NULL, CLI_END_NONE, 0, 0,
		"Ethernet aggregation interface", "汇聚接口" },
	//#ifdef BCM_53344_L3
	{ "vlan", CLI_CMD_UNUSAL, 0, IF_VLAN_PORT, do_interface_vlan, NULL, NULL, CLI_END_NONE, 0, 0,
		"VLAN interface", "vlan 接口"},
	//#endif
	{ "loopback", CLI_CMD_UNUSAL, 0, IF_LOOPBACK_PORT, do_interface_lo, NULL, NULL, CLI_END_NONE, 0, 0,
		"LOOPBACK interface", "loopback 接口" },
	{ "range", CLI_CMD, 0, IF_RANGE_PORT, do_interface_range, NULL, NULL, CLI_END_NONE, 0, 0,
		"Interface Range command", "进入批配置接口模式" },
	{ CMDS_END }
};

/* interface fast port */
static struct cmds interface_num_cmds[] = {
	{ "<0-0>", CLI_CHAR_NO_BLANK, 0, 0, do_interface_num, NULL, NULL, CLI_END_NONE, 0x30, 0x30,
		"Interface number", "槽号" },
	{ CMDS_END }
};
static struct cmds interface_slash_cmds[] = {
	{ "/", CLI_CHAR_NO_BLANK, 0, 0, do_interface_slash, NULL, NULL, CLI_END_NONE, 0, 0,
		"Slash", "斜杠" },
	{ CMDS_END }
};
static struct cmds interface_port_cmds[] = {
	{ "<x-x>", CLI_INT, 0, 0, do_interface_port, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Port number", "端口号"},
	{ CMDS_END }
};

/* interface port-aggregator */
static struct cmds interface_trunk_port_cmds[] = {
	{ "<1-6>", CLI_INT, 0, 0, do_interface_trunk_port, no_interface_trunk_port, NULL, CLI_END_FLAG|CLI_END_NO, 1, 6,
		"Port-aggregator interface number", "Port-aggregator 序号" },
	{ CMDS_END }
};

/* interface vlan */
static struct cmds interface_vlan_id_cmds[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_interface_vlan_id, no_interface_vlan_id, NULL, CLI_END_FLAG|CLI_END_NO, 1, 4094,
		"VLAN interface number", "VLAN 序号" },
	{ CMDS_END }
};

/* interface loopback */
static struct cmds interface_lo_id_cmds[] = {
	{ "<1-4>", CLI_INT, 0, 0, do_interface_lo_id, no_interface_lo_id, NULL, CLI_END_NONE | CLI_END_NO, 1, 4,
		"VLAN interface number", "VLAN 序号" },
	{ CMDS_END }
};

static struct cmds interface_loopback_ip_address_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_interface_lo_ipaddr, NULL, NULL, CLI_END_NONE, 0, 0,
		"IP address", "IP 地址" },
	{ CMDS_END }
};
static struct cmds interface_loopback_ip_mask_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4_MASK, 0, 0, do_interface_lo_ipmask, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"IP netmask", "IP 网络掩码" },
	{ CMDS_END  }
};


/* interface range port */
static struct cmds interface_range[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0, IF_FAST_PORT, do_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0, IF_GIGA_PORT, do_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口"},
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, IF_XE_PORT, do_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网接口"},
#endif
	{ CMDS_END }
};

/* interface range fast port */
static struct cmds interface_range_num_cmds[] = {
	{ "<0-0>", CLI_CHAR_NO_BLANK, 0, 0, do_interface_range_num, NULL, NULL, CLI_END_NONE, 0x30, 0x30,
		"Interface number", "接口号"},
	{ CMDS_END }
};
static struct cmds interface_range_slash_cmds[] = {
	{ "/", CLI_CHAR_NO_BLANK, 0, 0, do_interface_range_slash, NULL, NULL, CLI_END_NONE, 0, 0,
		"Slash", "斜杠" },
	{ CMDS_END }
};
static struct cmds interface_range_port_start_cmds[] = {
	{ "<x-x>", CLI_INT_UNUSAL, 0, 0, do_interface_range_port_start, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Port number", "端口号"},
	{ CMDS_END }
};
static struct cmds interface_symbol_cmds[] = {
	{ "-", CLI_CHAR_UNUSAL, 0, 0, do_interface_range_hyphen, NULL, NULL, CLI_END_NONE, 0, 0,
		"Hyphen", "横杠" },
	{ ",", CLI_CHAR_UNUSAL, 0, 0, do_interface_range_comma, NULL, NULL, CLI_END_NONE, 0, 0,
		"Comma", "逗号" },
	{ CMDS_END }
};
static struct cmds interface_range_port_end_cmds[] = {
	{ "<x-x>", CLI_INT_UNUSAL, 0, 0, do_interface_range_port_end, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Port number", "结束端口号"},
	{ CMDS_END }
};
static struct cmds interface_comma_end_cmds[] = {
	{ ",", CLI_CHAR_UNUSAL, 0, 0, do_interface_range_comma_end, NULL, NULL, CLI_END_NONE, 0, 0,
		"Comma", "逗号" },
	{ CMDS_END }
};

static int do_interface(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(interface_cmds, argc, argv, u);

	return retval;
}

static int do_interface_range(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(interface_range, argc, argv, u);

	return retval;
}

/* static, changed when start cmd parse */
static char port_num_start[MAX_ARGV_LEN] = {'\0'};
static char port_num_end[MAX_ARGV_LEN] = {'\0'};

/* interface fast port */
static int do_interface_ethernet(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(interface_num_cmds, argc, argv, u);

	return retval;
}

static int do_interface_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(interface_slash_cmds, argc, argv, u);

	return retval;
}

static int do_interface_slash(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct cmds *cmds_ptr = interface_port_cmds;

	memset(port_num_start, '\0', sizeof(port_num_start));

	/* Change argcmin and argcmax according to interface type */
	if(ISSET_CMD_MSKBIT(u, IF_FAST_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else if(ISSET_CMD_MSKBIT(u, IF_GIGA_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, GNUM);
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = GNUM;
	} 
	else if(ISSET_CMD_MSKBIT(u, IF_XE_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else
		sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

	/* Change name */
	cmds_ptr->name = port_num_start;
	
	retval = sub_cmdparse(interface_port_cmds, argc, argv, u);

	return retval;
}

static int do_interface_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application */
		func_if_port(u);
	}

	return retval;
}
 
 /* interface port-aggregator */
 static int do_interface_trunk(int argc, char *argv[], struct users *u)
 {
	 int retval = -1;
 
	 retval = sub_cmdparse(interface_trunk_port_cmds, argc, argv, u);
 
	 return retval;
 }
 
static int do_interface_trunk_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_if_trunk_port(u);
	}
	
	return retval;
}
 
 /* interface vlan */
 static int do_interface_vlan(int argc, char *argv[], struct users *u)
 {
	 int retval = -1;
 
	 retval = sub_cmdparse(interface_vlan_id_cmds, argc, argv, u);
 
	 return retval;
 }
 
static int do_interface_vlan_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application */
		func_if_vlan(u);
	}
	
	return retval;
}

 /* interface vlan */
static int do_interface_lo(int argc, char *argv[], struct users *u)
{
	 int retval = -1;
	 retval = sub_cmdparse(interface_lo_id_cmds, argc, argv, u);
	 return retval;
}

 /* interface vlan */
static int do_interface_lo_id(int argc, char *argv[], struct users *u)
{
	 int retval = -1;
	 retval = sub_cmdparse(interface_loopback_ip_address_cmds, argc, argv, u);
	 return retval;
}

 /* interface vlan */
static int do_interface_lo_ipaddr(int argc, char *argv[], struct users *u)
{
	 int retval = -1;
	 retval = sub_cmdparse(interface_loopback_ip_mask_cmds, argc, argv, u);
	 return retval;
}

static int do_interface_lo_ipmask(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	cli_debug_p("\n");
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application */
		func_if_lo(u);
	}
	
	return retval;
}

/* interface range fast port */
static int do_interface_range_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(interface_range_num_cmds, argc, argv, u);

	return retval;
}

static int do_interface_range_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(interface_range_slash_cmds, argc, argv, u);

	return retval;
}

static int do_interface_range_slash(int argc, char *argv[], struct users *u)
{
	int retval = -1;	
	struct cmds *cmds_ptr = interface_range_port_start_cmds;

	memset(port_num_start, '\0', sizeof(port_num_start));

	/* Change argcmin and argcmax according to interface type */
	if(ISSET_CMD_MSKBIT(u, IF_FAST_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else if(ISSET_CMD_MSKBIT(u, IF_GIGA_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, GNUM);
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = GNUM;
	} 
	else if(ISSET_CMD_MSKBIT(u, IF_XE_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}

	else
		sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

	/* Change name */
	cmds_ptr->name = port_num_start;
	
	retval = sub_cmdparse(interface_range_port_start_cmds, argc, argv, u);

	return retval;
}

static int do_interface_range_port_start(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_if_range_port(u);
	}

	retval = sub_cmdparse(interface_symbol_cmds, argc, argv, u);

	return retval;
}

static int do_interface_range_hyphen(int argc, char *argv[], struct users *u)
{
	int retval = -1, port_num_start = 0;
	struct cmds *cmds_ptr = interface_range_port_end_cmds;

	memset(port_num_end, '\0', sizeof(port_num_end));
	
	cli_param_get_range_edge(STATIC_PARAM, &port_num_start, u);
		
	/* Change argcmin and argcmax according to interface type */
	if(ISSET_CMD_MSKBIT(u, IF_FAST_PORT))
	{
		sprintf(port_num_end, "<%d-%d>", port_num_start, (PNUM-GNUM));
		cmds_ptr->argcmin = port_num_start;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else if(ISSET_CMD_MSKBIT(u, IF_GIGA_PORT))
	{
		sprintf(port_num_end, "<%d-%d>", port_num_start, GNUM);
		cmds_ptr->argcmin = port_num_start;
		cmds_ptr->argcmax = GNUM;
	}
	else
		sprintf(port_num_end, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

	/* Change name */
	cmds_ptr->name = port_num_end;
	
	retval = sub_cmdparse(interface_range_port_end_cmds, argc, argv, u);

	return retval;
}

static int do_interface_range_comma(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* cisco :sub_cmdparse(interface_range, argc, argv, u) */
	retval = sub_cmdparse(interface_range_port_start_cmds, argc, argv, u);

	return retval;
}

static int do_interface_range_port_end(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_if_range_port(u);
	}

	retval = sub_cmdparse(interface_comma_end_cmds, argc, argv, u);

	return retval;
}

static int do_interface_range_comma_end(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* cisco :sub_cmdparse(interface_range, argc, argv, u) */
	retval = sub_cmdparse(interface_range_port_start_cmds, argc, argv, u);

	return retval;
}

static int no_interface(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	SET_CMD_MSKBIT(u, IF_FAST_PORT|IF_GIGA_PORT|IF_XE_PORT|IF_RANGE_PORT);

	retval = sub_cmdparse(interface_cmds, argc, argv, u);

	return retval;
}

static int no_interface_trunk_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Negative application function */
		nfunc_if_trunk_port(u);
	}
	
	return retval;
}

static int no_interface_vlan_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Negative application function */
		nfunc_if_vlan(u);
	}
	
	return retval;
}


static int no_interface_lo_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Negative application function */
		nfunc_if_lo(u);
	}
	
	return retval;
}

int init_cli_interface(void)
{
	int retval = -1;

	retval = registerncmd(interface_topcmds, (sizeof(interface_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1,"init_cli_interface retval = %d\n", retval);

	return retval;
}

