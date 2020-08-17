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

#include "cli_mac.h"
#include "cli_mac_func.h"

/*
 *  top command struct
 *
 *	Author:  jiajie.gu
 *  Date:     2011/11/8
 */

static struct topcmds mac_topcmds[] = {
	{ "mac", 0, CONFIG_TREE, do_mac, NULL, NULL, CLI_END_NONE, 0, 0,
		"Global MAC configuration subcommands", "全局 MAC 配置命令" },
	{ TOPCMDS_END }
};

/*
 *  sub command struct
 *
 *	Author:  jiajie.gu
 *  Date:     2011/11/8
 */

static struct cmds mac_add[] = {
	{ "address-table", CLI_CMD, 0, 0, do_mac_add_agSt, NULL, NULL, CLI_END_NONE, 0, 0,
		"Configure the MAC address table", "配置 MAC 地址表" },
	{ "access-list", CLI_CMD, 0, 0, do_accl, NULL, NULL, CLI_END_NONE, 0, 0,
		"Named access-list", "配置访问列表" },
	{ "blackhole", CLI_CMD, 0, 0, do_mac_blackhole, no_mac_blackhole, NULL, CLI_END_NONE, 0, 0,
		"Mac Blackhole", "Mac黑洞" },
	{ CMDS_END }
};

static struct cmds mac_accl[] = {
	{ "WORD", CLI_WORD, 0, 0, do_accl_name, no_accl_name, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Access-list name", "访问列表名" },
	{ CMDS_END }
};

static struct cmds blackhole_mac[] = {
	{ "HH:HH:HH:HH:HH:HH", CLI_MAC, 0, 0, do_mac_add_blackhole, no_mac_add_blackhole, NULL,  CLI_END_NONE, 0, 0,
		"48 bit mac address", "48 bit mac 地址" },
	{ CMDS_END }
};


static struct cmds mac_add_ag[] = {
	{ "aging-time", CLI_CMD, 0, 0, do_mac_add_aging, no_mac_add_aging, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Set MAC address table entry maximum age", "设置 MAC 地址表老化时间" },
	{ "static", CLI_CMD, 0, 0, do_mac_add_st, NULL, NULL, CLI_END_NONE, 0, 0,
		"Static keyword", "配置静态 MAC 地址" },
	{ CMDS_END }
};

static struct cmds mac_add_st[] = {
	{ "HH:HH:HH:HH:HH:HH", CLI_MAC, 0, 0, do_mac_add_st_m, NULL, NULL, CLI_END_NONE, 0, 0,
		"48 bit mac address", "48 bit mac 地址" },
	{ CMDS_END }
};

static struct cmds mac_add_st_m[] = {
	{ "vlan", CLI_CMD, 0, 0, do_mac_add_st_m_v, NULL, NULL, CLI_END_NONE, 0, 0,
		"VLAN keyword", "Vlan值" },
	{ CMDS_END }
};

static struct cmds mac_add_bhole_v[] = {
	{ "vlan", CLI_CMD, 0, 0, do_mac_add_blackhole_v, no_mac_add_blackhole_v, NULL,  CLI_END_NONE, 0, 0,
		"VLAN Id", "Vlan值" },
	{ CMDS_END }
};


static struct cmds mac_add_st_m_vid[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_mac_add_st_m_vid, no_mac_add_st_m_vid, NULL, CLI_END_NONE|CLI_END_NO, 1, 4094,
		"VLAN id of mac address table", "MAC地址绑定所在的VLAN ID" },
	{ CMDS_END }
};

static struct cmds mac_add_bhole_vid[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_mac_blackhole_vid, no_mac_blackhole_vid, NULL, CLI_END_FLAG | CLI_END_NO, 1, 4094,
		"VLAN id ", "VLAN ID" },
	{ CMDS_END }
};


static struct cmds mac_add_st_m_v[] = {
	{ "interface", CLI_CMD, 0, 0, do_mac_add_st_m_v_int, NULL, NULL, CLI_END_NONE, 0, 0,
		"Interface", "接口" },
	{ CMDS_END }
};

static struct cmds mac_add_st_m_v_int[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0, MAC_IF_FAST_PORT_MSK, do_mac_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif		
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0, MAC_IF_GIGA_PORT_MSK, do_mac_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网端口" },
#if (XPORT==1)		
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, MAC_IF_XE_PORT_MSK, do_mac_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网端口" },
#endif		
	{ CMDS_END }
};

/* interface range fast port */
static struct cmds mac_interface_range_num_cmds[] = {
	{ "<0-0>", CLI_CHAR_NO_BLANK, 0, 0, do_mac_interface_range_num, NULL, NULL, CLI_END_NONE, 0x30, 0x30,
		"FastEthernet interface number", "FastEthernet 槽号" },
	{ CMDS_END }
};
static struct cmds mac_interface_range_slash_cmds[] = {
	{ "/", CLI_CHAR_NO_BLANK, 0, 0, do_mac_interface_range_slash, NULL, NULL, CLI_END_NONE, 0, 0,
		"Slash", "斜杠" },
	{ CMDS_END }
};
static struct cmds mac_interface_port_start_cmds[] = {
	{ "<x-x>", CLI_INT_UNUSAL, 0, 0, do_mac_interface_range_port_start, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Port number", "端口号" },
	{ CMDS_END }
};
static struct cmds mac_interface_symbol_cmds[] = {
	{ "-", CLI_CHAR_UNUSAL, 0, 0, do_mac_interface_range_hyphen, NULL, NULL, CLI_END_NONE, 0, 0,
		"Hyphen", "横杠" },
	{ ",", CLI_CHAR_UNUSAL, 0, 0, do_mac_interface_range_comma, NULL, NULL, CLI_END_NONE, 0, 0,
		"Comma", "逗号" },
	{ CMDS_END }
};
static struct cmds mac_interface_port_end_cmds[] = {
	{ "<x-x>", CLI_INT_UNUSAL, 0, 0, do_mac_interface_range_port_end, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Port number", "结束端口号" },
	{ CMDS_END }
};
static struct cmds mac_interface_comma_end_cmds[] = {
	{ ",", CLI_CHAR_UNUSAL, 0, 0, do_mac_interface_range_comma_end, NULL, NULL, CLI_END_NONE, 0, 0,
		"Comma", "逗号" },
	{ CMDS_END }
};

/*
 *  Function:  do_accl
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_accl(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_accl, argc, argv, u);
	
	return retval;
}


/*
 *  Function:  do_mac_blackhole
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  liujh
 *  Date:     2019/05/22
 */
static int do_mac_blackhole(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(blackhole_mac, argc, argv, u);
	
	return retval;
}
static int no_mac_blackhole(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(blackhole_mac, argc, argv, u);
	
	return retval;
}


/*
 *  Function:  do_accl_name
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_accl_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		//func_mac_acl_name(u);
		if(func_mac_acl_name(u) < 0)
			return -1;
		
		if((retval = change_con_level(MAC_ACL_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "%s", u->s_param.v_string[0]);
		}
	}
	
	return retval;
}

/*
 *  Function:  no_accl_name
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int no_accl_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_mac_acl_name(u);
	}
	
	return retval;
}

/*
 *  Function: do_mac 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_mac(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_add, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_mac_add_agSt 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_mac_add_agSt(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_add_ag, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_mac_add_st 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_mac_add_st(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_add_st, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_mac_add_st_m 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_mac_add_st_m(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_add_st_m, argc, argv, u);
	
	return retval;
}


/*
 *  Function: do_mac_add_blackhole 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  liujh
 *  Date:     2019/05/22
 */
static int do_mac_add_blackhole(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_add_bhole_v, argc, argv, u);
	
	return retval;
}
static int no_mac_add_blackhole(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_add_bhole_v, argc, argv, u);
	
	return retval;
}


/*
 *  Function: do_mac_add_blackhole_v 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  liujh
 *  Date:     2019/05/22
 */
static int do_mac_add_blackhole_v(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_add_bhole_vid, argc, argv, u);
	
	return retval;
}

static int no_mac_add_blackhole_v(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_add_bhole_vid, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_mac_add_st_m_v 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_mac_add_st_m_v(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_add_st_m_vid, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_mac_add_st_m_vid 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_mac_add_st_m_vid(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_add_st_m_v, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_mac_blackhole_vid 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  liujh
 *  Date:     2011/11/8
 */
static int do_mac_blackhole_vid(int argc, char *argv[], struct users *u)
{
	int retval = 0;
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{	
		char mac[32] = {0};
		int vid;

		cli_param_get_string(STATIC_PARAM,0,mac,u);
		cli_param_get_int(STATIC_PARAM,0,&vid,u);
		
		retval = cli_mac_blackhole_vid(mac, vid);

		if(1 == retval)
		{
			vty_output("  Mac entry already exists \n");
			return -1;
		}
		else if(-1 == retval)
		{
	        vty_output("  Invalid vid\n");
			return -1;
		}
		
	    retval = func_set_mac_blackhole(mac,vid);
		
	}
	
	return retval;
}

static int no_mac_blackhole_vid(int argc, char *argv[], struct users *u)
{
	int retval = -1;	
	
	//vty_output(" do_mac_blackhole_vid argc:%d argv:%s %s %s %s %s \n",argc,argv[0],argv[1],argv[2],argv[3],argv[4]);
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{	
		char mac[32] = {0};
		int vid;
		cli_param_get_string(STATIC_PARAM,0,mac,u);
		cli_param_get_int(STATIC_PARAM,0,&vid,u);
		//vty_output(" do_mac_blackhole_vid mac:%s vid:%d\n",mac,vid);
		
		if(0 != vid){
	    	func_del_mac_blackhole(mac,vid);
		} else
	        vty_output("Invalid vid\n");
	}
	
	return retval;
}

/*
 *  Function: no_mac_add_st_m_vid 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int no_mac_add_st_m_vid(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_mac_by_mac_vid(u);
	}
	
	return retval;
}


/*
 *  Function: do_mac_add_st_m_v_int 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_mac_add_st_m_v_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_add_st_m_v_int, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_mac_add_aging 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_mac_add_aging(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_INT;
	param.name = "<10-1000000>";
	param.ylabel = "Aging time in seconds";
	param.hlabel = "老化时间";
	param.min = 0;
	param.max = 1000000;
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
	
	cli_param_set(DYNAMIC_PARAM, &param, u);	
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{	
		int age_time;
		char age_time_str[8] = {0};

		cli_param_get_int(DYNAMIC_PARAM,0,&age_time,u);
		if(0 == age_time)
	    	func_set_aging_time("0");/*disable aging time*/
	    else if( (age_time >= 10)&&(age_time <= 1000000) ) {
	    	sprintf(age_time_str, "%d", age_time);
	    	func_set_aging_time(age_time_str);
		} else
	        vty_output("  Invalid numbers, the value should be 10 - 1000000, or 0 means disable\n");
	}
	
	return retval;
}

/*
 *  Function: no_mac_add_aging 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int no_mac_add_aging(int argc, char *argv[], struct users *u)
{
	int retval =-1;
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_set_aging_time_default();
	}
	
	return retval;
}

static char port_num_start[MAX_ARGV_LEN] = {'\0'};
static char port_num_end[MAX_ARGV_LEN] = {'\0'};

/* interface range fast port */
static int do_mac_interface_range_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_interface_range_num_cmds, argc, argv, u);

	return retval;
}

static int do_mac_interface_range_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mac_interface_range_slash_cmds, argc, argv, u);

	return retval;
}

static int do_mac_interface_range_slash(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct cmds *cmds_ptr = mac_interface_port_start_cmds;

	memset(port_num_start, '\0', sizeof(port_num_start));

	/* Change argcmin and argcmax according to interface type */
	if(ISSET_CMD_MSKBIT(u, MAC_IF_FAST_PORT_MSK))
	{
		sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else if(ISSET_CMD_MSKBIT(u, MAC_IF_GIGA_PORT_MSK))
	{
		sprintf(port_num_start, "<%d-%d>", 1, GNUM);
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = GNUM;
	}
	else
		sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

	/* Change name */
	cmds_ptr->name = port_num_start;
	
	retval = sub_cmdparse(mac_interface_port_start_cmds, argc, argv, u);

	return retval;
}

static int do_mac_interface_range_port_start(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		char mac_str[MAX_ARGV_LEN] = {0};
		cli_param_get_string(STATIC_PARAM,0,mac_str,u);
		
		int vid_int = 0;
		char vid_str[MAX_ARGV_LEN] = {0};
		cli_param_get_int(STATIC_PARAM,0,&vid_int, u);
		sprintf(vid_str, "%d", vid_int);
		char port_str[MAX_ARGV_LEN] = {0};
		cli_param_get_range(STATIC_PARAM, port_str, u);
		
		if(ISSET_CMD_MSKBIT(u, MAC_IF_FAST_PORT_MSK))
			func_set_mac_static_address(0,mac_str,vid_str,port_str+3);
		else if(ISSET_CMD_MSKBIT(u, MAC_IF_GIGA_PORT_MSK))
			func_set_mac_static_address(1,mac_str,vid_str,port_str+3);
		else if(ISSET_CMD_MSKBIT(u, MAC_IF_XE_PORT_MSK))
			func_set_mac_static_address(2,mac_str,vid_str,port_str+3);
		else
			DEBUG_MSG(1, "func_set_mac_static_address error!!\n", NULL);
	}

	retval = sub_cmdparse(mac_interface_symbol_cmds, argc, argv, u);

	return retval;
}

static int do_mac_interface_range_hyphen(int argc, char *argv[], struct users *u)
{
	int retval = -1, port_num_start = 0;
	struct cmds *cmds_ptr = mac_interface_port_end_cmds;

	memset(port_num_end, '\0', sizeof(port_num_end));
		
	cli_param_get_range_edge(STATIC_PARAM, &port_num_start, u);
		
	/* Change argcmin and argcmax according to interface type */
	if(ISSET_CMD_MSKBIT(u, MAC_IF_FAST_PORT_MSK))
	{
		sprintf(port_num_end, "<%d-%d>", port_num_start, (PNUM-GNUM));
		cmds_ptr->argcmin = port_num_start;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else if(ISSET_CMD_MSKBIT(u, MAC_IF_GIGA_PORT_MSK))
	{
		sprintf(port_num_end, "<%d-%d>", port_num_start, GNUM);
		cmds_ptr->argcmin = port_num_start;
		cmds_ptr->argcmax = GNUM;
	}
	else
		sprintf(port_num_end, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

	/* Change name */
	cmds_ptr->name = port_num_end;
	
	retval = sub_cmdparse(mac_interface_port_end_cmds, argc, argv, u);

	return retval;
}

static int do_mac_interface_range_comma(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* cisco :sub_cmdparse(mac_interface_range, argc, argv, u) */
	retval = sub_cmdparse(mac_interface_port_start_cmds, argc, argv, u);

	return retval;
}

static int do_mac_interface_range_port_end(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		char mac_str[MAX_ARGV_LEN] = {0};
		cli_param_get_string(STATIC_PARAM,0,mac_str,u);
		
		int vid_int = 0;
		char vid_str[MAX_ARGV_LEN] = {0};
		cli_param_get_int(STATIC_PARAM,0,&vid_int, u);
		sprintf(vid_str, "%d", vid_int);
		
		char port_str[MAX_ARGV_LEN] = {0};
		cli_param_get_range(STATIC_PARAM, port_str, u);
		
		if(ISSET_CMD_MSKBIT(u, MAC_IF_FAST_PORT_MSK))
			func_set_mac_static_address(0,mac_str,vid_str,port_str+3);
		else if(ISSET_CMD_MSKBIT(u, MAC_IF_GIGA_PORT_MSK))
			func_set_mac_static_address(1,mac_str,vid_str,port_str+3);
		else
			DEBUG_MSG(1, "func_set_mac_static_address error!!\n", NULL);
	}

	retval = sub_cmdparse(mac_interface_comma_end_cmds, argc, argv, u);

	return retval;
}

static int do_mac_interface_range_comma_end(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* cisco :sub_cmdparse(mac_interface_range, argc, argv, u) */
	retval = sub_cmdparse(mac_interface_port_start_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  init_cli_mac
 *  Purpose:  Register mac_topcmds[]
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
int init_cli_mac(void)
{
	int retval = -1;

	retval = registerncmd(mac_topcmds, (sizeof(mac_topcmds)/sizeof(struct topcmds) - 1));
	
	DEBUG_MSG(1, "init_cli_mac retval = %d\n", retval);

	return retval;
}

