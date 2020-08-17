/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_mirror.c
 * Function   : mirror command function
 * Auther     : jialong.chu
 * Version    : 1.0
 * Date       : 2011/11/4
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
 2011/11/08  1.01       jiajie.gu      mirror session <1-1> destination interface fastEthernet 0/N <cr>
                                       mirror session <1-1> destination interface GigaEthernet 0/N <cr>
                                       
                                       mirror session <1-1> source interface fastEthernet <0/P,0/M-N> both 
                                       mirror session <1-1> source interface fastEthernet <0/P,0/M-N> rx
                                       mirror session <1-1> source interface fastEthernet <0/P,0/M-N> tx
                                       mirror session <1-1> source interface fastEthernet <0/P,0/M-N> <cr>
                                       
                                       mirror session <1-1> source interface GigaEthernet <0/P,0/M-N> both 
                                       mirror session <1-1> source interface GigaEthernet <0/P,0/M-N> rx
                                       mirror session <1-1> source interface GigaEthernet <0/P,0/M-N> tx
                                       mirror session <1-1> source interface GigaEthernet <0/P,0/M-N> <cr>
                                       
                                       no mirror session 1 <cr>
                                       
                                       
                                                                             
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

#include "cli_mirror.h"
#include "cli_mirror_func.h"

/*
 *  top command struct
 *
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */

static struct topcmds mirror_topcmds[] = {
    { "mirror", 0, CONFIG_TREE, do_mirror, NULL, NULL, CLI_END_NONE, 0, 0,
        "Configure mirror", "配置监控" },
    { TOPCMDS_END }
};

/*
 *  sub command struct
 *
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */

static struct cmds mirror_session[] = {
    { "session", CLI_CMD, 0, 0, do_session, NULL, NULL, CLI_END_NONE, 0, 0,
        "Configure a SPAN session", "配置一个监控会话" },    
    /*{ "session-vlan", CLI_CMD, 0, 0, do_session_vlan, NULL, NULL, CLI_END_NONE, 0, 0,
        "Configure a SPAN session-VLAN", "配置一个vlan监控会话" },*/
    { CMDS_END }
};

static struct cmds mirror_session_num[] = {
    { "<1-4>", CLI_INT, 0, 0, do_session_num, no_session_num, NULL, CLI_END_NO, 1, 4,
        "SPAN session number", "监控会话号" },
    { CMDS_END }
};


static struct cmds mirror_session_interface[] = {
    { "destination", CLI_CMD, 0, MIRROR_IF_DST, do_session_type, NULL, NULL, CLI_END_NONE, 0, 0,
        "SPAN destination interface", "目的端口" },
    { "source", CLI_CMD, 0, MIRROR_IF_SRC, do_session_type, NULL, NULL, CLI_END_NONE, 0, 0,
        "SPAN source interface", "源端口" },    
    { CMDS_END }
};

static struct cmds mirror_session_type_interface[] = {
    { "interface", CLI_CMD, 0, 0, do_session_type_interface, NULL, NULL, CLI_END_NONE, 0, 0,
        "SPAN interface", "端口" },
    { "vlan", CLI_CMD, 0, 0, do_session_type_vlan, NULL, NULL, CLI_END_NONE, 0, 0,
        "SPAN VLAN interface", "VLAN" },
    { CMDS_END }
};


/* interface fast port */
static struct cmds mirror_session_interface_dst[] = {
#if (XPORT==0)
    { "FastEthernet", CLI_CMD_UNUSAL, 0, MIRROR_IF_FAST_PORT, do_mirror_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
        "FastEthernet interface", "快速以太网接口" },
#endif
    { "GigaEthernet", CLI_CMD_UNUSAL, 0, MIRROR_IF_GIGA_PORT, do_mirror_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
        "GigaEthernet interface", "千兆以太网端口" },
#if (XPORT==1)
    { "TenGigaEthernet", CLI_CMD_UNUSAL, 0, MIRROR_IF_XE_PORT, do_mirror_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
        "TenGigaEthernet interface", "万兆以太网接口" },
#endif
    { CMDS_END }
};
static struct cmds mirror_interface_num_cmds[] = {
    { "<0-0>", CLI_CHAR_NO_BLANK, 0, 0, do_mirror_interface_num, NULL, NULL, CLI_END_NONE, 0x30, 0x30,
        "Interface number", "槽号" },
    { CMDS_END }
};
static struct cmds mirror_interface_slash_cmds[] = {
    { "/", CLI_CHAR_NO_BLANK, 0, 0, do_mirror_interface_slash, NULL, NULL, CLI_END_NONE, 0, 0,
        "Slash", "斜杠" },
    { CMDS_END }
};
static struct cmds mirror_interface_port_cmds[] = {
    { "<x-x>", CLI_INT, 0, 0, do_mirror_interface_port, NULL, NULL, CLI_END_FLAG, 0, 0,
        "Port number", "端口号" },
    { CMDS_END }
};

/* interface range fast port */
static struct cmds mirror_session_interface_src[] = {
#if (XPORT==0)
    { "FastEthernet", CLI_CMD_UNUSAL, 0, MIRROR_IF_FAST_PORT, do_mirror_interface_range_port, do_mirror_interface_range_port, NULL, CLI_END_NONE, 0, 0,
        "FastEthernet interface", "快速以太网接口" },
#endif
    { "GigaEthernet", CLI_CMD_UNUSAL, 0, MIRROR_IF_GIGA_PORT, do_mirror_interface_range_port, do_mirror_interface_range_port, NULL, CLI_END_NONE, 0, 0,
        "GigaEthernet interface", "千兆以太网端口" },
#if (XPORT==1)
    { "TenGigaEthernet", CLI_CMD_UNUSAL, 0, MIRROR_IF_XE_PORT, do_mirror_interface_range_port, do_mirror_interface_range_port, NULL, CLI_END_NONE, 0, 0,
        "TenGigaEthernet interface", "万兆以太网接口" },
#endif
    { CMDS_END }
};
static struct cmds mirror_interface_range_num_cmds[] = {
    { "<0-0>", CLI_CHAR_NO_BLANK, 0, 0, do_mirror_interface_range_num, do_mirror_interface_range_num, NULL, CLI_END_NONE, 0x30, 0x30,
        "Interface number", "槽号" },
    { CMDS_END }
};

static struct cmds mirror_vlan_range_num_cmds[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_mirror_vlan_range_num, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 1, 4094,
		"VLAN interface number", "VLAN 序号" },
	{ CMDS_END }
};

static struct cmds mirror_interface_range_slash_cmds[] = {
    { "/", CLI_CHAR_NO_BLANK, 0, 0, do_mirror_interface_range_slash, do_mirror_interface_range_slash, NULL, CLI_END_NONE, 0, 0,
        "Slash", "斜杠" },
    { CMDS_END }
};
static struct cmds mirror_interface_range_port_start_cmds[] = {
    { "<x-x>", CLI_INT_UNUSAL, 0, 0, do_mirror_interface_range_port_start, no_mirror_interface_range_port_start, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Port number", "端口号" },
    { CMDS_END }
};

static struct cmds mirror_vlan_symbol_cmds[] = {
    { "-", CLI_CHAR_UNUSAL, 0, 0, do_mirror_interface_range_hyphen, NULL, NULL, CLI_END_NONE, 0, 0,
        "Specify another range of interfaces", "指定另一个VLAN接口" },
    { ",", CLI_CHAR_UNUSAL, 0, 0, do_mirror_interface_range_comma, NULL, NULL, CLI_END_NONE, 0, 0,
        "Specify a range of interface", "指定一组VLAN接口" },
    { CMDS_END }
};

static struct cmds mirror_interface_symbol_cmds[] = {
    { "-", CLI_CHAR_UNUSAL, 0, 0, do_mirror_interface_range_hyphen, do_mirror_interface_range_hyphen, NULL, CLI_END_NONE, 0, 0,
        "Specify another range of interfaces", "指定另一个接口" },
    { ",", CLI_CHAR_UNUSAL, 0, 0, do_mirror_interface_range_comma, do_mirror_interface_range_comma, NULL, CLI_END_NONE, 0, 0,
        "Specify a range of interface", "指定一组接口" },
    { "both", CLI_CMD, 0, MIRROR_IF_BOTH, do_mirror_interface_opt, no_mirror_interface_opt, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Monitor received and transmitted traffic", "监控发送和接收流量" },
    { "rx", CLI_CMD, 0, MIRROR_IF_RX, do_mirror_interface_opt, no_mirror_interface_opt, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Monitor received traffic only", "监控接收流量" },
    { "tx", CLI_CMD, 0, MIRROR_IF_TX, do_mirror_interface_opt, no_mirror_interface_opt, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Monitor transmitted traffic only", "监控发送流量" },
    { CMDS_END }
};
static struct cmds mirror_interface_range_port_end_cmds[] = {
    { "<x-x>", CLI_INT_UNUSAL, 0, 0, do_mirror_interface_range_port_end, no_mirror_interface_opt, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Port number", "结束端口号" },
    { CMDS_END }
};
static struct cmds mirror_interface_comma_end_cmds[] = {
    { ",", CLI_CHAR_UNUSAL, 0, 0, do_mirror_interface_range_comma_end, NULL, NULL, CLI_END_NONE, 0, 0,
        "Specify a range of interface", "指定一组接口" },
    { "both", CLI_CMD, 0, MIRROR_IF_BOTH, do_mirror_interface_opt, no_mirror_interface_opt, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Monitor received and transmitted traffic", "监控发送和接收流量" },
    { "rx", CLI_CMD, 0, MIRROR_IF_RX, do_mirror_interface_opt, no_mirror_interface_opt, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Monitor received traffic only", "监控接收流量" },
    { "tx", CLI_CMD, 0, MIRROR_IF_TX, do_mirror_interface_opt, no_mirror_interface_opt, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Monitor transmitted traffic only", "监控发送流量" },
    { CMDS_END }
};

/*mirror src vlan cli tree*/
/*static struct cmds mirror_session_vlan_num[] = {
    { "<1-4>", CLI_INT, 0, 0, do_session_vlan_num, no_session_vlan, NULL, CLI_END_NO, 1, 4,
        "SPAN session-VLAN number", "VLAN监控会话号" },
    { CMDS_END }
};

static struct cmds mirror_session_vlan_des_interface[] = {
    { "destination", CLI_CMD, 0, MIRROR_IF_DST, do_session_vlan_des_type, NULL, NULL, CLI_END_NONE, 0, 0,
        "SPAN destination interface", "目的端口" },  
    { CMDS_END }
};
*/
/* interface fast port */
/*static struct cmds mirror_session_vlan_interface_num[] = {
#if (XPORT==0)
    { "FastEthernet", CLI_CMD_UNUSAL, 0, MIRROR_IF_FAST_PORT, do_mirror_vlan_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
        "FastEthernet interface", "快速以太网接口" },
#endif
    { "GigaEthernet", CLI_CMD_UNUSAL, 0, MIRROR_IF_GIGA_PORT, do_mirror_vlan_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
        "GigaEthernet interface", "千兆以太网端口" },
#if (XPORT==1)
    { "TenGigaEthernet", CLI_CMD_UNUSAL, 0, MIRROR_IF_XE_PORT, do_mirror_vlan_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
        "TenGigaEthernet interface", "万兆以太网接口" },
#endif
    { CMDS_END }
};
static struct cmds mirror_vlan_interface_num_cmds[] = {
    { "<0-0>", CLI_CHAR_NO_BLANK, 0, 0, do_mirror_vlan_interface_num, NULL, NULL, CLI_END_NONE, 0x30, 0x30,
        "Interface number", "槽号" },
    { CMDS_END }
};
static struct cmds mirror_vlan_interface_slash_cmds[] = {
    { "/", CLI_CHAR_NO_BLANK, 0, 0, do_mirror_vlan_interface_slash, NULL, NULL, CLI_END_NONE, 0, 0,
        "Slash", "斜杠" },
    { CMDS_END }
};
static struct cmds mirror_vlan_interface_port_cmds[] = {
    { "<x-x>", CLI_INT, 0, 0, do_mirror_vlan_interface_port, NULL, NULL, CLI_END_NONE, 0, 0,
        "Port number", "端口号" },
    { CMDS_END }
};

static struct cmds mirror_session_vlan_src_interface[] = {
    { "source", CLI_CMD, 0, MIRROR_IF_SRC, do_session_vlan_src_type, NULL, NULL, CLI_END_NONE, 0, 0,
        "SPAN source interface", "源端口" }, 

    { CMDS_END }
};

static struct cmds mirror_session_vlan_type_interface[] = {
    { "interface", CLI_CMD, 0, 0, do_session_vlan_type_interface, NULL, NULL, CLI_END_NONE, 0, 0,
        "SPAN interface", "端口" },
    { "vlan", CLI_CMD, 0, 0, do_session_vlan_type_vlan, NULL, NULL, CLI_END_NONE, 0, 0,
        "SPAN VLAN interface", "VLAN" },
    { CMDS_END }
};

static struct cmds mirror_vlan_vlan_range_num_cmds[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_mirror_vlan_vlan_range_num, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 1, 4094,
		"VLAN interface number", "VLAN 序号" },
	{ CMDS_END }
};
*/

/*
 *  Function:  do_mirror
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_mirror(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(mirror_session, argc, argv, u);
    
    return retval;
}

/*
 *  Function: do_session 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_session(int argc, char *argv[], struct users *u)
{
    
    int retval = -1;

    retval = sub_cmdparse(mirror_session_num, argc, argv, u);
    
    return retval;
}

/*static int do_session_vlan(int argc, char *argv[], struct users *u)
{
    
    int retval = -1;

    retval = sub_cmdparse(mirror_session_vlan_num, argc, argv, u);
    
    return retval;
}*/

/*
 *  Function: do_session_num 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_session_num(int argc, char *argv[], struct users *u)
{
    
    int retval = -1;

    retval = sub_cmdparse(mirror_session_interface, argc, argv, u);
    
    return retval;
}

/*static int do_session_vlan_num(int argc, char *argv[], struct users *u)
{
    
    int retval = -1;

    retval = sub_cmdparse(mirror_session_vlan_des_interface, argc, argv, u);
    
    return retval;
}*/


/*
 *  Function: do_session_destination 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_session_type(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(mirror_session_type_interface, argc, argv, u);
    
    return retval;
}

/*static int do_session_vlan_des_type(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(mirror_session_vlan_interface_num, argc, argv, u);
    
    return retval;
}*/
/*
static int do_session_vlan_src_type(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(mirror_session_vlan_type_interface, argc, argv, u);
    
    return retval;
}
*/

/*
 *  Function:  do_session_type_interface
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_session_type_interface(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if(ISSET_CMD_MSKBIT(u, MIRROR_IF_SRC))
    {
        retval = sub_cmdparse(mirror_session_interface_src, argc, argv, u);
    }
    else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_DST))
    {
        retval = sub_cmdparse(mirror_session_interface_dst, argc, argv, u);
    }
    else
    {
        DEBUG_MSG(1, "Unknow mirror type!!\n", NULL);
        return -1;
    }
    
    return retval;
}

/*
static int do_session_vlan_type_interface(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if(ISSET_CMD_MSKBIT(u, MIRROR_IF_SRC))
    {
       // retval = sub_cmdparse(mirror_session_interface_src, argc, argv, u);
    }
    else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_DST))
    {
        retval = sub_cmdparse(mirror_session_vlan_interface_num, argc, argv, u);
    }
    else
    {
        DEBUG_MSG(1, "Unknow mirror type!!\n", NULL);
        return -1;
    }
    
    return retval;
}
*/

static int do_session_type_vlan(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if(ISSET_CMD_MSKBIT(u, MIRROR_IF_SRC))
    {
        retval = sub_cmdparse(mirror_vlan_range_num_cmds, argc, argv, u);
    }
    else
    {
        DEBUG_MSG(1, "Unknow mirror type!!\n", NULL);
        return -1;
    }
    
    return retval;
}
/*
static int do_session_vlan_type_vlan(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if(ISSET_CMD_MSKBIT(u, MIRROR_IF_SRC))
    {
        retval = sub_cmdparse(mirror_vlan_vlan_range_num_cmds, argc, argv, u);
    }
    else
    {
        DEBUG_MSG(1, "Unknow mirror type!!\n", NULL);
        return -1;
    }
    
    return retval;
}
*/

static char port_num_start[MAX_ARGV_LEN] = {'\0'};
static char port_num_end[MAX_ARGV_LEN] = {'\0'};

/* interface fast port */
static int do_mirror_interface_ethernet(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(mirror_interface_num_cmds, argc, argv, u);

    return retval;
}

/* interface fast port */
/*static int do_mirror_vlan_interface_ethernet(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(mirror_vlan_interface_num_cmds, argc, argv, u);

    return retval;
}
*/

static int do_mirror_interface_num(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(mirror_interface_slash_cmds, argc, argv, u);

    return retval;
}

/*static int do_mirror_vlan_interface_num(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(mirror_vlan_interface_slash_cmds, argc, argv, u);

    return retval;
}
*/

static int do_mirror_interface_slash(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    struct cmds *cmds_ptr = mirror_interface_port_cmds;

    memset(port_num_start, '\0', sizeof(port_num_start));

    /* Change argcmin and argcmax according to interface type */
    if(ISSET_CMD_MSKBIT(u, MIRROR_IF_FAST_PORT))
    {
        sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
        cmds_ptr->argcmin = 1;
        cmds_ptr->argcmax = (PNUM-GNUM);
    }
    else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_GIGA_PORT))
    {
        sprintf(port_num_start, "<%d-%d>", 1, GNUM);
        cmds_ptr->argcmin = 1;
        cmds_ptr->argcmax = GNUM;
    }
    else
        sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

    /* Change name */
    cmds_ptr->name = port_num_start;
    
    retval = sub_cmdparse(mirror_interface_port_cmds, argc, argv, u);

    return retval;
}
/*
static int do_mirror_vlan_interface_slash(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    struct cmds *cmds_ptr = mirror_vlan_interface_port_cmds;

    memset(port_num_start, '\0', sizeof(port_num_start));

    if(ISSET_CMD_MSKBIT(u, MIRROR_IF_FAST_PORT))
    {
        sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
        cmds_ptr->argcmin = 1;
        cmds_ptr->argcmax = (PNUM-GNUM);
    }
    else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_GIGA_PORT))
    {
        sprintf(port_num_start, "<%d-%d>", 1, GNUM);
        cmds_ptr->argcmin = 1;
        cmds_ptr->argcmax = GNUM;
    }
    else
        sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

    cmds_ptr->name = port_num_start;
    
    retval = sub_cmdparse(mirror_vlan_interface_port_cmds, argc, argv, u);

    return retval;
}
*/
static int do_mirror_interface_port(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application */
        func_mirror_interface_dst(u);
    }
    
    return retval;
}
/*
static int do_mirror_vlan_interface_port(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {

	    if (!(( ISSET_CMD_MSKBIT(u, MIRROR_IF_FAST_PORT) ) || 
				( ISSET_CMD_MSKBIT(u, MIRROR_IF_GIGA_PORT) )))
	    {
	        DEBUG_MSG(1, "Unknow interface type!!\n", NULL);;
	    }
    
    }

    retval = sub_cmdparse(mirror_session_vlan_src_interface, argc, argv, u);

    return retval;
}
*/

/* interface range fast port */
static int do_mirror_interface_range_port(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(mirror_interface_range_num_cmds, argc, argv, u);

    return retval;
}

static int do_mirror_interface_range_num(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(mirror_interface_range_slash_cmds, argc, argv, u);

    return retval;
}

static int do_mirror_interface_range_slash(int argc, char *argv[], struct users *u)
{
    int retval = -1;    
    struct cmds *cmds_ptr = mirror_interface_range_port_start_cmds;

    memset(port_num_start, '\0', sizeof(port_num_start));

    /* Change argcmin and argcmax according to interface type */
    if(ISSET_CMD_MSKBIT(u, MIRROR_IF_FAST_PORT))
    {
        sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
        cmds_ptr->argcmin = 1;
        cmds_ptr->argcmax = (PNUM-GNUM);
    }
    else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_GIGA_PORT))
    {
        sprintf(port_num_start, "<%d-%d>", 1, GNUM);
        cmds_ptr->argcmin = 1;
        cmds_ptr->argcmax = GNUM;
    }
    else
        sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

    /* Change name */
    cmds_ptr->name = port_num_start;
    
    retval = sub_cmdparse(mirror_interface_range_port_start_cmds, argc, argv, u);

    return retval;
}

static int do_mirror_interface_range_port_start(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application */
        func_mirror_interface_src(u);
    }
    
    retval = sub_cmdparse(mirror_interface_symbol_cmds, argc, argv, u);

    return retval;
}

static int do_mirror_interface_range_hyphen(int argc, char *argv[], struct users *u)
{
    int retval = -1, port_num_start = 0;
    struct cmds *cmds_ptr = mirror_interface_range_port_end_cmds;

    memset(port_num_end, '\0', sizeof(port_num_end));

    cli_param_get_range_edge(STATIC_PARAM, &port_num_start, u);
        
    /* Change argcmin and argcmax according to interface type */
    if(ISSET_CMD_MSKBIT(u, MIRROR_IF_FAST_PORT))
    {
        sprintf(port_num_end, "<%d-%d>", port_num_start, (PNUM-GNUM));
        cmds_ptr->argcmin = port_num_start;
        cmds_ptr->argcmax = (PNUM-GNUM);
    }
    else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_GIGA_PORT))
    {
        sprintf(port_num_end, "<%d-%d>", port_num_start, GNUM);
        cmds_ptr->argcmin = port_num_start;
        cmds_ptr->argcmax = GNUM;
    }
    else
        sprintf(port_num_end, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

    /* Change name */
    cmds_ptr->name = port_num_end;
    
    retval = sub_cmdparse(mirror_interface_range_port_end_cmds, argc, argv, u);

    return retval;
}

static int do_mirror_interface_range_comma(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    /* cisco :sub_cmdparse(mirror_interface_range, argc, argv, u) */
    retval = sub_cmdparse(mirror_interface_range_port_start_cmds, argc, argv, u);

    return retval;
}

static int do_mirror_interface_range_port_end(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application */
        func_mirror_interface_src(u);
    }
    retval = sub_cmdparse(mirror_interface_comma_end_cmds, argc, argv, u);

    return retval;
}

static int do_mirror_interface_range_comma_end(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    /* cisco :sub_cmdparse(mirror_interface_range, argc, argv, u) */
    retval = sub_cmdparse(mirror_interface_range_port_start_cmds, argc, argv, u);

    return retval;
}

static int do_mirror_interface_opt(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application */
        func_mirror_interface_src(u);
    }

    return retval;
}

static int no_session_num(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        /* Do application */
        nfunc_session_num(u);
    }
    
    SET_CMD_MSKBIT(u, MIRROR_IF_DST);
        
    retval = sub_cmdparse(mirror_session_interface, argc, argv, u);
    
    return retval;
}
/*
static int no_session_vlan(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
       // nfunc_session_num(u);
		retval = nfunc_mirror_vlan_by_session(u);
    }
    
    //SET_CMD_MSKBIT(u, MIRROR_IF_DST);       
    //retval = sub_cmdparse(mirror_session_interface, argc, argv, u);
    
    return retval;
}
*/

static int no_mirror_interface_range_port_start(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application */
        nfunc_mirror_interface_src(u);
    }
    
    retval = sub_cmdparse(mirror_interface_symbol_cmds, argc, argv, u);

    return retval;
}

static int no_mirror_interface_opt(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application */
        nfunc_mirror_interface_src(u);
    }
    retval = sub_cmdparse(mirror_interface_comma_end_cmds, argc, argv, u);

    return retval;
}

/*
 *  Function:  init_cli_mirror
 *  Purpose:  Register mirror_topcmds[]
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
int init_cli_mirror(void)
{
    int retval = -1;

    retval = registerncmd(mirror_topcmds, (sizeof(mirror_topcmds)/sizeof(struct topcmds) - 1));
    DEBUG_MSG(1,"init_cli_mirror retval = %d\n", retval);

    return retval;
}

static int do_mirror_vlan_range_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application */
		//func_mirror_soure_vlan(u);
		retval = func_mirror_vlan_set(u);
	}
	
	return retval;
}
/*
static int do_mirror_vlan_vlan_range_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{	
		//func_mirror_soure_vlan(u);
		retval = func_mirror_vlan_set(u);
	}
	
	return retval;
}
*/

