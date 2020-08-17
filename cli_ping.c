/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_ping.c
 * Function   : ping command function
 * Auther     : jialong.chu
 * Version    : 1.0
 * Date       : 2011/11/4
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
 2011/11/4  1.01        jialong.chu    ping -l (x)
                                       ping -a (x)
                                       ping -b (x)
                                       ping -n (x)
                                       ping -t (x)
                                       ping -s (x) 
                                       ping -w (x)

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

#include "cli_ping.h"
#include "cli_ping_func.h"

/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/4  1.01       jialong.chu      add the ping_topcmds[]
 2011/11/8  1.01	     jiajie.gu		modified help_cn/help_en/endflag
 */
static struct topcmds ping_topcmds[] = {
	{ "ping", 0, ENA_TREE|CONFIG_TREE, do_ping, NULL, NULL, CLI_END_NONE, 0, 0,
		"Test network status", "测试网络状态" },
	{ TOPCMDS_END }
};

/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/4  1.01       jialong.chu      add ping_dst_cmds[]
 2011/11/4  1.01       jialong.chu      add ping_dst_opt_cmds[]
 2011/11/8  1.01	   jiajie.gu		modified help_cn/help_en/endflag
 */
static struct cmds ping_dst_cmds[] = {
	{ "ipv6", CLI_CMD, 0, 0, do_ping_ipv6, NULL, NULL, CLI_END_NONE, 0, 0,
		"ipv6", "目的地址" },
	{ "X.X.X.X", CLI_IPV4, 0, PING_IPV4, do_ping_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Destination IP address", "目的地址" },	
	{ "WORD", CLI_WORD, 0, PING_HOST, do_ping_host, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Destination host", "目的主机名" },
	{ CMDS_END }
};

static struct cmds ping_ipv6[] = {
	{ "WORD", CLI_WORD, 0, 0, do_v6, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Destination host", "目的主机名" },
	{ CMDS_END }
};

static struct cmds ping_dst_opt_cmds[] = {
//	{ "a", CLI_CMD, 0, PING_OPT_ALL_TIME, do_ping_opt_a, NULL, NULL, CLI_END_FLAG, 0, 0,
//		"ping all the time", "一直 ping，直到被中断" },
	{ "l", CLI_CMD, 0, PING_OPT_PKT_LEN, do_ping_opt_l, NULL, NULL, CLI_END_NONE, 0, 0,
		"datalen", "数据长度" },
	{ "n", CLI_CMD, 0, PING_OPT_PKT_CNT, do_ping_opt_n, NULL, NULL, CLI_END_NONE, 0, 0,
		"counts of echo req", "发送的 echo 请求报文数" },
	{ "w", CLI_CMD, 0, PING_OPT_WAIT_TIME, do_ping_opt_w, NULL, NULL, CLI_END_NONE, 0, 0,
		"time of maxwait", "等待应答的时间(秒)" },
//	{ "b", CLI_CMD, 0, PING_OPT_INTERVAL_TIME, do_ping_opt_b, NULL, NULL, CLI_END_NONE, 0, 0,
//		"time of interval", "两个 Ping 报文之间的时间间隔(10ms)" },
//	{ "t", CLI_CMD, 0, PING_OPT_TTL, do_ping_opt_t, NULL, NULL, CLI_END_NONE, 0, 0,
//		"ttl", "TTL" },
//	{ "s", CLI_CMD, 0, PING_OPT_TOS, do_ping_opt_s, NULL, NULL, CLI_END_NONE, 0, 0,
//		"tos", "TOS" },
	{ CMDS_END }
};

/*
 *  Function:  do_ping
 *  Purpose:  ping topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_ping(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ping_dst_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_ping_ip
 *  Purpose:  ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_ping_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u))== 0) 
	{
		/* Do application function */
//		do_test_param(argc, argv, u);
		func_ping(u);
	}
	retval = sub_cmdparse(ping_dst_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_ping_host
 *  Purpose:  host subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_ping_host(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ping(u);
	}
	retval = sub_cmdparse(ping_dst_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_ping_ipv6
 *  Purpose:  -a subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */

static int do_ping_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ping_ipv6, argc, argv, u);

	return retval;
}

static int do_v6(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		func_v6(u);
	}

	return retval;
}


/*
 *  Function:  do_ping_opt_a
 *  Purpose:  -a subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_ping_opt_a(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ping(u);
	}
	SET_CMD_MSKBIT(u, PING_OPT_PKT_CNT);
	retval = sub_cmdparse(ping_dst_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_ping_opt_l
 *  Purpose:  -l subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *	modifier: gujiajie	2011/11/8  01/30/2012
 *  Date:     2011/11/4
 */
static int do_ping_opt_l(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<56-18024>";
	param.ylabel = "data bytes";
	param.hlabel = "数据字节";
	param.min = 56;
	param.max = 18024;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, PING_PKT_LEN_POS, param.value.v_int, u);
	
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ping(u);
	}
	retval = sub_cmdparse(ping_dst_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_ping_opt_n
 *  Purpose:  -n subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *	modifier: gujiajie	2011/11/8
 *  Date:     2011/11/4
 */
static int do_ping_opt_n(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-65535>";
	param.ylabel = "count value";
	param.hlabel = "次数";
	param.min = 1;
	param.max = 65535;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, PING_PKT_CNT_POS, param.value.v_int, u);

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ping(u);
	}

	SET_CMD_MSKBIT(u, PING_OPT_ALL_TIME);
	retval = sub_cmdparse(ping_dst_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_ping_opt_w
 *  Purpose:  -w subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *	modifier: gujiajie	2011/11/8
 *  Date:     2011/11/4
 */
static int do_ping_opt_w(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-60>";
	param.ylabel = "time value(uint:s)";
	param.hlabel = "时间值(单位:秒)";
	param.min = 1;
	param.max = 60;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, PING_WAIT_TIME_POS, param.value.v_int, u);

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ping(u);
	}

	retval = sub_cmdparse(ping_dst_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_ping_opt_b
 *  Purpose:  -b subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *	modifier: gujiajie	2011/11/8
 *  Date:     2011/11/4
 */
static int do_ping_opt_b(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-60>";
	param.ylabel = "time value(uint:s)";
	param.hlabel = "时间值(单位:秒)";
	param.min = 1;
	param.max = 60;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, PING_INTERVAL_TIME_POS, param.value.v_int, u);

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ping(u);
	}

	retval = sub_cmdparse(ping_dst_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_ping_opt_t
 *  Purpose:  -t subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *	modifier: gujiajie	2011/11/8
 *  Date:     2011/11/4
 */
static int do_ping_opt_t(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<0-255>";
	param.ylabel = "ttl value";
	param.hlabel = "TTL";
	param.min = 0;
	param.max = 255;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, PING_TTL_POS, param.value.v_int, u);

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ping(u);
	}

	retval = sub_cmdparse(ping_dst_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_ping_opt_s
 *  Purpose:  -s subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *	modifier: gujiajie	2011/11/8
 *  Date:     2011/11/4
 */
static int do_ping_opt_s(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "2,4,8,160";
	param.ylabel = "tos value";
	param.hlabel = "TOS";
	param.min = 0;
	param.max = 0;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	if(param.value.v_int != 2 
		&& param.value.v_int != 4 
		&& param.value.v_int != 8 
		&& param.value.v_int != 160)
	{
		SET_ERR_NO(u, CLI_ERR_INT_RANGE);
		return -1;
	}
	
	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, PING_TOS_POS, param.value.v_int, u);

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ping(u);
	}

	retval = sub_cmdparse(ping_dst_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  init_cli_ping
 *  Purpose:  Register ping_topcmds[]
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
int init_cli_ping(void)
{
	int retval = -1;

	/* Register ping_topcmds[] */
	retval = registerncmd(ping_topcmds, (sizeof(ping_topcmds)/sizeof(struct topcmds) - 1));
	
	DEBUG_MSG(1, "init_cli_ping retval = %d\n", retval);

	return retval;
}

