/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_lldp.c
 * Function   : lldp command function
 * Auther     : yaohui.jiang
 * Version    : 1.0
 * Date       : 2011/11/11
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
 2011/11/11  1.01        yaohui.jiang    lldp run
                                       lldp timer (5-65534)
                                       lldp holdtime (0-65535)
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

#include "cli_lldp.h"
#include "cli_lldp_func.h"

/*************************
static struct topcmds topcmds[] = {
	{ "name", pv_level, TREE, func, no_func, def_func, endflag, argcmin, argcmax,
		"help_en", "help_cn" },
	{ TOPCMDS_END }
};

static struct cmds cmds[] = {
	{ "name", MATCH_MODE, pv_level, maskbit, func, no_func, def_func, endflag, argcmin, argcmax,
		"help_en", "help_cn" },
	{ CMDS_END }
};
**************************/

extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/11 1.01       yaohui.jiang     add the lldp_topcmds[]
 */
 
static struct topcmds lldp_topcmds[] = {
	{ "lldp", 0, CONFIG_TREE, do_lldp, NULL, NULL, CLI_END_NONE, 0, 0,
		"LLDP configuration commands", "LLDP 配置命令" },
	{ TOPCMDS_END }
};

/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/11  1.01       yaohui.jiang      add lldp_cmds[]
 */
static struct cmds lldp_cmds[] = {
	{ "enable", CLI_CMD, 0, 0, do_lldp_run, no_lldp_run, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Enable PTOPO discovery protocol to run", "使能物理拓扑发现协议" },
	{ "holdtime", CLI_CMD, 0, 0, do_set_holdtime, no_set_holdtime, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Specify the holdtime (in sec) to be sent in packets", "设置报文中的保持时间(秒)" },
	{ "timer", CLI_CMD, 0, 0, do_set_interval_time, no_set_interval_time, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Specify the interval at which packets are sent", "指定报文发送间隔(秒)" },
	{ CMDS_END }
};
/*
 *  Function:  do_lldp
 *  Purpose:  lldp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2011/11/11
 */
static int do_lldp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(lldp_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_lldp_run
 *  Purpose:  run subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2011/11/11
 */
static int do_lldp_run(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = cmdend2(argc, argv, u);
	
	if(retval == 0) 
	{
		func_lldp_run(u);
	}
	
	return retval;
}

/*
 *  Function:  no_lldp_run
 *  Purpose:  no run subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2011/11/11
 */
static int no_lldp_run(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = cmdend2(argc, argv, u);
	
	if(retval == 0) 
	{
		nfunc_lldp_run(u);
	}
	
	return retval;
}

/*
 *  Function:  do_set_holdtime
 *  Purpose:  holdtime subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2011/11/11
 */
static int do_set_holdtime(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<0-65535>";
	param.ylabel = "Length of time(in sec) that receiver must keep this packet";
	param.hlabel = "接收到包后保持时间长度(秒)";
	param.min = 0;
	param.max = 65535;
	param.flag = 1;
	
	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
		
	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, LLDP_1_POS, param.value.v_int, u);

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	
	if(retval == 0) 
	{
		func_set_lldp_holdtime(u);
	}
	
	return retval;
		
}

/*
 *  Function:  no_set_holdtime
 *  Purpose:  no holdtime subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2011/11/11
 */
static int no_set_holdtime(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = cmdend2(argc, argv, u);
	
	if(retval == 0) 
	{
		nfunc_set_lldp_holdtime(u);
	}
	
	return retval;
}

/*
 *  Function:  do_set_interval_time
 *  Purpose:  interval time subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2011/11/11
 */
static int do_set_interval_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<5-65534>";
	param.ylabel = "Specify the interval at which packets are sent";
	param.hlabel = "LLDP包发送间隔时间(秒)";
	param.min = 5;
	param.max = 65534;
	param.flag = 1;
	
	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
	
	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, LLDP_2_POS, param.value.v_int, u);

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	
	if(retval == 0) 
	{
		func_set_lldp_interval_time(u);
	}
	
	return retval;
}

/*
 *  Function:  no_set_interval_time
 *  Purpose:  no interval time subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2011/11/11
 */
static int no_set_interval_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = cmdend2(argc, argv, u);
	
	if(retval == 0) 
	{
		nfunc_set_lldp_interval_time(u);
	}
	
	return retval;
}

/*
 *  Function:  init_cli_lldp
 *  Purpose:  Register lldp_topcmds[]
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:  yaohui.jiang
 *  Date:     2011/11/11
 */
int init_cli_lldp(void)
{
	int retval = -1;

	retval = registerncmd(lldp_topcmds, (sizeof(lldp_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1,"init_cli_lldp retval = %d\n", retval);

	return retval;
}

