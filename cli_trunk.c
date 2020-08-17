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

#include "cli_trunk.h"
#include "cli_trunk_func.h"

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
 2011/11/7  1.01       guiqin.li      add the trunk_topcmds[]
 2011/11/8  1.01       guiqin.li      add the intreface_trunk_topcmds[]
 2012/02/8  1.01       yaohui.jiang   add lacp bpdu-sent-interval
 */
static struct topcmds trunk_topcmds[] = {
	{ "aggregator-group", 0, CONFIG_TREE, do_trunk, no_trunk, NULL, CLI_END_NONE, 0, 0,
		"Aggregation configuration", "聚合配置" },
	{"lacp", 0, CONFIG_TREE, do_lacp, NULL, NULL, CLI_END_NONE, 0, 0,
		"LACP mode configuration", "动态汇聚配置" },
	{ TOPCMDS_END }
};



/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       guiqin.li      add trunk_dst_cmds[]
 2011/11/7  1.01       guiqin.li      add trunk_dst_opt_cmds[]
 2011/11/8  1.01       guiqin.li      add interface_trunk_group_cmds[]
 2011/11/8  1.01       guiqin.li      add cmds interface_trunk_mode_cmds[]
 2011/11/8  1.01       guiqin.li      add interface_trunk_mode_sel_cmds[]
 */
static struct cmds trunk_dst_cmds[] = {
	{ "load-balance", CLI_CMD, 0, 0, do_trunk_load_balance, no_trunk_load_balance, NULL, CLI_END_NO, 0, 0,
		"Load Balancing method", "流量方法" },
	{ CMDS_END }
};

static struct cmds lacp_dst_cmds[] = {
	{ "mode", CLI_CMD, 0, 0, do_lacp_interval_mode, no_lacp_interval_mode, NULL, CLI_END_NO, 0, 0,
		"LACP mode", "动态汇聚模式选择" },
	{ CMDS_END }
};

static struct cmds trunk_dst_opt_cmds[] = {
	{ "src-mac", CLI_CMD,  0, 0, do_trunk_load_balance_src_mac,  NULL, NULL, CLI_END_FLAG, 0, 0,
		"Src Mac Addr", "源MAC地址" },
	{ "dst-mac", CLI_CMD,  0, 0, do_trunk_load_balance_dst_mac,  NULL, NULL, CLI_END_FLAG, 0, 0,
		"Dst Mac Addr", "目的MAC地址" },
	{ "both-mac",CLI_CMD,  0, 0, do_trunk_load_balance_both_mac, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Src and Dst Mac Addr", "源和目的MAC地址" },
	{ "src-ip",  CLI_CMD,  0, 0, do_trunk_load_balance_src_ip,   NULL, NULL, CLI_END_FLAG, 0, 0,
		"Src Ip Addr", "源IP地址" },
	{ "dst-ip",  CLI_CMD,  0, 0, do_trunk_load_balance_dst_ip,   NULL, NULL, CLI_END_FLAG, 0, 0,
		"Dst Ip Addr", "目的IP地址" },
	{ "both-ip", CLI_CMD,  0, 0, do_trunk_load_balance_both_ip,  NULL, NULL, CLI_END_FLAG, 0, 0,
		"Src and Dst Ip Addr", "源和目的IP地址" },
	{ "src-port",CLI_CMD,  0, 0, do_trunk_load_balance_src_port,   NULL, NULL, CLI_END_FLAG, 0, 0,
		"Src port number", "源port" },
	{ "dst-port",CLI_CMD,  0, 0, do_trunk_load_balance_dst_port,   NULL, NULL, CLI_END_FLAG, 0, 0,
		"Dst port number", "目的port" },
//	{ "both-port",CLI_CMD,  0, 0, do_trunk_load_balance_both_port,  NULL, NULL, CLI_END_FLAG, 0, 0,
//		"Src and Dst port", "源和目的port" },				
	{ CMDS_END }
};

static struct cmds lacp_dst_opt_cmds[] = {
	{ "fast", CLI_CMD,  0, 0, do_lacp_interval_mode_fast,  NULL, NULL, CLI_END_FLAG, 0, 0,
		"fast mode ", "快速模式" },
	{ "normal", CLI_CMD,  0, 0, do_lacp_interval_mode_normal,  NULL, NULL, CLI_END_FLAG, 0, 0,
		"normal mode ", "一般模式" },
	{ CMDS_END }
};

/*
 *  Function:  do_trunk
 *  Purpose:  aggregator-group topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li	
 *  Date:     2011/11/7
 */
static int do_trunk(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(trunk_dst_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_lacp
 *  Purpose:  aggregator-group topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2012/02/27
 */
static int do_lacp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(lacp_dst_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_trunk
 *  Purpose:  no aggregator-group topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li	
 *  Date:     2011/11/7
 */
static int no_trunk(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(trunk_dst_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_lacp_interval_mode
 *  Purpose:  no aggregator-group topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2012/02/27
 */
static int no_lacp_interval_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_lacp_interval_mode();
	}

	return retval;
}

/*
 *  Function:  do_trunk_load_balance
 *  Purpose:  aggregator-group subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:    2011/11/7
 */
static int do_trunk_load_balance(int argc, char *argv[], struct users *u)
{
		
	int retval = -1;

	retval = sub_cmdparse(trunk_dst_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_lacp_interval_mode
 *  Purpose:  no aggregator-group topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2012/02/27
 */
static int do_lacp_interval_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(lacp_dst_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_trunk_load_balance
 *  Purpose:  no aggregator-group subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:    2011/11/7
 */
static int no_trunk_load_balance(int argc, char *argv[], struct users *u)
{
		
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_trunk_load_balance("0");
	}

	return retval;
}

/*
 *  Function:  do_trunk_load_balance_src_mac
 *  Purpose:  src mac subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int do_trunk_load_balance_src_mac(int argc, char *argv[], struct users *u)
{	
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_set_trunk_load_balance("2");
	}

	return retval;
}

/*
 *  Function:  do_trunk_load_balance_dst_mac
 *  Purpose:  dst mac subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int do_trunk_load_balance_dst_mac(int argc, char *argv[], struct users *u)
{	
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_set_trunk_load_balance("3");
	}

	return retval;
}

/*
 *  Function:  do_trunk_load_balance_both_mac
 *  Purpose:   both mac subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int do_trunk_load_balance_both_mac(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_set_trunk_load_balance("1");
	}

	return retval;
}

/*
 *  Function:  do_trunk_load_balance_src_ip
 *  Purpose:   src ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int do_trunk_load_balance_src_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_set_trunk_load_balance("5");
	}

	return retval;
}

/*
 *  Function:  do_trunk_load_balance_dst_ip
 *  Purpose:   dst ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int do_trunk_load_balance_dst_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_set_trunk_load_balance("6");
	}

	return retval;
}

/*
 *  Function:  do_trunk_load_balance_both_ip
 *  Purpose:   both ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int do_trunk_load_balance_both_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_set_trunk_load_balance("4");
	}

	return retval;
}
/*
 *  Function:  do_trunk_load_balance_src_L4 port number
 *  Purpose:   src ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int do_trunk_load_balance_src_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_set_trunk_load_balance("8");
	}

	return retval;
}

/*
 *  Function:  do_trunk_load_balance_dst_L4 port number
 *  Purpose:   dst ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int do_trunk_load_balance_dst_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_set_trunk_load_balance("9");
	}

	return retval;
}

/*
 *  Function:  do_trunk_load_balance_both_L4 port number
 *  Purpose:   both ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int do_trunk_load_balance_both_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_set_trunk_load_balance("7");
	}

	return retval;
}

/*
 *  Function:  do_lacp_interval_mode_fast
 *  Purpose:   both ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2012/02/27
 */
static int do_lacp_interval_mode_fast(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_lacp_interval_mode_select(1);
	}

	return retval;
}

/*
 *  Function:  do_lacp_interval_mode_normal
 *  Purpose:   both ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yaohui.jiang
 *  Date:     2012/02/27
 */
static int do_lacp_interval_mode_normal(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_lacp_interval_mode_select(0);
	}

	return retval;
}

int init_cli_trunk(void)
{
	int retval = -1;

	retval = registerncmd(trunk_topcmds, (sizeof(trunk_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1,"init_cli_trunk retval = %d\n", retval);

	return retval;
}

