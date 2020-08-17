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

#include "cli_others.h"
#include "cli_others_func.h"


static struct topcmds traceroute_topcmds[] = {
	{ "traceroute", 0, ENA_TREE, do_traceroute, NULL, NULL, CLI_END_NONE, 0, 0,
		"Trace route to destination", "跟踪到目的地的路由" },
	{ TOPCMDS_END }
};

static struct topcmds dot1q_topcmds[] = {
	{ "dot1q-tunnel", 0, CONFIG_TREE, do_dot1q, no_dot1q, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Enable dot1q tunnel globally", "启用全局dot1q tunnel特性" },
	{ TOPCMDS_END }
};

static struct topcmds anti_dos_topcmds[] = {
	{ "anti_dos", 0, CONFIG_TREE, do_anti_dos, NULL, NULL, CLI_END_NONE, 0, 0,
		"protect from dos attact", "防护DOS攻击" },
	{ TOPCMDS_END }
};

static struct topcmds exec_timeout_topcmds[] = {
	{ "exec_timeout", 0, CONFIG_TREE, do_exec_timeout, no_exec_timeout, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Set the EXEC timeout", "设置EXEC超时" },
	{ TOPCMDS_END }
};

static struct topcmds flow_interval_topcmds[] = {
	{ "flow_interval", 0, CONFIG_TREE, do_flow_interval, no_flow_interval, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Set statistical time interval", "设置统计时间间隔"},
	{ TOPCMDS_END }
};

static struct topcmds exec_errdis_topcmds[] = {
	{ "error-disable-recover", 0, CONFIG_TREE, do_error_disable_recover, no_error_disable_recover, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Set the EXEC timeout", "设置EXEC超时" },
	{ TOPCMDS_END }
};

static struct cmds dot1q_tunnel[] = {
	{ "tpid", CLI_CMD, 0, 0, do_dot1q_tpid, no_dot1q_tpid, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"set TPID tag", "设置TPID标签" },
	{ CMDS_END }
};

static struct cmds dot1q_tunnel_tpid[] = {
	{ "WORD", CLI_WORD, 0, 0, do_dot1q_tpid_word, NULL, NULL, CLI_END_FLAG, 0, 0,
		"TPID tag must be set 4 Hex number, such as '9100' or '8100'", "TPID标签必须是4个16进制数组成，如'9100' 或 '8100'" },
	{ CMDS_END }
};

static struct cmds traceroute[] = {
	{ "WORD", CLI_WORD, 0, 0, cmd_traceroute, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Trace route to destinaton address or hostname", "目的地址或主机名" },
	{ CMDS_END }
};

static struct cmds anti_dos[] = {
	{ "enable", CLI_CMD, 0, 0, do_anti_dos_ena, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Protect From Dos Attact", "防护DOS攻击使能" },
	{ CMDS_END }
};

static struct cmds exec_timeout[] = {
	{ "<60-3600s>", CLI_INT, 0, 0, cmd_exec_timeout, NULL, NULL, CLI_END_FLAG, 60, 3600,
		"Timeout in secends", "超时时间秒数" },
	{ CMDS_END }
};

static struct cmds flow_interval[] = {
	{ "<1-86400s>", CLI_INT, 0, 0, cmd_flow_interval, NULL, NULL, CLI_END_FLAG, 1, 86400,
		"Statistical time interval","统计时间间隔"},
	{ CMDS_END }
};

static struct cmds exec_error_disable_recover[] = {
	{ "enable", CLI_CMD, 0, 0, do_error_disable_recover_enable, NULL, NULL, CLI_END_FLAG, 0, 0,
		"enable error status to normal", "端口自动恢复" },
	{ "recovery-time", CLI_CMD, 0, 0, do_error_disable_recover_time, NULL, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"timeout check when error happen", "端口自动恢复时间" },
	{ CMDS_END }
};

static struct cmds exec_error_disable_recover_timeout[] = {
	{ "<300-3600s>", CLI_INT, 0, 0, cmd_error_disable_recover_timeout, NULL, NULL, CLI_END_FLAG, 300, 3600,
		"Timeout in secends", "超时时间秒数" },
	{ CMDS_END }
};

/*
 *  Function:  do_traceroute
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_traceroute(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(traceroute, argc, argv, u);
	
	return retval;
}

/*
 *  Function:  cmd_traceroute
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int cmd_traceroute(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change console level */
		func_traceroute(u);
	}
	
	return retval;
}

/*
 *  Function:  do_traceroute
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_anti_dos(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(anti_dos, argc, argv, u);
	
	return retval;
}

/*
 *  Function:  anti_dos_ena
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_anti_dos_ena(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change console level */
		func_anti_dos_ena(u);
	}
	
	return retval;
}

/*
 *  Function:  do_traceroute
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int do_exec_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(exec_timeout, argc, argv, u);
	
	return retval;
}

static int do_flow_interval(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(flow_interval, argc, argv, u);
	
	return retval;
}
/*
 *  Function:  cmd_exec_timeout
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int cmd_exec_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change console level */
		func_exec_timeout(u);
	}
	
	return retval;
}

static int cmd_flow_interval(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change console level */
		func_flow_interval(u);
	}
	
	return retval;
}
/*
 *  Function:  no_exec_timeout
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
static int no_exec_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change console level */
		nfunc_exec_timeout(u);
	}
	
	return retval;
}

static int no_flow_interval(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change console level */
		nfunc_flow_interval(u);
	}
	
	return retval;
}

/*error disable recovery*/
static int do_error_disable_recover(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(exec_error_disable_recover, argc, argv, u);
	
	return retval;
}

static int do_error_disable_recover_enable(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change console level */
		func_error_disable_recover_enable(u);
	}
	
	return retval;
}

static int do_error_disable_recover_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(exec_error_disable_recover_timeout, argc, argv, u);
	
	return retval;
}

static int cmd_error_disable_recover_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change console level */
		func_error_disable_recover_timeout(u);
	}
	
	return retval;
}

static int no_error_disable_recover(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change console level */
		nfunc_error_disable_recover(u);
	}
	
	return retval;
}

static int do_dot1q(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	//retval = cmdend2(argc, argv, u);
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_config_dot1q(u);
	}
	retval = sub_cmdparse(dot1q_tunnel, argc, argv, u);
	
	return retval;

}

static int no_dot1q(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	//retval = cmdend2(argc, argv, u);
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_config_dot1q(u);
	}else
		retval = sub_cmdparse(dot1q_tunnel, argc, argv, u);
	return retval;

}

static int do_dot1q_tpid(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	retval = sub_cmdparse(dot1q_tunnel_tpid, argc, argv, u);
	
	return retval;
}

static int no_dot1q_tpid(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_config_dot1q_tpid(u);
	}
	
	return retval;
}

static int do_dot1q_tpid_word(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_config_dot1q_tpid(u);
	}
	
	return retval;
}
/*
 *  Function:  init_cli_others
 *  Purpose:  Register clock function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
int init_cli_others(void)
{
	int retval = -1;
	retval = registerncmd(traceroute_topcmds, (sizeof(traceroute_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(anti_dos_topcmds, (sizeof(anti_dos_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(exec_timeout_topcmds, (sizeof(exec_timeout_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(flow_interval_topcmds, (sizeof(flow_interval_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(dot1q_topcmds, (sizeof(dot1q_topcmds)/sizeof(struct topcmds) - 1)); 
	retval += registerncmd(exec_errdis_topcmds, (sizeof(exec_errdis_topcmds)/sizeof(struct topcmds) - 1)); 
	
	DEBUG_MSG(1, "init_cli_others retval = %d\n", retval);

	return retval;
}
