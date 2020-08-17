/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_clock.c
 * Function   : show command function
 * Auther     : jialong.chu
 * Version    : 1.0
 * Date       : 2011/11/4
 *
 *********************Revision History****************
 Date       Version     Modifier            Command
 2011/11/7  1.01        yunchang.xuan       clock set hh:mm:ss day month year
                                            CONFIG_TREE:
                                            clock timezone WORD <-12 - +12> <cr>
                                            
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

#include "cli_clock.h"
#include "cli_clock_func.h"

/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       yunchang.xuan    clock_topcmds[]
                                        config_clock_topcmds[]

2011/12/9 1.0           dawei.hu	ntp_topcmds[]
 */
static struct topcmds clock_topcmds[] = {
	{ "clock", 0, ENA_TREE, do_clock, NULL, NULL, 0, 0, 0,
		"Clock", "时钟设置" },
	{ TOPCMDS_END }
};

static struct topcmds config_clock_topcmds[] = {
	{ "clock", 0, CONFIG_TREE, config_do_clock, NULL, NULL, 0, 0, 0,
		"Clock", "时间设置" },
	{ TOPCMDS_END }
};

static struct topcmds ntp_topcmds[] = {
	{ "ntp", 0, CONFIG_TREE, do_ntp, no_ntp, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"ntp configuration", "NTP设置" },
	{ TOPCMDS_END }
};
#if 0
static struct topcmds dot1q_topcmds[] = {
	{ "dot1q-tunnel", 0, CONFIG_TREE, do_dot1q, no_dot1q, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Enable dot1q tunnel globally", "启用全局dot1q tunnel特性" },
	{ TOPCMDS_END }
};
#endif
/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       yunchang.xuan    add clock_set[]
                                            clock_curtime[]
                                            clock_day[]
                                            clock_month[]
                                            clock_year[]
                                            clock_timezone[]
                                            timezone_name[]
                                            name_offset[]
 */
static struct cmds ntp_server_cmds[] = {
	{ "server", CLI_CMD, 0, NTP_SERVER, do_ntp_server, NULL, NULL, CLI_END_NONE, 0, 0,
		"ntp server", "NTP服务器" },
	{ "query-interval", CLI_CMD, 0, 0, do_ntp_query, no_ntp_query, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"set interval to query NTP server", "设置NTP服务器的响应间隔" },
	{ CMDS_END }
};

static struct cmds ntp_ip_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ntp_server_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"server IP", "服务器IP" },
	{ CMDS_END }
};	

static struct cmds ntp_time_cmds[] = {
	{ "1 - 8640", CLI_INT, 0, 0, do_ntp_minutes, NULL, NULL, CLI_END_FLAG, 1, 8640,
		"Minutes (default 1)", "分钟  (默认是 1)" },
	{ CMDS_END }
};

static struct cmds clock_set[] = {
	{ "set", CLI_CMD, 0, 0, do_clock_set, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set time", "配置时间" },

	{ CMDS_END }
};

static struct cmds clock_curtime[] = {
	{ "hh:mm:ss", CLI_TIME, 0, 0, do_clock_set_curtime, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set time", "配置当前时间" },

	{ CMDS_END }
};

static struct cmds clock_day[] = {
	{ "day", CLI_INT, 0, 0, do_clock_set_day, NULL, NULL, CLI_END_NONE, 1, 31,
		"Set day(1-31)", "配置当前日" },

	{ CMDS_END }
};

static struct cmds clock_month[] = {
	{ "month", CLI_INT, 0, 0, do_clock_set_month, NULL, NULL, CLI_END_NONE, 1, 12,
		"Set month(1-12)", "配置当前月" },

	{ CMDS_END }
};

static struct cmds clock_year[] = {
	{ "year", CLI_INT, 0, 0, do_clock_set_year, NULL, NULL, CLI_END_FLAG, 1995, 2035,
		"Set year(1995-2035)", "配 置 当 前 年" },

	{ CMDS_END }
};

static struct cmds clock_timezone[] = {
	{ "timezone", CLI_CMD, 0, 0, do_clock_timezone, no_clock_timezone, NULL, CLI_END_NO, 0, 0,
		"Timezone", "配置时区" },

	{ CMDS_END }
};

static struct cmds timezone_name[] = {
	{ "WORD", CLI_WORD, 0, 0, do_timezone_name, NULL, NULL, CLI_END_NONE, 0, 0,
		"Name of time zone", "配置时区的名字" },

	{ CMDS_END }
};

static struct cmds name_offset[] = {
	{ "<-12 - +12>", CLI_INT, 0, 0, do_name_offset, NULL, NULL, CLI_END_FLAG, -12, 12,
		"Hours offset from UTC", "UTC的时区补偿" },

	{ CMDS_END }
};

/*
 *  Function:  do_clock
 *  Purpose:   clock topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_clock(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(clock_set, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_clock_set
 *  Purpose:   set subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_clock_set(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(clock_curtime, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_clock_set_curtime
 *  Purpose:   curtime subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_clock_set_curtime(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(clock_day, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_clock_set_day
 *  Purpose:   day subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_clock_set_day(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(clock_month, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_clock_set_month
 *  Purpose:   month subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_clock_set_month(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(clock_year, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_clock_set_year
 *  Purpose:   year subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_clock_set_year(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_clock(u);
	}
	return retval;
}

/*
 *  Function:  config_do_clock
 *  Purpose:   clock topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int config_do_clock(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(clock_timezone, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_clock_timezone
 *  Purpose:   timezone subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_clock_timezone(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(timezone_name, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_timezone_name
 *  Purpose:   timezone_name subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_timezone_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(name_offset, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_name_offset
 *  Purpose:   name_offset subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_name_offset(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_timezone(u);
	}
	return retval;
}

/*
 *  Function:  no_clock_timezone
 *  Purpose:   timezone subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int no_clock_timezone(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_timezone(u);
	}
	return retval;
}
/*
 *  Function:  do_ntp
 *  Purpose:   ntp_topcmds
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/9
 */
static int do_ntp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ntp_server_cmds, argc, argv, u);
	return retval;

}

/*
 *  Function:  do_ntp_server
 *  Purpose:   ntp subcmds
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/9
 */

static int do_ntp_server(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ntp_ip_cmds, argc, argv, u);
	return retval;

}
/*
 *  Function:  do_ntp_server_ip
 *  Purpose:   ntp subcmds
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/9
 */

static int do_ntp_server_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_ntp_server(u);
	}
	return retval;

}

/*
 *  Function:  do_ntp_query
 *  Purpose:   ntp subcmds
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/9
 */

static int do_ntp_query(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(ntp_time_cmds, argc, argv, u);
	return retval;

}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  no_ntp_query
 *  Description:  Subcmd of no ntp query_interval
 * 		 Author:  gujiajie
 *		   Date:
 * =====================================================================================
 */
static int no_ntp_query(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		nfunc_ntp_query(u);
	}
	return retval;
}

/*
 *  Function:  do_ntp_minutes
 *  Purpose:   ntp subcmds
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/9
 */

static int do_ntp_minutes(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_ntp_time(u);
	}
	return retval;

}

/*
 *  Function:  no_ntp
 *  Purpose:   ntp topcmds
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/9
 */

static int no_ntp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	SET_CMD_MSKBIT(u, NTP_SERVER);
		
	if ((retval = cmdend2(argc, argv, u)) == 0) {
		/* Do application function */
		nfunc_ntp(u);
	}
	retval = sub_cmdparse(ntp_server_cmds, argc, argv, u);

	return retval;

}
#if 0
Move to cli_others.c
/*----------------------------------------------------------------------------------------------------------------*/
static int do_dot1q(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_config_dot1q(u);
	}
	return retval;

}

static int no_dot1q(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_config_dot1q(u);
	}
	return retval;

}
/*-----------------------------------------------------------------------------------------------------------------*/
#endif

/*
 *  Function:  init_cli_clock
 *  Purpose:  Register clock function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
int init_cli_clock(void)
{
	int retval = -1;
	
	retval = registerncmd(clock_topcmds, (sizeof(clock_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(config_clock_topcmds, (sizeof(config_clock_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(ntp_topcmds, (sizeof(ntp_topcmds)/sizeof(struct topcmds) - 1));	

	DEBUG_MSG(1,"init_cli_clock retval = %d\n", retval);

	return retval;
}


