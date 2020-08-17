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
 2011/11/7  1.01        yunchang.xuan       dot1x  enable
                                                   re-authentication enable
                                                   timeout re-authperiod <60-40000000>                                           
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
#include "bcmutils.h"

#include "cli_dot1x.h"
#include "cli_dot1x_func.h"

#define DOT1X_NO 0x00000001
#define CHECK_TRUNK_GROUP if \
	(CLI_FAILED == cli_check_interface_trunk_group(u)) \
		vty_output("The same aggregator group should have the same port properties, make sure!\n");

/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       yunchang.xuan    dot1x_topcmds[]
                                        interface_dot1x_topcmds[]
 */
static struct topcmds dot1x_topcmds[] = {
	{ "dot1x", 0, CONFIG_TREE, do_dot1x, no_dot1x, NULL, CLI_END_NO, 0, 0,
		"IEEE 802.1x config", "IEEE 802.1x全局配置" },
	{ TOPCMDS_END }
};

/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       yunchang.xuan    add dot1x_cmds[]
                                            dot1x_re_authentication[]
                                            dot1x_timeout[]
                                            dot1x_timeout_reauthperiod[]
                                            interface_dot1x_cmds[]
                                            forbid_cmds[]
                                            authentication_cmds[]
                                            type_cmds[]
                                            port_control_cmds[]
 */
static struct cmds dot1x_cmds[] = {
	{ "enable", CLI_CMD, 0, DOT1X_NO, do_dot1x_enable, no_dot1x, NULL, 1, 0, 0,
		"Enable IEEE 802.1x Protocols ", "启动802.1x协议功能" },
	{ "re-authentication", CLI_CMD, 0, DOT1X_NO, do_dot1x_re_authentication, NULL, NULL, 0, 0, 0,
		"Periodic 802.1x authentication", "配置802.1x协议的周期认证" },
	{ "timeout", CLI_CMD, 0, 0, do_dot1x_timeout, NULL, NULL, 0, 0, 0,
		"Set 802.1x timeout values", "配置802.1x超时值" },	
	 { "guest-vlan", CLI_CMD, 0, 0, do_guest_vlan, no_guest_vlan, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Enable guest-vlan", "打开全局下的guest-vlan功能" }, 
	{ CMDS_END }
};

static int do_guest_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_do_guest_vlan_enable();

	}

	return retval;
}

static int no_guest_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_no_guest_vlan_enable();

	}
	
	return retval;
}

static struct cmds dot1x_re_authentication[] = {
	{ "enable", CLI_CMD, 0, 0, do_re_authentication, NULL, NULL, 1, 0, 0,
		"Enable periodic 802.1x authentication ", "启动802.1x协议的周期认证" },
	{ CMDS_END }
};

static struct cmds dot1x_timeout[] = {
	{ "re-authperiod", CLI_CMD, 0, 0, do_timeout, no_timeout, NULL, CLI_END_NO, 0, 0,
		"Set period between reauthentication retry ", "配置周期认证的时间" },
	{ CMDS_END }
};

static struct cmds dot1x_timeout_reauthperiod[] = {
	{ "<60-40000000>", CLI_INT, 0, 0, do_timeout_reauthperiod, NULL, NULL, 1, 60, 40000000,
		"Seconds ", "配置超时时间" },
	{ CMDS_END }
};



/*
 *  Function:  do_dot1x
 *  Purpose:   dot1x topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_dot1x(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(dot1x_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_dot1x_enable
 *  Purpose:   dot1x_enable parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_dot1x_enable(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = cmdend2(argc, argv, u);
    if(retval == 0) 
	{
		/* Do application function */
		func_set_dot1x_enable();

	}
	return retval;
}

/*
 *  Function:  do_dot1x_re_authentication
 *  Purpose:   dot1x_re_authentication parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_dot1x_re_authentication(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(dot1x_re_authentication, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_dot1x_re_authentication
 *  Purpose:   dot1x_re_authentication parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_re_authentication(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = cmdend2(argc, argv, u);
    if(retval == 0) 
	{
		/* Do application function */
		func_set_dot1x_reauth_enable();

	}
	return retval;
}

/*
 *  Function:  do_dot1x_timeout
 *  Purpose:   do_dot1x_timeout parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_dot1x_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(dot1x_timeout, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_timeout
 *  Purpose:   do_timeout parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(dot1x_timeout_reauthperiod, argc, argv, u);
    
	return retval;
}

/*
 *  Function:  do_timeout_reauthperiod
 *  Purpose:   do_timeout_reauthperiod parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_timeout_reauthperiod(int argc, char *argv[], struct users *u)
{
	int time,retval = -1;
	char str[20] = {0};
	retval = cmdend2(argc, argv, u);
    if(retval == 0) 
	{
		/* Do application function */
		cli_param_get_int(STATIC_PARAM, 0, &time, u);
		sprintf(str,"%d",time);
		func_set_dot1x_reauth_time(str);
	}
	return retval;
}


/*
 *  Function:  no_dot1x
 *  Purpose:   no_dot1x parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int no_dot1x(int argc, char *argv[], struct users *u)
{	        
	int retval = -1;
	SET_CMD_MSKBIT(u, DOT1X_NO);
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{ 
		nfunc_set_dot1x_disable();	 
		return retval;
	}
	
	retval = sub_cmdparse(dot1x_cmds, argc, argv, u);
	return retval;
}


/*
 *  Function:  no_timeout
 *  Purpose:   no_timeout parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int no_timeout(int argc, char *argv[], struct users *u)
{
	
	int retval = -1;
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_set_dot1x_timeout_default();

	}
	return retval;

}



/*
 *  Function:  init_cli_dot1x
 *  Purpose:  Register dot1x function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
int init_cli_dot1x(void)
{
	int retval = -1;

	retval = registerncmd(dot1x_topcmds, (sizeof(dot1x_topcmds)/sizeof(struct topcmds) - 1));
	
	DEBUG_MSG(1,"init_cli_dot1x retval = %d\n", retval);

	return retval;
}


