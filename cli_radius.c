/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_radius_server.c
 * Function   : show command function
 * Auther     : jialong.chu
 * Version    : 1.0
 * Date       : 2011/11/4
 *
 *********************Revision History****************
 Date       Version     Modifier            Command
 2011/11/7  1.01        yunchang.xuan       radius-server  host
                                                                 A.B.C.D
                                                                 acct-port
                                                                            <0-65535>       
                                                                 auth-port 
                                                                            <0-65535>              
                                                           key
                                                                 WORD
                                                
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

#include "cli_radius.h"
#include "cli_radius_func.h"

/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       yunchang.xuan    radius_server_topcmds[]
 */
static struct topcmds radius_server_topcmds[] = {
	{ "radius-server", 0, CONFIG_TREE, do_radiusserver, NULL, NULL, 0, 0, 0,
		"RADIUS configuration", "配置RADIUS协议参数" },
	{ TOPCMDS_END }
};

/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       yunchang.xuan    add radius_server_cmds[]
                                            host_opt_cmds[]
 */
static struct cmds radius_server_cmds[] = {
	{ "host", CLI_CMD, 0, 0, do_radius_host, no_radius_host, NULL, 0, 0, 0,
		"Specify a RADIUS server ", "配置RADIUS服务器" },
	{ "key", CLI_CMD, 0, 0, do_radius_key, no_radius_key, NULL, CLI_END_NO, 0, 0,
		"Encryption key shared with the RADIUS servers", "配置RADIUS密钥" },
	{ CMDS_END }
};

static struct cmds host_opt_cmds[] = {
	{ "acct-port", CLI_CMD, 0, HOST_ACCTPORT, do_host_acctport, NULL, NULL, 0, 0, 0,
		"UDP port for RADIUS accounting server ", "配置RADIUS计费服务器的UDP端口号" },
	{ "auth-port", CLI_CMD, 0, HOST_AUTHPORT, do_host_authport, NULL, NULL, 0, 0, 0,
		"UDP port for RADIUS authentication server ", "配置RADIUS认证服务器的UDP端口号" },
	{ CMDS_END }
};

/*
 *  Function:  do_radiusserver
 *  Purpose:   radiusserver topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_radiusserver(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(radius_server_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_radius_host
 *  Purpose:   radius_host parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_radius_host(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	struct in_addr ip;
	char buf[50];

	memset(buf, 0, sizeof(buf));
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "Ip address of RADIUS system";
	param.min = 0;
	param.max = 0;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
    cli_param_set(STATIC_PARAM, &param, u);
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		cli_param_get_ipv4(STATIC_PARAM, 0, &ip, buf, sizeof(buf), u);
		func_set_radius_ip_port(buf, "1812", "1813");
	}

	retval = sub_cmdparse(host_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_host_acctport
 *  Purpose:   host_acctport parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_host_acctport(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
    struct in_addr ip;
	int authport,acctport;
	char auport[20],acport[20];
	char buf[50];

	memset(&param, 0, sizeof(struct parameter));
	memset(buf,0,sizeof(buf));
	memset(auport,0,sizeof(auport));
	memset(acport,0,sizeof(acport));
	

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<0-65535>";
	param.ylabel = "Port number for account";
	param.hlabel = "计费端口号";
	param.min = 0;
	param.max = 65535;
	if(ISSET_CMD_MSKBIT(u, HOST_AUTHPORT))
  	param.flag = 1;
  else
    param.flag = 0;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
    cli_param_set_int(DYNAMIC_PARAM, ACCTPORT_POS, param.value.v_int,u);
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		cli_param_get_ipv4(STATIC_PARAM, 0, &ip, buf, sizeof(buf), u);
		cli_param_get_int(DYNAMIC_PARAM, ACCTPORT_POS, &acctport, u);
		cli_param_get_int(DYNAMIC_PARAM, AUTHPORT_POS, &authport, u);
		sprintf(auport,"%d",authport);
		sprintf(acport,"%d",acctport);
	  	func_set_radius_ip_port(buf, auport,acport);
	}

	retval = sub_cmdparse(host_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_host_authport
 *  Purpose:   host_authport parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_host_authport(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	struct in_addr ip;
	int authport ,acctport;
	char auport[20],acport[20];
	char buf[50];
	
	memset(&param, 0, sizeof(struct parameter));
	memset(buf,0,sizeof(buf));
	memset(auport,0,sizeof(auport));
	memset(acport,0,sizeof(acport));
	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<0-65535>";
	param.ylabel = "Port number for authentication";
	param.hlabel = "认证端口号";
	param.min = 0;
	param.max = 65535;
	if(ISSET_CMD_MSKBIT(u, HOST_ACCTPORT))
  	param.flag = 1;
    else
    param.flag = 0;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
    cli_param_set_int(DYNAMIC_PARAM, AUTHPORT_POS, param.value.v_int,u);
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		cli_param_get_ipv4(STATIC_PARAM, 0, &ip, buf, sizeof(buf), u);
		cli_param_get_int(DYNAMIC_PARAM, ACCTPORT_POS, &acctport, u);
		cli_param_get_int(DYNAMIC_PARAM, AUTHPORT_POS, &authport, u);
		sprintf(auport,"%d",authport);
		sprintf(acport,"%d",acctport);
	    func_set_radius_ip_port(buf, auport,acport);
	}

	retval = sub_cmdparse(host_opt_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_radius_key
 *  Purpose:   radius_key parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_radius_key(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char key[20];
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	memset(key, 0, 20);

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Key string";
	param.hlabel = "认证密钥";
	param.min = 0;
	param.max = 0;
	param.flag = 1;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
    cli_param_set(STATIC_PARAM, &param, u);
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		cli_param_get_string(STATIC_PARAM, 0, key, u);
		func_set_radius_key(key);
	}

	return retval;
}

/*
 *  Function:  no_radius_host
 *  Purpose:   no radius_host parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int no_radius_host(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;

	/* Init paramter struct */
	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "Ip address of RADIUS system";
	param.min = 0;
	param.max = 0;
	param.flag = CLI_END_NO;
	
  /* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
    cli_param_set(STATIC_PARAM, &param, u);
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_radius_host();
	}
	return retval;
}

/*
 *  Function:  no_radius_key
 *  Purpose:   noradius_key parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int no_radius_key(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_radius_key();
	}
	return retval;
}

/*
 *  Function:  init_cli_radius_server
 *  Purpose:  Register radius_server function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
int init_cli_radius(void)
{
	int retval = -1;

	retval = registerncmd(radius_server_topcmds, (sizeof(radius_server_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1,"init_cli_radius retval = %d\n", retval);

	return retval;
}
