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

#include "cli_login.h"
#include "cli_login_func.h"

/*
 *  top command struct
 *
 *	Author:  dawei.hu
 *  Date:     2011/12/6
 */

static struct topcmds login_topcmds[] = {
	{ "ssh", 0, ENA_TREE, do_ssh, NULL, NULL, CLI_END_NONE, 0, 0,
		"Open a ssh connection", "打开一个ssh连接" },
	{ "telnet", 0, ENA_TREE|CONFIG_TREE|VIEW_TREE, do_telnet, NULL, NULL, CLI_END_NONE, 0, 0,
		"Open a telnet connection", "打开一个telnet连接" },
	{ TOPCMDS_END }
};

static struct topcmds ssh_topcmds[] = {
	{ "ssh", 0, CONFIG_TREE, do_ssh_server, no_ssh_server, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"SSH Server", "配置 SSH 服务" },
	{ TOPCMDS_END }
};

static struct cmds ssh_server[] = {
	{ "enable", CLI_CMD, 0, 0, do_ssh_enable, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Enable SSH", "允许SSH" },
	{ CMDS_END }
};


/*
 *  sub command struct
 *
 *	Author:  jiajie.gu
 *  Date:     2011/11/9
 */

static struct cmds ssh[] = {
	{ "-l", CLI_CMD, 0, SSH_L, do_ssh_l, NULL, NULL, CLI_END_NONE, 0, 0,
		"Userid", "用户名称" },
	{ "-d", CLI_CMD, 0, SSH_D, do_ssh_d, NULL, NULL, CLI_END_NONE, 0, 0,
		"IP address of the server", "服务器的IP地址" },
	{ CMDS_END }
};

static struct cmds ssh_p[] = {
	{ "-p", CLI_CMD, 0, SSH_P, do_ssh_p, NULL, NULL, CLI_END_NONE, 0, 0,
		"Port num", "" },
	{ "-c", CLI_CMD, 0, SSH_C, do_ssh_c, NULL, NULL, CLI_END_NONE, 0, 0,
		"Cipher", "" },
	{ CMDS_END }
};

static struct cmds ssh_pi[] = {
	{ "<0-65535>", CLI_INT, 0, 0, do_ssh_pi, NULL, NULL, CLI_END_FLAG, 0, 65535,
		"SSH Listen Port", "" },
	{ CMDS_END }
};

static struct cmds ssh_c[] = {
	{ "3des", CLI_CMD, 0, CIPHER_DES, do_ssh_cdes, NULL, NULL, CLI_END_FLAG, 0, 0,
		"3des", "" },
	{ "blowfish", CLI_CMD, 0, CIPHER_BLOW, do_ssh_cblow, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Blowfish", "" },
	{ CMDS_END }
};

static struct cmds telnet[] = {
	{ "X.X.X.X", CLI_IPV4, 0, 0, do_telnet_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Ip address of a remote system", "远端系统的IP地址" },
	{ "X:X::X", CLI_IPV6, 0, 0, do_telnet_ipv6, NULL, NULL, CLI_END_FLAG, 0, 0,
			"Ip address of a remote system", "远端系统的IPv6地址" },
	{ "WORD", CLI_WORD, 0, 0, do_telnet_host, NULL, NULL, CLI_END_FLAG, 0, 0,
		"host name of a remote system", "远端系统的主机名字" },
	{ CMDS_END }
};

/*
 *  Function: do_ssh
 *  Purpose:  topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_ssh(int argc, char *argv[], struct users *u) 
{
	int retval = -1;

	retval = sub_cmdparse(ssh, argc, argv, u);
	
	return retval;
}


/*
 *  Function: do_telnet
 *  Purpose:  topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_telnet(int argc, char *argv[], struct users *u) 
{
	int retval = -1;

	retval = sub_cmdparse(telnet, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_ssh_l
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_ssh_l(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "<WORD>";
	param.ylabel = "user name";
	param.hlabel = "用户帐号";
	if(ISSET_CMD_MSKBIT(u, SSH_D))
		param.flag = CLI_END_FLAG;
	
	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		func_ssh(u);
	}	

	if(ISSET_CMD_MSKBIT(u, SSH_D))
		retval = sub_cmdparse(ssh_p, argc, argv, u);
	else	
		retval = sub_cmdparse(ssh, argc, argv, u);

	return retval;
}

/*
 *  Function: do_ssh_d
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_ssh_d(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_IPV4;
	param.name = "<A.B.C.D>";
	param.ylabel = "IP address of SSH server";
	param.hlabel = "SSH 服务器的IP地址";
	if(ISSET_CMD_MSKBIT(u, SSH_L))
		param.flag = CLI_END_FLAG;
	

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		func_ssh(u);
	}	

	if(ISSET_CMD_MSKBIT(u, SSH_L))
		retval = sub_cmdparse(ssh_p, argc, argv, u);
	else 
		retval = sub_cmdparse(ssh, argc, argv, u);

	return retval;
}

/*
 *  Function: do_ssh_p
 *  Purpose:  topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_ssh_p(int argc, char *argv[], struct users *u) 
{
	int retval = -1;

	retval = sub_cmdparse(ssh_pi, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_ssh_c
 *  Purpose:  topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_ssh_c(int argc, char *argv[], struct users *u) 
{
	int retval = -1;

	retval = sub_cmdparse(ssh_c, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_ssh_cdes
 *  Purpose:  topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_ssh_cdes(int argc, char *argv[], struct users *u) 
{
	int retval = -1;
	
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		func_ssh(u);
	}	
	retval = sub_cmdparse(ssh_p, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_ssh_cblow
 *  Purpose:  topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_ssh_cblow(int argc, char *argv[], struct users *u) 
{
	int retval = -1;
	
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		func_ssh(u);
	}	
	retval = sub_cmdparse(ssh_p, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_ssh_pi
 *  Purpose:  topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_ssh_pi(int argc, char *argv[], struct users *u) 
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		func_ssh(u);
	}
	retval = sub_cmdparse(ssh_p, argc, argv, u);

	return retval;
}

/*
*  Function:  do_ssh_server
*  Purpose:  
*  Parameters:
*	  void
*  Returns:
*	  retval  -  
*  Author:	dawei.hu
*  Date:	 2011/12/5
*/

static int do_ssh_server(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ssh_server, argc, argv, u);
	
	return retval;
}

 
 /*
 *	Function:  no_ssh_server
 *	Purpose:  
 *	Parameters:
 *	   void
 *	Returns:
 *	   retval  -  
 *	Author:  dawei.hu
 *	Date:	  2011/12/5
 */
 static int no_ssh_server(int argc, char *argv[], struct users *u)
 {
	 int retval = -1;
		  
	 retval = cmdend2(argc, argv, u);
	 if(retval == 0) 
	 {
		  /* Do application function */
		 nfunc_ssh_enable(u);
	 }
	 return retval;
 
 }

/*
*  Function:  do_ssh_enable
*  Purpose:  
*  Parameters:
*	  void
*  Returns:
*	  retval  -  
*  Author:	dawei.hu
*  Date:	 2011/12/5
*/

static int do_ssh_enable(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		 
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		 /* Do application function */
		func_ssh_enable(u);
	}
	return retval;
}

 /*
 *  Function:  do_telnet_ip
 *  Purpose:  
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  
 *  Author:  dawei.hu
 *  Date:     2011/11/19
 */
static int do_telnet_ip(int argc, char *argv[], struct users *u)
{
	 int retval = -1;
	 
	 retval = cmdend2(argc, argv, u);
	 if(retval == 0) 
	 {
		 func_telnet_ip(u);
	 }
	 return retval;

}
 static int do_telnet_ipv6(int argc, char *argv[], struct users *u)
 {
	  int retval = -1;
	  
	  retval = cmdend2(argc, argv, u);
	  if(retval == 0) 
	  {
		  func_telnet_ipv6(u);
	  }
	  return retval;
 
 }

/*
 *  Function:  do_telnet_host
 *  Purpose:  
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  
 *  Author:  dawei.hu
 *  Date:     2011/11/19
 */
static int do_telnet_host(int argc, char *argv[], struct users *u)
{
	  int retval = -1;
	  
		  retval = cmdend2(argc, argv, u);
		  if(retval == 0) 
		  {
			  /* Do application function */
			  func_telnet_host(u);
		  }
		  return retval;
 
}


 /*
 *  Function:  init_cli_login
 *  Purpose:  Register login_topcmds[]
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:  jiajie.gu
 *  Date:     2011/11/9
 */
int init_cli_login(void)
{
	int retval = -1;

	retval = registerncmd(login_topcmds, (sizeof(login_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(ssh_topcmds, (sizeof(ssh_topcmds)/sizeof(struct topcmds) - 1));
	
	DEBUG_MSG(1,"init_cli_login retval = %d\n", retval);

	return retval;
}

