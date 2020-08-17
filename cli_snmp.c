/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_snmp.c
 * Function   : show command function
 * Auther     : jialong.chu
 * Version    : 1.0
 * Date       : 2011/11/4
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
 2011/11/7  1.01        xi.chen        show aaa users
                                       show vlan dot1q-tunnel


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

#include "cli_snmp.h"
#include "cli_snmp_func.h"

/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       xi.chen          add show_topcmds[]


 */
static struct topcmds snmp_topcmds[] = {
	{ "snmp-server", 0, CONFIG_TREE, do_snmp, NULL, NULL, CLI_END_NONE, 0, 0,
		"Modify SNMP parameters", "设置SNMP 参数" },
	{ TOPCMDS_END }
};

/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       xi.chen          add show_cmds[]


 */
static struct cmds snmp_cmds[] = {
	{ "view", CLI_CMD, 0, 0, do_snmp_view, no_snmp_view, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Enable SNMP", "启用SNMP" },
	{ "community", CLI_CMD, 0, 0, do_snmp_community, no_snmp_community, NULL, CLI_END_NONE, 0, 0,
		"set community string and access privs", "设置community 字符串" },
	{ "contact", CLI_CMD, 0, 0, do_snmp_contact, no_snmp_contact, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Text for mib object sysContact", "设置mib 对象sysContact" },
	{ "host", CLI_CMD, 0, 0, do_snmp_host, no_snmp_host, NULL, CLI_END_NONE, 0, 0,
		"Specify hosts to receive SNMP TRAPs", "指定接收SNMP TRAPs 的目的主机" },
	{ "location", CLI_CMD, 0, 0, do_snmp_location, no_snmp_location, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Text for mib object sysLocation", "设置mib 对象location" },
	{ "user", CLI_CMD, 0, 0, do_snmp_user, no_snmp_user, NULL, CLI_END_NONE, 0, 0,
		"Define a user who can access the snmp engine", "定义能够访问本SNMP 引擎的用户" },
	{ CMDS_END }
};

static struct cmds snmp_commu_cmds[] = {
	{ "ro", CLI_CMD, 0, 0, do_snmp_commu_ro, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Read-only access with this community string", "使 用 该 团 体 可 访 问 只 读 MIB" },
	{ "rw", CLI_CMD, 0, 0, do_snmp_commu_rw, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Read-write access with this community string", "使 用 该 团 体 可 访 问 读 写 MIB" },
	{ CMDS_END }
};

static struct cmds snmp_user_cmds[] = {
	{ "auth", CLI_CMD, 0, 0, do_snmp_user_auth, NULL, NULL, CLI_END_NONE, 0, 0,
		"Authentication parameter for the user", "设定用户的认证参数" },
	{ CMDS_END }
};

static struct cmds snmp_user_auth_cmds[] = {
	{ "md5", CLI_CMD, 0, 0, do_snmp_user_auth_md5, NULL, NULL, CLI_END_NONE, 0, 0,
		"Use HMAC MD5 algorithm for authentication", "使用MD5 算法" },
	{ "sha", CLI_CMD, 0, 0, do_snmp_user_auth_sha, NULL, NULL, CLI_END_NONE, 0, 0,
		"Use HMAC SHA algorithm for authentication", "使用SHA 算法" },
	{ CMDS_END }
};

static struct cmds snmp_user_auth_algo_cmds[] = {
	{ "priv", CLI_CMD, 0, 0, do_snmp_user_auth_algo_priv, NULL, NULL, CLI_END_NONE, 0, 0,
		"Encryption parameters for the user", "设定用户的加密参数" },
	{ CMDS_END }
};

static struct cmds snmp_user_auth_algo_priv_cmds[] = {
	{ "3des", CLI_CMD, 0, 0, do_snmp_user_auth_algo_priv_3des, NULL, NULL, CLI_END_NONE, 0, 0,
		"Use 168 bit 3DES algorithm for encryption", "使用168位3DES算法加密" },
	{ "aes", CLI_CMD, 0, 0, do_snmp_user_auth_algo_priv_aes, NULL, NULL, CLI_END_NONE, 0, 0,
		"Use AES algorithm for encryption", "使用AES算法加密" },
	{ "des", CLI_CMD, 0, 0, do_snmp_user_auth_algo_priv_des, NULL, NULL, CLI_END_NONE, 0, 0,
		"Use 56 bit DES algorithm for encryption", "使 用 56 位 DES 算 法 加 密" },
	{ CMDS_END }
};

static struct cmds snmp_user_auth_algo_priv_encr_cmds[] = {
	{ "ro", CLI_CMD, 0, 0, do_snmp_user_auth_algo_priv_encr_ro, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Read-only access with this user", "只读用户" },
	{ "rw", CLI_CMD, 0, 0, do_snmp_user_auth_algo_priv_encr_rw, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Read-write access with this user", "读写用户" },
	{ CMDS_END }
};

/*
 *  Function:  do_snmp
 *  Purpose:  snmp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(snmp_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_snmp_community
 *  Purpose:  community subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_community(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "SNMP community string";
	param.hlabel = "SNMP 团体名字符串";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_snmp_commu_ro(u);
	}

	/* parse next sub command */
	retval = sub_cmdparse(snmp_commu_cmds, argc, argv, u);

	return retval;
}

static int no_snmp_community(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "SNMP community string";
	param.hlabel = "SNMP 团体名字符串";
	param.flag = CLI_END_NO;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
	
	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_snmp_commu(u);
	}
	
	return retval;
}


/*
 *  Function:  do_snmp_commu_ro
 *  Purpose:  community ro subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_commu_ro(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_snmp_commu_ro(u);

	}

	return retval;
}

/*
 *  Function:  do_snmp_commu_rw
 *  Purpose:  community rw subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_commu_rw(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_snmp_commu_rw(u);

	}

	return retval;
}

/*
 *  Function:  do_snmp_contact
 *  Purpose:  contact subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_contact(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Text for mib object sysContact";
	param.hlabel = "该管理节点联系人";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_snmp_contact(u);

	}

	return retval;
}

static int no_snmp_contact(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_snmp_contact(u);
	}
	
	return retval;
}


/*
 *  Function:  do_snmp_host
 *  Purpose:  host subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_host(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "IP address of SNMP TRAP host";
	param.hlabel = "接 受 SNMP TRAP 主 机 的 IP 地 址";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_snmp_host(u);

	}

	return retval;
}

static int no_snmp_host(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "IP address of SNMP TRAP host";
	param.hlabel = "接 受 SNMP TRAP 主 机 的 IP 地 址";
	param.flag = CLI_END_NO;
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
	
	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_snmp_host(u);
	}
	
	return retval;
}


/*
 *  Function:  do_snmp_location
 *  Purpose:  location subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_location(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_LINE;
	param.name = "LINE";
	param.ylabel = "Text for mib object sysLocation";
	param.hlabel = "该节点的实际位置";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		//do_test_param(argc,argv,u);
		func_snmp_location(u);

	}

	return retval;
}

static int no_snmp_location(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		//do_test_param(argc,argv,u);
		nfunc_snmp_location(u);

	}

	return retval;
}


/*
 *  Function:  do_snmp_user
 *  Purpose:  snmp user subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_user(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Name of the user. The length must be less than 32";
	param.hlabel = "用户名，长度不能大于32位";
	param.min = 1;
	param.max = 32;
	param.flag = CLI_END_NONE;

	/* Restore the md5 auth to SNMP_USER_AUTH u->d_param struct */
	//if((retval = cli_param_set_int(DYNAMIC_PARAM, SNMP_USER_AUTH, SNMP_USER_AUTH_MD5, u)) != 0)
		//return retval;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(STATIC_PARAM, &param, u)) != 0)
		return retval;

	/* parse next sub command */
	retval = sub_cmdparse(snmp_user_cmds, argc, argv, u);

	return retval;
}

static int no_snmp_user(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Name of the user. The length must be less than 32";
	param.hlabel = "用户名，长度不能大于32位";
	param.min = 1;
	param.max = 32;
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		//do_test_param(argc,argv,u);
		nfunc_snmp_users(u);

	}

	return retval;
}


/*
 *  Function:  do_snmp_user_auth
 *  Purpose:  snmp user auth subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_user_auth(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(snmp_user_auth_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_snmp_user_auth_md5
 *  Purpose:  snmp user auth md5 subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_user_auth_md5(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Authentication password of user. The range of length is 8-32";
	param.hlabel = "用户认证密码，长度范围为8-32";
	param.min = 8;
	param.max = 32;
	param.flag = CLI_END_FLAG;

	/* Restore the md5 auth to SNMP_USER_AUTH u->d_param struct */
	if((retval = cli_param_set_int(DYNAMIC_PARAM, SNMP_USER_AUTH, SNMP_USER_AUTH_MD5, u)) != 0)
		return retval;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_md5(u);
	}

	retval = sub_cmdparse(snmp_user_auth_algo_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_snmp_user_auth_sha
 *  Purpose:  snmp user auth sha subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_user_auth_sha(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Authentication password of user. The range of length is 8-32";
	param.hlabel = "用户认证密码，长度范围为8-32";
	param.min = 8;
	param.max = 32;
	param.flag = CLI_END_FLAG;

	/* Restore the sha auth to SNMP_USER_AUTH u->d_param struct */
	if((retval = cli_param_set_int(DYNAMIC_PARAM, SNMP_USER_AUTH, SNMP_USER_AUTH_SHA, u)) != 0)
		return retval;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_sha(u);
	}

	retval = sub_cmdparse(snmp_user_auth_algo_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_snmp_user_auth_algo_priv
 *  Purpose:  snmp user auth algorithm priv subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_user_auth_algo_priv(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(snmp_user_auth_algo_priv_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_snmp_user_auth_algo_priv_3des
 *  Purpose:  snmp user auth algorithm priv 3des subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_user_auth_algo_priv_3des(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Encryption password of user. The range of length is 8-32";
	param.hlabel = "用户加密方式，长度范围为8-32";
	param.min = 8;
	param.max = 32;
	param.flag = CLI_END_NONE;

	/* Restore the 3des Encryption to SNMP_USER_PRIV u->d_param struct */
	if((retval = cli_param_set_int(DYNAMIC_PARAM, SNMP_USER_PRIV, SNMP_USER_PRIV_3DES, u)) != 0)
		return retval;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */

		retval = sub_cmdparse(snmp_user_auth_algo_priv_encr_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_snmp_user_auth_algo_priv_aes
 *  Purpose:  snmp user auth algorithm priv aes subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_user_auth_algo_priv_aes(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Encryption password of user. The range of length is 8-32";
	param.hlabel = "用户加密方式，长度范围为8-32";
	param.min = 8;
	param.max = 32;
	param.flag = CLI_END_NONE;

	/* Restore the aes Encryption to SNMP_USER_PRIV u->d_param struct */
	if((retval = cli_param_set_int(DYNAMIC_PARAM, SNMP_USER_PRIV, SNMP_USER_PRIV_AES, u)) != 0)
		return retval;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */

		retval = sub_cmdparse(snmp_user_auth_algo_priv_encr_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_snmp_user_auth_algo_priv_des
 *  Purpose:  snmp user auth algorithm priv des subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_user_auth_algo_priv_des(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Encryption password of user. The range of length is 8-32";
	param.hlabel = "用户加密方式，长度范围为8-32";
	param.min = 8;
	param.max = 32;
	param.flag = CLI_END_NONE;

	/* Restore the des Encryption to SNMP_USER_PRIV u->d_param struct */
	if((retval = cli_param_set_int(DYNAMIC_PARAM, SNMP_USER_PRIV, SNMP_USER_PRIV_DES, u)) != 0)
		return retval;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */
	
		retval = sub_cmdparse(snmp_user_auth_algo_priv_encr_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_snmp_user_auth_algo_priv_encr_ro
 *  Purpose:  snmp user auth algorithm priv encr ro subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_user_auth_algo_priv_encr_ro(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ro(u);

	}

	return retval;
}

/*
 *  Function:  do_snmp_user_auth_algo_priv_encr_rw
 *  Purpose:  snmp user auth algorithm priv encr rw subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_snmp_user_auth_algo_priv_encr_rw(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rw(u);

	}

	return retval;
}

/*
 *  Function:  init_cli_snmp
 *  Purpose:  Register snmp function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
int init_cli_snmp(void)
{
	int retval = -1;

	/* Register snmp_topcmds[] */
	retval = registerncmd(snmp_topcmds, (sizeof(snmp_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1, "init_cli_qos snmp_topcmds retval = %d\n", retval);

	return retval;
}


/*
 *  Function:  do_router_rip
 *  Purpose:   router rip command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_snmp_view(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(func_snmp_enable(u) == 0)
		    return 0;
	}

	return retval;
}

/*
 *  Function:  no_router_rip
 *  Purpose:   router isis command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_snmp_view(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(nfunc_snmp_enable(u) == 0)
		    return 0;
	}

	return retval;
}
