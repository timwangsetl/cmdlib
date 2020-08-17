/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name:   cli_line.c
 * Function:    line command function
 * Version:     1.0
 * Auther:      jiajie.gu
 * Date:        2012/01/17
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
2012/01/17   1.01       jiajie.gu      line
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

#include "cli_line.h"
#include "sk_define.h"
#include "cli_line_func.h"

#ifdef CLI_AAA_MODULE
static struct topcmds line_topcmds[] = {
	{ "line", 0, CONFIG_TREE, do_line, NULL, NULL, CLI_END_NONE, 0, 0,
		"Configure a terminal line", "配置终端模式"},
	{ TOPCMDS_END }
};


static struct cmds line[] = {
/* 	{ "console", CLI_CMD, 0, 0, do_console, NULL, NULL, CLI_END_NONE, 0, 0,
 * 		"Primary terminal line", ""},
 */
	{ "vty", CLI_CMD, 0, 0, do_vty, NULL, NULL, CLI_END_NONE, 0, 0,
		"Virtual terminal", ""},
	{ CMDS_END }
};

static struct cmds vty[] = {
	{ "<1-16>", CLI_INT, 0, 0, do_vty_first, no_do_vty_first, NULL, CLI_END_FLAG|CLI_END_NO, 1, 16, 
		"First line number", ""},
	{ CMDS_END }
};

static struct cmds vty_last[] = {
	{ "<1-16>", CLI_INT, 0, 0, do_vty_last, no_do_vty_last, NULL, CLI_END_FLAG|CLI_END_NO, 1, 16,
		"last line number", ""},
	{ CMDS_END }
};

static struct topcmds login_topcmds[] = {
	{ "login", 0, LINE_TREE, do_login, NULL, NULL, CLI_END_NONE, 0, 0,
		"Login AAA Settings", "登录AAA设置"},
	{ TOPCMDS_END }, 
};

static struct topcmds absolute_timeout_topcmds[] = {
	{ "absolute-timeout", 0, LINE_TREE, do_absolute_timeout, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set absolute timeout for line disconnection", "设置断开连接的绝对超时时间"},
	{ TOPCMDS_END }, 
};

static struct cmds absolute_timeout_val[] = {
	{ "<0-1440>", CLI_INT, 0, 0, do_set_absolute_timeout, NULL, NULL, CLI_END_FLAG, 0, 1440,
		"Absolute timeout interval in minutes", "绝对超时时间间隔(以分为单位)"},
	{ TOPCMDS_END }, 
};

static struct topcmds exec_timeout_topcmds[] = {
	{ "exec-timeout", 0, LINE_TREE, do_exec_timeout, no_exec_timeout, NULL, CLI_END_NONE, 0, 0,
		"Set the EXEC timeout", "设置超时时间秒数"},
	{ TOPCMDS_END }, 
};

static struct cmds exec_timeout_val[] = {
	{ "<60-3600>", CLI_INT, 0, 0, do_set_exec_timeout, NULL, NULL, CLI_END_FLAG, 60, 3600,
		"Timeout in minutes", "超时时间(以秒为单位)"},
	{ TOPCMDS_END },
};

static struct cmds login_cmds[] = {
	{ "accounting", CLI_CMD, 0, 0, do_login_method, no_login_method, NULL, CLI_END_NO,  0, 0,
		"Line accounting parameters", "登录记账参数" },
	{ "authentication", CLI_CMD, 0, 0, do_login_method, no_login_method, NULL, CLI_END_NO, 0, 0,
		"Line authentication parameters", "登录授权参数" },
	{ "authorization", CLI_CMD, 0, 0, do_login_method, no_login_method, NULL, CLI_END_NO, 0, 0,
		"Line authorization parameters", "登录认证参数" },
	{ CMDS_END },
};

static struct cmds login_method_name_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_login_method_name, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Named authentication list", "方式列表名" },
	{ "default", CLI_CMD, 0, 0, do_login_method_name, NULL, NULL, CLI_END_FLAG, 0, 0,
		"The default authentication list.", "缺省方式列表" },
	{ CMDS_END },
};


static int do_line(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(line, argc, argv, u);
	
	return retval;
}


static int do_console(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	
	param.type = CLI_INT;
	param.name = "<0-0>";
	param.ylabel = "First line number";
	param.hlabel = NULL;
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
	
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		if((retval = change_con_level(LINE_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "%s", u->s_param.v_string[0]);
		}
	}
	return retval;
}


static int do_vty(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(vty, argc, argv, u);
	
	return retval;
}


static int do_vty_first(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int line_id[2] = {0, 0};
	
	cli_param_get_int(STATIC_PARAM, 0, &line_id[0], u);

	if ((retval = cmdend2(argc, argv, u)) == 0){
		/* Change console level */
		memset(u->promptbuf, '\0', sizeof(u->promptbuf));
		if ((retval = change_con_level(LINE_TREE, u)) == 0){
			sprintf(u->promptbuf, "%d,%d", line_id[0], line_id[1]);
			/****check if need to creat vty***/
			func_create_vty_users(u, line_id[0], 0);
		}
	}

	retval += sub_cmdparse(vty_last, argc, argv, u);
	
	return retval;
}

static int no_do_vty_first(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int line_id[2] = {0, 0};
	
	cli_param_get_int(STATIC_PARAM, 0, &line_id[0], u);

	if ((retval = cmdend2(argc, argv, u)) == 0){
		memset(u->promptbuf, '\0', sizeof(u->promptbuf));
		sprintf(u->promptbuf, "%d,%d", line_id[0], line_id[1]);
		nfunc_line_vty( u );
	}

	retval += sub_cmdparse(vty_last, argc, argv, u);
	
	return retval;
}

static int no_do_vty_last(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int line_id[2] = {0, 0};
	
	cli_param_get_int(STATIC_PARAM, 0, &line_id[0], u);

	if ((retval = cmdend2(argc, argv, u)) == 0){
		memset(u->promptbuf, '\0', sizeof(u->promptbuf));
		sprintf(u->promptbuf, "%d,%d", line_id[0], line_id[1]);
		nfunc_line_vty( u );
	}
	
	return retval;
}


static int do_vty_last(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int line_id[2] = {0,0};

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		cli_param_get_int(STATIC_PARAM, 0, &line_id[0], u);
		cli_param_get_int(STATIC_PARAM, 1, &line_id[1], u);

		/* Change console level */
		retval = change_con_level(LINE_TREE, u);
		memset(u->promptbuf, '\0', sizeof(u->promptbuf));
		if ((retval = change_con_level(LINE_TREE, u)) == 0) 
		{
			sprintf(u->promptbuf, "%d,%d", line_id[0], line_id[1]);
			/***check if need to creat vty***/
			func_create_vty_users(u, line_id[0], line_id[1]);
		}

	}

	return retval;
}


static int do_login(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(login_cmds, argc, argv, u);
	
	return retval;
}


static int do_login_method(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if (!strpbrk(argv[argc - 1], "*?")) {
		cli_param_set_string(DYNAMIC_PARAM, 0, argv[0], u);
	}

	retval = sub_cmdparse(login_method_name_cmds, argc, argv, u);
	
	return retval;
}


static int do_login_method_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if (!retval) {
		func_login_method_name(u);
	} 

	return retval;
}


static int no_login_method(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if (!retval) {
		cli_param_set_string(DYNAMIC_PARAM, 0, argv[0], u);
		nfunc_login_method(u);
	} 

	return retval;
}


/*wei.zhang*/
static int do_absolute_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(absolute_timeout_val, argc, argv, u);

	return retval;
}

/*wei.zhang*/
static int do_set_absolute_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int absolute_time = 0;
	
	cli_param_get_int(STATIC_PARAM, 0, &absolute_time, u);
	func_set_absolute_timeout( u, 0, 0, absolute_time);
	
	return retval;
}

/*
 *  Function : do_exec_timeout
 *  Purpose:    
 *  Parameters:
 *     retval == -1 : failured, retval == 1 : succeed
 *  Author  : wei.zhang
 *  Date    :2012/5/3
 */
static int do_exec_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(exec_timeout_val, argc, argv, u);
	
	return retval;
}

/*
 *  Function : do_set_exec_timeout
 *  Purpose:
 *  Parameters: 
 *     retval == -1 : failured, retval == 1 : succeed
 *  Author  : wei.zhang
 *  Date    :2012/5/3
 */
static int do_set_exec_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int exec_time = 0;
	
	cli_param_get_int(STATIC_PARAM, 0, &exec_time, u);
	func_set_exec_timeout(u);
	
	return retval;
}
/*
 *  Function : no_exec_timeout
 *  Purpose:
 *  Parameters: 
 *     retval == -1 : failured, retval == 1 : succeed
 *  Author  : wei.zhang
 *  Date    :2012/5/3
 */
static int no_exec_timeout(int argc, char *argv[], struct users *u)
{
	
	int retval = -1;
	
	retval = nfunc_set_exec_timeout(u);
	
	return retval;
}

int init_cli_line(void)
{
	int retval = -1;

	retval = registerncmd(line_topcmds, (sizeof(line_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(login_topcmds, (sizeof(login_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(absolute_timeout_topcmds, (sizeof(absolute_timeout_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(exec_timeout_topcmds, (sizeof(exec_timeout_topcmds)/sizeof(struct topcmds) - 1));
	
	DEBUG_MSG(1,"init_cli_line retval = %d\n", retval);

	return retval;
}
#endif
