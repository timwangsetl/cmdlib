/**
 * console / enable
 *
 * Arthor: Yezhong Li
 * date: 2012.3.11
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
#include "cli_enable.h"
#include "cli_enable_func.h"

#ifdef CLI_AAA_MODULE
static struct topcmds enable_topcmds[] = {
	{ "enable", 0, CONFIG_TREE, do_enble, NULL, NULL, 0, 0, 0,
		"Modify enable password parameters", "修改enable密码参数" },
	{ TOPCMDS_END }
};

static struct cmds enable_cmds[] = {
	{ "password", CLI_CMD, 0, 0, do_enable_password, no_enable_password, NULL, CLI_END_NO , 0, 0,
		"Assign the privleged level password", "配置等级密码" },
	{ "secret", CLI_CMD, 0, 0, do_enable_secret, no_enable_secret, NULL, CLI_END_NO , 0, 0,
		"Assign the privleged level secret", "配置等级加密" },
	{ CMDS_END }
};

/* enable password ? */
static struct cmds password_cmds[] = {
	{ "0", CLI_CMD, 0, ZERO_SEVEN, do_password_0, NULL, NULL, 0, 0, 0,
		"Specifies an UNENCRYPTED password will follow", "输入没有加密的密码明文" },
	{ "7", CLI_CMD, 0, ZERO_SEVEN, do_password_7, NULL, NULL, 0, 0, 0,
		"Specifies a HIDDEN password will follow", "输入加密后的密码密文" },
	{ "LINE", CLI_LINE, 0, PASSWORD_LINE, do_password_line, NULL, NULL, 1, 0, 0,
		"The UNENCRYPIED <cleartext> enable password","输入没有加密的用户密码明文" },	
#if 0
	{ "level", CLI_CMD, 0, LEVEL_MASK, do_passwd_level, NULL, NULL, 0, 0, 0,
		"Set exec level password","输入没有加密的用户密码明文" },	
#endif
	{ CMDS_END }
};

static struct cmds passwd_level[] = {
	{ "<1-15>", CLI_INT, 0, 0, do_passwd_level_line, no_passwd_level_line, NULL, CLI_END_NO, 1, 15,
		"Level number", "等级号" },		
	{ CMDS_END },
};

static struct cmds secret_level[] = {
	{ "<1-15>", CLI_INT, 0, 0, do_secret_level_line, no_secret_level_line, NULL, CLI_END_NO, 1, 15,
		"Level number", "等级号" },		
	{ CMDS_END },
};

/* enable secret ? */
static struct cmds secret_cmds[] = {
	{ "0", CLI_CMD, 0, ZERO_SEVEN, do_secret_0, NULL, NULL, 0, 0, 0,
		"Specifies an UNENCRYPTED password will follow", "输入没有加密的密码明文" },
	{ "5", CLI_CMD, 0,ZERO_SEVEN, do_secret_5, NULL, NULL, 0, 0, 0,
		"Specifies a HIDDEN password will follow", "输入加密后的密码密文" },
	{ "LINE", CLI_LINE, 0, PASSWORD_LINE, do_secret_line, NULL, NULL, CLI_END_FLAG, 0, 0,
		"The UNENCRYPIED <cleartext> enable secret","输入没有加密的用户密码明文" },	
	{ "level", CLI_CMD, 0, LEVEL_MASK, do_secret_level, NULL, NULL, 0, 0, 0,
		"Set exec level password","输入执行等级" },	
	{ CMDS_END }
};

static int do_enble(int argc, char *argv[], struct users *u)
{
	int retval;

	retval = sub_cmdparse(enable_cmds, argc, argv, u);

	return retval;
}

static int do_enable_password(int argc, char *argv[], struct users *u)
{
	int retval;

	/* set enable secret flag, 1 is encrypted, 0 is unencrypted */
	cli_param_set_int(DYNAMIC_PARAM, 0, 0, u);

	retval = sub_cmdparse(password_cmds, argc, argv, u);

	return retval;
}

static int no_enable_password(int argc, char *argv[], struct users *u)
{
	int retval;
	retval = cmdend2(argc, argv, u);
	if (retval == 0) { 	
		return  nfunc_passwd_line(u);
	}
 	
	u->cmd_mskbits |= ZERO_SEVEN | PASSWORD_LINE;
	retval = sub_cmdparse(password_cmds, argc, argv, u);
	return retval;
}

static int do_password_0(int argc, char *argv[], struct users *u)
{
	int retval;
	u->cmd_mskbits |= LEVEL_MASK;
    retval = sub_cmdparse(password_cmds, argc, argv, u);
	return retval;
}

static int do_password_7(int argc, char *argv[], struct users *u)
{
	int retval;

	/* set enable secret flag, 1 is encrypted, 0 is unencrypted */
	struct cmds *p = password_cmds;
	p = p + 2;
	p->yhp = "The ENCRYPTED 'enable' password string";
	p->hhp =  "输入加密后的用户密码";

	u->cmd_mskbits |= LEVEL_MASK;
	cli_param_set_int(DYNAMIC_PARAM, 0, 1, u);
	retval = sub_cmdparse(password_cmds, argc, argv, u);
	
	return retval;
}

static int no_passwd_level_line(int argc, char *argv[], struct users *u)
{
	int retval;
	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		cli_param_set_int(DYNAMIC_PARAM, 0, atoi(argv[0]), u);
		return nfunc_passwd_line(u);
	}
	return retval;
}

static int do_password_line(int argc, char *argv[], struct users *u)
{
	int retval;
	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		return func_passwd_line(u);
	}
	return retval;
}

static int do_passwd_level(int argc, char *argv[], struct users *u)
{
	int retval;
	retval = sub_cmdparse(passwd_level, argc, argv, u);
	return retval;
}

static int do_passwd_level_line(int argc, char *argv[], struct users *u)
{
	int retval;

	cli_param_set_int(DYNAMIC_PARAM, 1, atoi(argv[0]), u);
	retval = sub_cmdparse(password_cmds, argc, argv, u);
	return retval;
}

static int no_password_level_line(int argc, char *argv[], struct users *u)
{
	int retval;
	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		return 0;
	}
	return retval;
}

static int do_secret_level(int argc, char *argv[], struct users *u)
{
	int retval;
	retval = sub_cmdparse(secret_level, argc, argv, u);
	return retval;
}

static int do_secret_level_line(int argc, char *argv[], struct users *u)
{
	int retval;

	cli_param_set_int(DYNAMIC_PARAM, 1, atoi(argv[0]), u);
	retval = sub_cmdparse(secret_cmds, argc, argv, u);
	return retval;
}


static int do_enable_secret(int argc, char *argv[], struct users *u)
{
	int retval;

	/* set enable secret flag, 1 is encrypted, 0 is unencrypted */
	cli_param_set_int(DYNAMIC_PARAM, 0, 0, u);

	retval = sub_cmdparse(secret_cmds, argc, argv, u);

	return retval;
}

static int no_enable_secret(int argc, char *argv[], struct users *u)
{
	int retval;
	retval = cmdend2(argc, argv, u);
	if (retval == 0) { 	
		return nfunc_secret_line(u);
	}
 	
	u->cmd_mskbits |= ZERO_SEVEN | PASSWORD_LINE;
	retval = sub_cmdparse(secret_cmds, argc, argv, u);
	return retval;
}

static int no_secret_level_line(int argc, char *argv[], struct users *u)
{
	int retval;
	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		cli_param_set_int(DYNAMIC_PARAM, 0, atoi(argv[0]), u);
		return nfunc_secret_line(u);
	}
	return retval;
}

static int do_secret_0(int argc, char *argv[], struct users *u)
{
	int retval;
	u->cmd_mskbits |= LEVEL_MASK;
	retval = sub_cmdparse(secret_cmds, argc, argv, u);
	return retval;
}

static int do_secret_5(int argc, char *argv[], struct users *u)
{
	int retval;

	/* set enable secret flag, 1 is encrypted, 0 is unencrypted */

	struct cmds *p = secret_cmds;
	p = p + 2;
	p->yhp =  "The ENCRYPTED 'enable' secret string";
	p->hhp = "输入加密后的字符串";

	u->cmd_mskbits |= LEVEL_MASK;
	cli_param_set_int(DYNAMIC_PARAM, 0, 1, u);
	retval = sub_cmdparse(secret_cmds, argc, argv, u);
	
	return retval;
}

static int do_secret_line(int argc, char *argv[], struct users *u)
{
	int retval;
	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		return func_secret_line(u);
	}
	return retval;
}

int init_cli_enable(void)
{
	int retval;

	retval = registerncmd(enable_topcmds, (sizeof(enable_topcmds)/sizeof(struct topcmds) - 1));
	
	DEBUG_MSG(1,"init_cli_enable_retval = %d\n", retval);

	return retval;
}
#endif
