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

#ifdef CLI_AAA_MODULE
#include "cli_aaa.h"
#include "cli_aaa_func.h"

static char buf[256];
//------------------------------------------------------------------------------
static struct topcmds aaa_topcmds[] = {
	{ "aaa", 0, CONFIG_TREE, do_aaa, NULL, NULL, 0, 0, 0,
		"AAA configuration", "������֤����Ȩ���¼" },
	{ TOPCMDS_END },
};

static struct cmds cmds[] = {
	{ "accounting", CLI_CMD, 0, 0, do_accounting, NULL, NULL, 0, 0, 0,
		"Accounting configurations parameters", "���ü�¼����" },
	{ "authentication", CLI_CMD, 0, 0, do_authentication, NULL, NULL, 0, 0, 0,
		"Authentication configurations parameters", "������֤����" },
	{ "authorization", CLI_CMD, 0, 0, do_authorization, NULL, NULL, 0, 0, 0,
		"Authorization configurations parameters", "������֤����" },
#if 0
	{ "group", CLI_CMD,0,0,do_group, NULL, NULL, 0, 0, 0,
		"Enter AAA group definitions", "���� AAA ��"},	
#endif
	{ CMDS_END },
};

//------------------------------------------------------------------------------
// authentication
static struct cmds authentication_cmds[] = {
	{ "banner", CLI_CMD, 0, 0, do_authentication_banner, no_authentication_banner, NULL, CLI_END_NO, 0, 0,
		"Message to use when starting login/authentication", "���õ�¼ʱ����ʾ��Ϣ" },
	{ "dot1x", CLI_CMD, 0, 0, do_authentication_dot1x, NULL, NULL, 0, 0, 0,
		"Set authentication lists for IEEE 802.1x.", "���� dot1x ģ����֤��ʽ�б�" },
	{ "enable", CLI_CMD, 0, 0, do_authentication_enable, NULL, NULL, 0, 0, 0,
		"Set authentication list for enable.", "���� enable ��֤��ʽ�б�" },
	{ "fail-message", CLI_CMD, 0, 0, do_authentication_fail_message, no_authentication_fail_message, NULL, CLI_END_NO, 0, 0,
		"Message to use for failed login/authentication.", "���õ�¼ʧ��ʱ����ʾ��Ϣ" },
	{ "login", CLI_CMD, 0, 0, do_authentication_login, NULL, NULL, 0, 0, 0,
		"Set authentication lists for logins.", "����login��֤��ʽ�б�" },
	{ "password-prompt", CLI_CMD, 0, 0, do_authentication_password_prompt, no_authentication_password_prompt, NULL, CLI_END_NO, 0, 0,
		"Text to use when prompting for a password", "����������ʾ��Ϣ" },
	{ "username-prompt", CLI_CMD, 0, 0, do_authentication_username_prompt, no_authentication_username_prompt, NULL, CLI_END_NO, 0, 0,
		"Text to use when prompting for a username", "�����û�����ʾ��Ϣ" },
	{ CMDS_END },
};

// dot1x
static struct cmds authentication_dot1x_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_authentication_dot1x_name, no_authentication_dot1x_name, NULL, CLI_END_NO, 0, 0,
		"Named authentication list", "��ʽ�б���" },
	{ "default", CLI_CMD, 0, 0, do_authentication_dot1x_name, no_authentication_dot1x_name, NULL, CLI_END_NO, 0, 0,
		"The default authentication list.", "ȱʡ��ʽ�б�" },
	{ CMDS_END },
};

static struct cmds authentication_dot1x_list_cmds[] = {
	{ "group", CLI_CMD, 0, AAA_OPT_GROUP, do_authentication_dot1x_list_group, NULL, NULL, 0, 0, 0,
		"Use server-group", "ʹ�÷������������֤" },
	{ "local", CLI_CMD, 0, AAA_OPT_LOCAL, do_authentication_dot1x_list_other, NULL, NULL, 1, 0, 0,
		"Use local username authentication", "ʹ�ñ����û���Ϣ������֤" },
#if 0
	{ "local-case", CLI_CMD, 0, AAA_OPT_LOCAL_CASE, do_authentication_dot1x_list_other, NULL, NULL, 1, 0, 0,
		"Use local username authentication(case sensitive)", "ʹ�ñ����û���Ϣ������֤(�û������ִ�Сд)" },
#endif
	{ "none", CLI_CMD, 0, AAA_OPT_NONE, do_authentication_dot1x_list_other, NULL, NULL, 1, 0, 0,
		"No AAA", "����ҪAAA����" },
	{ CMDS_END },
};

static struct cmds authentication_dot1x_list_group_cmds[] = {
#if 0
	{ "WORD", CLI_WORD, 0, 0, do_authentication_dot1x_list_group_done, NULL, NULL, 1, 0, 0,
		"Server-group name", "ʹ�÷������������֤" },    
#endif
	{ "radius", CLI_CMD, 0, 0, do_authentication_dot1x_list_group_done, NULL, NULL, 1, 0, 0,
		"Use list of all Radius hosts", "ʹ������ radius ��������֤" },
#if 0
	{ "tacacs+", CLI_CMD, 0, 0, do_authentication_dot1x_list_group_done,  NULL, NULL, 1, 0, 0,
		"Use list of all Tacacs+ hosts", "ʹ������ tacacs+ ��������֤" },		
#endif
	{ CMDS_END },
};

// enable
static struct cmds authentication_enable_cmds[] = {
	{ "default", CLI_CMD, 0, 0, do_authentication_enable_name, no_authentication_enable_name, NULL, CLI_END_NO, 0, 0,
		"The default authentication list.", "ȱʡ��ʽ�б�" },
	{ CMDS_END },
};

static struct cmds authentication_enable_list_cmds[] = {
	{ "enable", CLI_CMD, 0, AAA_OPT_LOCAL, do_authentication_enable_list_other, NULL, NULL, 1, 0, 0,
		"Use enable password for authentication", "ʹ�� enable ���������֤" },    
	{ "group", CLI_CMD, 0, AAA_OPT_GROUP, do_authentication_enable_list_group, NULL, NULL, 0, 0, 0,
		"Use server-group", "ʹ�÷������������֤" },
#if 0
	{ "line", CLI_CMD, 0, AAA_OPT_LINE, do_authentication_enable_list_other, NULL, NULL, 1, 0, 0,
		"Use line password for authentication", "ʹ�� line ���������֤" },
#endif
	{ "none", CLI_CMD, 0, AAA_OPT_NONE, do_authentication_enable_list_other, NULL, NULL, 1, 0, 0,
		"No AAA", "����ҪAAA����" },
	{ CMDS_END },
};


static struct cmds authentication_enable_list_group_cmds[] = {
#if 0
	{ "WORD", CLI_WORD, 0, 0, do_authentication_enable_list_group_done, NULL, NULL, 1, 0, 0,
		"Server-group name", "ʹ�÷������������֤" },    
#endif
	{ "radius", CLI_CMD, 0, 0, do_authentication_enable_list_group_done, NULL, NULL, 1, 0, 0,
		"Use list of all Radius hosts", "ʹ������ radius ��������֤" },
#if 0
	{ "tacacs+", CLI_CMD, 0, 0, do_authentication_enable_list_group_done,  NULL, NULL, 1, 0, 0,
		"Use list of all Tacacs+ hosts", "ʹ������ tacacs+ ��������֤" },		
#endif
	{ CMDS_END },
};

// login
static struct cmds authentication_login_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_authentication_login_name, no_authentication_login_name, NULL, CLI_END_NO, 0, 0,
		"Named authentication list", "��ʽ�б���" },
	{ "default", CLI_CMD, 0, 0, do_authentication_login_name, no_authentication_login_name, NULL, CLI_END_NO, 0, 0,
		"The default authentication list.", "ȱʡ��ʽ�б�" },
	{ CMDS_END },
};

static struct cmds authentication_login_list_cmds[] = {
#if 0
	{ "enable", CLI_CMD, 0, AAA_OPT_ENABLE, do_authentication_login_list_other, NULL, NULL, 1, 0, 0,
		"Use enable password for authentication", "ʹ�� enable ���������֤" },    
#endif
	{ "group", CLI_CMD, 0, AAA_OPT_GROUP, do_authentication_login_list_group, NULL, NULL, 0, 0, 0,
		"Use server-group", "ʹ�÷������������֤" },
#if 0
	{ "line", CLI_CMD, 0, AAA_OPT_LINE, do_authentication_login_list_other, NULL, NULL, 1, 0, 0,
		"Use line password for authentication", "ʹ�� line ���������֤" },		
#endif
	{ "local", CLI_CMD, 0, AAA_OPT_LOCAL, do_authentication_login_list_other, NULL, NULL, 1, 0, 0,
		"Use local username authentication", "ʹ�ñ����û���Ϣ������֤" },
#if 0
	{ "local-case", CLI_CMD, 0, AAA_OPT_LOCAL_CASE, do_authentication_login_list_other, NULL, NULL, 1, 0, 0,
		"Use local username authentication(case sensitive)", "ʹ�ñ����û���Ϣ������֤(�û������ִ�Сд)" },
#endif
	{ "none", CLI_CMD, 0, AAA_OPT_NONE, do_authentication_login_list_other, NULL, NULL, 1, 0, 0,
		"No AAA", "����ҪAAA����" },
	{ CMDS_END },
};

static struct cmds authentication_login_list_group_cmds[] = {
#if 0
	{ "WORD", CLI_WORD, 0, 0, do_authentication_login_list_group_done, NULL, NULL, 1, 0, 0,
		"Server-group name", "ʹ�÷������������֤" },    
#endif
	{ "radius", CLI_CMD, 0, 0, do_authentication_login_list_group_done, NULL, NULL, 1, 0, 0,
		"Use list of all Radius hosts", "ʹ������ radius ��������֤" },
#if 0
	{ "tacacs+", CLI_CMD, 0, 0, do_authentication_login_list_group_done,  NULL, NULL, 1, 0, 0,
		"Use list of all Tacacs+ hosts", "ʹ������ tacacs+ ��������֤" },		
#endif
	{ CMDS_END },
};

//------------------------------------------------------------------------------
// accounting
static struct cmds accounting_cmds[] = {
/* 	{ "connection", CLI_CMD, 0, 0, do_accounting_conn_exec, NULL, NULL, 0, 0, 0,
 * 		"For outbound connections", "����������ӽ��м�¼" },
 */
	{ "exec", CLI_CMD, 0, 0,  do_accounting_conn_exec, NULL, NULL, 0, 0, 0,
		"For starting an exec (shell)", "�� exec ������м�¼" },
	{ CMDS_END },
};

static struct cmds accounting_conn_exec_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_accounting_conn_exec_list, no_accounting_conn_exec_list, NULL, CLI_END_NO, 0, 0,
		"Named accounting list", "��ʽ�б���" },
	{ "default", CLI_CMD, 0, 0, do_accounting_conn_exec_list, no_accounting_conn_exec_list, NULL, CLI_END_NO, 0, 0,
		"The default accounting list.", "ȱʡ��ʽ�б�" },
	{ CMDS_END },
};

static struct cmds accounting_conn_exec_action_cmds[] = {
	{ "none", CLI_CMD, 0, 0, do_accounting_conn_exec_list_none, NULL, NULL, 1, 0, 0,
		"No AAA", "��Ҫ AAA ����" },
	{ "start-stop", CLI_CMD, 0, 0, do_accounting_conn_exec_list_action, NULL, NULL, 0, 0, 0,
		"Record start and stop without waiting", "�Է���Ŀ�ʼ�ͽ������м�¼" },
	{ "stop-only", CLI_CMD, 0, 0, do_accounting_conn_exec_list_action, NULL, NULL, 0, 0, 0,
		"Only record stop when service terminate", "ֻ�Է���Ľ������м�¼" },		
	{ CMDS_END },
};

static struct cmds accounting_conn_exec_group_cmds[] = {
	{ "group", CLI_CMD, 0, 0, do_accounting_conn_exec_list_group, NULL, NULL, 0, 0, 0,
		"Use server-group", "ʹ�÷������������֤" },
	{ CMDS_END },
};

static struct cmds accounting_conn_exec_group_list_cmds[] = {
/* 	{ "WORD", CLI_WORD, 0, 0, do_accounting_conn_exec_list_group_done, NULL, NULL, 1, 0, 0,
 * 		"Server-group name", "ʹ�÷������������֤" },    
 */

	{ "radius", CLI_CMD, 0, 0, do_accounting_conn_exec_list_group_done, NULL, NULL, 1, 0, 0,
		"Use list of all Radius hosts", "ʹ������ radius ��������֤" },
/* 	{ "tacacs+", CLI_CMD, 0, 0, do_accounting_conn_exec_list_group_done, NULL, NULL, 1, 0, 0,
 * 		"Use list of all Tacacs+ hosts", "ʹ������ tacacs+ ��������֤" },		
 */

	{ CMDS_END },
};


//------------------------------------------------------------------------------
// authorization
static struct cmds authorization_cmds[] = {
/* 	{ "commands", CLI_CMD, 0, 0, do_authorization_commands, NULL, NULL, 0, 0, 0,
 * 		"For exec (shell) commands", "��Ȩ EXEC �������" },
 * 	{ "config-commands", CLI_CMD, 0, 0, do_authorization_config, no_authorization_config, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
 * 		"For configuration mode commands", "����ģʽ�������" },
 */
	{ "exec", CLI_CMD, 0, 0, do_authorization_exec_net, NULL, NULL, 0, 0, 0,
		"For starting an exec (shell)", "��Ȩ EXEC ����" },
/* 	{ "network", CLI_CMD, 0, 0, do_authorization_exec_net, NULL, NULL, 0, 0, 0,
 * 		"For network services (ppp,slip)", "��Ȩ NETWORK ����(ppp,slip)" },		
 */
	{ CMDS_END },
};

static struct cmds authorization_level[] = {
	{ "<0-15>", CLI_INT, 0, 0, do_authorization_commands_level, no_authorization_commands_level, NULL, CLI_END_DEF | CLI_END_NO, 0, 15,
		"Enable level", "��Ȩ����" },		
	{ CMDS_END },
};


static struct cmds authorization_level_list[] = {
	{ "WORD", CLI_WORD, 0, 0, do_authorization_commands_level_list, no_authorization_commands_level_list, NULL, CLI_END_NO, 0, 0,
		"Named authentication list", "��ʽ�б���" },
	{ "default", CLI_CMD, 0, 0, do_authorization_commands_level_list, no_authorization_commands_level_list, NULL, CLI_END_NO, 0, 0,
		"The default authentication list.", "ȱʡ��ʽ�б�" },
	{ CMDS_END },
};

static struct cmds authorization_level_list_group[] = {
	{ "group", CLI_CMD, 0, AAA_OPT_GROUP, do_authorization_commands_level_list_group, NULL, NULL, 0, 0, 0,
		"Use Server-group", "ʹ�÷������������֤" },
#if 0
	{ "if-authenticated", CLI_CMD, 0, AAA_OPT_IF_AUTHENTICATED, do_authorization_commands_level_list_other, NULL, NULL, 1, 0, 0,
		"Succeed if user has authenticated", "�����ͨ����֤������Ȩͨ��" },
#endif
	{ "none", CLI_CMD, 0, AAA_OPT_NONE, do_authorization_commands_level_list_other, NULL, NULL, 1, 0, 0,
		"No AAA", "����Ҫ AAA ����" },		
	{ CMDS_END },
};

static struct cmds authorization_level_list_group_name[] = {
/* 	{ "WORD", CLI_WORD, 0, 0, do_authorization_commands_level_list_group_done, NULL, NULL, 1, 0, 0,
 * 		"Server-group name", "ʹ�÷������������֤" },    
 */
	{ "radius", CLI_CMD, 0, 0, do_authorization_commands_level_list_group_done, NULL, NULL, 1, 0, 0,
		"Use list of all Radius hosts", "ʹ������ radius ��������֤" },
/* 	{ "tacacs+", CLI_CMD, 0, 0, do_authorization_commands_level_list_group_done, NULL, NULL, 1, 0, 0,
 * 		"Use list of all Tacacs+ hosts", "ʹ������ tacacs+ ��������֤" },		
 */
	{ CMDS_END },
};


static struct cmds authorization_exe_net_list[] = {
	{ "WORD", CLI_WORD, 0, 0, do_authorization_exe_net_list, no_authorization_exe_net_list, NULL, CLI_END_NO, 0, 0,
		"Named authentication list", "��ʽ�б���" },
	{ "default", CLI_CMD, 0, 0, do_authorization_exe_net_list, no_authorization_exe_net_list, NULL, CLI_END_NO, 0, 0,
		"The default authentication list.", "ȱʡ��ʽ�б�" },
	{ CMDS_END },
};

static struct cmds authorization_exec_net_list_group[] = {
	{ "group", CLI_CMD, 0, AAA_OPT_GROUP, do_authorization_exe_net_list_group, NULL, NULL, 0, 0, 0,
		"Use Server-group", "ʹ�÷������������֤" },
/* 	{ "if-authenticated", CLI_CMD, 0, AAA_OPT_IF_AUTHENTICATED, do_authorization_exe_net_list_other, NULL, NULL, 1, 0, 0,
 * 		"Succeed if user has authenticated", "�����ͨ����֤������Ȩͨ��" },
 */
	{ "local", CLI_CMD, 0, AAA_OPT_LOCAL, do_authorization_exe_net_list_other, NULL, NULL, 1, 0, 0,
		"Use local username authentication", "ʹ�ñ����û���Ϣ������֤" },		
	{ "none", CLI_CMD, 0, AAA_OPT_NONE, do_authorization_exe_net_list_other, NULL, NULL, 1, 0, 0,
		"No AAA", "����Ҫ AAA ����" },		
	{ CMDS_END },
};

static struct cmds authorization_exec_net_list_group_name[] = {
/* 	{ "WORD", CLI_WORD, 0, 0, do_authorization_exe_net_list_group_done, NULL, NULL, 1, 0, 0,
 * 		"Server-group name", "ʹ�÷������������֤" },    
 */
	{ "radius", CLI_CMD, 0, 0, do_authorization_exe_net_list_group_done, NULL, NULL, 1, 0, 0,
		"Use list of all Radius hosts", "ʹ������ radius ��������֤" },
/* 	{ "tacacs+", CLI_CMD, 0, 0, do_authorization_exe_net_list_group_done, NULL, NULL, 1, 0, 0,
 * 		"Use list of all Tacacs+ hosts", "ʹ������ tacacs+ ��������֤" },		
 */
	{ CMDS_END },
};


//------------------------------------------------------------------------------
// group
static struct cmds group_cmds[] = {
	{ "server", CLI_CMD, 0, 0, do_group_server, NULL, NULL, 0, 0, 0,
		"Define AAA serverf group", "���� AAA ��������" },
	{ CMDS_END },
};

static struct cmds group_list_cmds[] = {
	{ "radius", CLI_CMD, 0, 0, do_group_server_list, NULL, NULL, 1, 0, 0,
		"Define radius server group", "���� radius ��������" },
	{ "tacacs+", CLI_CMD, 0, 0, do_group_server_list, NULL, NULL, 1, 0, 0,
		"Define tacacs+ server group", "���� tacacs+ ��������" },		
	{ CMDS_END },
};


static int do_aaa(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(cmds, argc, argv, u);

	return retval;     
}


static int do_accounting(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(accounting_cmds, argc, argv, u);

	return retval;     
}


static int do_accounting_conn_exec(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int cmd;

	if (*argv[0] == 'e' || *argv[0] == 'E')
		cmd = 'e';
	else
		cmd = 'c';

	cli_param_set_int(DYNAMIC_PARAM, 0, cmd, u);

	retval = sub_cmdparse(accounting_conn_exec_cmds, argc, argv, u);

	return retval;  
}


static int do_accounting_conn_exec_list(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_get_string(DYNAMIC_PARAM, 0, argv[0], u);

	retval = sub_cmdparse(accounting_conn_exec_action_cmds, argc, argv, u);

	return retval;     
}


static int no_accounting_conn_exec_list(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if (!retval) {
		nfunc_accounting_conn_exec_list_done(u);
	} 
    
    return retval;
} 


static int do_accounting_conn_exec_list_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(accounting_conn_exec_group_list_cmds, argc, argv, u);

	return retval;    

}


 static int do_accounting_conn_exec_list_none(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if (!retval)
		func_accounting_conn_exec_list_none(u);

	return retval;
} 


static int do_accounting_conn_exec_list_action(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int cmd;

	if (!strncasecmp(argv[0], "sta", 3))
		cmd = 't';
	else
		cmd = 'p';

	cli_param_set_int(DYNAMIC_PARAM, 1, cmd, u);


	retval = sub_cmdparse(accounting_conn_exec_group_cmds, argc, argv, u);

	return retval;    
}


static int do_accounting_conn_exec_list_group_done(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	cli_param_set_string(DYNAMIC_PARAM, 1, argv[0], u);

	if ((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_accounting_conn_exec_list_group_done(u);
	}
    
/* 	retval = sub_cmdparse(accounting_conn_exec_group_cmds, argc, argv, u);
 */

    return retval;
} 


//------------------------------------------------------------------------------
// authentication
static int do_authentication(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(authentication_cmds, argc, argv, u);

	return retval;    
}

// dot1x
static int do_authentication_dot1x(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(authentication_dot1x_cmds, argc, argv, u);

	return retval;    
}


static int do_authentication_dot1x_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	memset(buf, '\0', 256);

	cli_param_get_string(STATIC_PARAM, 0, buf, u);
	if (!buf[0]) {
		memcpy(buf, "default", 7);
	}
	strcat(buf, "@");

	retval = sub_cmdparse(authentication_dot1x_list_cmds, argc, argv, u);

	return retval;    
}   


static int no_authentication_dot1x_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		retval = nfunc_authentication_dot1x_list(u);
	}

	return retval;    
}

#define AAA_LIST_GROUP_FLAG_POS 13
#define AAA_LIST_COUNT_POS 12
static int do_authentication_dot1x_list_group(int argc, char *argv[], struct users *u)
{
	int retval = -1, cmds_cnt = 0;

	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, &cmds_cnt, u);
	cmds_cnt += 1;
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, cmds_cnt, u);

	if(cmds_cnt < 4)
		u->cmd_mskbits &= ~AAA_OPT_GROUP;
	else
		u->cmd_mskbits |= (AAA_OPT_GROUP|AAA_OPT_LOCAL|AAA_OPT_ENABLE|AAA_OPT_LOCAL_CASE|AAA_OPT_NONE | AAA_OPT_LINE);
	
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_GROUP_FLAG_POS, 1, u);



	retval = sub_cmdparse(authentication_dot1x_list_group_cmds, argc, argv, u);

	return retval;    
}


static int do_authentication_dot1x_list_group_done(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char *ptr;
	if (!strpbrk(argv[argc - 1], "*?")) {
		if (!strncasecmp("radius", argv[0], strlen(argv[0]))) {
			ptr = strchr(buf, '@') + 1;
			if (*ptr)
				strcat(buf, "|radius");
			else 
				strcat(buf, "radius");
		}
	}


	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		retval = func_authentication_dot1x_list(buf);
		return retval;
	}
	retval = sub_cmdparse(authentication_dot1x_list_cmds, argc, argv, u);

	return retval;    
}


static int do_authentication_dot1x_list_other(int argc, char *argv[], struct users *u)
{
	int retval = -1, group_flag = 0, cmds_cnt = 0;
	char *ptr;

	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_GROUP_FLAG_POS, &group_flag, u);
	if (group_flag == 1)
		u->cmd_mskbits &= ~AAA_OPT_GROUP;
	
	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, &cmds_cnt, u);
	cmds_cnt += 1;
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, cmds_cnt, u);
	

	if ((u->cmd_mskbits & AAA_OPT_NONE)  || cmds_cnt >= 4)
		u->cmd_mskbits |= (AAA_OPT_GROUP|AAA_OPT_LOCAL|AAA_OPT_ENABLE|AAA_OPT_LOCAL_CASE|AAA_OPT_NONE | AAA_OPT_LINE);
	
	if (!strpbrk(argv[argc - 1], "*?")) {
		ptr = strchr(buf, '@') + 1;
		if (*ptr)
			strcat(buf, "|");
		if (!strncasecmp("local", argv[0], strlen(argv[0]))) {
			if (strstr(buf, "local-case") || !strstr(buf, "local"))
				strcat(buf, "local");
			else
				strcat(buf, "local-case");
		} else if (!strncasecmp("local-case", argv[0], strlen(argv[0]))) {
			strcat(buf, "local-case");
		} else if (!strncasecmp("none", argv[0], strlen(argv[0]))) {
			strcat(buf, "none");
		}
	}

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		retval = func_authentication_dot1x_list(buf);
		return retval;
	}

	retval = sub_cmdparse(authentication_dot1x_list_cmds, argc, argv, u);

	return retval;    
}

// enable
static int do_authentication_enable(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(authentication_enable_cmds, argc, argv, u);

	return retval;    
}


static int do_authentication_enable_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	memset(buf, '\0', 256);

	cli_param_get_string(STATIC_PARAM, 0, buf, u);
	if (!buf[0]) {
		memcpy(buf, "default", 7);
	}
	strcat(buf, "@");

	retval = sub_cmdparse(authentication_enable_list_cmds, argc, argv, u);

	return retval;    
}   


static int no_authentication_enable_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		retval = nfunc_authentication_enable_list(u);
	}

	return retval;    
}


static int do_authentication_enable_list_group(int argc, char *argv[], struct users *u)
{
	int retval = -1, cmds_cnt = 0;

	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, &cmds_cnt, u);
	cmds_cnt += 1;
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, cmds_cnt, u);

	if(cmds_cnt < 4)
		u->cmd_mskbits &= ~AAA_OPT_GROUP;
	else
		u->cmd_mskbits |= (AAA_OPT_GROUP|AAA_OPT_LOCAL|AAA_OPT_ENABLE|AAA_OPT_LOCAL_CASE|AAA_OPT_NONE | AAA_OPT_LINE);
	
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_GROUP_FLAG_POS, 1, u);

	retval = sub_cmdparse(authentication_enable_list_group_cmds, argc, argv, u);

	return retval;    
}


static int do_authentication_enable_list_group_done(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char *ptr;

	if (!strpbrk(argv[argc - 1], "*?")) {
		if (!strncasecmp("radius", argv[0], strlen(argv[0]))) {
			ptr = strchr(buf, '@') + 1;
			if (*ptr)
				strcat(buf, "|radius");
			else 
					strcat(buf, "radius");
		}
	}

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		retval = func_authentication_enable_list(buf);
		return retval;
	}
	retval = sub_cmdparse(authentication_enable_list_cmds, argc, argv, u);

	return retval;    
}


static int do_authentication_enable_list_other(int argc, char *argv[], struct users *u)
{
	int retval = -1, group_flag = 0, cmds_cnt = 0;
	char *ptr;

	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_GROUP_FLAG_POS, &group_flag, u);
	if (group_flag == 1)
		u->cmd_mskbits &= ~AAA_OPT_GROUP;
	
	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, &cmds_cnt, u);
	cmds_cnt += 1;
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, cmds_cnt, u);

	if ((u->cmd_mskbits & AAA_OPT_NONE)  || cmds_cnt >= 4)
		u->cmd_mskbits |= (AAA_OPT_GROUP|AAA_OPT_LOCAL|AAA_OPT_ENABLE|AAA_OPT_LOCAL_CASE|AAA_OPT_NONE | AAA_OPT_LINE);

	if (!strpbrk(argv[argc - 1], "*?")) {
		ptr = strchr(buf, '@') + 1;
		if (*ptr)
			strcat(buf, "|");
		if (!strncasecmp("enable", argv[0], strlen(argv[0]))) {
			strcat(buf, "enable");
		} else if (!strncasecmp("line", argv[0], strlen(argv[0]))) {
			strcat(buf, "line");
		} else if (!strncasecmp("none", argv[0], strlen(argv[0]))) {
			strcat(buf, "none");
		}
	}

	
	if ((retval = cmdend2(argc, argv, u)) == 0) {
		retval = func_authentication_enable_list(buf);
		return retval;
	}
	retval = sub_cmdparse(authentication_enable_list_cmds, argc, argv, u);

	return retval;    
}



//------------------------------------------------------------------------------
// login
static int do_authentication_login(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(authentication_login_cmds, argc, argv, u);

	return retval;    
}


static int do_authentication_login_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	memset(buf, '\0', 256);

	cli_param_get_string(STATIC_PARAM, 0, buf, u);
	if (!buf[0]) {
		memcpy(buf, "default", 7);
	}
	strcat(buf, "@");

	retval = sub_cmdparse(authentication_login_list_cmds, argc, argv, u);

	return retval;    
}


static int no_authentication_login_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

    retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		retval = nfunc_authentication_login_list(u);
	}

	return retval;    
} 


static int do_authentication_login_list_group(int argc, char *argv[], struct users *u)
{
	int retval = -1, cmds_cnt = 0;
	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, &cmds_cnt, u);
	cmds_cnt += 1;
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, cmds_cnt, u);

	if(cmds_cnt < 4)
		u->cmd_mskbits &= ~AAA_OPT_GROUP;
	else
		u->cmd_mskbits |= (AAA_OPT_GROUP|AAA_OPT_LOCAL|AAA_OPT_ENABLE|AAA_OPT_LOCAL_CASE|AAA_OPT_NONE | AAA_OPT_LINE);
	
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_GROUP_FLAG_POS, 1, u);

	retval = sub_cmdparse(authentication_login_list_group_cmds, argc, argv, u);

	return retval;    
}


static int do_authentication_login_list_group_done(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char *ptr;

	if (!strpbrk(argv[argc - 1], "*?")) {
		if (!strncasecmp("radius", argv[0], strlen(argv[0]))) {
			ptr = strchr(buf, '@') + 1;
			if (*ptr)
				strcat(buf, "|radius");
			else 
				strcat(buf, "radius");
		}
	}


	if ((retval = cmdend2(argc, argv, u)) == 0) {
		/* Do application function */
		retval = func_authentication_login_list(buf);

		return retval;
	}
	retval = sub_cmdparse(authentication_login_list_cmds, argc, argv, u);

	return retval;    
}


static int do_authentication_login_list_other(int argc, char *argv[], struct users *u)
{
	int retval = -1, group_flag = 0, cmds_cnt = 0;
	char *ptr;

	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_GROUP_FLAG_POS, &group_flag, u);
	if (group_flag == 1)
		u->cmd_mskbits &= ~AAA_OPT_GROUP;

	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, &cmds_cnt, u);
	cmds_cnt += 1;
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, cmds_cnt, u);

	if ((u->cmd_mskbits & AAA_OPT_NONE)  || cmds_cnt >= 4)
		u->cmd_mskbits |= (AAA_OPT_GROUP|AAA_OPT_LOCAL|AAA_OPT_ENABLE|AAA_OPT_LOCAL_CASE|AAA_OPT_NONE | AAA_OPT_LINE);

	if (!strpbrk(argv[argc - 1], "*?")) {
		ptr = strchr(buf, '@') + 1;
		if (*ptr)
			strcat(buf, "|");

		if (!strncasecmp("local", argv[0], strlen(argv[0]))) {
			if (strstr(buf, "local-case") || !strstr(buf, "local"))
				strcat(buf, "local");
			else
				strcat(buf, "local-case");
		} else if (!strncasecmp("local-case", argv[0], strlen(argv[0]))) {
			strcat(buf, "local-case");
		} else if (!strncasecmp("enable", argv[0], strlen(argv[0]))) {
			strcat(buf, "enable");
		} else if (!strncasecmp("line", argv[0], strlen(argv[0]))) {
			strcat(buf, "line");
		} else if (!strncasecmp("none", argv[0], strlen(argv[0]))) {
			strcat(buf, "none");
		}
	}

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		retval = func_authentication_login_list(buf);
		return retval;
	}

	retval = sub_cmdparse(authentication_login_list_cmds, argc, argv, u);

	return retval;      
}

// banner 
static int do_authentication_banner(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_LINE;
	param.name = "LINE";
	param.ylabel = "LINE  \"message-text\", where '\"' is a delimiting character";
	param.hlabel =  "�ַ���";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, 0, param.value.v_int, u);

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		/* Do application function */
		func_authentication_banner(u);
	}

	return retval;
}


static int no_authentication_banner(int argc, char *argv[], struct users *u)
{
    int retval;
    
	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		nfunc_authentication_banner();
	}

    return retval;
}
    


// fail_message
static int do_authentication_fail_message(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_LINE;
	param.name = "LINE";
	param.ylabel = "LINE  \"message-text\", where '\"' is a delimiting character";
    param.hlabel = "�ַ���";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, 0, param.value.v_int, u);
	/* Check command end or not */
	if ((retval = cmdend2(argc, argv, u)) == 0) {
		/* Do application function */
		func_authentication_fail_message(u);
	}

	return retval;    
}


static int no_authentication_fail_message(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
	retval = cmdend2(argc, argv, u);
	if(retval == 0) {
		nfunc_authentication_fail_message();
	}

    return retval;
}


// password prompt
static int do_authentication_password_prompt(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_LINE;
	param.name = "LINE";
	param.ylabel = "Password prompt string";
    param.hlabel = "��ʾ��Ϣ�ַ���";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, 0, param.value.v_int, u);

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		/* Do application function */
		func_authentication_password_prompt(u);
	}

	return retval;        
}


static int no_authentication_password_prompt(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		nfunc_authentication_password_prompt();
	}

    return retval;
}

// username prompt   
static int do_authentication_username_prompt(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_LINE;
	param.name = "LINE";
	param.ylabel = "Username prompt string";
    param.hlabel = "��ʾ��Ϣ�ַ���";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, 0, param.value.v_int, u);

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if (retval == 0) {
		/* Do application function */
		func_authentication_username_prompt(u);
	}

	return retval;        
} 


static int no_authentication_username_prompt(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
	retval = cmdend2(argc, argv, u);
	if(retval == 0) {
		nfunc_authentication_username_prompt(u);
	}

    return retval;
}

//------------------------------------------------------------------------------
// authorization
static int do_authorization(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(authorization_cmds, argc, argv, u);

	return retval;      
}


static int do_authorization_commands(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(authorization_level, argc, argv, u);

	return retval;      
}


static int do_authorization_commands_level(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		do_test_param(argc, argv, u);
	
		return retval;
	}
	retval = sub_cmdparse(authorization_level_list, argc, argv, u);

	return retval;      
}


static int no_authorization_commands_level(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		do_test_param(argc, argv, u);
	
		return retval;
	}
	retval = sub_cmdparse(authorization_level_list, argc, argv, u);

	return retval;  
    
}

    
static int do_authorization_commands_level_list(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(authorization_level_list_group, argc, argv, u);

	return retval;      
}


static int no_authorization_commands_level_list(int argc, char *argv[], struct users *u)
{
	int retval = -1;

    retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		do_test_param(argc, argv, u);
	}

	return retval;  
    
}


static int do_authorization_commands_level_list_group(int argc, char *argv[], struct users *u)
{

	int retval = -1, cmds_cnt = 0;

	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, &cmds_cnt, u);
	cmds_cnt += 1;
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, cmds_cnt, u);

	if(cmds_cnt < 4)
		u->cmd_mskbits &= ~AAA_OPT_GROUP;
	else
		u->cmd_mskbits |= (AAA_OPT_GROUP | AAA_OPT_IF_AUTHENTICATED | AAA_OPT_NONE);
	
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_GROUP_FLAG_POS, 1, u);

	retval = sub_cmdparse(authorization_level_list_group_name, argc, argv, u);

	return retval;   
}


static int do_authorization_commands_level_list_group_done(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		do_test_param(argc, argv, u);
	
		return retval;
	}
	retval = sub_cmdparse(authorization_level_list_group, argc, argv, u);

	return retval;  
    
}


static int do_authorization_commands_level_list_other(int argc, char *argv[], struct users *u)
{
	int retval = -1, group_flag = 0, cmds_cnt = 0;

	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_GROUP_FLAG_POS, &group_flag, u);
	if (group_flag == 1)
		u->cmd_mskbits &= ~AAA_OPT_GROUP;
	
	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, &cmds_cnt, u);
	cmds_cnt += 1;
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, cmds_cnt, u);

	if ((u->cmd_mskbits & AAA_OPT_NONE)  || cmds_cnt >= 4)
		u->cmd_mskbits |= (AAA_OPT_GROUP| AAA_OPT_IF_AUTHENTICATED |AAA_OPT_NONE);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		do_test_param(argc, argv, u);
	
		return retval;
	}
	retval = sub_cmdparse(authorization_level_list_group, argc, argv, u);

	return retval;          
}


static int do_authorization_config(int argc, char *argv[], struct users *u)
{
	int retval = -1;

    retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		do_test_param(argc, argv, u);
	}
    
	return retval;     
}


/////////////////////////////////////////////////////////////////////////////////

static int do_authorization_exec_net(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int cmd;

	if (*argv[0] == 'e' || *argv[0] == 'E')
		cmd = 'e';
	else
		cmd = 'c';

	cli_param_set_int(DYNAMIC_PARAM, 0, cmd, u);
	retval = sub_cmdparse(authorization_exe_net_list, argc, argv, u);

	return retval;      
}


static int no_authorization_exec_net_level(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		do_test_param(argc, argv, u);
	
		return retval;
	}
	retval = sub_cmdparse(authorization_exe_net_list, argc, argv, u);

	return retval;  
    
}

    
static int do_authorization_exe_net_list(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_get_string(DYNAMIC_PARAM, 0, argv[0], u);
	retval = sub_cmdparse(authorization_exec_net_list_group, argc, argv, u);

	return retval;      
}


static int no_authorization_exe_net_list(int argc, char *argv[], struct users *u)
{
	int retval = -1;

    retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		do_test_param(argc, argv, u);
	}

	return retval;  
    
}


static int do_authorization_exe_net_list_group(int argc, char *argv[], struct users *u)
{

	int retval = -1, cmds_cnt = 0;

	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, &cmds_cnt, u);
	cmds_cnt += 1;
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, cmds_cnt, u);

	if(cmds_cnt < 4)
		u->cmd_mskbits &= ~AAA_OPT_GROUP;
	else
		u->cmd_mskbits |= (AAA_OPT_GROUP | AAA_OPT_IF_AUTHENTICATED | AAA_OPT_NONE);
	
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_GROUP_FLAG_POS, 1, u);

	retval = sub_cmdparse(authorization_exec_net_list_group_name, argc, argv, u);

	return retval;   
}


static int do_authorization_exe_net_list_group_done(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_string(DYNAMIC_PARAM, 1, argv[0], u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
/* 		do_test_param(argc, argv, u);
 */
	
		return retval;
	}
/* 	retval = sub_cmdparse(authorization_exec_net_list_group, argc, argv, u);
 */

	return retval;  
    
}


static int do_authorization_exe_net_list_other(int argc, char *argv[], struct users *u)
{
	int retval = -1, group_flag = 0, cmds_cnt = 0;

	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_GROUP_FLAG_POS, &group_flag, u);
	if (group_flag == 1)
		u->cmd_mskbits &= ~AAA_OPT_GROUP;
	
	cli_param_get_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, &cmds_cnt, u);
	cmds_cnt += 1;
	cli_param_set_int(DYNAMIC_PARAM, AAA_LIST_COUNT_POS, cmds_cnt, u);

	if ((u->cmd_mskbits & AAA_OPT_NONE)  || cmds_cnt >= 4)
		u->cmd_mskbits |= (AAA_OPT_GROUP| AAA_OPT_IF_AUTHENTICATED |AAA_OPT_NONE);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
/* 		do_test_param(argc, argv, u);
 */
	
		return retval;
	}
	retval = sub_cmdparse(authorization_exec_net_list_group, argc, argv, u);

	return retval;          
}


static int no_authorization_config(int argc, char *argv[], struct users *u)
{
	int retval = -1;

    retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		do_test_param(argc, argv, u);
	}
    
	return retval;     
}


//------------------------------------------------------------------------------
// aaa group   
static int do_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(group_cmds, argc, argv, u);

	return retval;      
}


static int do_group_server(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(group_list_cmds, argc, argv, u);

	return retval;     
}


static int do_group_server_list(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Use server-group";
    param.hlabel = "����������";
	param.flag = CLI_END_FLAG | CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set_string(DYNAMIC_PARAM, 0, param.value.v_string, u);

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		do_test_param(argc, argv, u);
	}

	return retval;        
}


int init_cli_aaa(void)
{
	int retval = -1;

	retval = registerncmd(aaa_topcmds, (sizeof(aaa_topcmds)/sizeof(struct topcmds) - 1));

	DEBUG_MSG(1,"init_cli_aaa retval = %d\n", retval);

	return retval;
}
#endif
