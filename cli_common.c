/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name:  cli_ping.c
 * Function:    ping command function
 * Version:     1.0
 * Auther:      jialong.chu
 * Date:         2011/11/4
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
 2011/11/4  1.01        jialong.chu    exit
                                       help
                                       end
                                       no
                                       default
                                       chinese
                                       english
                                       enable
                                       reboot
                                       config
                                       username
                                       hostname
                                       quit
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
#include <sys/un.h>
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

#include "cli_common.h"
#include "cli_common_func.h"
#include "nvram.h"


/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/4  1.01       jialong.chu      add the common_topcmds[]
                                        add the unique_topcmds[]
 */
static struct topcmds common_topcmds[] = {
	{ "exit", 0, ALL_TREE, do_exit, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Exit", "退回或退出" },
	{ "help", 0, ALL_TREE, do_help, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Description of the interactive help system", "交互式帮助系统描述" },
	{ "end", 0, PRIVILEGE_TREE, do_end, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Exit to EXEC mode", "退到特权模式" },
	{ "no", 0, PRIVILEGE_TREE, do_no, NULL, NULL, 0, 0, 0,
		"Negate configuration", "取消配置" },
//	{ "default", 0, PRIVILEGE_TREE, do_default, NULL, NULL, 0, 0, 0,
//		"Default configuration", "恢复缺省配置" },
	{ "chinese", 0, VIEW_TREE|ENA_TREE|CONFIG_TREE, do_chinese, NULL, NULL, CLI_END_FLAG, 0, 0,
		"show chinese comment", "中文帮助信息" },
	{ "english", 0, VIEW_TREE|ENA_TREE|CONFIG_TREE, do_english, NULL, NULL, CLI_END_FLAG, 0, 0,
		"show english comment", "英文帮助信息" },
	{ "quit", 0, VIEW_TREE|ENA_TREE|CONFIG_TREE, do_quit, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Quit", "退出登录" },
	{ TOPCMDS_END }
};
		
static struct topcmds unique_topcmds[] = {
#ifdef CLI_AAA_MODULE

	{ "enable", 0, VIEW_TREE, do_ena, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Turn on privileged commands", "进入特权模式" },
#endif
	{ "reboot", 0, ENA_TREE, do_reboot, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Restart system", "重启动系统" },
	{ "restore_factory", 0, ENA_TREE, do_restore_factery, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Reset system", "恢复出厂" },
	{ "config", 0, ENA_TREE, do_config, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Enter configurative mode", "进入配置模式" },
#ifdef CLI_AAA_MODULE
	{ "username", 0, CONFIG_TREE, do_username, no_username, NULL, CLI_END_NONE, 0, 0,
		"Configuring user parameter", "建立本地用户信息" },
#endif
	{ "hostname", 0, CONFIG_TREE, do_hostname, no_hostname, NULL, CLI_END_NO, 0, 0,
		"Set system hostname", "设置系统名字" },
	{ TOPCMDS_END }
};

#ifdef CLI_AAA_MODULE
static struct cmds username_cmds[] = {
	{ "password", CLI_CMD, 0, 0, do_username_password, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specify the password for the user", "配置用户密码" },
	{ "privilege", CLI_CMD, 0, PRIVILEGE, do_username_privilege, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set user privilege level", "设置用户权限级别" },
	{ CMDS_END }
};

static struct cmds enable_level_cmds[] = {
	{ "<1-15>", CLI_INT, 0, 0, do_ena_level, NULL, NULL, CLI_END_FLAG, 1, 15,
		"Enable Level", "等级号" },		
	{ CMDS_END },
};

static struct cmds password_cmds[] = {
	{ "0", CLI_CMD, 0, ZERO_SEVEN, do_password_0, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specifies an UNENCRYPTED password will follow", "输入没有加密的密码明文" },
	{ "7", CLI_CMD, 0, ZERO_SEVEN, do_password_7, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specifies a HIDDEN password will follow", "输入加密后的密码密文" },
	{ "LINE", CLI_LINE, 0, PASSWORD_LINE, do_password_line, NULL, NULL, CLI_END_FLAG, 0, 0,
		"The UNENCRYPIED <cleartext> user password","输入没有加密的用户密码明文" },	
	{ CMDS_END }
};
#endif

/*
   Function:  do_exit
 *  Purpose:  exit topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Modifier: gujiajie     01/29/2012
 *  Modifier: liyezhong    03/16/2012
 *  Date:     2011/11/4
 */
#ifdef CLI_AAA_MODULE
static int do_exit(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buf[256];
	char pid_str[6];
	FILE *fp;
	pid_t own;
	
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		if(u->con_level > CONFIG_TREE)
		{
			/* Change console level */
			change_con_level(CONFIG_TREE, u);
		}
		else if(u->con_level > VIEW_TREE && u->con_level <= CONFIG_TREE)
		{
			/* Change console level */
			u->cur_con_level = u->con_level >> 1;
			change_con_level(u->cur_con_level, u);
		}
		else
		{
			own = getpid();
			snprintf(pid_str, 6, "%d", own);
			fp = popen("ps", "r");
			if (fp == NULL) {
				printf("error\n");
				return retval;
			}
			while (fgets(buf, 256, fp)) {
				if (strstr(buf, pid_str) && strstr(buf, "-c")) {
				acct_report_state(AAA_ACCT_EXEC_STOP);
					kill(0, 9);
				}
			}
			pclose(fp);

			/* Change authenticated state */
			vty_output("\n\n\nUser Access Verification!\n\n");
			SET_AUTH_STAT(u, CLI_AUTH_USER);
		}
	}

	return retval;
}
#else
static int do_exit(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buf[256];
	char pid_str[6];
	FILE *fp;
	pid_t own;
	
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		if(u->con_level > CONFIG_TREE)
		{
			/* Change console level */
			change_con_level(CONFIG_TREE, u);
		}
		else if(u->con_level > VIEW_TREE && u->con_level <= CONFIG_TREE)
		{
			/* Change console level */
			u->cur_con_level = u->con_level >> 1;
			change_con_level(u->cur_con_level, u);
		}
		else
		{
			own = getpid();
			snprintf(pid_str, 6, "%d", own);
			fp = popen("ps", "r");
			if (fp == NULL) {
				printf("error\n");
				return retval;
			}
			while (fgets(buf, 256, fp)) {
				if (strstr(buf, pid_str) && strstr(buf, "-c")) {
					//acct_report_state(AAA_ACCT_STOP);
					kill(0, 9);
				}
			}
			pclose(fp);

			/* Change authenticated state */
			vty_output("\n\n\nUser Access Verification!\n\n");
			SET_AUTH_STAT(u, CLI_AUTH_USER);
		}
	}

	return retval;
}
#endif

/*
 *  Function:  do_help
 *  Purpose:  help topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_help(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		system("cat /usr/etc/help");
		vty_output("\n");
	}

	return retval;
}

/*
 *  Function:  do_end
 *  Purpose:  end topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_end(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change console level */
		change_con_level(ENA_TREE, u);
	}

	return retval;
}


/*
 *  Function:  do_no
 *  Purpose:  no prefix topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_no(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Change u->cmd_st state */
	SET_CMD_ST(u, CMD_ST_NO);

	/* Restart parse top cmds */
	retval = top_cmdparse(argc, argv, u);

	return retval;
}

/*
 *  Function:  do_default
 *  Purpose:  default prefix topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_default(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Change u->cmd_st state */
	SET_CMD_ST(u, CMD_ST_DEF);
	
	/* Restart parse top cmds */
	retval = top_cmdparse(argc, argv, u);

	return retval;
}

#ifdef CLI_AAA_MODULE
/*
 *  Function:  passwd_check
 *  Purpose:   check password 
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yezhong.li
 *  Date:     2012/03/4
 */
static int passwd_check(char *passwd, int length)
{
	struct cli_msg msg;

	memset(&msg, 0, sizeof(msg));
	sprintf(msg.user, "$enab%d$", sta_info.level);
	memcpy(msg.password, passwd, length);
	msg.nas_port = sta_info.nas_port;
	msg.nas_port_type = sta_info.nas_port_type;

	if (sta_info.remote_type != CLI_LOCAL) {
		msg.type = AAA_LOGIN_LINE | AAA_ENABLE_CHECK;
		msg.nas_port = sta_info.nas_port;
	} else
		msg.type = AAA_LOGIN_LOCAL | AAA_ENABLE_CHECK;
	
	 return aaa_send_msg(&msg);
}

static int do_ena(int argc, char *argv[], struct users *u)
{
	int retval;

	/* Check command end or not */
	if ((retval = cmdend2(argc, argv, u)) == 0) {
		return func_enable(u);
	}

	retval = sub_cmdparse(enable_level_cmds, argc, argv, u);

	return retval;
}

static int do_ena_level(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		return func_enable(u);
	}

	return retval;
}
#endif

/*
 *  Function:  do_config
 *  Purpose:  config topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_config(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change console level */
		retval = change_con_level(CONFIG_TREE, u);
	}
	
	return retval;
}

/*
 *  Function:  do_chinese
 *  Purpose:  chinese topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_chinese(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change u->cmd_st state */
		SET_CMD_ST(u, CMD_ST_CN);
	}
	
	return retval;
}

/*
 *  Function:  do_english
 *  Purpose:  english topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_english(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Change u->cmd_st state */
		CLEAR_CMD_ST(u, CMD_ST_CN);
	}
	
	return retval;
}

/*
 *  Function:  do_reboot
 *  Purpose:  reboot topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_reboot(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		printf("Do you want to reboot the Switch(y/n)? ");
		
		while(1)
		{
			char ch = '\0';
			ch = getc(stdin);
			if(ch == ' ')
				continue;
			if( (ch == 'Y')||(ch == 'y') ) {
				printf("\n");
				syslog(LOG_NOTICE, "[CONFIG-5-REBOOT]: Reset system, %s\n", getenv("LOGIN_LOG_MESSAGE"));
				//system("sleep 1 && echo reboot > /proc/watchdog &&  echo reboot > /proc/wtd &");
				system("sleep 1 &&  echo reboot > /proc/wtd &");
				system("reboot");
				break;
			}else {
				printf("\n");
				break;
			}
		}			
	}
	
	return retval;
}

static int do_restore_factery(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char * lan_ipaddr;
    char * lan_netmask;
    char * lan_gateway;
    char * lan_dns;
    char * language;
    

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		printf("Do you want to reboot the Switch(y/n)? ");
		
		while(1)
		{
			char ch = '\0';
			ch = getc(stdin);
			if(ch == ' ')
				continue;
			if( (ch == 'Y')||(ch == 'y') ) {


				 lan_ipaddr=nvram_safe_get("lan_ipaddr");
                 lan_netmask=nvram_safe_get("lan_netmask");
                 lan_gateway=nvram_safe_get("lan_gateway");
                 lan_dns=nvram_safe_get("lan_dns");
                 language=nvram_safe_get("language");
				printf("\n");
				syslog(LOG_NOTICE, "[CONFIG-5-REBOOT]:restore factery, %s\n", getenv("LOGIN_LOG_MESSAGE"));
				SYSTEM("/bin/cp %s %s && /usr/sbin/nvram commit",NVRAM_DEFAULT,NVRAM_TMP_PATH);
				sleep(1);

				

				scfgmgr_set("lan_ipaddr", lan_ipaddr);
                scfgmgr_set("lan_netmask", lan_netmask);
                scfgmgr_set("lan_gateway", lan_gateway);
                scfgmgr_set("lan_dns", lan_dns);
                scfgmgr_set("language", language);
				nvram_set("system_start","1");	
	            nvram_commit();
				sleep(1);
				system("reboot");
				break;
			}else {
				printf("\n");
				break;
			}
		}			
	}
	
	return retval;
}

#ifdef CLI_AAA_MODULE
/*
 *  Function:  do_username
 *  Purpose:  username topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  modify:  yezhong.li
 */
static int do_username(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "User name";
	param.hlabel = "用户名";
	param.min = 0;
	param.max = 15;
	param.flag = CLI_END_FLAG;


	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
	
	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

//	if((retval = cmdend2(argc, argv, u)) == 0) 
//	{
//		/* Do application function */
//		func_username(u);
//	}
//	else
	{		
		retval = sub_cmdparse(username_cmds, argc, argv, u);
	}

	
	return retval;
}

/*
 *  Function:  do_username_password
 *  Purpose:  pwd cmds parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_username_password(int argc, char *argv[], struct users *u)
{
	int retval = -1, zero_flag = 1;
	cli_param_set_int(DYNAMIC_PARAM, 1, zero_flag, u);
	retval = sub_cmdparse(password_cmds, argc, argv, u);
	
	return retval;
}

/*
 *  Function:  do_username_privilege
 *  Purpose:  privilege cmds parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  modify:  yezhong.li
 *  Date:     2011/11/4
 */
static int do_username_privilege(int argc, char *argv[], struct users *u)
{
	int retval = -1, privilege_flag;		

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<0-15>";
	param.ylabel = "User privilege level";
	param.hlabel = "用户权限级别";
	param.min = 0;
	param.max = 15;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
	
	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_username_privilege(u);
	}
	else
	{
		privilege_flag = 1;		
		cli_param_set_int(DYNAMIC_PARAM, 2, privilege_flag, u);
		retval = sub_cmdparse(username_cmds, argc, argv, u);
	}
	
	return retval;
}


static int do_password_0(int argc, char *argv[], struct users *u)
{
	int retval;
	retval = sub_cmdparse(password_cmds, argc, argv, u);
	return retval;
}


static int do_password_7(int argc, char *argv[], struct users *u)
{
	int retval = -1, zero_flag = 0;
	cli_param_set_int(DYNAMIC_PARAM, 1, zero_flag, u);

	retval = sub_cmdparse(password_cmds, argc, argv, u);
	
	return retval;
}

/*
 *  Function:  do_password_line
 *  Purpose:  password LINE cmds parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  yunchangxuan
 *  Date:     2012/02/28
 */

static int do_password_line(int argc, char *argv[], struct users *u)
{
	int retval;

	u->cmd_mskbits |= ZERO_SEVEN;
	retval = cmdend2(argc, argv, u);
	
	if (retval == 0) {
		return func_username_passwd_line(u);
	}
	return retval;
}
#endif


/*
 *  Function:  do_hostname
 *  Purpose:  hostname topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int do_hostname(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Name of switch";
	param.hlabel = "交换机名称";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_hostname(u);
	}
	
	return retval;
}

#ifdef CLI_AAA_MODULE
/*
 *  Function:  do_quit
 *  Purpose:  quit topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   jialong.chu  2011/11/4
 *  Modifier: gujiajie     01/29/2012
 */
static int do_quit(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buf[256];
	char pid_str[6];
	FILE *fp;
	pid_t own;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		own = getpid();
		snprintf(pid_str, 6, "%d", own);
		fp = popen("ps", "r");
		if (fp == NULL) {
			printf("error\n");
			return retval;
		}
		while (fgets(buf, 256, fp)) {
			if (strstr(buf, pid_str) && strstr(buf, "-c")) {
		acct_report_state(AAA_ACCT_EXEC_STOP);
				kill(0, 9);
			}
		}
		pclose(fp);

		/* Change authenticated state */
		vty_output("\n\n\nUser Access Verification!\n\n");
		SET_AUTH_STAT(u, CLI_AUTH_USER);
	}

	return retval;
}
#else
static int do_quit(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buf[256];
	char pid_str[6];
	FILE *fp;
	pid_t own;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		own = getpid();
		snprintf(pid_str, 6, "%d", own);
		fp = popen("ps", "r");
		if (fp == NULL) {
			printf("error\n");
			return retval;
		}
		while (fgets(buf, 256, fp)) {
			if (strstr(buf, pid_str) && strstr(buf, "-c")) {
				//acct_report_state(AAA_ACCT_STOP);
				kill(0, 9);
			}
		}
		pclose(fp);

		/* Change authenticated state */
		vty_output("\n\n\nUser Access Verification!\n\n");
		SET_AUTH_STAT(u, CLI_AUTH_USER);
	}

	return retval;
}
#endif

/*
 *  Function:  no_username
 *  Purpose:  no username topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  modify:  yezhong.li
 */
static int no_username(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "User name";
	param.hlabel = "用户名";
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
	
	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_username(u);
	}
	
	return retval;
}

/*
 *  Function:  no_hostname
 *  Purpose:  no hostname topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jialong.chu
 *  Date:     2011/11/4
 */
static int no_hostname(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_hostname(u);
	}
	
	return retval;
}

int do_test(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		int i = 0;
		printf("do_test() : argc = %d ", argc);
		for(i = 0; i < argc; i++)
			printf("argv[%d]=%s ", i, argv[i]);
		printf("\n");
	}
	
	return retval;
}

int do_test_param(int argc, char *argv[], struct users *u)
{
	int i = 0;
	
	printf("do_test_param() : argc = %d ", argc);
	for(i = 0; i < argc; i++)
		printf("argv[%d]=%s ", i, argv[i]);
	printf("\n");

	struct g_param *t_param = NULL;
	int cnt = 0;
	char buff[MAX_ARGV_LEN] = {'\0'};
	t_param = &(u->s_param);
	printf("*****users s_param*****\n");
	for(cnt = 0; cnt < 2; cnt++)
	{
		if(t_param->v_int_cnt != 0)
		{
			for(i = 0; i < MAX_V_INT; i++)
				printf("v_int[%d]=%d\n", i, t_param->v_int[i]);
		}
		if(t_param->v_string_cnt != 0)
		{
			for(i = 0; i < MAX_V_STRING; i++)
				printf("v_string=%s\n", t_param->v_string[i]);
		}
		if(t_param->v_range_len != 0)
			printf("v_range=%s\n", t_param->v_range);
		if(t_param->v_sin_addr_cnt != 0)
		{
			for(i = 0; i < MAX_V_IP; i++)
			{
				memset(buff, '\0', sizeof(buff));
				inet_ntop(AF_INET, &(t_param->v_sin_addr[i]), buff, sizeof(buff));
				printf("v_sin[%d]=%s\n", i, buff);
			}
		}
		if(t_param->v_sin6_addr_cnt != 0)
		{
		
			for(i = 0; i < MAX_V_IPV6; i++)
			{
				memset(buff, '\0', sizeof(buff));
				inet_ntop(AF_INET6, &(t_param->v_sin6_addr[i]), buff, sizeof(buff));
				printf("v_sin6[%d]=%s, mask=%d\n", i, buff, t_param->v_int[MAX_V_INT+i]);
			}
		}

		if(cnt == 0)
		{
			t_param = &(u->d_param);
			printf("*****users d_param*****\n");
		}
		else
			printf("**********end**********\n");
	}

	return 0;
}


int init_cli_common(void)
{
	int retval = -1;

	retval = registerncmd(common_topcmds, (sizeof(common_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(unique_topcmds, (sizeof(unique_topcmds)/sizeof(struct topcmds) - 1));
	
	DEBUG_MSG(1, "init_cli_common retval = %d\n", retval);
	
	return retval;
}

#ifdef CLI_SHELL
static struct topcmds shell_topcmds[] = {
	{ "shell", 0, ALL_TREE, do_shell, NULL, NULL, CLI_END_NONE, 0, 0,
		"Shell", "Shell" },
	{ TOPCMDS_END }
};

static struct cmds shell_cmds[] = {
	{ "LINE", CLI_LINE, 0, 0, do_shell_cmds, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Shell", "Shell" },
	{ CMDS_END }
};

int do_shell(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(shell_cmds, argc, argv, u);
	
	return retval;
}

int do_shell_cmds(int argc, char *argv[], struct users *u)
{
	int retval = -1, line_addr = 0;
	char *exec_cmds = NULL;

	if((retval = cmdend2(argc, argv, u)) == 0) 
		cli_param_get_int(STATIC_PARAM, 0, &line_addr, u);

	exec_cmds = line_addr;
	printf("exec %s\n", exec_cmds);

	if(exec_cmds != NULL && strlen(exec_cmds) > 0)
		SYSTEM(exec_cmds);
	
	return retval;
}

int init_cli_shell(void)
{
	int retval = -1;
	retval += registerncmd(shell_topcmds, (sizeof(shell_topcmds)/sizeof(struct topcmds) - 1));
	return retval;
}
#endif

