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
 2011/11/4  1.01        jialong.chu    rmon
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

#include "cli_rmon.h"
#include "cli_rmon_func.h"

/*
****************Revision History****************
Date       Version    Modifier         Modifications
2011/11/4  1.01       jialong.chu      add the ping_topcmds[]
*/
static struct topcmds rmon_topcmds[] = {
	{ "rmon", 0, CONFIG_TREE, do_rmon, NULL, NULL, CLI_END_NONE, 0, 0,
		"Remote Monitoring", "Զ�̼��" },
	{ TOPCMDS_END }
};

/*
****************Revision History****************
Date       Version    Modifier         Modifications
2011/11/4  1.01       jialong.chu      add ping_dst_cmds[]
2011/11/4  1.01       jialong.chu      add ping_dst_opt_cmds[]
*/
static struct cmds rmon_conf_type_cmds[] = {
	{ "alarm", CLI_CMD, 0, 0, do_rmon_alarm, no_rmon_alarm, NULL, CLI_END_NONE, 0, 0,
		"help_en", "����RMON�澯" },
	{ "event", CLI_CMD, 0, 0, do_rmon_event, no_rmon_event, NULL, CLI_END_NONE, 0, 0,
		"Test each sample directly", "����RMON�¼�" },
	{ CMDS_END }
};

static struct cmds rmon_alarm_mode_cmds[] = {
	{ "delta", CLI_CMD, 0, 0, do_rmon_alarm_delta, NULL, NULL, CLI_END_NONE, 0, 0,
		"Test delta between samples", "��������ȡ��ֵ�Ĳ�" },
	{ "absolute", CLI_CMD, 0, 0, do_rmon_alarm_absolute, NULL, NULL, CLI_END_NONE, 0, 0,
		"help_en", "ֱ�Ӵ���ȡ������ֵ" },
	{ CMDS_END }
};

static struct cmds rmon_alarm_mode_rising_cmds[] = {
	{ "rising-threshold", CLI_CMD, 0, 0, do_rmon_alarm_mode_rising, NULL, NULL, CLI_END_NONE, 0, 0,
		"Configure the rising threshold", "���������澯��ֵ" },
	{ CMDS_END }
};

static struct cmds rmon_alarm_mode_falling_cmds[] = {
	{ "falling-threshold", CLI_CMD, 0, RMON_FALLING_THR_MSK, do_rmon_alarm_mode_falling, NULL, NULL, CLI_END_NONE, 0, 0,
		"Configure the falling threshold", "�����½��澯��ֵ" },
	{ "<1-65535>", CLI_INT, 0, RMON_RISING_EVENT_MSK, do_rmon_alarm_mode_rising_event, NULL, NULL, CLI_END_NONE, 0, 0,
		"Event to fire on rising threshold crossing", "�ﵽ�����澯��ֵʱ��Ҫ�������¼�" },
	{ CMDS_END }
};

static struct cmds rmon_alarm_mode_owner_cmds[] = {
	{ "owner", CLI_CMD, 0, RMON_OWNER_MSK, do_rmon_alarm_mode_owner, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specify an owner for the alarm", "ָ�����澯��������" },
	{ "<1-65535>", CLI_INT, 0, RMON_FALLING_EVENT_MSK, do_rmon_alarm_mode_falling_event, NULL, NULL, CLI_END_NONE, 0, 0,
		"Event to fire on falling threshold crossing", "�ﵽ�½��澯��ֵʱ��Ҫ�������¼�" },
	{ CMDS_END }
};

static struct cmds rmon_event_cmds[] = {
	{ "description", CLI_CMD, 0, 0, do_rmon_event_description, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specify a description of the event", "ָ�����¼���������Ϣ" },
	{ "log", CLI_CMD, 0, 0, do_rmon_event_log, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Generate RMON log when the event fires", "�¼�����ʱ��log��������һ����¼" },
	{ "trap", CLI_CMD, 0, 0, do_rmon_event_trap, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Generate SNMP trap when the event fires", "�¼�����ʱ����һ��trap����" },
	{ CMDS_END }
};

static int do_rmon(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(rmon_conf_type_cmds, argc, argv, u);

	return retval;
}

static int do_rmon_alarm(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter *param = NULL;
	param = (struct parameter *)malloc(sizeof(struct parameter));
	
	memset(param, 0, sizeof(struct parameter));
	param->type = CLI_INT;
	param->name = "<1-65535>";
	param->ylabel = "Alarm number";
	param->hlabel = "�澯����";
	param->min = 1;
	param->max = 65535;
	
	if((retval = getparameter(argc, argv, u, param)) != 0)
	{
		free(param);
		return retval;
	}

	cli_param_set_int(DYNAMIC_PARAM, RMON_ALARM_NUM, param->value.v_int, u);

	memset(param, 0, sizeof(struct parameter));
	param->type = CLI_WORD;
	param->name = "WORD";
	param->ylabel = "MIB object to monitor";
	param->hlabel = "��Ҫ��ص�MIB����";
	
	if((retval = getparameter(argc, argv, u, param)) != 0)
	{
		free(param);
		return retval;
	}

	cli_param_set(DYNAMIC_PARAM, param, u);
	
	memset(param, 0, sizeof(struct parameter));
	param->type = CLI_INT;
	param->name = "<1-20000000>";
	param->ylabel = "Sample interval";
	param->hlabel = "ȡ�����ʱ��";
	param->min = 1;
	param->max = 20000000;
	
	if((retval = getparameter(argc, argv, u, param)) != 0)
	{
		free(param);
		return retval;
	}

	cli_param_set_int(DYNAMIC_PARAM, RMON_SAMPLE_INTVERVAL, param->value.v_int, u);

	free(param);
	
	retval = sub_cmdparse(rmon_alarm_mode_cmds, argc, argv, u);

	return retval;
}

static int do_rmon_alarm_delta(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, RMON_MODE_FLAG, RMON_MODE_DELTA, u);

	retval = sub_cmdparse(rmon_alarm_mode_rising_cmds, argc, argv, u);

	return retval;
}

static int do_rmon_alarm_absolute(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, RMON_MODE_FLAG, RMON_MODE_ABSOLUTE, u);

	retval = sub_cmdparse(rmon_alarm_mode_rising_cmds, argc, argv, u);

	return retval;
}

static int do_rmon_alarm_mode_rising(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter *param = NULL;
	param = (struct parameter *)malloc(sizeof(struct parameter));
	
	memset(param, 0, sizeof(struct parameter));
	param->type = CLI_INT;
	param->name = "<-20000000-20000000>";
	param->ylabel = "Rising threshold value";
	param->min = -20000000;
	param->max = 20000000;
	
	if((retval = getparameter(argc, argv, u, param)) != 0)
	{
		free(param);
		return retval;
	}

	cli_param_set_int(DYNAMIC_PARAM, RMON_RISING_THR, param->value.v_int, u);

	free(param);
	
	retval = sub_cmdparse(rmon_alarm_mode_falling_cmds, argc, argv, u);

	return retval;
}

static int do_rmon_alarm_mode_falling(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter *param = NULL;
	param = (struct parameter *)malloc(sizeof(struct parameter));
	
	memset(param, 0, sizeof(struct parameter));
	param->type = CLI_INT;
	param->name = "<-20000000-20000000>";
	param->ylabel = "Falling threshold value";
	param->min = -20000000;
	param->max = 20000000;
	
	if((retval = getparameter(argc, argv, u, param)) != 0)
	{
		free(param);
		return retval;
	}

	cli_param_set_int(DYNAMIC_PARAM, RMON_FALLING_THR, param->value.v_int, u);

	free(param);

	retval = sub_cmdparse(rmon_alarm_mode_owner_cmds, argc, argv, u);

	return retval;
}

static int do_rmon_alarm_mode_rising_event(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(rmon_alarm_mode_falling_cmds, argc, argv, u);

	return retval;
}

static int do_rmon_alarm_mode_owner(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter *param = NULL;
	param = (struct parameter *)malloc(sizeof(struct parameter));

	memset(param, 0, sizeof(struct parameter));
	param->type = CLI_WORD;
	param->name = "WORD";
	param->ylabel = "Alarm owner";
	param->flag = CLI_END_FLAG;
	
	if((retval = getparameter(argc, argv, u, param)) != 0)
	{
		free(param);
		return retval;
	}

	cli_param_set(DYNAMIC_PARAM, param, u);

	free(param);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_alarm(u);
	}
	
	return retval;
}
static int do_rmon_alarm_mode_falling_event(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(rmon_alarm_mode_owner_cmds, argc, argv, u);

	return retval;
}

static int do_rmon_event(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter *param = NULL;
	param = (struct parameter *)malloc(sizeof(struct parameter));
	
	memset(param, 0, sizeof(struct parameter));
	param->type = CLI_INT;
	param->name = "<1-65535>";
	param->ylabel = "Event number";
	param->hlabel = "�¼�����";
	param->min = 1;
	param->max = 65535;
	
	if((retval = getparameter(argc, argv, u, param)) != 0)
	{
		free(param);
		return retval;
	}

	cli_param_set_int(DYNAMIC_PARAM, RMON_EVENT_NUM, param->value.v_int, u);

	free(param);
	
	retval = sub_cmdparse(rmon_event_cmds, argc, argv, u);

	return retval;
}

static int do_rmon_event_description(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	struct parameter *param = NULL;
	param = (struct parameter *)malloc(sizeof(struct parameter));
	
	memset(param, 0, sizeof(struct parameter));
	param->type = CLI_LINE;
	param->name = "LINE";
	param->ylabel = "Event description";
	param->flag = CLI_END_FLAG;
	
	if((retval = getparameter(argc, argv, u, param)) != 0)
	{
		free(param);
		return retval;
	}

	cli_param_set(DYNAMIC_PARAM, param, u);

	free(param);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_event(u);
	}
	
	return retval;
}

static int do_rmon_event_log(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_event(u);
	}

	return retval;
}

static int do_rmon_event_trap(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_event(u);
	}

	return retval;
}

static int no_rmon_alarm(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter *param = NULL;
	param = (struct parameter *)malloc(sizeof(struct parameter));
	
	memset(param, 0, sizeof(struct parameter));
	param->type = CLI_INT;
	param->name = "<1-65535>";
	param->ylabel = "Alarm number";
	param->hlabel = "�����";
	param->min = 1;
	param->max = 65535;
	param->flag = CLI_END_NO;
	
	if((retval = getparameter(argc, argv, u, param)) != 0)
	{
		free(param);
		return retval;
	}

	cli_param_set_int(DYNAMIC_PARAM, RMON_ALARM_NUM, param->value.v_int, u);
	free(param);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_rmon_alarm(u);
	}

	return retval;
}

static int no_rmon_event(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter *param = NULL;
	param = (struct parameter *)malloc(sizeof(struct parameter));
	
	memset(param, 0, sizeof(struct parameter));
	param->type = CLI_INT;
	param->name = "<1-65535>";
	param->ylabel = "Event number";
	param->hlabel = "�¼���";
	param->min = 1;
	param->max = 65535;
	param->flag = CLI_END_NO;
	
	if((retval = getparameter(argc, argv, u, param)) != 0)
	{
		free(param);
		return retval;
	}

	cli_param_set_int(DYNAMIC_PARAM, RMON_EVENT_NUM, param->value.v_int, u);
	free(param);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_rmon_event(u);
	}

	return retval;
}

int init_cli_rmon(void)
{
	int retval = -1;

	retval = registerncmd(rmon_topcmds, (sizeof(rmon_topcmds)/sizeof(struct topcmds) - 1));
	
	DEBUG_MSG(1, "init_cli_rmon retval = %d\n", retval);

	return retval;
}

