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

#include "cli_time_range.h"
#include "cli_time_range_func.h"

/*
 *  top command struct
 *
 *	Author:  jiajie.gu
 *  Date:     2011/11/8
 */
 
static struct topcmds time_range_name_topcmds[] = {
	{ "time-range", 0, CONFIG_TREE, do_time_range, NULL, NULL, CLI_END_NONE, 0, 0,
		"time-range configuration commands", "time-rane��������" },
	{ TOPCMDS_END }
};

static struct cmds time_range_name[] = {
	{ "WORD", CLI_WORD, 0, 0, do_time_range_name, no_time_range_name, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Time-range name", "��Χʱ����" },
	{ CMDS_END }
};

static int do_time_range(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_name, argc, argv, u);
	
	return retval;
}

static int do_time_range_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		if(func_time_range_name(u) < 0)
			return -1;
		
		if((retval = change_con_level(TIME_RANGE_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "%s", u->s_param.v_string[0]);
		}
	}
	
	return retval;
}

static int no_time_range_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_time_range_name(u);
	}
	
	return retval;
}





static struct topcmds time_range_set_topcmds[] = {
	{ "absolute", 0, TIME_RANGE_TREE, do_time_range_absolute, NULL, NULL, CLI_END_NONE, 0, 0,
		"absolute time", "����ʱ��" },
	{ "periodic", 0, TIME_RANGE_TREE, do_time_range_periodic, NULL, NULL, CLI_END_NONE, 0, 0,
		"periodic time", "����ʱ��" },

	{ TOPCMDS_END }
};

static struct cmds time_range_absolute_1_cmds[] = {
	{ "start", CLI_CMD, 0, 0, do_time_range_absolute_1, NULL, NULL, CLI_END_NONE, 0, 0,
		"start time", "��ʼʱ��" },
	{ CMDS_END }
};

static struct cmds time_range_absolute_2_cmds[] = {
	{ "hh:mm:ss", CLI_TIME, 0, 0, do_time_range_absolute_2, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set time", "����ʱ��" },
	{ CMDS_END }
};

static struct cmds time_range_absolute_3_cmds[] = {
	{ "day", CLI_INT, 0, 0, do_time_range_absolute_3, NULL, NULL, CLI_END_NONE, 1, 31,
		"Set day(1-31)", "������" },
	{ CMDS_END }
};

static struct cmds time_range_absolute_4_cmds[] = {
	{ "month", CLI_INT, 0, 0, do_time_range_absolute_4, NULL, NULL, CLI_END_NONE, 1, 12,
		"Set month(1-12)", "������" },
	{ CMDS_END }
};

static struct cmds time_range_absolute_5_cmds[] = {
	{ "year", CLI_INT, 0, 0, do_time_range_absolute_5, NULL, NULL, CLI_END_FLAG, 1995, 2035,
		"Set year(1995-2035)", "������" },
	{ CMDS_END }
};

static struct cmds time_range_absolute_6_cmds[] = {
	{ "to", CLI_CMD, 0, 0, do_time_range_absolute_6, NULL, NULL, CLI_END_NONE, 0, 0,
		"end time", "����ʱ��" },
	{ CMDS_END }
};

static struct cmds time_range_absolute_7_cmds[] = {
	{ "hh:mm:ss", CLI_TIME, 0, 0, do_time_range_absolute_7, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set time", "����ʱ��" },
	{ CMDS_END }
};

static struct cmds time_range_absolute_8_cmds[] = {
	{ "day", CLI_INT, 0, 0, do_time_range_absolute_8, NULL, NULL, CLI_END_NONE, 1, 31,
		"Set day(1-31)", "������" },
	{ CMDS_END }
};

static struct cmds time_range_absolute_9_cmds[] = {
	{ "month", CLI_INT, 0, 0, do_time_range_absolute_9, NULL, NULL, CLI_END_NONE, 1, 12,
		"Set month(1-12)", "������" },
	{ CMDS_END }
};

static struct cmds time_range_absolute_10_cmds[] = {
	{ "year", CLI_INT, 0, 0, do_time_range_absolute_10, NULL, NULL, CLI_END_FLAG | CLI_END_NO, 1995, 2035,
		"Set year(1995-2035)", "������" },
	{ CMDS_END }
};


static int do_time_range_absolute(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_absolute_1_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_absolute_1(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_absolute_2_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_absolute_2(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_absolute_3_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_absolute_3(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_absolute_4_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_absolute_4(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_absolute_5_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_absolute_5(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_absolute_6_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_absolute_6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_absolute_7_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_absolute_7(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_absolute_8_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_absolute_8(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_absolute_9_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_absolute_9(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_absolute_10_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_absolute_10(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_time_range_set(u);
	}
	return retval;
}

static struct cmds time_range_periodic_1_cmds[] = {
	{ "daily", CLI_CMD, 0, 0, do_time_range_periodic_1, NULL, NULL, CLI_END_NONE, 0, 0,
		"daily", "ÿ��" },
	{ "weekdays", CLI_CMD, 0, 0, do_time_range_periodic_1, NULL, NULL, CLI_END_NONE, 0, 0,
		"weekdays", "������" },
	{ "weekend", CLI_CMD, 0, 0, do_time_range_periodic_1, NULL, NULL, CLI_END_NONE, 0, 0,
		"weekend", "��ĩ" },
	{ "Sun", CLI_CMD, 0, 0, do_time_range_periodic_1, NULL, NULL, CLI_END_NONE, 0, 0,
		"Sunday", "������" },
	{ "Mon", CLI_CMD, 0, 0, do_time_range_periodic_1, NULL, NULL, CLI_END_NONE, 0, 0,
		"Monday", "����һ" },
	{ "Tue", CLI_CMD, 0, 0, do_time_range_periodic_1, NULL, NULL, CLI_END_NONE, 0, 0,
		"Tuesday", "���ڶ�" },
	{ "Wed", CLI_CMD, 0, 0, do_time_range_periodic_1, NULL, NULL, CLI_END_NONE, 0, 0,
		"Wednesday", "������" },
	{ "Thu", CLI_CMD, 0, 0, do_time_range_periodic_1, NULL, NULL, CLI_END_NONE, 0, 0,
		"Thursday", "������" },
	{ "Fri", CLI_CMD, 0, 0, do_time_range_periodic_1, NULL, NULL, CLI_END_NONE, 0, 0,
		"Friday", "������" },
	{ "Sat", CLI_CMD, 0, 0, do_time_range_periodic_1, NULL, NULL, CLI_END_NONE, 0, 0,
		"Saturday", "������" },
	{ CMDS_END }
};

static struct cmds time_range_periodic_2_cmds[] = {
	{ "hh:mm:ss", CLI_TIME, 0, 0, do_time_range_periodic_2, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set time", "����ʱ��" },
	{ CMDS_END }
};

static struct cmds time_range_periodic_3_cmds[] = {
	{ "to", CLI_CMD, 0, 0, do_time_range_periodic_3, NULL, NULL, CLI_END_NONE, 0, 0,
		"end time command", "����ʱ������" },
	{ CMDS_END }
};

static struct cmds time_range_periodic_4_cmds[] = {
	{ "hh:mm:ss", CLI_TIME, 0, 0, do_time_range_periodic_4, NULL, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Set time", "����ʱ��" },
	{ CMDS_END }
};

static int do_time_range_periodic(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_periodic_1_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_periodic_1(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_periodic_2_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_periodic_2(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_periodic_3_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_periodic_3(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(time_range_periodic_4_cmds, argc, argv, u);
	
	return retval;
}

static int do_time_range_periodic_4(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_time_range_set(u);
	}
	return retval;
}

/*
 *  Function:  init_cli_mac
 *  Purpose:  Register mac_topcmds[]
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
int init_cli_time_range(void)
{
	int retval = -1;
	
	retval = registerncmd(time_range_name_topcmds, (sizeof(time_range_name_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(time_range_set_topcmds, (sizeof(time_range_set_topcmds)/sizeof(struct topcmds) - 1));
	
	DEBUG_MSG(1, "init_cli_time_range retval = %d\n", retval);

	return retval;
}



