/*
 * Copyright 2016 by Kuaipao Corporation
 *
 * All Rights Reserved
 *
 * File name  : cli_syslog.c
 * Function   : logging command function
 * Auther     : jialong.chu
 * Version    : 1.0
 * Date       : 2011/11/4
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
 2011/11/08  1.01       chunli.wu      logging buffered <4096-1048576> <cr>
                                       logging buffered alerts <cr>
                                       logging buffered critical <cr>
                                       logging buffered debugging <cr>
                                       logging buffered emergencies <cr>
                                       logging buffered errors <cr>
                                       logging buffered informational <cr>
                                       logging buffered notifications <cr>
                                       logging buffered warnings <cr>

                                       logging host A.B.C.D <cr>

                                       logging on <cr>

                                       logging console alerts <cr>
                                       logging console critical <cr>
                                       logging console debugging <cr>
                                       logging console emergencies <cr>
                                       logging console errors <cr>
                                       logging console informational <cr>
                                       logging console notifications <cr>
                                       logging console warnings <cr>

                                       logging trap alerts <cr>
                                       logging trap critical <cr>
                                       logging trap debugging <cr>
                                       logging trap emergencies <cr>
                                       logging trap errors <cr>
                                       logging trap informational <cr>
                                       logging trap notifications <cr>
                                       logging trap warnings <cr>

                                       no logging buffered <cr>
                                       no logging buffered level <cr>
                                       no logging host <cr>
                                       no logging on <cr>
                                       no logging console <cr>
                                       no logging trap <cr>
 Date       Version     Modifier       Command
 2012/02/29  1.02       chunli.wu      logging count <cr>
                                       logging rate-limit <1-10000> <cr>
                                       logging facility kernel <cr>
                                       logging facility user-level <cr>
                                       logging facility mail <cr>
                                       logging facility daemon <cr>
                                       logging facility security1 <cr>
                                       logging facility syslog <cr>
                                       logging facility line-printer <cr>
                                       logging facility news <cr>
                                       logging facility UUCP <cr>
                                       logging facility clock1 <cr>
                                       logging facility security2 <cr>
                                       logging facility FTP <cr>
                                       logging facility NTP <cr>
                                       logging facility log-audit <cr>
                                       logging facility log-alert <cr>
                                       logging facility clock2 <cr>
                                       logging facility local0 <cr>
                                       logging facility local1 <cr>
                                       logging facility local2 <cr>
                                       logging facility local3 <cr>
                                       logging facility local4 <cr>
                                       logging facility local5 <cr>
                                       logging facility local6 <cr>
                                       logging facility local7 <cr>
                                       logging userinfo <cr>
                                       logging command <cr>

                                       service timestamps <cr>
                                       service timestamps debug <cr>
                                       service timestamps debug datetime <cr>
                                       service timestamps debug uptime <cr>
                                       service timestamps log <cr>
                                       service timestamps log datetime <cr>
                                       service timestamps log uptime <cr>
                                       service sysname <cr>
                                       service sequence-numbers <cr>

                                       no logging count <cr>
                                       no logging rate-limit <cr>
                                       no logging facility <cr>
                                       no logging userinfo <cr>
                                       no logging command <cr>

                                       no service timestamps <cr>
                                       no service timestamps debug <cr>
                                       no service timestamps log <cr>
                                       no service sysname <cr>
                                       no service sequence-numbers <cr>
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

#include "cli_syslog.h"
#include "cli_syslog_func.h"

/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/08  1.01      chunli.wu        add syslog_topcmds[]


 */
static struct topcmds syslog_topcmds[] = {
{ "logging", 0, CONFIG_TREE, do_syslog, do_syslog, NULL, 0, 0, 0,
  "Set message logging facilities", "设置消息日志机制" },
/*wuchunli 2012-2-24 13:17:59*/
#if 0
{ "service", 0, CONFIG_TREE, do_service, do_service, NULL, 0, 0, 0,
  "Set system services", "设置系统服务" },
#endif
{ TOPCMDS_END }
};


/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/08  1.01      chunli.wu        add syslog_cmds[]
 2012/02/24  1.02      chunli.wu        add new function(service_cmds[]) according to ruijie

 */

/*wuchunli 2012-2-24 15:47:14 begin*/
static struct cmds service_cmds[] = {
{ "timestamps", CLI_CMD, 0, 0, do_service_time, no_do_service_time, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Timestamp debug/log messages", "调试和日志信息的时戳设置" },
{ "sysname", CLI_CMD, 0, 0, do_service_sysname, no_do_service_sysname, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Sysname in syslog messages", "显示日志系统名" },
{ "sequence-numbers", CLI_CMD, 0, 0, do_service_number, no_do_service_number, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Stamp logger messages with a sequence number", "显示日志序列号" },
{ CMDS_END }
};

static struct cmds service_time_cmds[] = {
{ "debug", CLI_CMD, 0, 0, do_service_time_debug, no_do_service_time_debug, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Timestamp debug messages", "调试信息时戳设置" },
{ "log", CLI_CMD, 0, 0, do_service_time_log, no_do_service_time_log, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Timestamp log messages", "日志信息时戳设置" },
{ CMDS_END }
};

static struct cmds service_time_debug_cmds[] = {
{ "datetime", CLI_CMD, 0, 0, do_service_time_debug_date, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Timestamp with date and time", "日期时戳" },
{ "uptime", CLI_CMD, 0, 0, do_service_time_debug_up, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Timestamp with system uptime", "系统运行时间时戳" },
{ CMDS_END }
};

static struct cmds service_time_log_cmds[] = {
{ "datetime", CLI_CMD, 0, 0, do_service_time_log_date, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Timestamp with date and time", "日期时戳" },
{ "uptime", CLI_CMD, 0, 0, do_service_time_log_up, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Timestamp with system uptime", "系统运行时间时戳" },
{ CMDS_END }
};
/*wuchunli 2012-2-24 15:47:32 end*/

static struct cmds syslog_cmds[] = {
{ "buffered", CLI_CMD, 0, 0, do_log_buff, no_do_log_buff, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Set buffered logging parameters", "设置系统缓存日志参数" },
{ "host", CLI_CMD, 0, 0, do_log_host, no_do_log_host, NULL, CLI_END_NO, 0, 0,
  "Host ip", "日志主机ip" },
{ "on", CLI_CMD, 0, 0, do_log_on, no_do_log_on, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Enable logging to all supported destinations", "打开系统日志" },
{ "console", CLI_CMD, 0, 0, do_log_console, no_do_log_console, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Set console logging level", "配置监控口日志级别" },
{ "trap", CLI_CMD, 0, 0, do_log_trap, no_do_log_trap, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Set syslog server logging level", "设置日志服务器日志级别" },
/*wuchunli 2012-2-27 9:25:56 begin*/
#if 0
{ "count", CLI_CMD, 0, 0, do_log_count, no_do_log_count, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Count every log message and timestamp last occurance", "统计日志和最后事件的时间戳" },
{ "rate-limit", CLI_CMD, 0, 0, do_log_rate, no_do_log_rate, NULL, CLI_END_NO, 0, 0,
  "Set messages per second limit", "设置对日志信息进行速率控制" },
{ "facility", CLI_CMD, 0, 0, do_log_facility, no_do_log_facility, NULL, CLI_END_NO, 0, 0,
  "Facility parameter for syslog messages", "设置日志消息设备" },
{ "userinfo", CLI_CMD, 0, 0, do_log_userinfo, no_do_log_userinfo, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Logging user login/logout ", "设置用户登录/退出的日志信息" },
{ "command", CLI_CMD, 0, 0, do_log_command, no_do_log_command, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Logging while each command being executed", "启用命令日志输出功能" },
/*wuchunli 2012-2-27 10:03:57 end*/
#endif
{ CMDS_END }
};

/*wuchunli 2012-2-27 10:08:44 begin*/
static struct cmds syslog_rate_cmds[] = {
{ "<1-10000>", CLI_INT, 0, 0, do_log_rate_value, NULL, NULL,CLI_END_FLAG, 1, 10000,
  "Messages per second", "设置每秒输出日志条数" },
{ CMDS_END }
};

/*Facility values MUST be in the range of 0 to 23 inclusive*/
static struct cmds syslog_facility_cmds[] = {
{ "kernel", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Kernel[0]", "内核[0]" },
{ "user-level", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "User-level messages[1]", "用户进程[1]" },
{ "mail", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "mail system[2]", "邮件系统[2]" },
{ "daemon", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "system daemons[3]", "系统守护进程[3]" },
{ "security1", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "security/authorization messages(note1)[4]", "安全认证1[4]" },
{ "syslog", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "messages generated internally by syslogd[5]", "SYSLOG自己[5]" },
{ "line-printer", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "line printer subsystem[6]", "行打印机系统[6]" },
{ "news", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "network news subsystem[7]", "USENET新闻[7]" },
{ "UUCP", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "UUCP subsystem[8]", "Unix到Unix拷贝系统[8]" },
{ "clock1", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "clock daemon(note1)[9]", "时钟进程1[9]" },
{ "security2", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "security/authorization messages[10]", "安全认证2[10]" },
{ "FTP", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "FTP daemon[11]", "FTP守护进程[11]" },
{ "NTP", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "NTP subsystem[12]", "网络时钟[12]" },
{ "log-audit", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "log audit[13]", "日志审计[13]" },
{ "log-alert", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "log alert[14]", "日志警告[14]" },
{ "clock2", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "clock daemon (note 2)[15]", "时钟进程2[15]" },
{ "local0", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "local use 0[16]", "本地使用0[16]" },
{ "local1", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "local use 1[17]", "本地使用1[17]" },
{ "local2", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "local use 2[18]", "本地使用2[18]" },
{ "local3", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "local use 3[19]", "本地使用3[19]" },
{ "local4", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "local use 4[20]", "本地使用4[20]" },
{ "local5", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "local use 5[21]", "本地使用5[21]" },
{ "local6", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "local use 6[22]", "本地使用6[22]" },
{ "local7", CLI_CMD, 0, 0, do_log_facility_value, NULL, NULL, CLI_END_FLAG, 0, 0,
  "local use 7[23]", "本地使用7[23]" },
{ CMDS_END }
};
/*wuchunli 2012-2-27 10:08:51 end*/


static struct cmds syslog_buff_cmds[] = {
{ "<4096-1048576>", CLI_INT, 0, 0, do_log_buff_value, NULL, NULL, CLI_END_FLAG, 4096, 1048576,
  "Logging buffer size(bytes)", "日志缓存容量(字节数)" },
{ "alerts", CLI_CMD, 0, 0, do_log_buff_alerts, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Immediate action needed[1]", "需要马上行动[1]" },
{ "critical", CLI_CMD, 0, 0, do_log_buff_crit, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Critical conditions[2]", "临界情况[2]" },
{ "debugging", CLI_CMD, 0, 0, do_log_buff_debug, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Debugging messages[7]", "调试信息[7]" },
{ "emergencies", CLI_CMD, 0, 0, do_log_buff_emerg, NULL, NULL, CLI_END_FLAG, 0, 0,
  "System is unusable[0]", "系统不可用[0]" },
{ "errors", CLI_CMD, 0, 0, do_log_buff_erro, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Error conditions[3]", "错误情况[3]" },
{ "informational", CLI_CMD, 0, 0, do_log_buff_infor, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Informational messages[6]", "报告性信息[6]" },
{ "notifications", CLI_CMD, 0, 0, do_log_buff_notif, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Normal but significant conditions[5]", "正常但很重要的情况[5]" },
{ "warnings", CLI_CMD, 0, 0, do_log_buff_warni, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Warning conditions[4]", "警告情况[4]" },
{ CMDS_END }
};

static struct cmds syslog_host_cmds[] = {
{ "A.B.C.D", CLI_IPV4, 0, 0, do_log_host_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
  "IP address of the logging host", "日志主机ip地址" },
{ CMDS_END }
};

static struct cmds syslog_console_cmds[] = {
{ "alerts", CLI_CMD, 0, 0, do_log_cons_alerts, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Immediate action needed[1]", "需要马上行动[1]" },
{ "critical", CLI_CMD, 0, 0, do_log_cons_crit, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Critical conditions[2]", "临界情况[2]" },
{ "debugging", CLI_CMD, 0, 0, do_log_cons_debug, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Debugging messages[7]", "调试信息[7]" },
{ "emergencies", CLI_CMD, 0, 0, do_log_cons_emerg, NULL, NULL, CLI_END_FLAG, 0, 0,
  "System is unusable[0]", "系统不可用[0]" },
{ "errors", CLI_CMD, 0, 0, do_log_cons_erro, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Error conditions[3]", "错误情况[3]" },
{ "informational", CLI_CMD, 0, 0, do_log_cons_infor, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Informational messages[6]", "报告性信息[6]" },
{ "notifications", CLI_CMD, 0, 0, do_log_cons_notif, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Normal but significant conditions[5]", "正常但很重要的情况[5]" },
{ "warnings", CLI_CMD, 0, 0, do_log_cons_warni, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Warning conditions[4]", "警告情况[4]" },
{ CMDS_END }
};

static struct cmds syslog_trap_cmds[] = {
{ "alerts", CLI_CMD, 0, 0, do_log_trap_alerts, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Immediate action needed[1]", "需要马上行动[1]" },
{ "critical", CLI_CMD, 0, 0, do_log_trap_crit, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Critical conditions[2]", "临界情况[2]" },
{ "debugging", CLI_CMD, 0, 0, do_log_trap_debug, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Debugging messages[7]", "调试信息[7]" },
{ "emergencies", CLI_CMD, 0, 0, do_log_trap_emerg, NULL, NULL, CLI_END_FLAG, 0, 0,
  "System is unusable[0]", "系统不可用[0]" },
{ "errors", CLI_CMD, 0, 0, do_log_trap_erro, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Error conditions[3]", "错误情况[3]" },
{ "informational", CLI_CMD, 0, 0, do_log_trap_infor, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Informational messages[6]", "报告性信息[6]" },
{ "notifications", CLI_CMD, 0, 0, do_log_trap_notif, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Normal but significant conditions[5]", "正常但很重要的情况[5]" },
{ "warnings", CLI_CMD, 0, 0, do_log_trap_warni, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Warning conditions[4]", "警告情况[4]" },
{ CMDS_END }
};

/*wuchunli 2012-2-24 15:51:22 begin*/
static int do_log_count(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_log_count\n");
    }
    return retval;
}

static int no_do_log_count(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("no_do_log_count\n");
    }
    return retval;
}

static int do_log_facility_value(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_log_facility_value\n");
    }
    return retval;
}

static int no_do_log_facility(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("no_do_log_facility\n");
    }
    return retval;
}

static int do_log_rate(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(syslog_rate_cmds, argc, argv, u);

    return retval;
}

static int no_do_log_rate(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("no_do_log_rate\n");
    }
    return retval;
}

static int do_log_rate_value(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_log_rate_value\n");
    }
    return retval;
}

static int do_log_facility(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(syslog_facility_cmds, argc, argv, u);

    return retval;
}

static int do_log_userinfo(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_log_userinfo\n");
    }
    return retval;
}

static int no_do_log_userinfo(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("no_do_log_userinfo\n");
    }
    return retval;
}

static int do_log_command(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_log_command\n");
    }
    return retval;
}

static int no_do_log_command(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("no_do_log_command\n");
    }
    return retval;
}

static int do_service(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(service_cmds, argc, argv, u);

    return retval;
}

static int do_service_time(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_service_time\n");
    }

    retval = sub_cmdparse(service_time_cmds, argc, argv, u);

    return retval;
}

static int do_service_time_debug(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_service_time_debug\n");
    }

    retval = sub_cmdparse(service_time_debug_cmds, argc, argv, u);

    return retval;
}

static int do_service_time_log(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_service_time_log\n");
    }

    retval = sub_cmdparse(service_time_log_cmds, argc, argv, u);

    return retval;
}

static int do_service_time_debug_date(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_service_time_debug_date\n");
    }

    return retval;
}

static int do_service_time_debug_up(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_service_time_debug_up\n");
    }

    return retval;
}

static int do_service_time_log_date(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_service_time_log_date\n");
    }

    return retval;
}

static int do_service_time_log_up(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_service_time_log_up\n");
    }

    return retval;
}

static int do_service_sysname(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_service_sysname\n");
    }

    return retval;
}

static int do_service_number(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("do_service_number\n");
    }

    return retval;
}

static int no_do_service_time(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("no_do_service_time\n");
    }

    retval = sub_cmdparse(service_time_cmds, argc, argv, u);

    return retval;
}

static int no_do_service_time_debug(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("no_do_service_time_debug\n");
    }

    return retval;
}

static int no_do_service_time_log(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("no_do_service_time_log\n");
    }

    return retval;
}

static int no_do_service_sysname(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("no_do_service_sysname\n");
    }

    return retval;
}

static int no_do_service_number(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        printf("no_do_service_number\n");
    }

    return retval;
}
/*wuchunli 2012-2-24 15:52:03 end*/

/*
 *  Function:  do_syslog
 *  Purpose:  topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_syslog(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(syslog_cmds, argc, argv, u);

    return retval;
}

/*
 *  Function:  do_log_buff
 *  Purpose:  logging buffered subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_buff(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_buf_default(u);
    }

    retval = sub_cmdparse(syslog_buff_cmds, argc, argv, u);

    return retval;
}

/*
 *  Function:  no_do_log_buff
 *  Purpose:  no logging buffered subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int no_do_log_buff(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        nfunc_log_buff(u);
    }

    return retval;
}

/*
 *  Function:  no_do_log_host
 *  Purpose:  no logging host subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int no_do_log_host(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
          nfunc_log_host(u);
    }
    return retval;
}

/*
 *  Function:  no_do_log_on
 *  Purpose:  no logging on subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int no_do_log_on(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
       nfunc_log_on(u);
    }
    return retval;
}

/*
 *  Function:  no_do_log_console
 *  Purpose:  no logging console subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int no_do_log_console(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        nfunc_log_console(u);
    }
    return retval;
}

/*
 *  Function:  no_do_log_trap
 *  Purpose:  no logging trap subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int no_do_log_trap(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        nfunc_log_trap(u);
    }
    return retval;
}

/*
 *  Function:  do_log_host
 *  Purpose:  logging host subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_host(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(syslog_host_cmds, argc, argv, u);

    return retval;
}

/*
 *  Function:  do_log_on
 *  Purpose:  logging on subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_on(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_on(u);
    }
    return retval;
}

/*
 *  Function:  do_log_console
 *  Purpose:  logging console subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_console(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_con_default(u);
    }

    retval = sub_cmdparse(syslog_console_cmds, argc, argv, u);

    return retval;
}

/*
 *  Function:  do_log_trap
 *  Purpose:  logging trap subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_trap(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_trap_default(u);
    }

    retval = sub_cmdparse(syslog_trap_cmds, argc, argv, u);

    return retval;
}

/*
 *  Function:  do_log_buff_value
 *  Purpose:  logging buffered <4096-1048576> subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_buff_value(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_buff_value(u);
    }
    return retval;
}

/*
 *  Function:  do_log_buff_alerts
 *  Purpose:  logging buffered alerts subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_buff_alerts(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_buff_alerts(u);
    }
    return retval;
}

/*
 *  Function:  do_log_buff_crit
 *  Purpose:  logging buffered critical subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_buff_crit(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_buff_crit(u);
    }
    return retval;
}

/*
 *  Function:  do_log_buff_debug
 *  Purpose:  logging buffered debugging subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_buff_debug(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_buff_debug(u);
    }
    return retval;
}

/*
 *  Function:  do_log_buff_emerg
 *  Purpose:  logging buffered emergencies subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_buff_emerg(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_buff_emerg(u);
    }
    return retval;
}

/*
 *  Function:  do_log_buff_erro
 *  Purpose:  logging buffered errors subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_buff_erro(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_buff_erro(u);
    }
    return retval;
}

/*
 *  Function:  do_log_buff_infor
 *  Purpose:  logging buffered informational subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_buff_infor(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_buff_infor(u);
    }
    return retval;
}

/*
 *  Function:  do_log_buff_notif
 *  Purpose:  logging buffered notifications subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_buff_notif(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
     func_log_buff_notif(u);
    }
    return retval;
}

/*
 *  Function:  do_log_buff_warni
 *  Purpose:  logging buffered warnings subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_buff_warni(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_buff_warni(u);
    }
    return retval;
}

/*
 *  Function:  do_log_host_ip
 *  Purpose:  logging host A.B.C.D subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_host_ip(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_host_ip(u);
    }
    return retval;
}

/*
 *  Function:  do_log_cons_alerts
 *  Purpose:  logging console alerts subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_cons_alerts(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
       func_log_cons_alerts(u);
    }
    return retval;
}

/*
 *  Function:  do_log_cons_crit
 *  Purpose:  logging console critical subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_cons_crit(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_cons_crit(u);
    }
    return retval;
}

/*
 *  Function:  do_log_cons_debug
 *  Purpose:  logging console debugging subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_cons_debug(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_cons_debug(u);
    }
    return retval;
}

/*
 *  Function:  do_log_cons_emerg
 *  Purpose:  logging console emergencies subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_cons_emerg(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_cons_emerg(u);
    }
    return retval;
}

/*
 *  Function:  do_log_cons_erro
 *  Purpose:  logging console errors subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_cons_erro(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
      func_log_cons_erro(u);
    }
    return retval;
}

/*
 *  Function:  do_log_cons_infor
 *  Purpose:  logging console informational subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_cons_infor(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_cons_infor(u);
    }
    return retval;
}

/*
 *  Function:  do_log_cons_notif
 *  Purpose:  logging console notifications subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_cons_notif(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
       func_log_cons_notif(u);
    }
    return retval;
}

/*
 *  Function:  do_log_cons_warni
 *  Purpose:  logging console warnings subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_cons_warni(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
      func_log_cons_warni(u);
    }
    return retval;
}

/*
 *  Function:  do_log_trap_alerts
 *  Purpose:  logging trap alerts subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_trap_alerts(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_trap_alerts(u);
    }
    return retval;
}

/*
 *  Function:  do_log_trap_crit
 *  Purpose:  logging trap critical subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_trap_crit(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
      func_log_trap_crit(u);
    }
    return retval;
}

/*
 *  Function:  do_log_trap_debug
 *  Purpose:  logging trap debugging subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_trap_debug(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
       func_log_trap_debug(u);
    }
    return retval;
}

/*
 *  Function:  do_log_trap_emerg
 *  Purpose:  logging trap emergencies subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_trap_emerg(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_trap_emerg(u);
    }
    return retval;
}

/*
 *  Function:  do_log_trap_erro
 *  Purpose:  logging trap errors subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_trap_erro(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
       func_log_trap_erro(u);
    }
    return retval;
}

/*
 *  Function:  do_log_trap_infor
 *  Purpose:  logging trap informational subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_trap_infor(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
       func_log_trap_infor(u);
    }
    return retval;
}

/*
 *  Function:  do_log_trap_notif
 *  Purpose:  logging trap notifications subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_trap_notif(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
        func_log_trap_notif(u);
    }
    return retval;
}

/*
 *  Function:  do_log_trap_warni
 *  Purpose:  logging trap warnings subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
static int do_log_trap_warni(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /* Do application function */
       func_log_trap_warni(u);
    }
    return retval;
}

/*
 *  Function:  init_cli_syslog
 *  Purpose:  Register syslog function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:   chunli.wu
 *  Date:    2011/11/08
 */
int init_cli_syslog(void)
{
    int retval = -1;

	   retval = registerncmd(syslog_topcmds, (sizeof(syslog_topcmds)/sizeof(struct topcmds) - 1));
	   DEBUG_MSG(1,"init_cli_syslog retval = %d\n", retval);

	   return retval;
}

