/*
 * Copyright 2016 by Kuaipao Corporation
 *
 * All Rights Reserved
 *
 * File name  : cli_err_dis_rec.c
 * Function   : errdisable command function
 * Auther     : jialong.chu
 * Version    : 1.00
 * Date       : 2011/11/7
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
 2011/11/7  1.01        shanming.ren   errdisable detect cause all
                                       errdisable detect cause aggregation-flap
                                       errdisable detect cause arp-inspection
                                       errdisable detect cause bpduguard
                                       errdisable detect cause loopback
                                       errdisable detect cause security-violation
                                       errdisable detect cause sfp-config-mismatch
                                       errdisable detect cause udld
                                       errdisable recover cause all
                                       errdisable recover cause aggregation-flap
                                       errdisable recover cause arp-inspection
                                       errdisable recover cause bpduguard
                                       errdisable recover cause loopback
                                       errdisable recover cause security-violation
                                       errdisable recover cause sfp-config-mismatch
                                       errdisable recover cause udld
                                       errdisable recover interval xxx
                                       no errdisable detect cause all
                                       no errdisable detect cause aggregation-flap
                                       no errdisable detect cause arp-inspection
                                       no errdisable detect cause bpduguard
                                       no errdisable detect cause loopback
                                       no errdisable detect cause security-violation
                                       no errdisable detect cause sfp-config-mismatch
                                       no errdisable detect cause udld
                                       no errdisable recover cause all
                                       no errdisable recover cause aggregation-flap
                                       no errdisable recover cause arp-inspection
                                       no errdisable recover cause bpduguard
                                       no errdisable recover cause loopback
                                       no errdisable recover cause security-violation
                                       no errdisable recover cause sfp-config-mismatch
                                       no errdisable recover cause udld
                                       no errdisable recover interval xxx

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

#include "cli_errdisable.h"
#include "cli_errdisable_func.h"
#include "../err_disable/err_disable.h"
#include "../bcmutils/bcmutils.h"
/*************************
static struct topcmds topcmds[] =
{
    { "name", pv_level, TREE, func, no_func, def_func, endflag, argcmin, argcmax,
        "help_en", "help_cn" },
    { TOPCMDS_END }
};

static struct cmds cmds[] =
{
    { "name", MATCH_MODE, pv_level, maskbit, func, no_func, def_func, endflag, argcmin, argcmax,
        "help_en", "help_cn" },
    { CMDS_END }
};
**************************/

extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       shanming.ren      add the edr_topcmds[]

 */
static struct topcmds edr_topcmds[] =
{
    { "errdisable", 0, CONFIG_TREE, do_edr, do_edr, NULL, CLI_END_NONE, 0, 0,
        "Error disable configuation ", "有关错误机制的配置" },
    { TOPCMDS_END }
};

/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       shangming.ren    add edr_det_cmds[]
 2011/11/7  1.01       shangming.ren    add edr_rec_cmds[]

 */
static struct cmds edr_cmds[] =
{
    { "detect", CLI_CMD, 0, 0, do_edr_det, do_edr_det, NULL, CLI_END_NONE, 0, 0,
        "Error disable detection", "错误检测配置" },
    { "recovery", CLI_CMD, 0, 0, do_edr_rec, do_edr_rec, NULL, CLI_END_NONE, 0, 0,
        "Error disable recovery", "错误消失后的恢复配置" },
    { CMDS_END }
};

static struct cmds edr_det_cmds[] =
{
    { "cause", CLI_CMD, 0, 0, do_edr_det_cau, do_edr_det_cau, NULL, CLI_END_NONE, 0, 0,
        "Error disable detection", "错误检测" },
    { CMDS_END }
};
static struct cmds edr_det_cau_cmds[] =
{
    { "all", CLI_CMD, 0, 0, do_edr_det_cau_all, no_do_edr_det_cau_all, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable error detection on all cases", "所有错误检测" },
    { "aggregation-flap", CLI_CMD, 0, 0, do_edr_det_cau_agg, no_do_edr_det_cau_agg, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable error detection on aggregation-flap", "汇聚组震荡检测" },
		/*
    { "arp-inspection", CLI_CMD, 0, 0, do_edr_det_cau_arp, no_do_edr_det_cau_arp, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable error detection for arp inspection", "ARP 检测" },
		*/
    { "bpduguard", CLI_CMD, 0, 0, do_edr_det_cau_bpdu, no_do_edr_det_cau_bpdu, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable error detection on bpdu-guard", "BPDU 包防护检测" },
    { "loopback", CLI_CMD, 0, 0, do_edr_det_cau_loopback, no_do_edr_det_cau_loopback, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable error detection on loopback", "回环检测" },
		/*
    { "security-violation", CLI_CMD, 0, 0, do_edr_det_cau_sv, no_do_edr_det_cau_sv, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable error detection on 802.1x-guard", "802.1x 协议安全防护检测" },
    { "sfp-config-mismatch", CLI_CMD, 0, 0, do_edr_det_cau_sfp, no_do_edr_det_cau_sfp, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable error detection on SFP config mismatch", "SFP 配置不匹配检测" },
    { "udld", CLI_CMD, 0, 0, do_edr_det_cau_udld, no_do_edr_det_cau_udld, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable error detection on udld error", "单向链路检测" },
		*/
    { CMDS_END }
};

static struct cmds edr_rec_cmds[] =
{
    { "cause", CLI_CMD, 0, 0, do_edr_rec_cau, NULL, NULL, CLI_END_NONE, 0, 0,
        "Enable error disable recovery for application", "启用错误恢复的应用" },
    { "interval", CLI_CMD, 0, 0, do_edr_rec_itv, no_do_edr_rec_itv, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
        "Error disable recovery timer value", "错误恢复的时间配置" },
    { CMDS_END }
};

static struct cmds edr_rec_cau_cmds[] =
{
    { "all", CLI_CMD, 0, 0, do_edr_rec_cau_all, no_do_edr_rec_cau_all, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable timer to recover from all errors", "对所有错误启用恢复机制" },
    { "aggregation-flap", CLI_CMD, 0, 0, do_edr_rec_cau_agg, no_do_edr_rec_cau_agg, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable timer to recover from channel misconfig error", "对汇聚组震荡启用恢复机制" },
		/*
    { "arp-inspection", CLI_CMD, 0, 0, do_edr_rec_cau_arp, no_do_edr_rec_cau_arp, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable timer to recover from arp inspection error", "对ARP错误启用恢复机制" },
		*/
    { "bpduguard", CLI_CMD, 0, 0, do_edr_rec_cau_bpdu, no_do_edr_rec_cau_bpdu, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable timer to recover from BPDU Guard error", "对 BPDU 错误启用恢复机制" },
    { "loopback", CLI_CMD, 0, 0, do_edr_rec_cau_loopback, no_do_edr_rec_cau_loopback, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable timer to recover from loopback error", "对回环错误启用恢复机制" },
		/*
    { "security-violation", CLI_CMD, 0, 0, do_edr_rec_cau_sv, no_do_edr_rec_cau_sv, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable timer to recover from 802.1x violation error", "对 802.1x 认证错误启用恢复机制" },
    { "sfp-config-mismatch", CLI_CMD, 0, 0, do_edr_rec_cau_sfp, no_do_edr_rec_cau_sfp, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable timer to recover from SFP config mismatch error", "对 SFP 配置不匹配错误启用恢复机制" },
    { "udld", CLI_CMD, 0, 0, do_edr_rec_cau_udld, no_do_edr_rec_cau_udld, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
        "Enable timer to recover from udld error", "对单向链路错误启用恢复机制" },
		*/
    { CMDS_END }
};

static struct cmds edr_rec_itv_cmds[] =
{
    { "<30-86400>", CLI_INT, 0, 0, do_edr_rec_itv_val, NULL, NULL, CLI_END_FLAG, 30, 86400,
        "Timer-interval(sec)", "时间值(单位为秒)" },
    { CMDS_END }
};

/*
 * Function Name:do_edr
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      parse the string behind of "errdisable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 *
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(edr_cmds, argc, argv, u);

    return retval;
}

/*
 * Function Name:do_edr_det
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      parse the string behind of "errdisable detect"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 *
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_det(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(edr_det_cmds, argc, argv, u);

    return retval;
}

/*
 * Function Name:do_edr_det_cau
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      parse the string behind of "errdisable detect cause"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 *
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_det_cau(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(edr_det_cau_cmds, argc, argv, u);

    return retval;
}

/*
 * Function Name:do_edr_det_cau_all
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable detect cause all", change the config of "err_disable_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 *
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_det_cau_all(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    int i;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*errdisable detect cause all*/
        for(i = 0; i < EVENT_NUMBER-1; i++)
        {
            func_set_errdisable_detect(i);
        }
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
		if(access(IPC_PATH_LACP, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR1 lacp >/dev/null 2>&1");
		}
		if(access(IPC_PATH_RSTP, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
		}
		if(access(IPC_PATH_LOOPBACK, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR1 loopback >/dev/null 2>&1");
		}
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Enable error disable detection on all cases, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_det_cau_agg
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable detect cause aggregation-flap", change the config of "err_disable_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 *
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_det_cau_agg(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*errdisable detect cause aggregation-flap*/
        func_set_errdisable_detect(ERR_SRC_AGGREGATION);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
		if(access(IPC_PATH_LACP, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR1 lacp >/dev/null 2>&1");
		}
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Enable error disable detection on aggregation-flap, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_det_cau_arp
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable detect cause arp-inspection", change the config of "err_disable_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 *
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_det_cau_arp(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*errdisable detect cause arp-inspection*/
        func_set_errdisable_detect(ERR_SRC_ARP);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Enable error disable detection on arp-inspection, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_det_cau_bpdu
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable detect cause bpduguard", change the config of "err_disable_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 *
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_det_cau_bpdu(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*errdisable detect cause bpduguard*/
        func_set_errdisable_detect(ERR_SRC_BPDUGUARD);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
		if(access(IPC_PATH_RSTP, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
		}
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Enable error disable detection on bpdu-guard, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_det_cau_loopback
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable detect cause loopback", change the config of "err_disable_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 *
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_det_cau_loopback(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*errdisable detect cause loopback*/
        func_set_errdisable_detect(ERR_SRC_LOOPBACK);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
		if(access(IPC_PATH_LOOPBACK, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR1 loopback >/dev/null 2>&1");
		}
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Enable error disable detection on loopback, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_det_cau_sv
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable detect cause security-violation", change the config of "err_disable_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_det_cau_sv(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*errdisable detect cause security-violation*/
        func_set_errdisable_detect(ERR_SRC_SECURITY);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Enable error disable detection on 802.1x-guard, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_det_cau_sfp
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable detect cause sfp-config-mismatch", change the config of "err_disable_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_det_cau_sfp(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*errdisable detect cause sfp-config-mismatch*/
        func_set_errdisable_detect(ERR_SRC_SFP);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Enable error disable detection on SFP config mismatch, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_det_cau_udld
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable detect cause udld", change the config of "err_disable_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_det_cau_udld(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*errdisable detect cause udld*/
        func_set_errdisable_detect(ERR_SRC_UDLD);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Enable error disable detection on udld, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_rec
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      parse the string behind of "errdisable recover"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(edr_rec_cmds, argc, argv, u);

    return retval;
}

/*
 * Function Name:do_edr_rec_cau
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      parse the string behind of "errdisable recover cause"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec_cau(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(edr_rec_cau_cmds, argc, argv, u);

    return retval;
}

/*
 * Function Name:do_edr_rec_cau_all
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable recover cause all", change the config of "err_recover_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec_cau_all(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    int i;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        for(i = 0; i < EVENT_NUMBER-1; i++)
        {
            func_set_recover_detect(i);
        }
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Enable timer to recover from all errors, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_rec_cau_agg
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable recover cause aggregation-flap", change the config of "err_recover_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec_cau_agg(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*Enable timer to recover from aggregation-flap errors*/
        func_set_recover_detect(ERR_SRC_AGGREGATION);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Enable timer to recover from aggregation-flap error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_rec_cau_arp
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable recover cause arp-inspection", change the config of "err_recover_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec_cau_arp(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*Enable timer to recover from arp-inspection error*/
        func_set_recover_detect(ERR_SRC_ARP);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Enable timer to recover from arp-inspection error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_rec_cau_bpdu
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable recover cause bpduguard", change the config of "err_recover_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec_cau_bpdu(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*Enable timer to recover from bpduguard error*/
        func_set_recover_detect(ERR_SRC_BPDUGUARD);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Enable timer to recover from bpdu-guard error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_rec_cau_loopback
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable recover cause loopback", change the config of "err_recover_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec_cau_loopback(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*Enable timer to recover from loopback error*/
        func_set_recover_detect(ERR_SRC_LOOPBACK);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Enable timer to recover from loopback error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_rec_cau_sv
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable recover cause security-violation", change the config of "err_recover_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec_cau_sv(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*Enable timer to recover from security-violation error*/
        func_set_recover_detect(ERR_SRC_SECURITY);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Enable timer to recover from 802.1x-guard error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_rec_cau_sfp
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable recover cause sfp-config-mismatch", change the config of "err_recover_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec_cau_sfp(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*Enable timer to recover from sfp-config-mismatch error*/
        func_set_recover_detect(ERR_SRC_SFP);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Enable timer to recover from sfp-config-mismatch error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_rec_cau_udld
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable recover cause udld", change the config of "err_recover_cfg"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec_cau_udld(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*Enable timer to recover from udld error*/
        func_set_recover_detect(ERR_SRC_UDLD);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Enable timer to recover from udld error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:do_edr_rec_itv
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      parse the string behind of "errdisable recover interval"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec_itv(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    retval = sub_cmdparse(edr_rec_itv_cmds, argc, argv, u);

    return retval;
}

/*
 * Function Name:do_edr_rec_itv_val
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "errdisable recover interval xxx", change the config of "err_recover_time"
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int do_edr_rec_itv_val(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*Error disable recovery timer value*/
        func_set_recover_time(argv[0]);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: The time of error recovery was set to %s, %s\n", argv[0], getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_det_cau_all
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable detect cause all", change the config of "err_disable_cfg"
 *      -- disable all error detection
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_det_cau_all(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    int iTmp;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*no errdisable detect cause all*/
        for(iTmp = 0; iTmp < EVENT_NUMBER-1; iTmp++)
        {
            nfunc_set_errdisable_detect(iTmp);
        }
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
		if(access(IPC_PATH_LACP, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR1 lacp >/dev/null 2>&1");
		}
		if(access(IPC_PATH_RSTP, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
		}
		if(access(IPC_PATH_LOOPBACK, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR1 loopback >/dev/null 2>&1");
		}
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Disable error disable detection on all cases, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_det_cau_agg
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable detect cause aggregation-flap", change the config of "err_disable_cfg"
 *      -- disable aggregation-flap error detection
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_det_cau_agg(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_errdisable_detect(ERR_SRC_AGGREGATION);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
		if(access(IPC_PATH_LACP, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR1 lacp >/dev/null 2>&1");
		}
		
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Disable error disable detection on aggregation-flap, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_det_cau_arp
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable detect cause arp-inspection", change the config of "err_disable_cfg"
 *      -- disable arp-inspection error detection
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_det_cau_arp(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_errdisable_detect(ERR_SRC_ARP);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Disable error disable detection on arp-inspection, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_det_cau_bpdu
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable detect cause bpduguard", change the config of "err_disable_cfg"
 *      -- disable bpduguard error detection
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_det_cau_bpdu(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_errdisable_detect(ERR_SRC_BPDUGUARD);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
		if(access(IPC_PATH_RSTP, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
		}
		
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Disable error disable detection on bpdu-guard, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_det_cau_loopback
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable detect cause loopback", change the config of "err_disable_cfg"
 *      -- disable loopback error detection
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_det_cau_loopback(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_errdisable_detect(ERR_SRC_LOOPBACK);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
		if(access(IPC_PATH_LOOPBACK, F_OK) == 0)
		{
			SYSTEM("/usr/bin/killall -SIGUSR1 loopback >/dev/null 2>&1");
		}
		
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Disable error disable detection on loopback, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_det_cau_sv
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable detect cause security-violation", change the config of "err_disable_cfg"
 *      -- disable security-violation error detection
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_det_cau_sv(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_errdisable_detect(ERR_SRC_SECURITY);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Disable error disable detection on 802.1x-guard, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_det_cau_sfp
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable detect cause sfp-config-mismatch", change the config of "err_disable_cfg"
 *      -- disable sfp-config-mismatch error detection
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_det_cau_sfp(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_errdisable_detect(ERR_SRC_SFP);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Disable error disable detection on SFP config mismatch, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}


/*
 * Function Name:no_do_edr_det_cau_udld
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable detect cause udld", change the config of "err_disable_cfg"
 *      -- disable udld error detection
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_det_cau_udld(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_errdisable_detect(ERR_SRC_UDLD);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_DISABLE]: Disable error disable detection on udld, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_rec_cau_all
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable recover cause all", change the config of "err_recover_cfg"
 *      -- disable all errors recovery
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_rec_cau_all(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    int iTmp;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        /*no errdisable detect cause all*/
        for(iTmp = 0; iTmp < EVENT_NUMBER-1; iTmp++)
        {
            nfunc_set_recover_detect(iTmp);
        }
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Disable timer to recover from all errors, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_rec_cau_agg
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable recover cause aggregation-flap", change the config of "err_recover_cfg"
 *      -- disable aggregation-flap error recovery
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_rec_cau_agg(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_recover_detect(ERR_SRC_AGGREGATION);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Disable timer to recover from aggregation-flap error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_rec_cau_arp
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable recover cause arp-inspection", change the config of "err_recover_cfg"
 *      -- disable arp-inspection error recovery
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_rec_cau_arp(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_recover_detect(ERR_SRC_ARP);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Disable timer to recover from arp-inspection error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_rec_cau_bpdu
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable recover cause bpduguard", change the config of "err_recover_cfg"
 *      -- disable bpduguard error recovery
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_rec_cau_bpdu(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_recover_detect(ERR_SRC_BPDUGUARD);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Disable timer to recover from bpdu-guard error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}


/*
 * Function Name:no_do_edr_rec_cau_loopback
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable recover cause loopback", change the config of "err_recover_cfg"
 *      -- disable loopback error recovery
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_rec_cau_loopback(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_recover_detect(ERR_SRC_LOOPBACK);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Disable timer to recover from loopback error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_rec_cau_sv
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable recover cause security-violation", change the config of "err_recover_cfg"
 *      -- disable security-violation error recovery
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_rec_cau_sv(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_recover_detect(ERR_SRC_SECURITY);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Disable timer to recover from 802.1x-guard error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}


/*
 * Function Name:no_do_edr_rec_cau_sfp
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable recover cause sfp-config-mismatch", change the config of "err_recover_cfg"
 *      -- disable sfp-config-mismatch error recovery
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_rec_cau_sfp(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_recover_detect(ERR_SRC_SFP);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Disable timer to recover from sfp-config-mismatch error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_rec_cau_udld
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable recover cause udld", change the config of "err_recover_cfg"
 *      -- disable udld error recovery
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_rec_cau_udld(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_recover_detect(ERR_SRC_UDLD);
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: Disable timer to recover from udld error, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:no_do_edr_rec_itv
 *
 * Parameters: argc -- "argc" characters is left not parse
 * Parameters: argv -- the string of not parse
 * Parameters: u    -- the global environment variable, if you want to get some parameters of command,
 *                     you can call the library function by passing this parameter
 *
 * Function description:
 *      if the command is "no errdisable recover interval", change the config of "err_recover_time"
 *      -- error recovery time will be set to the default
 *      and send a sigal to process "err_disable"
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
static int no_do_edr_rec_itv(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0)
    {
        nfunc_set_recover_time();
        SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-ERR_RECOVERY]: The time of error recovery was set to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }

    return retval;
}

/*
 * Function Name:init_cli_edr
 *
 *
 * Function description: register errdisable commands
 *
 * Returns: success return 0
 *          fail    retuen -1
 *          the end of command "help"/"tab"  return 1
 *
 * Author:  shanming.ren
 * Date:    2011-11-8
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
int init_cli_errdisable(void)
{
    int retval = -1;
	#if (1==ERR_DISABLE_MODULE)
    retval = registerncmd(edr_topcmds, (sizeof(edr_topcmds)/sizeof(struct topcmds) - 1));
	#endif
    DEBUG_MSG(1,"init_cli_errdisable retval = %d\n", retval);

    return retval;
}

