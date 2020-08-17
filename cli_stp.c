/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_stp.c
 * Function   : spanning-tree command function
 * Auther     : jialong.chu
 * Version    : 1.0
 * Date       : 2011/11/4
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
 2011/11/07  1.01       chunli.wu
                                       CONFIG_TREE:
                                       spanning-tree <cr>
                                       spanning-tree mode rstp <cr>
                                       spanning-tree rstp forward-time <4-30> <cr>
                                       spanning-tree rstp hello-time <1-10> <cr>
                                       spanning-tree rstp max-age <6-40> <cr> 
                                       spanning-tree rstp priority <0-61440> <cr>
                                       spanning-tree portfast bpdufilter default <cr>
                                       
                                       no spanning-tree <cr>
                                       no spanning-tree rstp forward-time <cr>
                                       no spanning-tree rstp hello-time <cr>
                                       no spanning-tree rstp max-age <cr>
                                       no spanning-tree rstp priority <cr>
                                       no spanning-tree portfast bpdufilter default <cr>
 
 2013/06/05	 1.0.2		Luo Le		   RSTP has been insteaded by MSTP.
									   CONFIG_TREE:
    								   spanning-tree mode mstp <cr>
    								   spanning-tree mst WORD priority <0-61440> <cr>
    								   spanning-tree mst configuration <cr>
    								   spanning-tree mst forward-time <4-30> <cr>
                                       spanning-tree mst hello-time <1-10> <cr>
    								   spanning-tree mst max-age <6-40> <cr>
    								   spanning-tree mst max-hops <1-255> <cr>
    								   spanning-tree portfast bpdufilter default <cr>
    								   CONFIG_MST_TREE:
    								   instance <1-15> vlan <1-4094> <cr>
    								   name WORD <cr>
    								   revision <0-65535> <cr>
 
                                       
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

#include "cli_stp.h"
#include "cli_stp_func.h"
#include "../bcmutils/bcmutils.h"
/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/07  1.01      chunli.wu        add stp_topcmds[]


 */

static struct topcmds stp_topcmds[] = {
{ "spanning-tree", 0, CONFIG_TREE, do_stp, no_do_stp, NULL, CLI_END_NO, 0, 0,
  "Spanning Tree Subsystem", "配置spanning-tree协议" },
{ TOPCMDS_END }
};

static struct topcmds config_mst_topcmds[] = {
{ "instance", 0, CONFIG_MST_TREE, do_mst_instance, no_do_mst_instance, NULL, CLI_END_NONE, 0, 0,
  "Map vlans to an MST instance", "映射vlan到一个MST实例" },
{ "name", 0, CONFIG_MST_TREE, do_mst_name, no_do_mst_name, NULL, CLI_END_NO, 0, 0,
  "Set configuration name(the max length of name is 32 chars)", "设置配置名称(最大长度不能超过32个字符)" },
#if 0
{ "private-vlan", 0, CONFIG_MST_TREE, do_mst_privlan, NULL, NULL, CLI_END_NO, 0, 0,
  "Set private-vlan synchronization", "设置私有vlan同步" },
#endif
{ "revision", 0, CONFIG_MST_TREE, do_mst_revision, no_do_mst_revision, NULL, CLI_END_NO, 0, 0,
  "Set configuration revision level", "设置配置修订级别" },
#if 0
{ "show", 0, CONFIG_MST_TREE, do_mst_show, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Display region configurations", "显示域配置信息" },
#endif
{ TOPCMDS_END }
};

/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/07  1.01      chunli.wu        add stp_cmds[]


 */
static struct cmds stp_cmds[] = {
{ "mode", CLI_CMD, 0, 0, do_stp_mode, NULL, NULL, 0, 0, 0,
  "Setup spanning-tree protocol mode", "配置生成树协议的模式" },
{ "mst", CLI_CMD, 0, 0, do_stp_mst, NULL, NULL, 0, 0, 0,
  "Multiple spanning tree configuration", "配置多生成树协议的网桥参数" }, /* added by l.l */
{ "stp", CLI_CMD, 0, 0, do_stp_stp, NULL, NULL, 0, 0, 0,
  "Setup spanning-tree protocol on stp mode", "配置生成树协议的网桥参数" },
{ "rstp", CLI_CMD, 0, 0, do_stp_rstp, NULL, NULL, 0, 0, 0,
  "Setup spanning-tree protocol on rstp mode", "配置快速生成树协议的网桥参数" },
//#if (ERR_DISABLE_RSTP)
{ "portfast", CLI_CMD, 0, 0, do_stp_portfast, NULL, NULL, 0, 0, 0,
  "Spanning tree portfast options", "配置生成树协议的 portfast 功能" },
//#endif
{ CMDS_END }
};

static struct cmds no_stp_cmds[] = {
{ "stp", CLI_CMD, 0, 0, NULL, do_stp_stp, NULL, 0, 0, 0,
  "Setup spanning-tree protocol on stp mode", "配置快速生成树协议的网桥参数" },
{ "rstp", CLI_CMD, 0, 0, NULL, do_stp_rstp, NULL, 0, 0, 0,
  "Setup spanning-tree protocol on rstp mode", "配置快速生成树协议的网桥参数" },
{ "mst", CLI_CMD, 0, 0, NULL, no_do_stp_mst, NULL, 0, 0, 0,
  "Multiple spanning tree configuration", "配置多生成树协议的网桥参数" }, /* added by l.l */
//#if(ERR_DISABLE_RSTP)
{ "portfast", CLI_CMD, 0, 0, NULL, do_stp_portfast, NULL, 0, 0, 0,
  "Spanning tree portfast options", "配置生成树协议的 portfast 功能" },
//#endif
{ CMDS_END }
};

static struct cmds stp_mode_cmds[] = {
{ "stp", CLI_CMD, 0, 0, do_stp_mode_stp, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Setup spanning-tree protocol mode", "配置生成树协议为快速生成树模式" },
{ "rstp", CLI_CMD, 0, 0, do_stp_mode_rstp, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Setup rapid spanning-tree protocol mode", "配置生成树协议为快速生成树模式" },
{ "mstp", CLI_CMD, 0, 0, do_stp_mode_mstp, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Setup multiple spanning-tree protocol mode", "配置生成树协议为多生成树模式" }, /* added by luole */
{ CMDS_END }
};

/* added by luole */
static struct cmds stp_mst_cmds[] = {
	{ "WORD", CLI_INT_MULTI, 0, 0, do_stp_mst_word, NULL, NULL, CLI_END_NONE, 0, 15,
		"MST instance range, example: 0-3,5,7-9", "MST实例范围，如：0-3,5,7-9" },
	{ "configuration", CLI_CMD, 0, 0, do_stp_mst_configuration, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Enter MST configuration submode", "进入MST配置模式" },
	{ "forward-time",CLI_CMD, 0, 0, do_stp_mst_fwdtime, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set the forward delay for the spanning tree", "设置转发时延" },
	{ "hello-time", CLI_CMD, 0, 0, do_stp_mst_hellotime, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set the hello interval for the spanning tree", "设置BPDU更新间隔" },
	{ "max-age", CLI_CMD, 0, 0, do_stp_mst_maxage, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set the max age interval for the spanning tree", "设置BPDU最大生存时间" },
	{ "max-hops", CLI_CMD, 0, 0, do_stp_mst_maxhops, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set the max hops value for the spanning tree", "设置BPDU最大跳转数" },
	{ CMDS_END }
};

static struct cmds no_stp_mst_cmds[] = {
	{ "WORD", CLI_INT_MULTI, 0, 0, NULL, do_stp_mst_word, NULL, CLI_END_NONE, 0, 15,
		"MST instance range, example: 0-3,5,7-9", "MST实例范围，如：0-3,5,7-9" },
	{ "forward-time",CLI_CMD, 0, 0, NULL, no_do_stp_mst_fwdtime, NULL, CLI_END_NO, 0, 0,
		"Set the forward delay for the spanning tree", "设置转发时延" },
	{ "hello-time", CLI_CMD, 0, 0, NULL, no_do_stp_mst_hellotime, NULL, CLI_END_NO, 0, 0,
		"Set the hello interval for the spanning tree", "设置BPDU更新间隔" },
	{ "max-age", CLI_CMD, 0, 0, NULL, no_do_stp_mst_maxage, NULL, CLI_END_NO, 0, 0,
		"Set the max age interval for the spanning tree", "设置BPDU最大生存时间" },
	{ "max-hops", CLI_CMD, 0, 0, NULL, no_do_stp_mst_maxhops, NULL, CLI_END_NO, 0, 0,
		"Set the max hops value for the spanning tree", "设置BPDU最大跳转数" },
	{ CMDS_END }
};

static struct cmds stp_mst_word_cmds[] = {
	{ "priority", CLI_CMD, 0, 0, do_stp_mst_word_priority, no_do_stp_mst_word_prio, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Set the bridge priority for the spanning tree", "设置网桥优先级" },
	#if 0
	{ "root", CLI_CMD, 0, 0, do_stp_mst_word_root, do_stp_mst_word_root, NULL, CLI_END_NONE, 0, 0,
		"Configure switch as root", "配置当前交换机为根桥" },
	#endif
	{ CMDS_END }
};

static struct cmds stp_mst_word_priority_cmds[] = {
	{ "<0-61440>", CLI_INT, 0, 0, do_stp_mst_word_priority_param, NULL, NULL, CLI_END_FLAG, 0, 61440,
		"bridge priority in increments of 4096", "网桥优先级为4096的倍数" },
	{ CMDS_END }
};

static struct cmds stp_mst_word_root_cmds[] = {
	{ "primary", CLI_CMD, 0, INSTANCE_ROOT_PRIMARY, do_stp_mst_word_root_param, no_do_stp_mst_word_rt, NULL, 
		CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Configure this switch as primary root for this spanning tree", "It's Chinese!" },
	{ "secondary", CLI_CMD, 0, INSTANCE_ROOT_SECONDARY, do_stp_mst_word_root_param, no_do_stp_mst_word_rt, NULL, 
		CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Configure switch as secondary root", "It's Chinese!" },
	{ CMDS_END }
};

static struct cmds mst_instance_cmds[] = {
	{ "<1-15>", CLI_INT, 0, 0, do_mst_instance_id, NULL, NULL, CLI_END_NONE, 1, 15,
		"MST instance id", "MST实例号" },
	{ CMDS_END }
};

static struct cmds no_mst_instance_cmds[] = {
	{ "<1-15>", CLI_INT, 0, 0, NULL, no_do_mst_instance_id, NULL, CLI_END_NO, 1, 15,
		"MST instance id", "MST实例号" },
	{ CMDS_END }
};

static struct cmds mst_instance_id_cmds[] = {
	{ "vlan", CLI_CMD, 0, 0, do_mst_instance_id_vlan, NULL, NULL, CLI_END_NONE, 0, 0,
		"Range of vlans to add to the instance mapping", "添加VLAN到实例映射" },
	{ CMDS_END }
};

static struct cmds mst_instance_id_vlan_cmds[] = {
	{ "<1-4094>", CLI_INT_MULTI, 0, 0, do_mst_instance_id_vlan_line, no_do_mst_instance_id_vlan_line, NULL, CLI_END_FLAG|CLI_END_NO, 1, 4094,
		"VLAN IDs(1-4094), such as(1,3,5,7) or (1,3-5,7) or (1-7) ", "VLAN范围1-4094，如：(1,3,5,7)或者(1,3-5,7)或者(1-7)" },
	{ CMDS_END }
};

static struct cmds mst_name_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_mst_name_word, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Set configuration name", "设置配置名称" },
	{ CMDS_END }
};

static struct cmds mst_privatevlan_cmds[] = {
	{ "synchronize", CLI_CMD, 0, 0, do_mst_privlan_sync, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Synchronize vlans", "同步VLAN" },
	{ CMDS_END }
};

static struct cmds mst_revision_cmds[] = {
	{ "<0-65535>", CLI_INT, 0, 0, do_mst_revision_param, NULL, NULL, CLI_END_FLAG, 0, 65535,
		"Configuration revision level", "配置修订级别" },
	{ CMDS_END }
};

static struct cmds mst_show_cmds[] = {
	{ "current", CLI_CMD, 0, 0, do_mst_show_current, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Display mst configuration currently used", "显示当前的MST配置信息" },
	{ "pending", CLI_CMD, 0, 0, do_mst_show_pending, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Display the new mst configuration to be applied", "显示未提交的MST配置" },
	{ CMDS_END }
};

static struct cmds stp_mst_fwdtime_cmds[] = {
	{ "<4-30>", CLI_INT, 0, 0, do_stp_mst_fwdtime_param, NULL, NULL, CLI_END_FLAG, 4, 30,
		"number of seconds for the forward delay timer", "MSTP模式下的转发时延" },
	{ CMDS_END }
};

static struct cmds stp_mst_hellotime_cmds[] = {
	{ "<1-10>", CLI_INT, 0, 0, do_stp_mst_hellotime_param, NULL, NULL, CLI_END_FLAG, 1, 10,
		"number of seconds between generation of config BPDUs", "MSTP模式下BPDU的更新间隔" },
	{ CMDS_END }
};

static struct cmds stp_mst_maxage_cmds[] = {
	{ "<6-40>", CLI_INT, 0, 0, do_stp_mst_maxage_param, NULL, NULL, CLI_END_FLAG, 6, 40,
		"maximum number of seconds the information in a BPDU is valid", "MSTP模式下BPDU的最大生存时间" },
	{ CMDS_END }
};

static struct cmds stp_mst_maxhops_cmds[] = {
	{ "<6-40>", CLI_INT, 0, 0, do_stp_mst_maxhops_param, NULL, NULL, CLI_END_FLAG, 6, 40,
		"maximum number of hops a BPDU is valid", "MSTP模式下BPDU的最大跳转次数" },
	{ CMDS_END }
};
/* add end */

static struct cmds stp_rstp_cmds[] = {
{ "forward-time", CLI_CMD, 0, 0, do_stp_rstp_forwardtime, no_do_stp_rstp_forwardtime, NULL, CLI_END_NO, 0, 0,
  "Rstp mode forward time", "Rstp 模式下的转发时延" },
{ "hello-time", CLI_CMD, 0, 0, do_stp_rstp_hellotime, no_do_stp_rstp_hellotime, NULL, CLI_END_NO, 0, 0,
  "Rstp mode hello time", "Rstp 模式下的更新间隔" },
{ "max-age", CLI_CMD, 0, 0, do_stp_rstp_maxage, no_do_stp_rstp_maxage, NULL, CLI_END_NO, 0, 0,
  "Rstp mode max age", "Rstp 模式下的最大生存时间" },
{ "priority", CLI_CMD, 0, 0, do_stp_rstp_priority, no_do_stp_rstp_priority, NULL, CLI_END_NO, 0, 0,
  "Rstp mode priority", "Rstp 模式下的优先值" },
{ CMDS_END }
};

static struct cmds stp_stp_cmds[] = {
{ "forward-time", CLI_CMD, 0, 0, do_stp_rstp_forwardtime, no_do_stp_rstp_forwardtime, NULL, CLI_END_NO, 0, 0,
  "STP mode forward time", "STP 模式下的转发时延" },
{ "hello-time", CLI_CMD, 0, 0, do_stp_rstp_hellotime, no_do_stp_rstp_hellotime, NULL, CLI_END_NO, 0, 0,
  "STP mode hello time", "STP 模式下的更新间隔" },
{ "max-age", CLI_CMD, 0, 0, do_stp_rstp_maxage, no_do_stp_rstp_maxage, NULL, CLI_END_NO, 0, 0,
  "STP mode max age", "STP 模式下的最大生存时间" },
{ "priority", CLI_CMD, 0, 0, do_stp_rstp_priority, no_do_stp_rstp_priority, NULL, CLI_END_NO, 0, 0,
  "STP mode priority", "STP 模式下的优先值" },
{ CMDS_END }
};

static struct cmds stp_portfast_cmds[] = {
{ "bpdufilter", CLI_CMD, 0, 0, do_stp_portfast_bpdufilter, NULL, NULL, 0, 0, 0,
  "Enable portfast bdpu filter on this switch", "启动bpdu过滤" },
{ CMDS_END }
};

static struct cmds stp_portfast_bpdu_cmds[] = {
{ "default", CLI_CMD, 0, 0, do_stp_portfast_bpdu_defau, no_do_stp_portfast_bpdu_defau, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Enable bdpu filter by default on all portfast ports", "对所有具有portfast属性端口启用bpdu过滤" },
{ CMDS_END }
};

/*
 *  Function:  do_stp
 *  Purpose:  topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int do_stp(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        /* Do application function */
        func_stp_mode_rstp(u);
    }

    retval = sub_cmdparse(stp_cmds, argc, argv, u);

    return retval;
}

/*
 *  Function:  no_do_stp
 *  Purpose:   topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int no_do_stp(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        /* Do application function */
        nfunc_stp_enable(u);
    }

    retval = sub_cmdparse(no_stp_cmds, argc, argv, u);

    return retval;
}

/*
 *  Function:  do_stp_mode
 *  Purpose:  stp mode subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int do_stp_mode(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    retval = sub_cmdparse(stp_mode_cmds, argc, argv, u);
    
    return retval;
}

/* do_stp_mode_mstp */
static int do_stp_mode_mstp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_stp_mode_mstp(u);
	}

	return retval;
}

/*
 *  Function:  do_stp_mode_rstp
 *  Purpose:  stp mode rstp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int do_stp_mode_rstp(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        /* Do application function */
        func_stp_mode_rstp(u);
    }
    return retval;
}

static int do_stp_mode_stp(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        /* Do application function */
        func_stp_mode_stp(u);
    }
    return retval;
}

/* added by l.l */
static int do_stp_mst(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(stp_mst_cmds, argc, argv, u);

	return retval;
}

static int no_do_stp_mst(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(no_stp_mst_cmds, argc, argv, u);

	return retval;
}

static int do_stp_mst_word(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(stp_mst_word_cmds, argc, argv, u);

	return retval;
}

static int do_stp_mst_word_priority(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(stp_mst_word_priority_cmds, argc, argv, u);

	return retval;
}

static int no_do_stp_mst_word_prio(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		nfunc_stp_mst_word_prio(u);
	}

	return retval;
}

static int do_stp_mst_word_priority_param(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_stp_mst_word_priority(u);
	}

	return retval;
}

static int do_stp_mst_word_root(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(stp_mst_word_root_cmds, argc, argv, u);

	return retval;
}

static int do_stp_mst_word_root_param(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_stp_mst_word_root(u);
	}

	return retval;
}

static int no_do_stp_mst_word_rt(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		nfunc_stp_mst_word_rt(u);
	}

	return retval;
}

static int do_stp_mst_configuration(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		retval = change_con_level(CONFIG_MST_TREE, u);
	}

	return retval;
}

static int do_mst_instance(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mst_instance_cmds, argc, argv, u);

	return retval;
}

static int no_do_mst_instance(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(no_mst_instance_cmds, argc, argv, u);

	return retval;
}

static int do_mst_instance_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mst_instance_id_cmds, argc, argv, u);

	return retval;
}

static int no_do_mst_instance_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		nfunc_mst_instance_id(u);
	} else {
		retval = sub_cmdparse(mst_instance_id_cmds, argc, argv, u);
	}

	return retval;
}

static int do_mst_instance_id_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mst_instance_id_vlan_cmds, argc, argv, u);

	return retval;
}

static int do_mst_instance_id_vlan_line(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_mst_instance_id_vlan_line(u);
	}

	return retval;
}

static int no_do_mst_instance_id_vlan_line(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		nfunc_mst_instance_id_vlan_line(u);
	}

	return retval;
}

static int do_mst_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mst_name_cmds, argc, argv, u);

	return retval;
}

static int no_do_mst_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		nfunc_mst_name(u);
	}

	return retval;
}

static int do_mst_name_word(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_mst_name_word(u);
	}

	return retval;
}

static int do_mst_privlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mst_privatevlan_cmds, argc, argc, u);

	return retval;
}

static int do_mst_privlan_sync(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_mst_privlan_sync(u);
	}

	return retval;
}

static int do_mst_revision(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mst_revision_cmds, argc, argv, u);

	return retval;
}

static int no_do_mst_revision(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		nfunc_mst_revision(u);
	}

	return retval;
}

static int do_mst_revision_param(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_mst_revision_param(u);
	}

	return retval;
}

static int do_mst_show(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_mst_show(u);
	} else {
		retval = sub_cmdparse(mst_show_cmds, argc, argv, u);
	}

	return retval;
}

static int do_mst_show_current(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_mst_show_current(u);
	}

	return retval;
}

static int do_mst_show_pending(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_mst_show(u);
	}

	return retval;
}

static int do_stp_mst_fwdtime(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(stp_mst_fwdtime_cmds, argc, argv, u);

	return retval;
}

static int do_stp_mst_fwdtime_param(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_stp_mst_fwdtime_param(u);
	}

	return retval;
}

static int no_do_stp_mst_fwdtime(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0) {
		nfunc_stp_mst_fwdtime(u);
	}

	return retval;
}

static int do_stp_mst_hellotime(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(stp_mst_hellotime_cmds, argc, argv, u);

	return retval;
}

static int do_stp_mst_hellotime_param(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_stp_mst_hellotime_param(u);
	}

	return retval;
}

static int no_do_stp_mst_hellotime(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        nfunc_stp_mst_hellotime(u);
    }
    return retval;
}

static int do_stp_mst_maxage(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(stp_mst_maxage_cmds, argc, argv, u);

	return retval;
}

static int do_stp_mst_maxage_param(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_stp_mst_maxage_param(u);
	}

	return retval;
}

static int no_do_stp_mst_maxage(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc,argv,u)) == 0) {
		nfunc_stp_mst_maxage(u);
	}

	return retval;
}

static int do_stp_mst_maxhops(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(stp_mst_maxhops_cmds, argc, argv, u);

	return retval;
}

static int do_stp_mst_maxhops_param(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_stp_mst_maxhops_param(u);
	}

	return retval;
}

static int no_do_stp_mst_maxhops(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        nfunc_stp_mst_maxhops(u);
    }
    return retval;
}

/*
 *  Function:  do_stp_portfast_bpdufilter
 *  Purpose:  stp portfast bpdufilter subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int do_stp_portfast_bpdufilter(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    retval = sub_cmdparse(stp_portfast_bpdu_cmds, argc, argv, u);
    
    return retval;
}

/*
 *  Function:  do_stp_portfast_bpdufilter
 *  Purpose:  stp portfast bpdufilter default subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int do_stp_portfast_bpdu_defau(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        /* Do application function */
        //func_stp_portfast_bpdu_defau(u);
		func_stp_portfast_bpdufilter(u);
    }
    return retval;
}

/*
 *  Function:  no_do_stp_portfast_bpdufilter
 *  Purpose:  no stp portfast bpdufilter default subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/23
 */
static int no_do_stp_portfast_bpdu_defau(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        /* Do application function */
        //nfunc_stp_portfast_bpdu_defau(u);
		nfunc_stp_portfast_bpdufilter(u);
    }
    return retval;
}

/*
 *  Function:  do_stp_rstp_forwardtime
 *  Purpose:  stp rstp forward-time subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int do_stp_rstp_forwardtime(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    struct parameter param;
    memset(&param, 0, sizeof(struct parameter));

    /* Init paramter struct */
    param.type = CLI_INT;
    param.name = "<4-30>";
    param.ylabel = "Rstp mode forward time";
    param.hlabel = "rstp 模式下的转发时延";
    param.min = 4;
    param.max = 30;
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
        func_stp_rstp_forwardtime(u);
    }

    return retval;
}

/*
 *  Function:  no_do_stp_rstp_forwardtime
 *  Purpose:  no stp rstp forward-time subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int no_do_stp_rstp_forwardtime(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        /* Do application function */
        nfunc_stp_rstp_forwardtime(u);
    }
    return retval;
}

/*
 *  Function:  do_stp_rstp_hellotime
 *  Purpose:  stp rstp hello-time subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int do_stp_rstp_hellotime(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    struct parameter param;
    memset(&param, 0, sizeof(struct parameter));

    /* Init paramter struct */
    param.type = CLI_INT;
    param.name = "<1-10>";
    param.ylabel = "Rstp mode hello time";
    param.hlabel = "rstp 模式下的更新间隔 [1-10]秒";
    param.min = 1;
    param.max = 10;
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
        func_stp_rstp_hellotime(u);
    }

    return retval;
}

/*
 *  Function:  no_do_stp_rstp_hellotime
 *  Purpose:  no stp rstp hello-time subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int no_do_stp_rstp_hellotime(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        /* Do application function */
        nfunc_stp_rstp_hellotime(u);
    }
    return retval;
}

/*
 *  Function:  do_stp_rstp_maxage
 *  Purpose:  stp rstp max-age subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int do_stp_rstp_maxage(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    struct parameter param;
    memset(&param, 0, sizeof(struct parameter));

    /* Init paramter struct */
    param.type = CLI_INT;
    param.name = "<6-40>";
    param.ylabel = "Rstp mode max-age time";
    param.hlabel = "rstp 模式下的最大生存时间";
    param.min = 6;
    param.max = 40;
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
        func_stp_rstp_maxage(u);
    }

    return retval;
}

/*
 *  Function:  no_do_stp_rstp_maxage
 *  Purpose:  no stp rstp max-age subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int no_do_stp_rstp_maxage(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        /* Do application function */
        nfunc_stp_rstp_maxage(u);
    }
    return retval;
}

/*
 *  Function:  do_stp_rstp_priority
 *  Purpose:  stp rstp priority subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int do_stp_rstp_priority(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    struct parameter param;
    memset(&param, 0, sizeof(struct parameter));

    /* Init paramter struct */
    param.type = CLI_INT;
    param.name = "<0-61440>";
    param.ylabel = "Rstp mode priority value";
    param.hlabel = "rstp 模式下的优先权值";
    param.min = 0;
    param.max = 61440;
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
        func_stp_rstp_priority(u);
    }

    return retval;
}

/*
 *  Function:  no_do_stp_rstp_priority
 *  Purpose:  no stp rstp priority subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int no_do_stp_rstp_priority(int argc, char *argv[], struct users *u)
{
    int retval = -1;

    /* Check command end or not */
    if((retval = cmdend2(argc, argv, u)) == 0) 
    {
        /* Do application function */
        nfunc_stp_rstp_priority(u);
    }
    return retval;
}

/*
 *  Function:  do_stp_rstp
 *  Purpose:  stp rstp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int do_stp_rstp(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    retval = sub_cmdparse(stp_rstp_cmds, argc, argv, u);
    
    return retval;
}

static int do_stp_stp(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    retval = sub_cmdparse(stp_stp_cmds, argc, argv, u);
    
    return retval;
}

/*
 *  Function:  do_stp_portfast
 *  Purpose:  stp portfast subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
static int do_stp_portfast(int argc, char *argv[], struct users *u)
{
    int retval = -1;
    
    retval = sub_cmdparse(stp_portfast_cmds, argc, argv, u);
    
    return retval;
}


/*
 *  Function:  init_cli_stp
 *  Purpose:  Register stp function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:   chunli.wu
 *  Date:    2011/11/07
 */
int init_cli_stp(void)
{
    int retval = -1;
	
    retval = registerncmd(stp_topcmds, (sizeof(stp_topcmds)/sizeof(struct topcmds) - 1));
    DEBUG_MSG(1,"init_cli_stp retval = %d\n", retval);

    return retval;
}

int init_cli_config_mst(void)
{
	int retval = -1;

	retval = registerncmd(config_mst_topcmds, (sizeof(config_mst_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1,"init_cli_config_mst retval = %d\n", retval);

	return retval;
}

