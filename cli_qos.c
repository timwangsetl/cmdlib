/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_qos.c
 * Function   : qos command function
 * Auther     : jialong.chu
 * Version    : 1.0
 * Date       : 2011/11/4
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
 2011/11/7  1.01        xi.chen        scheduler policy sp
                                       scheduler policy wrr
                                       scheduler policy fcfs
                                       scheduler wrr bandwidth (x) (x) (x) (x)
                                       policy-map (x)
                                       classify ip access-group (x)
                                       classify dscp (x)
                                       classify mac access-group (x)
                                       classify vlan (x)
                                       classify cos (x)
                                       classify any


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

#include "cli_qos.h"
#include "cli_qos_func.h"

/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       xi.chen          add qos_topcmds[]
                                        add pol_map_topcmds[]
 */

static struct topcmds qos_topcmds[] = {
	{ "policy-map", 0, CONFIG_TREE, do_policy_map, no_policy_map, NULL, CLI_END_NONE, 0, 0,
		"Config qos policy", "配置qos 策略" },
	{ "scheduler", 0, CONFIG_TREE, do_scheduler, no_scheduler, NULL, CLI_END_NONE, 0, 0,
		"Global scheduler configuration", "全局调度配置" },
	{ "qos", 0, CONFIG_TREE, do_qos, no_qos, NULL, CLI_END_FLAG |CLI_END_NO, 0, 0,
		"Qos configuration", "Qos 配置" },
	{ TOPCMDS_END }
};

static struct topcmds pol_map_topcmds[] = {
	{ "classify", 0, POLICY_MAP_TREE, do_classify, no_classify, NULL, CLI_END_NONE, 0, 0,
		"Config qos policy classification", "配置qos 策略的数据流分类" },
	{ TOPCMDS_END }
};

static struct topcmds classfy_topcmds[] = {
	{ "bandwidth", 0, CLASSIFY_TREE, do_class_bandwidth, no_class_bandwidth, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Config bandwidth", "设置带宽" },
	{ "drop", 0, CLASSIFY_TREE, do_class_drop, no_class_drop, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Drop the data packet", "丢掉数据包" },
	{ "set", 0, CLASSIFY_TREE, do_class_set, no_class_set, NULL, CLI_END_NONE, 0, 0,
		"Config cos", "设置cos" },
	{ "exit", 0, CLASSIFY_TREE, do_classify_exit, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Exit", "退回或退出" },
	{ TOPCMDS_END }
};

/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       xi.chen          add sched_cmds[]
                                        add sched_pol_cmds[]
                                        add sched_wrr_cmds[]
                                        add sched_wrr_1_cmds[]
                                        add sched_wrr_2_cmds[]
                                        add sched_wrr_3_cmds[]
                                        add sched_wrr_4_cmds[]
                                        add classify_cmds[]
                                        add classify_ip_cmds[]
                                        add classify_mac_cmds[]
 

 */
static struct cmds sched_cmds[] = {
	{ "policy", CLI_CMD, 0, 0, do_sched_pol, no_sched_pol, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Config cos priority queue schedule policy", "配置cos 优先级队列调度策略" },
	{ "wrr", CLI_CMD, 0, 0, do_sched_wrr, no_sched_wrr, NULL, CLI_END_NONE, 0, 0,
		"Config wrr mode", "设置cos 优先级队列的wrr 模式" },
	{ CMDS_END }
};

static struct cmds qos_trust_cmds[] = {
	{ "dot1p", CLI_CMD, 0, 0, do_trust_dot1p, no_trust_dot1p, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Config Qos trust dot1p", "配置Qos信任dot1p" },
	{ "dscp", CLI_CMD, 0, 0, do_trust_dscp, no_trust_dscp, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Config Qos trust dscp",  "配置Qos信任dscp" },
	{ CMDS_END }
};

static struct cmds qos_cmds[] = {
	{ "trust", CLI_CMD, 0, 0, do_trust, no_trust, NULL, CLI_END_NONE, 0, 0,
		"Config Qos trust", "Qos信任模式" },
	{ CMDS_END }
};

static struct cmds sched_pol_cmds[] = {
	{ "sp", CLI_CMD, 0, 0, do_sched_pol_sp, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Schedule policy is sp", "严格优先级调度" },
	{ "wrr", CLI_CMD, 0, 0, do_sched_pol_wrr, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Schedule policy is wrr", "加权轮询调度" },
	{ "drr", CLI_CMD, 0, 0, do_sched_pol_drr, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Schedule policy is drr", "赤字轮询调度" },
	{ "wfq", CLI_CMD, 0, 0, do_sched_pol_wfq, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Schedule policy is wfq", "公平队列调度" },
	{ "wred", CLI_CMD, 0, 0, do_sched_pol_wred, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Schedule policy is wred", "权重丢弃" },
	{ CMDS_END }
};

static struct cmds sched_wrr_cmds[] = {
	{ "bandwidth", CLI_CMD, 0, 0, do_sched_wrr_band, no_sched_wrr_band, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Config cos priority queue bandwidth", "配置cos 优先级队列带宽" },
	{ CMDS_END }
};

static struct cmds sched_wrr_1_cmds[] = {
	{ "<1-255>", CLI_INT, 0, 0, do_sched_wrr_band_1, NULL, NULL, CLI_END_FLAG, 1, 255,
		"enter bandwidth weight for queue id 1", "请输入队列 1 的带宽倍数值" },
	{ CMDS_END }
};

static struct cmds sched_wrr_2_cmds[] = {
	{ "<1-255>", CLI_INT, 0, 0, do_sched_wrr_band_2, NULL, NULL, CLI_END_FLAG, 1, 255,
		"enter bandwidth weight for queue id 2", "请输入队列 2 的带宽倍数值" },
	{ CMDS_END }
};

static struct cmds sched_wrr_3_cmds[] = {
	{ "<1-255>", CLI_INT, 0, 0, do_sched_wrr_band_3, NULL, NULL, CLI_END_FLAG, 1, 255,
		"enter bandwidth weight for queue id 3", "请输入队列 3 的带宽倍数值" },
	{ CMDS_END }
};

static struct cmds sched_wrr_4_cmds[] = {
	{ "<1-255>", CLI_INT, 0, 0, do_sched_wrr_band_4, NULL, NULL, CLI_END_FLAG, 1, 255,
		"enter bandwidth weight for queue id 4", "请输入队列 4 的带宽倍数值" },
	{ CMDS_END }
};

static struct cmds sched_wrr_5_cmds[] = {
	{ "<1-255>", CLI_INT, 0, 0, do_sched_wrr_band_5, NULL, NULL, CLI_END_FLAG, 1, 255,
		"enter bandwidth weight for queue id 5", "请输入队列 5 的带宽倍数值" },
	{ CMDS_END }
};

static struct cmds sched_wrr_6_cmds[] = {
	{ "<1-255>", CLI_INT, 0, 0, do_sched_wrr_band_6, NULL, NULL, CLI_END_FLAG, 1, 255,
		"enter bandwidth weight for queue id 6", "请输入队列 6 的带宽倍数值" },
	{ CMDS_END }
};

static struct cmds sched_wrr_7_cmds[] = {
	{ "<1-255>", CLI_INT, 0, 0, do_sched_wrr_band_7, NULL, NULL, CLI_END_FLAG, 1, 255,
		"enter bandwidth weight for queue id 7", "请输入队列 7 的带宽倍数值" },
	{ CMDS_END }
};

static struct cmds sched_wrr_8_cmds[] = {
	{ "<1-255>", CLI_INT, 0, 0, do_sched_wrr_band_8, NULL, NULL, CLI_END_FLAG, 1, 255,
		"enter bandwidth weight for queue id 8", "请输入队列 8 的带宽倍数值" },
	{ CMDS_END }
};

static struct cmds classify_cmds[] = {
	{ "ip", CLI_CMD, 0, QOS_CLASSITY_IP, do_classify_ip, no_classify_ip, NULL, CLI_END_NONE, 0, 0,
		"Specify IP access list", "指定IP 访问列表" },
	{ "dscp", CLI_CMD, 0, QOS_CLASSITY_DSCP, do_classify_dscp, no_classify_dscp, NULL, CLI_END_NONE, 0, 0,
		"Specify the diffserv field", "指定IP 报文中的diffserv 字段" },
	{ "mac", CLI_CMD, 0, QOS_CLASSITY_MAC, do_classify_mac, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specify mac access list", "指定mac 访问列表" },
	{ "vlan", CLI_CMD, 0, QOS_CLASSITY_VLAN, do_classify_vlan, no_classify_vlan, NULL, CLI_END_NONE, 0, 0,
		"Specify the matching vlan", "指定匹配的VLAN" },
	{ "cos", CLI_CMD, 0, QOS_CLASSITY_COS, do_classify_cos, no_classify_cos, NULL, CLI_END_NONE, 0, 0,
		"Specify the matching cos", "指定匹配的cos" },
	{ "any", CLI_CMD, 0, QOS_CLASSITY_ANY, do_classify_any, no_classify_any, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Match any data flow", "匹配任意数据流" },
	{ CMDS_END }
};

static struct cmds classify_ip_cmds[] = {
	{ "access-group", CLI_CMD, 0, 0, do_classify_ip_access, no_classify_ip_access, NULL, CLI_END_NONE, 0, 0,
		"Ip access list", "IP 访问列表" },
	{ CMDS_END }
};

static struct cmds classify_mac_cmds[] = {
	{ "access-group", CLI_CMD, 0, 0, do_classify_mac_access, no_classify_mac_access, NULL, CLI_END_NONE, 0, 0,
		"Mac access list", "MAC 访问列表" },
	{ CMDS_END }
};

static struct cmds class_set_cmds[] = {
	{ "cos", CLI_CMD, 0, 0, do_class_set_cos, no_class_set_cos, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Config cos", "设置cos" },
	{ "dscp", CLI_CMD, 0, 0, do_class_set_dscp, no_class_set_dscp, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Config the diffserv field", "设置不同的服务范围" },
	{ "vlanID", CLI_CMD, 0, 0, do_class_set_vlanid, no_class_set_vlanid, NULL, CLI_END_NONE, 0, 0,
		"Config vlanid", "配置入端口QOS 策略" },
	{ CMDS_END }
};

static struct topcmds filter_topcmds[] = {
	{ "filter", 0, CONFIG_TREE, do_filter, no_filter, NULL, CLI_END_NONE, 0, 0,
		"filter configuration", "攻击检测" },
	{ TOPCMDS_END }
};

static struct cmds filter_cmds[] = {
	{ "period", CLI_CMD, 0, 0, do_filter_period, no_filter_period, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Config filter period", "配置攻击检测周期" },
	{ "threshold", CLI_CMD, 0, 0, do_filter_threshold, no_filter_threshold, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Config filter threshold", "配置攻击检测阀值" },
	{ "block-time", CLI_CMD, 0, 0, do_filter_block, no_filter_block, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Config filter block time", "配置攻击检测阻塞时间" },
	{ "igmp", CLI_CMD, 0, 0, do_filter_igmp, no_filter_igmp, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Config filter IGMP", "配置攻击检测 IGMP 协议" },
	{ "ip", CLI_CMD, 0, 0, do_filter_ip, no_filter_ip, NULL, CLI_END_NONE, 0, 0,
		"Config filter IP", "配置攻击检测 IP 协议" },
	{ "arp", CLI_CMD, 0, 0, do_filter_arp, no_filter_arp, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Config filter ARP", "配置攻击检测 ARP 协议" },
	{ "enable", CLI_CMD, 0, 0, do_filter_enable, no_filter_enable, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Config filter enable", "配置攻击检测使能" },	
	{ TOPCMDS_END }
};

static struct cmds filter_period_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_filter_period_time, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"Config filter period", "配置攻击检测周期时间" },
	{ CMDS_END }
};

static struct cmds filter_threshold_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_filter_threshold_value, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"Config filter threshold", "配置攻击检测阀值" },
	{ CMDS_END }
};

static struct cmds filter_block_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_filter_block_value, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"Config filter block time", "配置攻击检测阻塞时间" },
	{ CMDS_END }
};

static struct cmds filter_ip_cmds[] = {
	{ "source-ip", CLI_CMD, 0, 0, do_filter_ip_source, no_filter_ip_source, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Config filter source ip", "配置攻击检测 源 IP 协议" },
	{ CMDS_END }
};

static struct topcmds cluster_topcmds[] = {
	{ "cluster", 0, CONFIG_TREE, do_cluster, no_cluster, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Config cluster", "配置集群" },
	{ TOPCMDS_END }
};

static struct cmds cluster_cmds[] = {
	{ "member", CLI_CMD, 0, 0, do_cluster_member, NULL, NULL, CLI_END_NONE, 0, 0,
		"Config cluster member", "配置集群成员" },
	{ TOPCMDS_END }
};

static struct cmds cluster_member_cmds[] = {
	{ "<0-255>", CLI_INT, 0, 0, do_cluster_member_id, NULL, NULL, CLI_END_NONE, 0, 255,
		"Config cluster member", "配置集群成员编号" },
	{ CMDS_END }
};

static struct cmds cluster_member_id_cmds[] = {
	{ "mac-address", CLI_CMD, 0, 0, do_cluster_member_id_mac, NULL, NULL, CLI_END_NONE, 0, 0,
		"Config cluster MAC address", "配置集群成员 MAC 地址" },
	{ CMDS_END }
};

static struct cmds cluster_member_id_mac_cmds[] = {
	{ "HH:HH:HH:HH:HH:HH", CLI_MAC, 0, 0, do_cluster_member_id_mac_addr, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Config cluster MAC address", "配置集群成员 MAC 地址" },
	{ CMDS_END }
};

static struct topcmds ring_topcmds[] = {
	{ "ring", 0, CONFIG_TREE, do_ring, no_ring, NULL, CLI_END_NONE, 0, 0,
		"Config RING", "配置环网" },
	{ TOPCMDS_END }
};

static struct cmds ring_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_ring_id, no_ring_id, NULL, CLI_END_NONE | CLI_END_NO, 1, 65535,
		"Config RING id", "配置环网编号" },
	{ CMDS_END }
};

static struct cmds ring_id_cmds[] = {
	{ "mode", CLI_CMD, 0, 0, do_ring_id_mode, NULL, NULL, CLI_END_NONE, 0, 0,
		"Config RING mode", "配置环网模式" },
	{ CMDS_END }
};

static struct cmds ring_id_mode_cmds[] = {
	{ "single", CLI_CMD, 0, 0, do_ring_id_mode_single, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Config RING single mode", "配置单环网模式" },
	{ "double", CLI_CMD, 0, 0, do_ring_id_mode_double, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Config RING double mode", "配置双环网模式" },
	{ "coupling", CLI_CMD, 0, 0, do_ring_id_mode_coupling, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Config RING coupling mode", "配置耦合环网模式" },
	{ CMDS_END }
};

/*
 *  Function:  do_scheduler
 *  Purpose:  scheduler topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_scheduler(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(sched_cmds, argc, argv, u);

	return retval;
}

static int no_scheduler(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(sched_cmds, argc, argv, u);

	return retval;
}


/*
 *  Function:  do_qos
 *  Purpose:  scheduler topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  liujh
 *  Date:    2019/05/5
 */
static int do_qos(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(qos_cmds, argc, argv, u);

	return retval;
}

static int no_qos(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		no_qos_set(u);
	}	
	/* parse next sub command */
	retval = sub_cmdparse(qos_cmds, argc, argv, u);

	return retval;
}



/*
 *  Function:  do_sched_pol
 *  Purpose:  policy subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_sched_pol(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(sched_pol_cmds, argc, argv, u);

	return retval;
}

static int no_sched_pol(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_sched_pol(u);

	}

	return retval;

}


/*
 *  Function:  do_trust_dot1p
 *  Purpose:  policy subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  liujh
 *  Date:    2019/5/14
 */
static int do_trust_dot1p(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0)
	{
		/* Do application function */
		do_trust_dot1p_set(u);
	}

	return retval;
}

static int no_trust_dot1p(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0)
	{
		/* Do application function */
		no_trust_dot1p_set(u);
	}

	return retval;
}

/*
 *  Function:  do_trust
 *  Purpose:  policy subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  liujh
 *  Date:    2019/5/15
 */

static int do_trust(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(qos_trust_cmds, argc, argv, u);

	return retval;
}

static int no_trust(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(qos_trust_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_trust_dscp
 *  Purpose:  policy subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  liujh
 *  Date:    2019/5/14
 */
static int do_trust_dscp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	printf("%s %d retval:%d\n",__FUNCTION__,__LINE__,retval);
	if(retval == 0)
	{
		/* Do application function */
		do_trust_dscp_set(u);
	}

	return retval;
}

static int no_trust_dscp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0)
	{
		/* Do application function */
		no_trust_dscp_set(u);
	}

	return retval;
}

/*
 *  Function:  do_sched_pol_sp
 *  Purpose:  sp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_sched_pol_sp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_po_sp(u);

	}

	return retval;
}

/*
 *  Function:  do_sched_pol_wrr
 *  Purpose:  wrr subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_sched_pol_wrr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_po_wrr(u);

	}

	return retval;
}

/*
 *  Function:  do_sched_pol_drr
 *  Purpose:  fcfs subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   liujh
 *  Date:    2019/05/16
 */
static int do_sched_pol_drr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_po_drr(u);

	}

	return retval;
}

static int do_sched_pol_wfq(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_po_wfq(u);

	}

	return retval;
}

static int do_sched_pol_wred(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_po_wred(u);

	}

	return retval;
}

/*
 *  Function:  do_sched_wrr
 *  Purpose:  wrr subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_sched_wrr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(sched_wrr_cmds, argc, argv, u);

	return retval;
}

static int no_sched_wrr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(sched_wrr_cmds, argc, argv, u);

	return retval;

}
/*
 *  Function:  do_sched_wrr_band
 *  Purpose:  bandwidth subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_sched_wrr_band(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(sched_wrr_1_cmds, argc, argv, u);

	return retval;
}

static int no_sched_wrr_band(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
	/* Do application function */
	nfunc_sched_wrr_band(u);

	}

	return retval;

}
/*
 *  Function:  do_sched_wrr_band_1
 *  Purpose:  queue 1 subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_sched_wrr_band_1(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_wrr_ban_1(u);
	}

	retval = sub_cmdparse(sched_wrr_2_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_sched_wrr_band_2
 *  Purpose:  queue 2 subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_sched_wrr_band_2(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_wrr_ban_2(u);
	}

	retval = sub_cmdparse(sched_wrr_3_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_sched_wrr_band_3
 *  Purpose:  queue 3 subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_sched_wrr_band_3(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_wrr_ban_3(u);
	}

	retval = sub_cmdparse(sched_wrr_4_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_sched_wrr_band_4
 *  Purpose:  queue 4 subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_sched_wrr_band_4(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_wrr_ban_4(u);
	}

	retval = sub_cmdparse(sched_wrr_5_cmds, argc, argv, u);

	return retval;
}

static int do_sched_wrr_band_5(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_wrr_ban_5(u);
	}

	retval = sub_cmdparse(sched_wrr_6_cmds, argc, argv, u);

	return retval;
}

static int do_sched_wrr_band_6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_wrr_ban_6(u);
	}

	retval = sub_cmdparse(sched_wrr_7_cmds, argc, argv, u);

	return retval;
}

static int do_sched_wrr_band_7(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_wrr_ban_7(u);
	}

	retval = sub_cmdparse(sched_wrr_8_cmds, argc, argv, u);

	return retval;
}

static int do_sched_wrr_band_8(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_qos_sch_wrr_ban_8(u);
	}

	return retval;
}

/*
 *  Function:  do_policy_map
 *  Purpose:  policy-map topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_policy_map(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Policy-map name";
	param.hlabel = "Policy-map名称";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->s_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		func_qos_policy_map(u);
		if((retval = change_con_level(POLICY_MAP_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "%s", u->s_param.v_string[0]);
		}
	}

	return retval;
}

static int no_policy_map(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Policy-map name";
	param.hlabel = "Policy-map名称";
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->s_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_qos_policy_map(u);
	}

	return retval;

}

/*
 *  Function:  do_classify
 *  Purpose:  classify topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_classify(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(classify_cmds, argc, argv, u);

	return retval;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  do_classify_exit
 *  Description:  classify exit topcmd parse function 
 * 		 Author:  gujiajie
 *		   Date:  05/22/2012
 * =====================================================================================
 */
static int do_classify_exit(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	if ((retval = cmdend2(argc, argv, u)) == 0) {
		change_con_level(POLICY_MAP_TREE, u);
	}

	return retval;
}

static int no_classify(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(classify_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_classify_ip
 *  Purpose:  classify ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_classify_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(classify_ip_cmds, argc, argv, u);

	return retval;
}

static int no_classify_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(classify_ip_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_classify_ip_access
 *  Purpose:  classify ip access-group subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_classify_ip_access(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Access list name";
	param.hlabel = "访问列表名称";
	param.min = 0;
	param.max = 0;
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
		//do_test_param(argc, argv, u);
		
		if(func_qos_classify(u) == 0)
			change_con_level(CLASSIFY_TREE, u);
	}

	return retval;
}

/*
 *  Function:  do_classify_dscp
 *  Purpose:  classify dscp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_classify_dscp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<0-63>";
	param.ylabel = "Dscp value";
	param.hlabel = "Dscp 值";
	param.min = 0;
	param.max = 63;
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
		//do_test_param(argc, argv, u);
		
		if(func_qos_classify(u) == 0)
			change_con_level(CLASSIFY_TREE, u);
	}

	return retval;
}

/*
 *  Function:  do_classify_mac
 *  Purpose:  classify mac subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_classify_mac(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(classify_mac_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_classify_mac_access
 *  Purpose:  classify mac access-group subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_classify_mac_access(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Access list name";
	param.hlabel = "访问列表名称";
	param.min = 0;
	param.max = 0;
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
		//do_test_param(argc, argv, u);
		
		if(func_qos_classify(u) == 0)
			change_con_level(CLASSIFY_TREE, u);
	}

	return retval;
}

/*
 *  Function:  do_classify_vlan
 *  Purpose:  classify vlan subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_classify_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-4094>";
	param.ylabel = "Vlan id";
	param.hlabel = "Vlan 的ID 号";
	param.min = 1;
	param.max = 4094;
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
		//do_test_param(argc, argv, u);
		
		if(func_qos_classify(u) == 0)
			change_con_level(CLASSIFY_TREE, u);
	}

	return retval;
}

/*
 *  Function:  do_classify_cos
 *  Purpose:  classify cos subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_classify_cos(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<0-7>";
	param.ylabel = "Cos value";
	param.hlabel = "Cos 值";
	param.min = 0;
	param.max = 7;
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
		//do_test_param(argc, argv, u);
		
		if(func_qos_classify(u) == 0)
			change_con_level(CLASSIFY_TREE, u);
	}

	return retval;
}

/*
 *  Function:  do_classify_any
 *  Purpose:  classify any subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_classify_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application function */
		//do_test_param(argc, argv, u);
		
		if(func_qos_classify(u) == 0)
			change_con_level(CLASSIFY_TREE, u);
	}

	return retval;
}

/*
 *  Function:  no_classify_ip_access
 *  Purpose:  no classify ip access-group subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_classify_ip_access(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Access list name";
	param.hlabel = "访问列表名称";
	param.min = 0;
	param.max = 0;
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
		nfunc_classify_ip_access(u);
	}

	return retval;
}

/*
 *  Function:  no_classify_dscp
 *  Purpose:  no classify dscp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_classify_dscp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<0-63>";
	param.ylabel = "Dscp value";
	param.hlabel = "Dscp 值";
	param.min = 0;
	param.max = 63;
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
		nfunc_classify_dscp(u);
	}

	return retval;
}

/*
 *  Function:  no_classify_mac_access
 *  Purpose:  no classify mac access-group subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_classify_mac_access(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Access list name";
	param.hlabel = "访问列表名称";
	param.min = 0;
	param.max = 0;
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
		nfunc_classify_mac_acc(u);
	}

	return retval;
}

/*
 *  Function:  no_classify_vlan
 *  Purpose:  no classify vlan subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_classify_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-4094>";
	param.ylabel = "Vlan id";
	param.hlabel = "Vlan 的ID 号";
	param.min = 1;
	param.max = 4094;
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
		nfunc_classify_vlan(u);
	}

	return retval;
}

/*
 *  Function:  no_classify_cos
 *  Purpose:  no classify cos subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_classify_cos(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<0-7>";
	param.ylabel = "Cos value";
	param.hlabel = "Cos 值";
	param.min = 0;
	param.max = 7;
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
		nfunc_classify_cos(u);
	}

	return retval;
}

/*
 *  Function:  no_classify_any
 *  Purpose:  no classify any subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_classify_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application function */
		nfunc_classify_any(u);
	}

	return retval;
}



/*-----------------------------CLASSIFY TREE COMMAND    By dawei.hu------↓↓↓↓↓↓↓↓↓↓-----------------*/

static int do_class_bandwidth(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "1-1600";
	param.ylabel = "Configure Bandwidth(unit:64kbps)";
	param.hlabel = "设置带宽 (单位:64kbps)";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		 func_class_band(u);
	}

	return retval;

}

static int do_class_drop(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_class_drop(u);
	}

	return retval;
}


static int do_class_set(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(class_set_cmds, argc, argv, u);

	return retval;

}

static int do_class_set_cos(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	
	param.type = CLI_INT;
	param.name = "<0-7>";
	param.ylabel = "Config cos value";
	param.hlabel = "设置value号";
	param.flag =CLI_END_FLAG;
	param.min = 0;
	param.max = 7;
	
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
		
	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		func_class_set_cos(u);
	}
	return retval;

}

static int do_class_set_dscp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	
	param.type = CLI_INT;
	param.name = "<0-63>";
	param.ylabel = "Config dscp value";
	param.hlabel = "设置dscp号";
	param.flag =CLI_END_FLAG;
	param.min = 0;
	param.max = 63;
	
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
		
	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		 func_class_set_dscp(u);
	}
	return retval;

}

static int do_class_set_vlanid(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	
	param.type = CLI_INT;
	param.name = "<1-4049>";
	param.ylabel = "Config vlanid value";
	param.hlabel = "设置vlanid号";
	param.flag =CLI_END_FLAG;
	param.min = 1;
	param.max = 4049;
	
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
		
	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		 func_class_set_vlanid(u);
	}
	
	return retval;

}

static int no_class_bandwidth(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_class_band(u);
	}

	return retval;

}

static int no_class_drop(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_class_drop(u);
	}

	return retval;
}


static int no_class_set(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(class_set_cmds, argc, argv, u);

	return retval;

}

static int no_class_set_cos(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		 nfunc_class_set_cos(u);
	}
	return retval;

}

static int no_class_set_dscp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		 nfunc_class_set_dscp(u);
	}
	return retval;

}

static int no_class_set_vlanid(int argc, char *argv[], struct users *u)
{
	
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	
	param.type = CLI_INT;
	param.name = "<1-4049>";
	param.ylabel = "Config vlanid value";
	param.hlabel = "设置vlanid号";
	param.flag =CLI_END_NO;
	param.min = 1;
	param.max = 4049;
	
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
		
	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		 nfunc_class_set_vlanid(u);
	}
	
	return retval;
}

static int do_cluster(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(cluster_cmds, argc, argv, u);

	return retval;
}

static int no_cluster(int argc, char *argv[], struct users *u)
{	
    int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_cluster_member_id(u);       
	}
	
	return retval;
}

static int do_cluster_member(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(cluster_member_cmds, argc, argv, u);

	return retval;
}

static int do_cluster_member_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(cluster_member_id_cmds, argc, argv, u);

	return retval;
}

static int do_cluster_member_id_mac(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(cluster_member_id_mac_cmds, argc, argv, u);

	return retval;
}

static int do_cluster_member_id_mac_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_cluster_member_id(u);       
	}
	
	return retval;
}

static int do_filter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(filter_cmds, argc, argv, u);

	return retval;
}

static int no_filter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(filter_cmds, argc, argv, u);

	return retval;
}

static int do_filter_period(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(filter_period_cmds, argc, argv, u);

	return retval;
}

static int do_filter_period_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_filter_period(u);       
	}
	
	return retval;
}

static int no_filter_period(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_filter_period(u);       
	}
	
	return retval;
}

static int do_filter_threshold(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(filter_threshold_cmds, argc, argv, u);

	return retval;
}

static int do_filter_threshold_value(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_filter_threshold(u);       
	}
	
	return retval;
}

static int no_filter_threshold(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_filter_threshold(u);       
	}
	
	return retval;
}

static int do_filter_block(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(filter_block_cmds, argc, argv, u);

	return retval;
}

static int do_filter_block_value(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_filter_block(u);       
	}
	
	return retval;
}

static int no_filter_block(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_filter_block(u);       
	}
	
	return retval;
}
static int do_filter_igmp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_filter_igmp(u);       
	}
	
	return retval;
}

static int no_filter_igmp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_filter_igmp(u);       
	}
	
	return retval;
}

static int do_filter_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(filter_ip_cmds, argc, argv, u);

	return retval;
}

static int do_filter_ip_source(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_filter_ip_source(u);       
	}
	
	return retval;
}

static int no_filter_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(filter_ip_cmds, argc, argv, u);

	return retval;
}

static int no_filter_ip_source(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_filter_ip_source(u);       
	}
	
	return retval;
}


static int do_filter_arp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_filter_arp(u);       
	}
	
	return retval;
}

static int no_filter_arp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_filter_arp(u);       
	}
	
	return retval;
}


static int do_filter_enable(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_filter_enable(u);       
	}
	
	return retval;
}

static int no_filter_enable(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_filter_enable(u);       
	}
	
	return retval;
}

static int do_ring(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(ring_cmds, argc, argv, u);

	return retval;
}

static int no_ring(int argc, char *argv[], struct users *u)
{	
    int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(ring_cmds, argc, argv, u);
	
	return retval;
}

static int do_ring_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(ring_id_cmds, argc, argv, u);

	return retval;
}

static int no_ring_id(int argc, char *argv[], struct users *u)
{	
    int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ring_id(u);       
	}
	return retval;
}

static int do_ring_id_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(ring_id_mode_cmds, argc, argv, u);

	return retval;
}

static int do_ring_id_mode_single(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ring_id_mode_single(u);       
	}
	
	return retval;
}

static int do_ring_id_mode_double(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ring_id_mode_double(u);       
	}
	
	return retval;
}

static int do_ring_id_mode_coupling(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ring_id_mode_coupling(u);       
	}
	
	return retval;
}


/*-----------------------------CLASSIFY TREE COMMAND    By dawei.hu------END   END   END   END  END-----------------*/


/*
 *  Function:  init_cli_qos
 *  Purpose:  Register qos function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
int init_cli_qos(void)
{
	int retval = -1;

	/* Register qos_topcmds[] */
	retval = registerncmd(qos_topcmds, (sizeof(qos_topcmds)/sizeof(struct topcmds) - 1));

	/* Register pol_map_topcmds[] */
	retval += registerncmd(pol_map_topcmds, (sizeof(pol_map_topcmds)/sizeof(struct topcmds) - 1));

	/* Register classfy_topcmds[] */
	retval += registerncmd(classfy_topcmds, (sizeof(classfy_topcmds)/sizeof(struct topcmds) - 1));
	
	/* Register cluster_topcmds[] */
	retval += registerncmd(cluster_topcmds, (sizeof(cluster_topcmds)/sizeof(struct topcmds) - 1));
	
	/* Register filter_topcmds[] */
	retval += registerncmd(filter_topcmds, (sizeof(filter_topcmds)/sizeof(struct topcmds) - 1));
	
	/* Register ring[] */
	retval += registerncmd(ring_topcmds, (sizeof(ring_topcmds)/sizeof(struct topcmds) - 1));
	
	DEBUG_MSG(1, "init_cli_qos class_set_topcmds retval = %d\n", retval);

	return retval;
}

