/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_show.c
 * Function   : show command function
 * Auther     : jialong.chu
 * Version    : 1.0
 * Date       : 2011/11/4
 *
 *********************Revision History****************
 Date       Version     Modifier       Command
 2011/11/7  1.01        xi.chen        show aaa users
                                       show access-list
                                       show aggregator-group (x) brief
                                       show aggregator-group (x) detail
                                       show aggregator-group (x) summary
                                       show aggregator-group brief
                                       show aggregator-group detail
                                       show aggregator-group summary
                                       show aggregator-group load-balance
                                       show arp
                                       show clock
                                       show dot1x info
                                       show dot1x interface FastEthernet (x)
                                       show dot1x interface GigaEthernet (x)
                                       show dot1x statistics
                                       show exec_timeout
                                       show flow_interval
                                       show history
                                       show interface brief
                                       show interface FastEthernet (x)
                                       show interface GigaEthernet (x)
                                       show interface port-aggregator (x)
                                       show ip access-lists
                                       show ip dhcp snooping binding all
                                       show ip igmp-snooping
                                       show ip interface brief
                                       show ip source binding
                                       show ipv6 interface brief
                                       show ipv6 dhcp
                                       show ipv6 route
                                       show lldp neighbors
                                       show lldp neighbors detail
                                       show logging
                                       show loopback-status
                                       show mac address-table
                                       show mac address-table (x)
                                       show mac address-table dynamic
                                       show mac address-table dynamic interface FastEthernet (x)
                                       show mac address-table dynamic interface GigaEthernet (x)
                                       show mac address-table interface FastEthernet (x)
                                       show mac address-table interface GigaEthernet (x)
                                       show mac address-table multicast
                                       show mac address-table static
                                       show mac address-table vlan (x)
                                       show memory
                                       show ntp
                                       show policy-map
                                       show process cpu
                                       show rnning-config
                                       show rnning-config interface FastEthernet (x)
                                       show rnning-config interface GigaEthernet (x)
                                       show rnning-config vlan (x)
                                       show spaning-tree
                                       show startup-config
                                       show ssh
                                       show telnet
                                       show version
                                       show vlan
                                       show vlan id (x)
                                       show vlan interface FastEthernet (x)
                                       show vlan interface GigaEthernet (x)
                                       show vlan dot1q-tunnel


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

#include "bcmutils.h"
#include "console.h"
#include "cmdparse.h"
#include "parameter.h"

#include "cli_show.h"
#include "cli_show_func.h"
#include "cli_line_func.h"

#define show_debug(fmt,arg...)	//printf(fmt,##arg)
/*
 *  top command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       xi.chen          add show_topcmds[]


 */
static struct topcmds show_topcmds[] = {
	{ "show", 0, GLOBAL_TREE, do_show, NULL, NULL, 0, 0, 0,
		"Show configuration and status", "显示配置和状态" },
	{ TOPCMDS_END }
};

/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       xi.chen          add show_cmds[] */
 
static struct cmds show_cmds[] = {
	{ "aaa", CLI_CMD, 0, 0, do_show_aaa, NULL, NULL, CLI_END_NONE, 0, 0,
		"Show AAA information", "显示AAA 信息" },
	{ "access-list", CLI_CMD, 0, 0, do_show_access, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Named access-list", "访问列表" },
	{ "aggregator-group", CLI_CMD, 0, 0, do_show_agg, NULL, NULL, CLI_END_NONE, 0, 0,
		"Link Aggregation information", "端口聚合状态信息" },
	{ "clock", CLI_CMD, 0, 0, do_show_clock, NULL, NULL, CLI_END_FLAG, 0, 0,
		"current time", "当前时间" },
	{ "dot1x", CLI_CMD, 0, 0, do_show_dot1x, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show 802.1X configuration", "IEEE 802.1X 状态信息" },
	#if (ERR_DISABLE_MODULE==1)
	{ "errdisable", CLI_CMD, 0, 0, do_show_error, NULL, NULL, CLI_END_NONE, 0, 0,
		"Error disable", "错误禁止" },
	#endif
	{ "exec-timeout", CLI_CMD, 0, 0, do_show_exec_timeout, NULL, NULL, CLI_END_FLAG, 0, 0,
		"The EXEC timeout", "终端超时" },
	{ "flow_interval", CLI_CMD, 0, 0, do_show_flow_interval, NULL, NULL, CLI_END_FLAG, 0, 0,
		"The flow_interval", "统计时间间隔" },
	{ "history", CLI_CMD, 0, 0, do_show_history, NULL, NULL, CLI_END_FLAG, 0, 0,
		"History command", "历史命令" },
	{ "interface", CLI_CMD, 0, SHOW_IF_PORT, do_show_inter, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Interface status and configuration", "接口状态和配置" },
	{ "ip", CLI_CMD, 0, 0, do_show_ip, NULL, NULL, CLI_END_NONE, 0, 0,
		"IP Configuration information", "IP 配置信息" },
	{ "ipv6", CLI_CMD, 0, 0, do_show_ipv6, NULL, NULL, CLI_END_NONE, 0, 0,
		"IPv6 Configuration information", "IPv6 配置信息" },
	{ "line", CLI_CMD, 0, 0, do_show_line, NULL, NULL, CLI_END_NONE, 0, 0,
		"TTY line information", "虚拟终端信息"},
	{ "lldp", CLI_CMD, 0, 0, do_show_lldp, NULL, NULL, CLI_END_NONE, 0, 0,
		"Show the lldp information", "显示LLDP 信息" },
	{ "logging", CLI_CMD, 0, 0, do_show_logging, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show the contents of logging buffers", "显示日志信息" },
	{ "loopback-status", CLI_CMD, 0, 0, do_show_loopback, NULL, NULL, CLI_END_FLAG, 0, 0,
		"show loopback port status", "自环状态" },
	{ "mac", CLI_CMD, 0, 0, do_show_mac, NULL, NULL, CLI_END_NONE, 0, 0,
		"MAC configuration", "MAC 配置" },
	{ "memory", CLI_CMD, 0, 0, do_show_mem, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Memory information", "内存统计信息" },
	{ "mirror", CLI_CMD, 0, 0, do_show_mirr, NULL, NULL, CLI_END_NONE, 0, 0,
		"Show a mirror session", "显示监控会话" },
	{ "mst-config", CLI_CMD, 0, 0, do_show_mstcfg, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show the configuration of MST", "显示MST域配置信息" },
	{ "ntp", CLI_CMD, 0, 0, do_show_ntp, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Ntp infomation", "网络时间信息" },
	{ "policy-map", CLI_CMD, 0, 0, do_show_pol, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show policy-map", "显示policy-map" },
	{ "process", CLI_CMD, 0, 0, do_show_process, NULL, NULL, CLI_END_NONE, 0, 0,
		"Processes information", "显示进程信息" },
	{ "running-config", CLI_CMD, 0, SHOW_RUN_IF_PORT, do_show_running, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Current configuration", "当前配置" },
	{ "spanning-tree", CLI_CMD, 0, 0, do_show_spanning, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Display spanning-tree state", "显示生成树状态信息" },
	{ "startup-config", CLI_CMD, 0, 0, do_show_startup, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Startup configuration", "开机配置" },
	{ "ssh", CLI_CMD, 0, 0, do_show_ssh, NULL, NULL, CLI_END_FLAG, 0, 0,
		"The LINES connected in", "SSH 入连接" },
	{ "telnet", CLI_CMD, 0, 0, do_show_telnet, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show incoming telnet connection", "显示连入的telnet 连接" },
	{ "version", CLI_CMD, 0, 0, do_show_version, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Device version information", "设备版本信息" },
	{ "vlan", CLI_CMD, 0, 0, do_show_vlan, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Vlan information", "Vlan 状态信息" },
	{ "cluster", CLI_CMD, 0, 0, do_show_cluster, NULL, NULL, CLI_END_FLAG, 0, 0,
		"cluster information", "集群信息" },
	{ "ring", CLI_CMD, 0, 0, do_show_ring, NULL, NULL, CLI_END_FLAG, 0, 0,
		"ring information", "环网信息" },
	{ "svn_version", CLI_CMD, 0, 0, do_show_svn_version, NULL, NULL, CLI_END_FLAG, 0, 0,
		"ring information", "环网信息" },
	{ "gvrp", CLI_CMD, 0, 0, do_show_gvrp, NULL, NULL, CLI_END_FLAG, 0, 0,
		"gvrp information", "GVRP信息" },
	{ "gmrp", CLI_CMD, 0, 0, do_show_gmrp, NULL, NULL, CLI_END_FLAG, 0, 0,
		"gmrp information", "GMRP信息" },	
	{ "garp", CLI_CMD, 0, 0, do_show_garp, NULL, NULL, CLI_END_FLAG, 0, 0,
		"GARP information", "GARP信息" },	
	{ "erps", CLI_CMD, 0, 0, do_show_erps, NULL, NULL, CLI_END_FLAG, 0, 0,
		"ERPS information", "ERPS信息" },
	{ "multicast-vlan", CLI_CMD, 0, 0, do_show_multicast_vlan, NULL, NULL, CLI_END_FLAG, 0, 0,
		"multicast-vlan information", "multicast-vlan信息" },	
	{ CMDS_END }
};

static struct cmds show_ipv6_cmds[] = {
	{ "interface", CLI_CMD, 0, 0, do_show_ipv6_interface, NULL, NULL, CLI_END_NONE, 0, 0,
		"IPv6 information and configuration of interface", "接口的IPV6信息和配置" },
		#if 0
	{ "dhcp", CLI_CMD, 0, 0, do_show_ipv6_dhcp, NULL, NULL, CLI_END_FLAG, 0, 0,
		"DHCP Server information", "DHCP服务器信息" },
	{ "neighbors", CLI_CMD, 0, 0, do_show_ipv6_neighbors, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show IPv6 neighbor cache entries", "显示 IPv6 邻居缓存列表" },
	{ "ospf", CLI_CMD, 0, 0, do_show_ipv6_ospf, NULL, NULL, CLI_END_NONE, 0, 0,
		"OSPF routing protocol information", "OSPF 路由协议信息" },
	{ "rip", CLI_CMD, 0, 0, do_show_ipv6_rip, NULL, NULL, CLI_END_NONE, 0, 0,
		"RIP routing protocol information", "RIP 路由协议信息" },
	{ "route", CLI_CMD, 0, 0, do_show_ipv6_route, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show IPv6 route table entries", "显示 IPv6 路由表" },
	{ "mld", CLI_CMD, 0, 0, do_show_ipv6_mld, NULL, NULL, CLI_END_NONE, 0, 0,
		"Show IPv6 MLD information", "显示 IPv6 MLD 信息" },
	{ "mroute", CLI_CMD, 0, 0, do_show_ipv6_mroute, NULL, NULL, CLI_END_FLAG, 0, 0,
		"mroute", "组播路由信息" },
		#endif
	{ CMDS_END }
};

static struct cmds show_error_cmds[] = {
	{ "detect", CLI_CMD, 0, 0, do_show_error_detect, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Error disable detection", "错误检测配置" },
	{ "recovery", CLI_CMD, 0, 0, do_show_error_recovery, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Error disable recovery", "错误自动恢复配置" },
	{ CMDS_END }
};

static struct cmds show_vty_cmds[] = {
	{"vty", CLI_CMD, 0, 0, do_vty, NULL, NULL, CLI_END_NONE|CLI_END_FLAG, 0, 0,
		"Virtual terminal","虚拟终端"},
	{ CMDS_END }
};

static struct cmds show_vty_first[] = {
	{"<1-16>", CLI_INT, 0, 0, do_vty_first, NULL, NULL, CLI_END_NONE, 1, 16,
		"First Line range", "第一个参数"},
	{ CMDS_END }
};

static struct cmds show_vty_last[] = {
	{"<1-16>", CLI_INT, 0, 0, do_vty_last, NULL, NULL, CLI_END_FLAG, 1, 16,
		"Last Line range","第二个参数"},
	{ CMDS_END }
};


static struct cmds show_ipv6_in_cmds[] = {
	{ "brief", CLI_CMD, 0, 0, do_show_ipv6_interface_brief, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IPv6 brief information and configuration of interface", "接口的IPV6简要信息和配置" },
	//{ "vlan", CLI_CMD, 0, 0, do_show_ipv6_interface_vlan, NULL, NULL, CLI_END_NONE, 0, 0,
	//	"Catalyst Vlans", "VLANs" },
	{ CMDS_END }
};

static struct cmds show_ipv6_in_vlan_cmds[] = {
	{"<1-4095>", CLI_INT, 0, 0, do_show_ipv6_interface_vlan_id, NULL, NULL, CLI_END_FLAG, 1, 4095,
		"Vlan interface number","VLAN 号"},
	{ CMDS_END }
};

static struct cmds show_ipv6_dhcp_snooping_cmds[] = {
	{ "snooping", CLI_CMD, 0, 0, show_ipv6_dhcp_snooping, NULL, NULL, CLI_END_NONE, 0, 0,
		"show dhcp snooping", "侦听DHCP" },
	{ "binding", CLI_CMD, 0, 0, do_show_ipv6_dhcp_binding, NULL, NULL, CLI_END_FLAG, 0, 0,
		"show dhcp binding", "DHCP 绑定表" },
	{ "interface", CLI_CMD, 0, 0, do_show_ipv6_dhcp_inter, NULL, NULL, CLI_END_FLAG, 0, 0,
		"show dhcp interface", "DHCP 接口信息" },
	{ "pool", CLI_CMD, 0, 0, do_show_ipv6_dhcp_pool, NULL, NULL, CLI_END_FLAG, 0, 0,
		"show dhcp pool", "DHCP 地址池" },
	{ CMDS_END }
};

static struct cmds show_ipv6_dhcp_snooping_binding_cmds[] = {
	{ "binding", CLI_CMD, 0, 0, show_ipv6_dhcp_snooping_binding, NULL, NULL, CLI_END_NONE, 0, 0,
		"show dhcp snooping", "侦听DHCP" },
	{ CMDS_END }
};


static struct cmds show_ipv6_dhcp_snooping_binding_all_cmds[] = {
	{ "all", CLI_CMD, 0, 0, do_show_ipv6_dhcp_snooping_binding_all, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show DHCPv6 snooping binding", "显示DHCPv6的绑定信息" },
	{ CMDS_END }
};

static struct cmds show_ipv6_dhcp_pool_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_show_ipv6_dhcp_pool_name, NULL, NULL, CLI_END_FLAG, 0, 0,
		"pool name", "地址池名称" },
	{ CMDS_END }
};

static struct cmds show_ipv6_ospf_cmds[] = {
	{ "neighbor", CLI_CMD, 0, 0, do_show_ipv6_ospf_neighbor, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Neighbor list", "邻居列表" },
	{ CMDS_END }
};

static struct cmds show_ipv6_rip_cmds[] = {
	{ "next-hops", CLI_CMD, 0, 0, do_show_ipv6_rip_hops, NULL, NULL, CLI_END_FLAG, 0, 0,
		"RIP next-hops", "RIP 下一跳" },
	{ CMDS_END }
};

static struct cmds show_ipv6_mld_cmds[] = {
	{ "interface", CLI_CMD, 0, 0, do_show_ipv6_mld_int, NULL, NULL, CLI_END_NONE, 0, 0,
		"interface vlan", "接口信息" },
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_show_ipv6_mld_group, NULL, NULL, CLI_END_FLAG, 0, 0,
		"MLD IP address", "MLD IP 地址" },
	{ "detail", CLI_CMD, 0, 0, do_show_ipv6_mld_detail, NULL, NULL, CLI_END_FLAG, 0, 0,
		"detail", "详细信息" },
	{ CMDS_END }
};

static struct cmds show_ipv6_mld_int_cmds[] = {
	{ "VLAN", CLI_CMD, 0, 0, do_show_ipv6_mld_int_vlan, NULL, NULL, CLI_END_NONE, 0, 0,
		"interface vlan", "MLD 接口信息" },
	{ CMDS_END }
};

static struct cmds show_ipv6_mld_int_vlan_cmds[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_show_ipv6_mld_int_vlan_num, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"interface vlan", "MLD 接口信息" },
	{ CMDS_END }
};



static struct cmds show_aaa_cmds[] = {
	{ "users", CLI_CMD, 0, 0, do_show_aaa_users, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Users", "用户" },
	{ CMDS_END }
};

static struct cmds show_agg_cmds[] = {
	{ "<1-6>", CLI_INT, 0, 0, do_show_agg_grp, NULL, NULL, CLI_END_NONE, 1, 6,
		"Aggregator group number", "聚合组号" },
	{ "brief", CLI_CMD, 0, 0, do_show_agg_brief, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Brief information", "主要状态信息" },
//	{ "detail", CLI_CMD, 0, 0, do_show_agg_detail, NULL, NULL, CLI_END_FLAG, 0, 0,
//		"Detail information", "详细状态信息" },
	{ "load-balance", CLI_CMD, 0, 0, do_show_agg_load, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Load balancing method", "负载均衡模式" },
	{ "summary", CLI_CMD, 0, 0, do_show_agg_summary, NULL, NULL, CLI_END_FLAG, 0, 0,
		"One-line summary per aggregator-group", "每一组统计状态信息" },
	{ CMDS_END }
};

static struct cmds show_agg_grp_cmds[] = {
//	{ "brief", CLI_CMD, 0, 0, do_show_agg_grp_bri, NULL, NULL, CLI_END_FLAG, 0, 0,
//		"Brief information", "主要状态信息" },
//	{ "detail", CLI_CMD, 0, 0, do_show_agg_grp_det, NULL, NULL, CLI_END_FLAG, 0, 0,
//		"Detail information", "详细状态信息" },
	{ "summary", CLI_CMD, 0, 0, do_show_agg_grp_sum, NULL, NULL, CLI_END_FLAG, 0, 0,
		"One-line summary per aggregator-group", "每一组统计状态信息" },
	{ CMDS_END }
};

static struct cmds show_dot1x_cmds[] = {
	{ "info", CLI_CMD, 0, 0, do_show_dot1x_info, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IEEE 802.1X info", "IEEE 802.1X 信息" },
//	{ "interface", CLI_CMD, 0, SHOW_DOT1X_IF_PORT, do_show_dot1x_inter, NULL, NULL, CLI_END_NONE, 0, 0,
//		"IEEE 802.1X interface status", "IEEE 802.1X 接口状态信息" },
//	{ "statistics", CLI_CMD, 0, 0, do_show_dot1x_stat, NULL, NULL, CLI_END_FLAG, 0, 0,
//		"IEEE 802.1X statistics", "IEEE 802.1X 统计接口" },
	{ CMDS_END }
};

static struct cmds show_dot1x_inter_cmds[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0,SHOW_IF_FAST_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0,SHOW_IF_GIGA_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口" },
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_XE_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网接口" },
#endif
	{ CMDS_END }
};
//show int f0/xxx
static struct cmds show_inter_cmds[] = {
	{ "vlan", CLI_CMD, 0, SHOW_IF_VLAN_PORT, do_show_interface_vlan, NULL, NULL, CLI_END_FLAG, 0, 0,
		"vlan Interface brief", "VLAN简要信息" },
	{ "brief", CLI_CMD, 0, 0, do_show_inter_bri, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Interface brief", "端口简要信息" },
	{ "Tranceiver", CLI_CMD, 0, 0, do_show_inter_ddm, NULL, NULL, CLI_END_FLAG, 0, 0,
			"SFP Tranceiver Infomation", "SFP Device Informations" },
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0,SHOW_IF_FAST_PORT , do_show_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0,SHOW_IF_GIGA_PORT, do_show_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口" },
#if (XPORT==1)		
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_XE_PORT, do_show_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网接口" },
#endif
	{ "port-aggregator", CLI_CMD, 0, 0, do_show_inter_agg, NULL, NULL, CLI_END_NONE, 0, 0,
		"Ethernet aggregation interface", "以太网聚合端口" },
	{ CMDS_END }
};

static struct cmds show_ip_cmds[] = {
	{ "access-lists", CLI_CMD, 0, 0, do_show_ip_access, NULL, NULL, CLI_END_FLAG, 0, 0,
		"List IP access lists", "列出IP 访问列表" },
	{ "igmp-snooping", CLI_CMD, 0, 0, do_show_ip_igmp_sn, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show igmp-snooping", "IGMP Snooping 信息" },
	{ "igmp", CLI_CMD, 0, 0, do_show_ip_igmp, NULL, NULL, CLI_END_NONE, 0, 0,
		"igmp", "组播信息" },
	{ CMDS_END }
};

static struct cmds show_ip_access_name[] = {
	{ "WORD", CLI_WORD, 0, 0, do_show_ip_access_word, NULL, NULL, CLI_END_FLAG, 0, 0,
		"List an access-list name", "列出某个 IP 访问列表名" },
	{ CMDS_END }
};

static struct cmds show_ip_dhcp_cmds[] = {
	{ "snooping", CLI_CMD, 0, 0, do_show_ip_dhcp_snoop, NULL, NULL, CLI_END_NONE, 0, 0,
		"Show DHCP relay snooping", "显示DHCP Relay Snooping 信息" },
	{ "binding", CLI_CMD, 0, 0, do_show_ip_dhcp_binding, NULL, NULL, CLI_END_NONE, 0, 0,
		"Show DHCP binding", "显示DHCP 绑定列表" },
	{ "server", CLI_CMD, 0, 0, do_show_ip_dhcp_server, NULL, NULL, CLI_END_NONE, 0, 0,
		"Show DHCP server", "显示DHCP 服务器" },
	{ CMDS_END }
};

static struct cmds show_ip_dhcp_snoop_cmds[] = {
	{ "binding", CLI_CMD, 0, 0, do_show_ip_dhcp_snoop_bind, NULL, NULL, CLI_END_NONE, 0, 0,
		"Show DHCP relay snooping binding", "显示DHCP Relay Snooping binding 信息" },
	{ CMDS_END }
};

static struct cmds show_ip_dhcp_snoop_bind_cmds[] = {
	{ "all", CLI_CMD, 0, 0, do_show_ip_dhcp_snoop_bind_all, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show all DHCP snooping binding", "显示所有DHCP Snooping 绑定" },	
	{ CMDS_END }
};

static struct cmds show_ip_dhcp_binding_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_show_ip_dhcp_binding_addr, NULL, NULL, CLI_END_FLAG, 0, 0,
		"special IP address", "特定IP 地址" },
	{ "all", CLI_CMD, 0, 0, do_show_ip_dhcp_binding_all, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show all DHCP snooping binding", "显示所有DHCP 绑定列表" },
	{ "manual", CLI_CMD, 0, 0, do_show_ip_dhcp_binding_manual, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show manual DHCP snooping binding", "显示手动DHCP 绑定列表" },
	{ "dynamic", CLI_CMD, 0, 0, do_show_ip_dhcp_binding_dynamic, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show dynamic DHCP snooping binding", "显示动态DHCP 绑定列表" },
	{ CMDS_END }
};

static struct cmds show_ip_dhcp_server_cmds[] = {
	{ "statistics", CLI_CMD, 0, 0, do_show_ip_dhcp_server_stats, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show DHCP server statistics", "显示DHCP 服务器状态" },	
	{ CMDS_END }
};

static struct cmds show_ip_inter_cmds[] = {
	{ "brief", CLI_CMD, 0, 0, do_show_ip_inter_bri, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Ip brief information and configuration of interface", "IP 简要端口状态和配置" },
	{ "detail", CLI_CMD, 0, 0, do_show_ip_inter_det, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Ip detail information and configuration of interface", "IP 详细端口状态和配置" },
	{ CMDS_END }
};

static struct cmds show_ip_source_cmds[] = {
	{ "binding", CLI_CMD, 0, 0, do_show_ip_source_binding, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show ip source binding", "显示源 IP 绑定信息" },
	{ CMDS_END }
};

static struct cmds show_lldp_cmds[] = {
	{ "neighbors", CLI_CMD, 0, 0, do_show_lldp_neigh, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show the lldp neighbors info", "显示LLDP 邻居信息" },
//	{ "interface", CLI_CMD, 0, SHOW_LLDP_IF_PORT, do_show_lldp_inter, NULL, NULL, CLI_END_NONE, 0, 0,
//		"LLDP information on a specific interface", "显示特定端口的LLDP 邻居信息" },
	{ CMDS_END }
};

static struct cmds show_lldp_neigh_cmds[] = {
	{ "detail", CLI_CMD, 0, 0, do_show_lldp_neigh_det, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Show the lldp detailed information", "显示LLDP 详情信息" },
	{ CMDS_END }
};

static struct cmds show_lldp_inter_cmds[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_FAST_PORT, do_show_interface_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_GIGA_PORT, do_show_interface_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口" },
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_FAST_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "快速以太网接口" },
#endif
	{ CMDS_END }
};

static struct cmds show_mac_cmds[] = {
	{ "address-table", CLI_CMD, 0, 0, do_show_mac_addr, NULL, NULL, CLI_END_FLAG, 0, 0,
		"MAC forwarding table", "MAC 转发表" },
	{ CMDS_END }
};

static struct cmds show_mac_addr_cmds[] = {
	{ "HH:HH:HH:HH:HH:HH", CLI_MAC, 0, 0, do_show_mac_addr_value, NULL, NULL, CLI_END_FLAG, 0, 0,
		"List a specific MAC addresses", "显示特定MAC 地址" },
	{ "dynamic", CLI_CMD, 0, 0, do_show_mac_addr_dynamic, NULL, NULL, CLI_END_FLAG, 0, 0,
		"List dynamic MAC addresses", "显示动态MAC 地址表" },
	{ "interface", CLI_CMD, 0, SHOW_MAC_IF_PORT, do_show_mac_addr_inter, NULL, NULL, CLI_END_NONE, 0, 0,
		"List MAC addressed on a specific interface", "显示特定端口的MAC 地址表" },
	{ "multicast", CLI_CMD, 0, 0, do_show_mac_addr_mul, NULL, NULL, CLI_END_FLAG, 0, 0,
		"List multicast MAC addresses", "显示多播MAC 地址表" },
	{ "static", CLI_CMD, 0, 0, do_show_mac_addr_static, NULL, NULL, CLI_END_FLAG, 0, 0,
		"List static MAC addresses", "显示静态MAC 地址表" },
	{ "vlan", CLI_CMD, 0, 0, do_show_mac_addr_vlan, NULL, NULL, CLI_END_NONE, 0, 0,
		"List MAC addresses on a specific vlan", "显示特定Vlan 的MAC 地址表" },
	{ "blackhole", CLI_CMD, 0, 0, do_show_mac_addr_blackhole, NULL, NULL, CLI_END_FLAG, 0, 0,
		"List blackhole MAC addresses", "显示黑洞MAC 地址表" },
	{ CMDS_END }
};

static struct cmds show_mac_addr_dyna_cmds[] = {
	{ "interface", CLI_CMD, 0, SHOW_MAC_DYNAMIC_IF_PORT, do_show_mac_addr_dyna_inter, NULL, NULL, CLI_END_NONE, 0, 0,
		"List MAC addressed on a specific interface", "显示特定端口的MAC 地址表" },
	{ CMDS_END }
};

static struct cmds show_mac_addr_dyna_inter_cmds[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0,SHOW_IF_FAST_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0,SHOW_IF_GIGA_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口" },
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0,SHOW_IF_XE_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网接口" },
#endif
	{ CMDS_END }
};

static struct cmds show_mac_addr_inter_cmds[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_FAST_PORT, do_show_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_GIGA_PORT, do_show_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口" },
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_XE_PORT, do_show_interface_range_port, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网接口" },
#endif
	{ CMDS_END }
};

static struct cmds show_mirror_cmds[] = {
	{ "session", CLI_CMD, 0, 0, do_show_mirror_session, NULL, NULL, CLI_END_NONE, 0, 0,
		"SPAN session", "监控会话" },
	{ CMDS_END }
};

static struct cmds show_process_cmds[] = {
	{ "cpu", CLI_CMD, 0, 0, do_show_process_cpu, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Cpu info", "Cpu 信息" },
	{ CMDS_END }
};

static struct cmds show_running_cmds[] = {
	{ "interface", CLI_CMD, 0, 0, do_show_running_inter, NULL, NULL, CLI_END_NONE, 0, 0,
		"Current interface configuration", "当前接口配置" },
	{ CMDS_END }
};
static struct cmds do_show_one_pol[] = {
	{ "WORD", CLI_WORD, 0, 0, do_show_one_pol_map, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Policy-map name", "Policy-map名称" },
	{ CMDS_END }
};

static struct cmds show_running_inter_cmds[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_FAST_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_GIGA_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口" },
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_XE_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网接口" },
#endif
	{ "vlan", CLI_CMD_UNUSAL, 0, SHOW_IF_VLAN_PORT, do_show_interface_vlan, NULL, NULL, CLI_END_NONE, 0, 0,
		"VLAN interface", "vlan 接口" },
	{ CMDS_END }
};

static struct cmds show_spanning_cmds[] = {
	{ "mst", CLI_CMD, 0, 0, do_show_spanning_mst, NULL, NULL, CLI_END_NONE, 0, 0,
		"Multiple spanning trees", "多生成树" },
	{ CMDS_END }
};

static struct cmds show_spanning_mst_cmds[] = {
	{ "<0-15>", CLI_INT, 0, 0, do_show_spanning_mst_id, NULL, NULL, CLI_END_FLAG, 0, 15,
		"MST instance list, example 0,2-4,6,8-12", "多生成树实例，如0，2-4，6，8-12" },
	{ "configuration", CLI_CMD, 0, 0, do_show_mstcfg, NULL, NULL, CLI_END_FLAG, 0, 0,
		"MST current region configuration", "当前的MST域配置信息" },
	{ CMDS_END }
};

static struct cmds show_vlan_cmds[] = {
	{ "id", CLI_CMD, 0, 0, do_show_vlan_id, NULL, NULL, CLI_END_NONE, 0, 0,
		"VLAN status by VLAN id", "特定Vlan 具体状态信息" },
	{ "interface", CLI_CMD, 0, SHOW_VLAN_IF_PORT, do_show_vlan_inter, NULL, NULL, CLI_END_NONE, 0, 0,
		"Interface status and configuration", "接口下的Vlan 状态信息" },
	{ "dot1q-tunnel", CLI_CMD, 0, 0, do_show_vlan_dot1q, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Global Dot1Q Tunnel Infomation", "全局的Dot1Q Tunnel 信息" },
	{ CMDS_END }
};

static struct cmds show_vlan_inter_cmds[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_FAST_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_GIGA_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口" },
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_XE_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网接口" },
#endif
	{ CMDS_END }
};

/* interface fast port */
static struct cmds show_interface_num_cmds[] = {
	{ "<0-0>", CLI_CHAR_NO_BLANK, 0, 0, do_show_interface_num, NULL, NULL, CLI_END_NONE, 0x30, 0x30,
		"Interface number", "槽号" },
	{ CMDS_END }
};
static struct cmds show_interface_slash_cmds[] = {
	{ "/", CLI_CHAR_NO_BLANK, 0, 0, do_show_interface_slash, NULL, NULL, CLI_END_NONE, 0, 0,
		"Slash", "斜杠" },
	{ CMDS_END }
};
static struct cmds show_interface_port_cmds[] = {
	{ "<x-x>", CLI_INT, 0, 0, do_show_dy_interface, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Port number", "端口号" },
	{ CMDS_END }
};

/* interface vlan */
static struct cmds show_interface_vlan_id_cmds[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_show_interface_vlan_id, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"VLAN interface number", "VLAN 序号" },
	{ CMDS_END }
};

/* interface range fast port */
static struct cmds show_interface_range_num_cmds[] = {
	{ "<0-0>", CLI_CHAR_NO_BLANK, 0, 0, do_show_interface_range_num, NULL, NULL, CLI_END_NONE, 0x30, 0x30,
		"Interface number", "槽号" },
	{ CMDS_END }
};
static struct cmds show_interface_range_slash_cmds[] = {
	{ "/", CLI_CHAR_NO_BLANK, 0, 0, do_show_interface_range_slash, NULL, NULL, CLI_END_NONE, 0, 0,
		"Slash", "斜杠" },
	{ CMDS_END }
};
static struct cmds show_interface_range_port_start_cmds[] = {
	{ "<x-x>", CLI_INT_UNUSAL, 0, 0, do_show_interface_range_port_start, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Port number", "端口号" },
	{ CMDS_END }
};
static struct cmds show_interface_symbol_cmds[] = {
	{ "-", CLI_CHAR_UNUSAL, 0, 0, do_show_interface_range_hyphen, NULL, NULL, CLI_END_NONE, 0, 0,
		"Hyphen", "横杠" },
	{ ",", CLI_CHAR_UNUSAL, 0, 0, do_show_interface_range_comma, NULL, NULL, CLI_END_NONE, 0, 0,
		"Comma", "逗号" },
	{ CMDS_END }
};
static struct cmds show_interface_range_port_end_cmds[] = {
	{ "<x-x>", CLI_INT_UNUSAL, 0, 0, do_show_interface_range_port_end, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Port number", "结束端口号" },
	{ CMDS_END }
};
static struct cmds show_interface_comma_end_cmds[] = {
	{ ",", CLI_CHAR_UNUSAL, 0, 0, do_show_interface_range_comma_end, NULL, NULL, CLI_END_NONE, 0, 0,
		"Comma", "逗号" },
	{ CMDS_END }
};

static struct cmds show_vrrp_cmds[] = {
	{ "brief", CLI_CMD, 0, 0, do_show_vrrp_brief, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Brief output", "详细输出" },
	{ "interface", CLI_CMD, 0, 0, do_show_vrrp_int, NULL, NULL, CLI_END_NONE, 0, 0,
		"interface vlan", "接口" },
	{ CMDS_END }
};

static struct cmds show_bgp_cmds[] = {
	{ "ipv6", CLI_CMD, 0, 0, do_show_bgp_ipv6, NULL, NULL, CLI_END_NONE, 0, 0,
		"Address family", "地址簇" },
	{ CMDS_END }
};

static struct cmds show_bgp_ipv6_cmds[] = {
	{ "unicast", CLI_CMD, 0, 0, do_show_bgp_ipv6_unicast, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Address Family modifier", "地址簇变换" },
	{ CMDS_END }
};

static struct cmds show_isis_cmds[] = {
	{ "neighbors", CLI_CMD, 0, 0, do_show_isis_neighbors, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IS-IS neighbors", "IS-IS 邻居" },
	{ CMDS_END }
};

static struct cmds show_gvrp_cmds[] = {
	{ "statistics", CLI_CMD, 0, 0, do_show_gvrp_stats, NULL, NULL, CLI_END_NONE, 0, 0,
		"GVRP statistics", "GVRP 状态" },
	{ CMDS_END }
};

static struct cmds show_gvrp_stats_cmds[] = {
	{ "interface", CLI_CMD, 0, SHOW_GVRP_IF_PORT, do_show_gvrp_stats_inter, NULL, NULL, CLI_END_NONE, 0, 0,
		"Interface status and configuration", "接口下的GVRP 状态信息" },
};

static struct cmds show_gvrp_stats_inter_cmds[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_FAST_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_GIGA_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口" },
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_XE_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网接口" },
#endif
	{ CMDS_END }
};

static struct cmds show_ip_ospf_cmds[] = {
	{ "neighbor", CLI_CMD, 0, 0, do_show_ip_ospf_neighbor, NULL, NULL, CLI_END_FLAG, 0, 0,
		"OSPF neighbor", "OSPF 邻居" },
	{ CMDS_END }
};

static struct cmds show_clns_cmds[] = {
	{ "neighbor", CLI_CMD, 0, 0, do_show_clns_neighbor, NULL, NULL, CLI_END_FLAG, 0, 0,
		"CLNS neighbor", "CLNS 邻居" },
	{ CMDS_END }
};

static struct cmds show_ip_bgp_cmds[] = {
	{ "summary", CLI_CMD, 0, 0, do_show_ip_bgp_summary, NULL, NULL, CLI_END_FLAG, 0, 0,
		"BGP summary", "BGP 摘要信息" },
	{ CMDS_END }
};

static struct cmds show_garp_cmds[] = {
	{ "timer", CLI_CMD, 0, 0, do_show_garp_timer, NULL, NULL, CLI_END_FLAG, 0, 0,
		"GARP timer", "GARP 定时器" },
	{ "statistics", CLI_CMD, 0, 0, do_show_garp_stats, NULL, NULL, CLI_END_NONE, 0, 0,
		"GARP statistics", "GARP 状态" },
	{ CMDS_END }
};
static struct cmds show_erps_ring_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_show_erps_ring_id, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"RING id", "环网编号" },
	{ CMDS_END }
};

static struct cmds show_erps_instance_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_show_erps_instance_id, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"Instance id", "环网编号" },
	{ CMDS_END }
};


static struct cmds show_erps_cmds[] = {
	{ "ring", CLI_CMD, 0, 0, do_show_erps_ring, NULL, NULL, CLI_END_FLAG, 0, 0,
		"ring id", "环ID" },
	{ "instance", CLI_CMD, 0, 0, do_show_erps_instance, NULL, NULL, CLI_END_FLAG, 0, 0,
		"instance name", "实例名称" },
	{ "profile", CLI_CMD, 0, 0, do_show_erps_profile, NULL, NULL, CLI_END_FLAG, 0, 0,
		"instance name", "实例名称" },	
	{ CMDS_END }
};

static struct cmds show_garp_stats_cmds[] = {
	{ "interface", CLI_CMD, 0, SHOW_GARP_IF_PORT, do_show_garp_stats_inter, NULL, NULL, CLI_END_NONE, 0, 0,
		"Interface status and configuration", "接口下的GARP 状态信息" },
};

static struct cmds show_garp_stats_inter_cmds[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_FAST_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_GIGA_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口" },
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_XE_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网接口" },
#endif
	{ CMDS_END }
};

static struct cmds show_gmrp_cmds[] = {
	{ "status", CLI_CMD, 0, 0, do_show_gmrp_status, NULL, NULL, CLI_END_FLAG, 0, 0,
		"GMRP statistics", "GMRP 状态" },
	{ "statistics", CLI_CMD, 0, 0, do_show_gmrp_stats, NULL, NULL, CLI_END_NONE, 0, 0,
		"GMRP statistics", "GMRP 状态" },
	{ CMDS_END }
};

static struct cmds show_gmrp_stats_cmds[] = {
	{ "interface", CLI_CMD, 0, SHOW_GMRP_IF_PORT, do_show_gmrp_stats_inter, NULL, NULL, CLI_END_NONE, 0, 0,
		"Interface status and configuration", "接口下的GMRP 状态信息" },
};

static struct cmds show_gmrp_stats_inter_cmds[] = {
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_FAST_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_GIGA_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网接口" },
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, SHOW_IF_XE_PORT, do_show_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网接口" },
#endif
	{ CMDS_END }
};

static struct cmds show_ip_mroute_cmds[] = {
	{ "static", CLI_CMD, 0, 0, do_show_ip_mroute_static, NULL, NULL, CLI_END_FLAG, 0, 0,
		"mroute static", "组播路由状态" },
	{ "pim-dm", CLI_CMD, 0, 0, do_show_ip_mroute_pim, NULL, NULL, CLI_END_FLAG, 0, 0,
		"mroute pim-dm", "组播路由 dm" },
	{ "pim-sm", CLI_CMD, 0, 0, do_show_ip_mroute_sm, NULL, NULL, CLI_END_FLAG, 0, 0,
		"mroute pim-sm", "组播路由 sm" },
	{ CMDS_END }
};

static struct cmds show_ip_mroute_pim_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_show_ip_mroute_pim_group, NULL, NULL, CLI_END_FLAG, 0, 0,
		"mroute IP group", "mroute IP 组地址" },
	{ CMDS_END }
};

static struct cmds show_ip_mroute_pim_group_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_show_ip_mroute_pim_group_src, NULL, NULL, CLI_END_FLAG, 0, 0,
		"mroute IP source", "mroute IP 源地址" },
	{ CMDS_END }
};

static struct cmds show_ip_igmp_cmds[] = {
	{ "interface", CLI_CMD, 0, 0, do_show_ip_igmp_int, NULL, NULL, CLI_END_NONE, 0, 0,
		"interface vlan", "接口信息" },
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_show_ip_igmp_group, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IGMP IP address", "组播 IP 地址" },
	{ "detail", CLI_CMD, 0, 0, do_show_ip_igmp_detail, NULL, NULL, CLI_END_FLAG, 0, 0,
		"detail", "详细信息" },
	{ CMDS_END }
};

static struct cmds show_ip_igmp_int_cmds[] = {
	{ "VLAN", CLI_CMD, 0, 0, do_show_ip_igmp_int_vlan, NULL, NULL, CLI_END_NONE, 0, 0,
		"interface vlan", "组播路由状态" },
	{ CMDS_END }
};

static struct cmds show_ip_igmp_int_vlan_cmds[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_show_ip_igmp_int_vlan_num, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"interface vlan", "组播路由状态" },
	{ CMDS_END }
};

static struct cmds show_ip_pim_cmds[] = {
	{ "neighbor", CLI_CMD, 0, 0, do_show_ip_pim_neighbor, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP pim-dm neighbor", "IP pim-dm 邻居" },
	{ "interface", CLI_CMD, 0, 0, do_show_ip_pim_interface, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP pim-dm interface", "IP pim-dm 接口" },
	{ CMDS_END }
};

static struct cmds show_ip_pim_neighbor_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_show_ip_pim_neighbor_int, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP pim-dm neighbor interface", "IP pim-dm 邻居接口" },
	{ CMDS_END }
};

static struct cmds show_ip_sm_cmds[] = {
	{ "neighbor", CLI_CMD, 0, 0, do_show_ip_sm_neighbor, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP pim-sm neighbor", "IP pim-sm 邻居" },
	{ "rp", CLI_CMD, 0, 0, do_show_ip_sm_rp, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP pim-sm rp", "IP pim-sm rp" },
	{ CMDS_END }
};

static struct cmds show_ip_sm_neighbor_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_show_ip_sm_neighbor_int, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP pim-sm neighbor interface", "IP pim-sm 邻居接口" },
	{ CMDS_END }
};

static struct cmds show_ip_sm_rp_cmds[] = {
	{ "mapping", CLI_CMD, 0, 0, do_show_ip_sm_rp_map, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP pim-sm rp mapping", "IP pim-sm rp 映射" },
	{ "metric", CLI_CMD, 0, 0, do_show_ip_sm_rp_met, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP pim-sm rp metric", "IP pim-sm rp metric" },
	{ CMDS_END }
};

static struct cmds show_ipv6_mroute_cmds[] = {
	{ "pim", CLI_CMD, 0, 0, do_show_ipv6_mroute_pim, NULL, NULL, CLI_END_FLAG, 0, 0,
		"mroute pim", "组播路由" },
	{ CMDS_END }
};

static struct cmds show_ipv6_mroute_pim_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_show_ipv6_mroute_pim_group, NULL, NULL, CLI_END_FLAG, 0, 0,
		"mroute IPv6 group", "mroute IPv6 组地址" },
	{ CMDS_END }
};

static struct cmds show_ipv6_mroute_pim_group_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_show_ipv6_mroute_pim_group_src, NULL, NULL, CLI_END_FLAG, 0, 0,
		"mroute IPv6 source", "mroute IPv6 源地址" },
	{ CMDS_END }
};

static struct cmds show_vrrp_int_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_show_vrrp_int_vlan, NULL, NULL, CLI_END_FLAG, 0, 0,
		"VRRP interface vlan", "VRRP 接口" },
	{ CMDS_END }
};

static struct cmds show_bfd_cmds[] = {
	{ "neighbors", CLI_CMD, 0, 0, do_show_bfd_neighbors, NULL, NULL, CLI_END_NONE, 0, 0,
		"BFD neighbors", "BFD 邻居" },
	{ CMDS_END }
};

static struct cmds show_bfd_neighbors_cmds[] = {
	{ "details", CLI_CMD, 0, 0, do_show_bfd_neighbors_details, NULL, NULL, CLI_END_FLAG, 0, 0,
		"BFD neighbors details", "BFD 邻居详情" },
	{ CMDS_END }
};

static struct cmds show_ring_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_show_ring_id, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"RING id", "环网编号" },
	{ CMDS_END }
};

/*
 *  Function:  do_show
 *  Purpose:  show topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
 
static int do_show(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_aaa
 *  Purpose:  aaa subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_aaa(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_aaa_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_aaa_users
 *  Purpose:  aaa user subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_aaa_users(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
//		vty_output("the command doesn't support in the version\n");
		func_show_aaa_user();
	}

	return retval;
}

/*
 *  Function:  do_show_access
 *  Purpose:  access-list subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_access(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_access_list();
	}

	return retval;
}

/*
 *  Function:  do_show_agg
 *  Purpose:  aggregator-group subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_agg(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_agg_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_agg_grp
 *  Purpose:  aggregator-group id subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_agg_grp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_agg_grp_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_agg_grp_bri
 *  Purpose:  id brief subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_agg_grp_bri(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		vty_output("the command dons't support this version\n");

	}

	return retval;
}

/*
 *  Function:  do_show_agg_grp_det
 *  Purpose:  id detial subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_agg_grp_det(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		vty_output("the command dons't support this version\n");

	}

	return retval;
}

/*
 *  Function:  do_show_agg_grp_sum
 *  Purpose:  id summary subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_agg_grp_sum(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{	
		int group = 0;
		cli_param_get_int(STATIC_PARAM, 0, &group, u);
		func_show_aggregator_group(group);

	}

	return retval;
}

/*
 *  Function:  do_show_agg_brief
 *  Purpose:  aggregator-group brief subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_agg_brief(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		cli_show_agg_brief();
	}

	return retval;
}

/*
 *  Function:  do_show_agg_detail
 *  Purpose:  aggregator-group detail subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_agg_detail(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		vty_output("the command doesn't support this version\n");

	}

	return retval;
}

/*
 *  Function:  do_show_agg_load
 *  Purpose:  aggregator-group load-balance subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_agg_load(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_aggregator_load_balance();

	}

	return retval;
}

/*
 *  Function:  do_show_agg_summary
 *  Purpose:  aggregator-group summary subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_agg_summary(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_aggregator_group(0);

	}

	return retval;
}

/*
 *  Function:  do_show_arp
 *  Purpose:  arp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_arp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_arp();
	}

	return retval;
}

/*
 *  Function:  do_show_clock
 *  Purpose:  clock subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_clock(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_clock();
	}

	return retval;
}

/*
 *  Function:  do_show_dot1x
 *  Purpose:  dot1x subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_dot1x(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_dot1x(CLI_SHOW_GLOABAL,0 );
	}
	retval = sub_cmdparse(show_dot1x_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_dot1x_info
 *  Purpose:  dot1x info subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_dot1x_info(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		show_dot1x_info();

	}

	return retval;
}

/*
 *  Function:  do_show_dot1x_inter
 *  Purpose:  dot1x interface subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_dot1x_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_dot1x_inter_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_dot1x_stat
 *  Purpose:  dot1x statistics subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_dot1x_stat(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		vty_output("the command doesn't support in the version\n");

	}

	return retval;
}

/*
 *  Function:  do_show_exec_timeout
 *  Purpose:  exec-timeout subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_exec_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_exec_timeout();
	}

	return retval;
}

static int do_show_flow_interval(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_flow_interval();
	}

	return retval;
}
/*
 *  Function:  do_show_history
 *  Purpose:  history subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_history(int argc, char *argv[], struct users *u)
{
	int retval = -1;
    struct hisentry *p;
    int i;

    /* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
    	p = u->his_head;
        for (i = 0; i < u->his_count; i++) {
            vty_output("%s\n", p->buffer);
            p= p->next;
        }    
    }
	return retval;
}

/*
 *  Function:  do_show_inter
 *  Purpose:  interface subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_inter();
	}
	retval = sub_cmdparse(show_inter_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_inter_bri
 *  Purpose:  interface brief subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_inter_bri(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_inter_bri();

	}

	return retval;
}

//Jil -- Fow show DDM 20160624
static int do_show_inter_ddm(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_inter_ddm();
	}

	return retval;
}
//End of Jil

/*
 *  Function:  do_show_inter_agg
 *  Purpose:  interface port-aggregator subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_inter_agg(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-6>";
	param.ylabel = "Port-aggregator interface number";
	param.hlabel = "汇聚端口号";
	param.min = 1;
	param.max = 6;
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
		func_show_inter_agg( u);

	}

	return retval;
}

/*
 *  Function:  do_show_ip
 *  Purpose:  ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_ip_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_ip_access
 *  Purpose:  ip access-lists subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_access(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_all_ip_acl();
	} else
		retval = sub_cmdparse(show_ip_access_name, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_ip_access_word
 *  Purpose:  ip access-lists word subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  gujiajie 
 *  Date:    03/01/2012
 */
static int do_show_ip_access_word(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_one_ip_acl(u);
	} 
	return retval;
}

/*
 *  Function:  do_show_ip_dhcp
 *  Purpose:  ip dhcp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_ip_dhcp_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_ip_dhcp_snoop
 *  Purpose:  dhcp snooping subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_dhcp_snoop(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_ip_dhcp_snoop_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_ip_dhcp_snoop_bind
 *  Purpose:  dhcp snooping binding subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_dhcp_snoop_bind(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_ip_dhcp_snoop_bind_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_ip_dhcp_snoop_bind_all
 *  Purpose:  dhcp snooping binding all subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_dhcp_snoop_bind_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_ip_dhcp_snoopy();

	}

	return retval;
}
#if 0
static int do_show_ip_dhcp_snoop_bind_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		cli_show_ip_dhcp_snoopy_bind_vlan();

	}

	return retval;
}
#endif

/*
 *  Function:  do_show_ip_dhcp_binding
 *  Purpose:  dhcp binding subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_dhcp_binding(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_ip_dhcp_binding_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_dhcp_binding_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_dhcp_binding_addr(u);

	}

	return retval;
}

static int do_show_ip_dhcp_binding_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_dhcp_binding_all(u);

	}

	return retval;
}

static int do_show_ip_dhcp_binding_manual(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_dhcp_binding_manual(u);

	}

	return retval;
}

static int do_show_ip_dhcp_binding_dynamic(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_dhcp_binding_dynamic(u);

	}

	return retval;
}

/*
 *  Function:  do_show_ip_dhcp_server
 *  Purpose:  dhcp server subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_dhcp_server(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_ip_dhcp_server_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_dhcp_server_stats(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_dhcp_server_stats(u);

	}

	return retval;
}

/*
 *  Function:  do_show_ip_igmp_sn
 *  Purpose:  ip igmp-snooping subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_igmp_sn(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_igmp_snooping();

	}

	return retval;
}

/*
 *  Function:  do_show_ip_inter
 *  Purpose:  ip interface subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_ip_inter_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_ip_inter_bri
 *  Purpose:  ip interface brief subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_inter_bri(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_interface();

	}

	return retval;
}

/*
 *  Function:  do_show_ip_inter_det
 *  Purpose:  ip interface detail subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_inter_det(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_interface_detail();

	}

	return retval;
}

/*
 *  Function:  do_show_ip_source
 *  Purpose:  ip source subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_source(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_ip_source_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_ip_source_snoop
 *  Purpose:  ip source snooping subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_source_binding(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_source_binding();

	}

	return retval;
}

/*
 *  Function:  do_show_lldp
 *  Purpose:  lldp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_lldp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_lldp_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_lldp_neigh
 *  Purpose:  lldp neigbbor subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_lldp_neigh(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_lldp_neighbor();
	}
	retval = sub_cmdparse(show_lldp_neigh_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_lldp_neigh_det
 *  Purpose:  lldp neighbor detial subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_lldp_neigh_det(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_lldp_neigh_det();

	}

	return retval;
}

/*
 *  Function:  do_show_lldp_inter
 *  Purpose:  lldp interface subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_lldp_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_lldp_inter_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_logging
 *  Purpose:  logging subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_logging(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_loggin(SHOW_LOGGING);

	}

	return retval;
}

/*
 *  Function:  do_show_loopback
 *  Purpose:  loopback subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_loopback(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_loopback();

	}

	return retval;
}

/*
 *  Function:  do_show_mac
 *  Purpose:  mac subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mac(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_mac_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_mac_addr
 *  Purpose:  mac address subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mac_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_mac_add();
	}
	retval = sub_cmdparse(show_mac_addr_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_mac_addr_value
 *  Purpose:  mac address value subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mac_addr_value(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_mac_addr_value( u);

	}

	return retval;
}

/*
 *  Function:  do_show_mac_addr_dynamic
 *  Purpose:  dynamic subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mac_addr_dynamic(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_mac_add_dy();
	}
	retval = sub_cmdparse(show_mac_addr_dyna_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_mac_addr_dyna_inter
 *  Purpose:  dynamic interface subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mac_addr_dyna_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_mac_addr_dyna_inter_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_mac_addr_inter
 *  Purpose:  interface subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mac_addr_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_mac_addr_inter_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_mac_addr_mul
 *  Purpose:  address multicast subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mac_addr_mul(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_mac_addr_mul();

	}

	return retval;
}

/*
 *  Function:  do_show_mac_addr_static
 *  Purpose:  address static subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mac_addr_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_mac_addr_static();

	}

	return retval;
}

/*
 *  Function:  do_show_mac_addr_vlan
 *  Purpose:  address vlan subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mac_addr_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-4094>";
	param.ylabel = "VLAN IDs 1-4094";
	param.hlabel = "Vlan 值";
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
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_mac_addr_vlan(u);

	}

	return retval;
}

static int do_show_mac_addr_blackhole(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_mac_addr_blackhole();
	}

	return retval;
}

/*
 *  Function:  do_show_mem
 *  Purpose:  memory subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mem(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_memery();

	}

	return retval;
}

/*
 *  Function:  do_show_mirr
 *  Purpose:  mirror subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mirr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_mirror_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_mirror_session
 *  Purpose:  miror session subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_mirror_session(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-1>";
	param.ylabel = "Input number value";
	param.hlabel = "输入规定范围内的数值";
	param.min = 1;
	param.max = 1;
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
		func_show_mirror_session();

	}

	return retval;
}

/* show mst-config */
static int do_show_mstcfg(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		func_show_mstcfg();
	}

	return retval;
}

/*
 *  Function:  do_show_ntp
 *  Purpose:  ntp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ntp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ntp();

	}

	return retval;
}

/*
 *  Function:  do_show_pol
 *  Purpose:  policy-map subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
 static int do_show_pol(int argc, char *argv[], struct users *u)//hualimin
 {
 	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		do_show_all_pol();
	}
	retval = sub_cmdparse(do_show_one_pol, argc, argv, u);

	return retval;



 }
static int do_show_one_pol_map(int argc, char *argv[], struct users *u)
{

		int retval = -1;
	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_pol(u);

	}

	return retval;
}

/*
 *  Function:  do_show_process
 *  Purpose:  process subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_process(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_process_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_process_cpu
 *  Purpose:  process cpu subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_process_cpu(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_process_cpu();

	}

	return retval;
}

/*
 *  Function:  do_show_running
 *  Purpose:  running-config subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_running(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_running(CLI_SHOW_ALL, 0);
	}
	retval = sub_cmdparse(show_running_cmds, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_show_running_inter
 *  Purpose:  running-config interface subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_running_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_running_inter_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_spanning
 *  Purpose:  spanning-tree subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_spanning(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_spanning();

	}

	retval = sub_cmdparse(show_spanning_cmds, argc, argv, u);

	return retval;
}

static int do_show_spanning_mst(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_spanning_mst_cmds, argc, argv, u);

	return retval;
}

static int do_show_spanning_mst_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		func_show_spanning_msti(u);
	}

	return retval;
}

/*
 *  Function:  do_show_startup
 *  Purpose:  startup-config subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_startup(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_startup();

	}

	return retval;
}

/*
 *  Function:  do_show_ssh
 *  Purpose:  ssh subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ssh(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
#ifdef CLI_AAA_MODULE
		/* Do application function */
		func_show_ssh();
#endif
	}

	return retval;
}

/*
 *  Function:  do_show_telnet
 *  Purpose:  telnet subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_telnet(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if (retval == 0){
		/* Do application function */
#ifdef CLI_AAA_MODULE
		func_show_telnet();
#endif
	}

	return retval;
}

/*
 *  Function:  do_show_version
 *  Purpose:  version subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_version(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_version();

	}

	return retval;
}

/*
 *  Function:  do_show_vlan
 *  Purpose:  vlan subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_vlan(0);
	}
	retval = sub_cmdparse(show_vlan_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_vlan_id
 *  Purpose:  vlan id subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_vlan_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-4094>";
	param.ylabel = "VLAN IDs 1-4094";
	param.hlabel = "Vlan 值";
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
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_vlan_id(u);

	}

	return retval;
}

/*
 *  Function:  do_show_vlan_inter
 *  Purpose:  vlan interface subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_vlan_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(show_vlan_inter_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_vlan_dot1q
 *  Purpose:  vlan interface dot1q-tunnel subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_vlan_dot1q(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2( argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		vty_output("the command doesn't support in the version\n");

	}

	return retval;
}

/* static, changed when start cmd parse */
static char port_num_start[MAX_ARGV_LEN] = {'\0'};
static char port_num_end[MAX_ARGV_LEN] = {'\0'};

/* interface fast port */
static int do_show_interface_ethernet(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_interface_num_cmds, argc, argv, u);

	return retval;
}

static int do_show_interface_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_interface_slash_cmds, argc, argv, u);

	return retval;
}
static int do_show_dot1x_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct cmds *cmds_ptr = show_interface_port_cmds;

	memset(port_num_start, '\0', sizeof(port_num_start));

	/* Change argcmin and argcmax according to interface type */
	if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, GNUM);
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = GNUM;
	}
	else
		sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

	/* Change name */
	cmds_ptr->name = port_num_start;
	
	retval = sub_cmdparse(show_interface_port_cmds, argc, argv, u);

	return retval;
}
//show mac dy?
static int do_show_dy_interface(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application */
		func_show_interface_port(u);
	}

	return retval;
}
static int do_show_interface_slash(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct cmds *cmds_ptr = show_interface_port_cmds;

	memset(port_num_start, '\0', sizeof(port_num_start));

	/* Change argcmin and argcmax according to interface type */
	if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, GNUM);
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = GNUM;
	}
	else
		sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

	/* Change name */
	cmds_ptr->name = port_num_start;
	
	retval = sub_cmdparse(show_interface_port_cmds, argc, argv, u);

	return retval;
}

static int do_show_interface_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application */
		func_show_interface_port(u);
	}

	return retval;
}

 /* interface vlan */
 static int do_show_interface_vlan(int argc, char *argv[], struct users *u)
 {
	 int retval = -1;

     if(1 == argc)
        cli_show_running_vlan(1);
     else   
	    retval = sub_cmdparse(show_interface_vlan_id_cmds, argc, argv, u);
 
	 return retval;
 }
 
static int do_show_interface_vlan_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application */
		func_show_interface_vlan(u);
	}
	
	return retval;
}

/* interface range fast port */
static int do_show_interface_range_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_interface_range_num_cmds, argc, argv, u);

	return retval;
}

static int do_show_interface_range_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_interface_range_slash_cmds, argc, argv, u);

	return retval;
}
//show int
static int do_show_interface_range_slash(int argc, char *argv[], struct users *u)
{
	int retval = -1;	
	struct cmds *cmds_ptr = show_interface_range_port_start_cmds;

	memset(port_num_start, '\0', sizeof(port_num_start));

	/* Change argcmin and argcmax according to interface type */
	if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, GNUM);
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = GNUM;
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_IF_XE_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else
		sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

	/* Change name */
	cmds_ptr->name = port_num_start;
	
	retval = sub_cmdparse(show_interface_range_port_start_cmds, argc, argv, u);

	return retval;
}

static int do_show_interface_range_port_start(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_interface(u);
	}

	retval = sub_cmdparse(show_interface_symbol_cmds, argc, argv, u);

	return retval;
}

static int do_show_interface_range_hyphen(int argc, char *argv[], struct users *u)
{
	int retval = -1, port_num_start = 0;
	struct cmds *cmds_ptr = show_interface_range_port_end_cmds;

	memset(port_num_end, '\0', sizeof(port_num_end));
	
	cli_param_get_range_edge(STATIC_PARAM, &port_num_start, u);
		
	/* Change argcmin and argcmax according to interface type */
	if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
	{
		sprintf(port_num_end, "<%d-%d>", port_num_start, (PNUM-GNUM));
		cmds_ptr->argcmin = port_num_start;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
	{
		sprintf(port_num_end, "<%d-%d>", port_num_start, GNUM);
		cmds_ptr->argcmin = port_num_start;
		cmds_ptr->argcmax = GNUM;
	}
	else
		sprintf(port_num_end, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

	/* Change name */
	cmds_ptr->name = port_num_end;
	
	retval = sub_cmdparse(show_interface_range_port_end_cmds, argc, argv, u);

	return retval;
}

static int do_show_interface_range_comma(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* cisco :sub_cmdparse(show_interface_range, argc, argv, u) */
	retval = sub_cmdparse(show_interface_range_port_start_cmds, argc, argv, u);

	return retval;
}

static int do_show_interface_range_port_end(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_interface(u);
	}

	retval = sub_cmdparse(show_interface_comma_end_cmds, argc, argv, u);

	return retval;
}

static int do_show_interface_range_comma_end(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* cisco :sub_cmdparse(show_interface_range, argc, argv, u) */
	retval = sub_cmdparse(show_interface_range_port_start_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(show_ipv6_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_interface(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(show_ipv6_in_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_dhcp(u);
	}

	retval = sub_cmdparse(show_ipv6_dhcp_snooping_cmds, argc, argv, u);

	return retval;
}

static int show_ipv6_dhcp_snooping(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(show_ipv6_dhcp_snooping_binding_cmds, argc, argv, u);

	return retval;
}

static int show_ipv6_dhcp_snooping_binding(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(show_ipv6_dhcp_snooping_binding_all_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_dhcp_binding(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_dhcp_binding(u);
	}
	
	return retval;
}

static int do_show_ipv6_dhcp_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_dhcp_inter_all(u);
	}
	
	return retval;
}

static int do_show_ipv6_dhcp_pool(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_dhcp_pool_all(u);
	}

	retval = sub_cmdparse(show_ipv6_dhcp_pool_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_dhcp_pool_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_dhcp_pool_name(u);
	}

	return retval;
}

static int do_show_ipv6_interface_brief(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_brief(u);
	}
	
	return retval;
}

static int do_show_ipv6_interface_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(show_ipv6_in_vlan_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_interface_vlan_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_vlan(u);
	}
	
	return retval;
}

static int do_show_ipv6_neighbors(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_neighbors(u);
	}
	
	return retval;
}

static int do_show_ipv6_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(show_ipv6_ospf_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_ospf_neighbor(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_ospf_neighbor(u);
	}
	
	return retval;
}

static int do_show_ipv6_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(show_ipv6_rip_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_rip_hops(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_rip_hops(u);
	}
	
	return retval;
}

static int do_show_ipv6_route(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_route(u);
	}
	
	return retval;
}

/*
 *  Function:  do_show_ipv6_mld
 *  Purpose:  ip igmp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ipv6_mld(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_ipv6_mld_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_mld_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_ipv6_mld_int_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_mld_int_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_ipv6_mld_int_vlan_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_mld_int_vlan_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ipv6_mld_int(u);
	}

	return retval;
}

static int do_show_ipv6_mld_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ipv6_mld_group(u);
	}

	return retval;
}

static int do_show_ipv6_mld_detail(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ipv6_mld_detail(u);
	}

	return retval;
}

static int do_show_ipv6_dhcp_snooping_binding_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_ipv6_dhcp_snooping_binding_all();
	}

	return retval;
}

static int do_show_error(int argc, char *argv[], struct users *u)
{	
	int retval = -1;
	
	retval = sub_cmdparse(show_error_cmds, argc, argv, u);

	return retval;
}

static int do_show_error_detect(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_error_detect();
	}

	return retval;
}

static int do_show_error_recovery(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_error_recovery();
	}

	return retval;
}

/*by wei.zhang*/
static int do_show_line(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_vty_cmds, argc, argv, u);

	return retval;
}
/*by wei.zhang*/
static int do_vty(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_show_line_vty( 1, MAX_VTY );
	}
	retval = sub_cmdparse(show_vty_first, argc, argv, u);

	return retval;
}
/*by wei.zhang*/
static int do_vty_first(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_vty_last, argc, argv, u);

	return retval;
}

/*by wei.zhang*/
static int do_vty_last(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int line_id[2] = {0,0};


	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		cli_param_get_int(STATIC_PARAM, 0, &line_id[0], u);
		cli_param_get_int(STATIC_PARAM, 1, &line_id[1], u);
		/* Do application */
		func_show_line_vty( line_id[0], line_id[1] );
	}
	
	return retval;
}

/*
 *  Function:  do_show_vrrp
 *  Purpose:  do show vrrp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_show_vrrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_vrrp_cmds, argc, argv, u);

	return retval;
}

static int do_show_vrrp_brief(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_show_vrrp_brief(u);
	}

	return retval;
}

static int do_show_vrrp_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_vrrp_int_cmds, argc, argv, u);

	return retval;
}

static int do_show_vrrp_int_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_show_vrrp_int(u);
	}

	return retval;
}

/*
 *  Function:  do_show_bgp
 *  Purpose:  do show bgp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_show_bgp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_bgp_cmds, argc, argv, u);

	return retval;
}

static int do_show_bgp_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_bgp_ipv6_cmds, argc, argv, u);

	return retval;
}

static int do_show_bgp_ipv6_unicast(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_show_bgp_ipv6_unicast(u);
	}

	return retval;
}

/*
 *  Function:  do_show_isis
 *  Purpose:  do show isis subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_show_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_isis_cmds, argc, argv, u);

	return retval;
}

static int do_show_isis_neighbors(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_show_isis_beighbors(u);
	}

	return retval;
}

/*
 *  Function:  do_show_gvrp
 *  Purpose:  do show gvrp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_show_gvrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_gvrp_cmds, argc, argv, u);

	return retval;
}

static int do_show_gvrp_stats(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_gvrp_stats_cmds, argc, argv, u);

	return retval;
}

static int do_show_gvrp_stats_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_gvrp_stats_inter_cmds, argc, argv, u);

	return retval;
}


/*
 *  Function:  do_show_ip_route
 *  Purpose:  ip route subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_route(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_route(u);
	}

	return retval;
}

/*
 *  Function:  do_show_ip_ospf
 *  Purpose:  ip route subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_ip_ospf_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_ospf_neighbor(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_ospf_neighbor(u);
	}

	return retval;
}

/*
 *  Function:  do_show_ip_rip
 *  Purpose:  ip route subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_rip(u);
	}

	return retval;
}

/*
 *  Function:  do_show_clns
 *  Purpose:  clns subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_clns(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_clns_cmds, argc, argv, u);

	return retval;
}

static int do_show_clns_neighbor(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_clns_neighbor(u);
	}

	return retval;
}

/*
 *  Function:  do_show_garp
 *  Purpose:  garp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_garp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_garp_cmds, argc, argv, u);

	return retval;
}

static int do_show_erps(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_erps_cmds, argc, argv, u);

	return retval;
}
static int do_show_multicast_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_multicast_vlan(u);
	}

	return retval;
}

static int do_show_garp_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_garp_timer(u);
	}

	return retval;
}

static int do_show_garp_stats(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_garp_stats_cmds, argc, argv, u);

	return retval;
}

static int do_show_garp_stats_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_garp_stats_inter_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_gmrp
 *  Purpose:  gmrp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_gmrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_gmrp_cmds, argc, argv, u);

	return retval;
}

static int do_show_gmrp_status(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_gmrp_status(u);
	}

	return retval;
}

static int do_show_gmrp_stats(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_gmrp_stats_cmds, argc, argv, u);

	return retval;
}

static int do_show_gmrp_stats_inter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_gmrp_stats_inter_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_show_ip_bgp
 *  Purpose:  ip route subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_bgp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_ip_bgp_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_bgp_summary(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_bgp_summary(u);
	}

	return retval;
}

/*
 *  Function:  do_show_ip_mroute
 *  Purpose:  ip mroute subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_mroute(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_mroute(u);
	} else
		retval = sub_cmdparse(show_ip_mroute_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_mroute_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_mroute_static(u);
	}

	return retval;
}

static int do_show_ip_mroute_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_mroute_pim(u);
	} else
		retval = sub_cmdparse(show_ip_mroute_pim_cmds, argc, argv, u);

	return retval;
}


static int do_show_ip_mroute_pim_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_mroute_pim_group(u);
	} else
		retval = sub_cmdparse(show_ip_mroute_pim_group_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_mroute_pim_group_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_mroute_pim_group_src(u);
	}

	return retval;
}

static int do_show_ip_mroute_sm(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_mroute_sm(u);
	}

	return retval;
}

/*
 *  Function:  do_show_ip_igmp
 *  Purpose:  ip igmp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_igmp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_ip_igmp_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_igmp_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_ip_igmp_int_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_igmp_int_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_ip_igmp_int_vlan_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_igmp_int_vlan_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_igmp_int(u);
	}

	return retval;
}

static int do_show_ip_igmp_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_igmp_group(u);
	}

	return retval;
}

static int do_show_ip_igmp_detail(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_igmp_detail(u);
	}

	return retval;
}

/*
 *  Function:  do_show_ip_pim
 *  Purpose:  ip pim-md subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_ip_pim_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_pim_neighbor(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_pim_neighbor(u);
	} else
		retval = sub_cmdparse(show_ip_pim_neighbor_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_pim_neighbor_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_pim_neighbor_int(u);
	}

	return retval;
}

static int do_show_ip_pim_interface(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_pim_interface(u);
	}

	return retval;
}

static int do_show_ip_pim_interface_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_pim_interface_int(u);
	}

	return retval;
}

/*
 *  Function:  do_show_ip_sm
 *  Purpose:  ip pim-sd subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ip_sm(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_ip_sm_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_sm_neighbor(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_sm_neighbor(u);
	} 
//	else
//		retval = sub_cmdparse(show_ip_sm_neighbor_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_sm_neighbor_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_sm_neighbor_int(u);
	}

	return retval;
}

static int do_show_ip_sm_rp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_sm_rp(u);
	} 
//	else
//		retval = sub_cmdparse(show_ip_sm_rp_cmds, argc, argv, u);

	return retval;
}

static int do_show_ip_sm_rp_map(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_sm_rp_map(u);
	}

	return retval;
}

static int do_show_ip_sm_rp_met(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ip_sm_rp_met(u);
	}

	return retval;
}

/*
 *  Function:  do_show_ipv6_mroute
 *  Purpose:  ipv6 mroute subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ipv6_mroute(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ipv6_mroute(u);
	} else
		retval = sub_cmdparse(show_ipv6_mroute_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_mroute_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ipv6_mroute_pim(u);
	} else
		retval = sub_cmdparse(show_ipv6_mroute_pim_cmds, argc, argv, u);

	return retval;
}


static int do_show_ipv6_mroute_pim_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ipv6_mroute_pim_group(u);
	} else
		retval = sub_cmdparse(show_ipv6_mroute_pim_group_cmds, argc, argv, u);

	return retval;
}

static int do_show_ipv6_mroute_pim_group_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ipv6_mroute_pim_group_src(u);
	}

	return retval;
}

/*
 *  Function:  do_show_bfd
 *  Purpose:  bfd subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_bfd_cmds, argc, argv, u);

	return retval;
}

static int do_show_bfd_neighbors(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_bfd_neighbors_cmds, argc, argv, u);

	return retval;
}

static int do_show_bfd_neighbors_details(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_bfd_neighbors_details(u);
	}

	return retval;
}

/*
 *  Function:  do_show_filter
 *  Purpose:  filter subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_filter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_filter(u);
	}

	return retval;
}

/*
 *  Function:  do_show_tunnel
 *  Purpose:  tunnel subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_tunnel(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_tunnel(u);
	}

	return retval;
}

/*
 *  Function:  do_show_cluster
 *  Purpose:  cluster subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_cluster(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_cluster(u);
	}

	return retval;
}

/*
 *  Function:  do_show_ring
 *  Purpose:  bfd subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_show_ring(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ring(0);
	}
	retval = sub_cmdparse(show_ring_cmds, argc, argv, u);


	return retval;

}

static int do_show_ring_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_ring_id(u);
	}

	return retval;
}
static int do_show_erps_ring(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_erps_ring_cmds, argc, argv, u);

	return retval;
}

static int do_show_erps_ring_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_erps_ring_id(u);
	}

	return retval;
}
static int do_show_erps_instance(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(show_erps_instance_cmds, argc, argv, u);

	return retval;
}

static int do_show_erps_instance_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_erps_instance_id(u);
	}

	return retval;
}
static int do_show_erps_profile(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_show_erps_profile(u);
	}

	return retval;
}


#define PATH_SVN_VERSION		"/usr/etc/svn_info"
void get_svn_version(char *str_p)
{
	FILE *fp = NULL;
	
	fp = fopen(PATH_SVN_VERSION,"r");
	if(NULL == fp){
		*str_p = 0;	
		return ;
	}
	fread(str_p,32,32,fp);
	fclose(fp);
}

static int do_show_svn_version(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char svn_ver[32] = {0};
	
	get_svn_version(svn_ver);
	svn_ver[sizeof(svn_ver) - 1] = '\0';
	
	vty_output("svn version:%s\n",svn_ver);

	return retval;
}


/*
 *  Function:  init_cli_show
 *  Purpose:  Register show function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
int init_cli_show(void)
{
	int retval = -1;

	retval = registerncmd(show_topcmds, (sizeof(show_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1, "init_cli_qos show_topcmds retval = %d\n", retval);

	return retval;
}




