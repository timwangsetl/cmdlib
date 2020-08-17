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

#include "cli_vlan.h"
#include "cli_vlan_func.h"

/*************************
static struct topcmds topcmds[] = {
	{ "name", pv_level, TREE, func, no_func, def_func, endflag, argcmin, argcmax,
		"help_en", "help_cn" },
	{ TOPCMDS_END }
};

static struct cmds cmds[] = {
	{ "name", MATCH_MODE, pv_level, maskbit, func, no_func, def_func, endflag, argcmin, argcmax,
		"help_en", "help_cn" },
	{ CMDS_END }
};
**************************/

/* vlan command */
static struct topcmds vlan_topcmds[] = {
	{ "vlan", 0, CONFIG_TREE, do_vlan, no_vlan, NULL, CLI_END_NONE, 0, 0,
		"Enter vlan congfiguration  mode", "Vlan 配置命令" },
	{ "gvrp", 0, CONFIG_TREE, do_gvrp, no_gvrp, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Enable GVRP protocol", "使能 GVRP 协议" },
	{ "name", 0, VLAN_TREE, do_vlan_name, no_vlan_name, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Config the name of current vlan", "配置当前vlan的名称" },
#ifdef CLI_PRIVATE_VLAN
	{ "private-vlan", 0, VLAN_TREE, do_private_vlan, NULL, NULL, CLI_END_FLAG, 0, 0,
		"enter Private VLAN", "配置私有vlan" },
#endif
	{ TOPCMDS_END }
};

static struct topcmds multicast_vlan_topcmds[] = {
	{ "multicast-vlan", 0, CONFIG_TREE, do_multicast_vlan, no_multicast_vlan, NULL, CLI_END_NONE, 0, 0,
		"Config multicast-vlan ", "multicast-vlan 配置命令" },
	
	{ TOPCMDS_END }
};

static struct cmds multicast_vlan_id_cmds[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_multicast_vlan_id, NULL, NULL, CLI_END_NONE|CLI_END_NO, 1, 4094,
		"Config vlan ID", "配置 multicast vlan id" },
	{ "enable", 0, 0,0, do_multicast_vlan_enable, no_multicast_vlan_enable, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Enable multicast vlan", "使能multicast vlan" },		
	{ CMDS_END }
};

static struct cmds multicast_vlan_subvlan_cmds[] = {
	{ "subvlan", 0, 0, 0, do_multicast_subvlan, NULL, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Config subvlan ID", "配置组播vlan的子VLAN" },
	{ CMDS_END }
};

/* interface vlan command */
static struct topcmds interface_vlan_topcmds[] = {
	/*{ "ip", 0, IF_VLAN_TREE, do_vlan_ip, no_vlan_ip, NULL, CLI_END_NONE, 0, 0,
		"IP configuration commands", "IP 配置命令" },*/
	{ "gvrp", 0, IF_VLAN_TREE, do_gvrp, no_gvrp, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Enable GVRP protocol", "使能 GVRP 协议" },
	{ "name", 0, IF_VLAN_TREE, do_vlan_name, no_vlan_name, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Config the name of current vlan", "配置当前vlan的名称" },
	{ "supervlan", 0, IF_VLAN_TREE, do_supervlan, no_supervlan, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Super vlan", "配置vlan聚合" },
	{ "subvlan", 0, IF_VLAN_TREE, do_subvlan, no_subvlan, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Config the name of current vlan", "配置当前vlan的名称" },
	{ TOPCMDS_END }
};

static struct cmds vlan_subvlan[] = {
	{ "WORD", CLI_WORD, 0, 0, do_vlan_subvlan, NULL, NULL, CLI_END_FLAG, 0, 0,
		"VLAN IDs such as (1,3,5,7) Or (1,3-5,7) Or (1-7)", "类似(1,3,5,7) 或 (1,3-5,7) 或 (1-7)表示的VLAN 范围表" },
	{ CMDS_END }
};

/* interface vlan: ip sub command */
static struct cmds interface_vlan_ip_cmds[] = {
	/*wuchunli 2012-4-17 9:04:49 
	access-group is invalid*/
#if 0
	{ "access-group", CLI_CMD, 0, 0, do_vlan_ip_access_group, no_vlan_ip_access_group, NULL, CLI_END_NONE, 0, 0,
		"Apply access-list", "指定访问控制" },
#endif
	{ "address", CLI_CMD, 0, 0, do_vlan_ip_address, no_vlan_ip_address, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"address", "IP 地址" },
	{ "igmp", CLI_CMD, 0, 0, do_vlan_ip_igmp, no_vlan_ip_igmp, NULL, CLI_END_NONE, 0, 0 ,
		"Configure igmp", "配置 IGMP" } ,	
	{ CMDS_END }
};

static struct cmds interface_vlan_ip_access_group_cmds[] = {
	{ "in", CLI_CMD, 0, 0, do_vlan_ip_access_group_in, no_vlan_ip_access_group_in, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Inbound packets", "进入的报文" },
	{ "out", CLI_CMD, 0, 0, do_vlan_ip_access_group_out, no_vlan_ip_access_group_out, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Outbound packets", "出去的报文" },
	{ CMDS_END }
};

/* interface vlan: ipv6 sub command */
static struct cmds interface_vlan_ipv6_cmds[] = {
	{ "address", CLI_CMD, 0, 0, do_vlan_ipv6_address_global, no_vlan_ipv6_address_global, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"IPv6 address", "IPv6 地址" },
//	{ "enable", CLI_CMD, 0, 0, do_vlan_ipv6_enable, no_vlan_ipv6_enable, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
//		"Enable IPv6 on interface", "开启接口 IPv6" },
	{ "dhcp", CLI_CMD, 0, 0, do_vlan_ipv6_dhcp, no_vlan_ipv6_dhcp, NULL, CLI_END_NONE, 0, 0,
		"Configure DHCPv6 server and relay parameters", "配置 DHCPv6 服务器 和中继参数" },
	{ "ospf", CLI_CMD, 0, 0, do_vlan_ipv6_ospf, no_vlan_ipv6_ospf, NULL, CLI_END_NONE, 0, 0,
		"OSPF interface commands", "OSPF 接口命令" },
	{ "rip", CLI_CMD, 0, 0, do_vlan_ipv6_rip, no_vlan_ipv6_rip, NULL, CLI_END_NONE, 0, 0,
		"Configure RIP routing protocol", "配置 RIP 路由协议" },
	{ "router", CLI_CMD, 0, 0, do_vlan_ipv6_router, no_vlan_ipv6_router, NULL, CLI_END_NONE, 0, 0,
		"IPv6 Router interface commands", "IPv6 路由接口命令" },
	{ "isis", CLI_CMD, 0, 0, do_vlan_ipv6_isis, no_vlan_ipv6_isis, NULL, CLI_END_NONE, 0, 0,
		"IS-IS commands", "IS-IS 命令" },
	{ "traffic-filter", CLI_CMD, 0, 0, do_vlan_ipv6_traffic, no_vlan_ipv6_traffic, NULL, CLI_END_NONE, 0, 0,
		"Access control list for packets", "ACL 数据包" },
	{ "mld", CLI_CMD, 0, 0, do_vlan_ipv6_mld, no_vlan_ipv6_mld, NULL, CLI_END_NONE, 0, 0,
		"MLD protocol", "MLD 协议" },
	{ "pim", CLI_CMD, 0, 0, do_vlan_ipv6_pim, no_vlan_ipv6_pim, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0 ,
		"Configure pim", "配置 pim" } ,	
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_dhcp_cmds[] = {
	{ "realy", CLI_CMD, 0, 0, do_vlan_ipv6_dhcp_realy, NULL, NULL, CLI_END_NONE, 0, 0,
		"Configure DHCPv6 relay ", "配置 中继" },		
	{ CMDS_END }
};

static struct cmds interface_no_vlan_ipv6_dhcp_cmds[] = {
	{ "realy", CLI_CMD, 0, 0, NULL, no_vlan_ipv6_dhcp_relay, NULL, CLI_END_NO, 0, 0,
		"Configure DHCPv6 relay ", "配置 中继" },		
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_dhcp_realy_cmds[] = {
	{ "X:X:X:X::X", CLI_IPV6, 0, 0, do_vlan_ipv6_dhcp_realy_address, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Configure DHCPv6 relay server address ", "配置中继地址" },		
	{ CMDS_END }
};

/* interface vlan: ip address sub command */
static struct cmds interface_vlan_ip_address_cmds[] = {
	{ "dhcp", CLI_CMD, 0, 0, do_vlan_ip_address_dhcp, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP address negotiated via DHCP", "通过DHCP 协商IP 地址" },
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_vlan_ip_address_static, NULL, NULL, CLI_END_NONE, 0, 0,
		"IP address", "IP 地址" },
	{ CMDS_END }
};

/* interface vlan: ipv6 address sub command */
static struct cmds interface_vlan_ipv6_address_cmds[] = {
	{ "global", CLI_CMD, 0, 0, do_vlan_ipv6_address_global, NULL, NULL, CLI_END_NONE, 0, 0,
		"global IPv6 address", "IPv6 全局地址" },
	{ "local-link", CLI_CMD, 0, 0, do_vlan_ipv6_address_local, NULL, NULL, CLI_END_NONE, 0, 0,
		"local-link IPv6 address", "IPv6 本地地址" },
	{ CMDS_END }
};

static struct cmds interface_no_vlan_ipv6_addr_cmds[] = {
	{ "global", CLI_CMD, 0, 0, NULL , no_vlan_ipv6_address_global, NULL, CLI_END_NO, 0, 0,
		"global IPv6 address", "IPv6 全局地址" },
	{ "local-link", CLI_CMD, 0, 0, NULL, no_vlan_ipv6_address_local, NULL, CLI_END_NO, 0, 0,
		"local-link IPv6 address", "IPv6 本地地址" },
	{ CMDS_END }
};

/* interface vlan: ipv6 ospf sub command */
static struct cmds interface_vlan_ipv6_ospf_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_vlan_ipv6_ospf_pid, no_vlan_ipv6_ospf_pid, NULL, CLI_END_NONE, 1, 65535,
		"Process ID", "进程号" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_ospf_pid_cmds[] = {
	{ "area", CLI_CMD, 0, 0, do_vlan_ipv6_ospf_pid_area, no_vlan_ipv6_ospf_pid_area, NULL, CLI_END_NONE, 0, 0,
		"Set the OSPF area ID", "设置OSFP 区域号" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_ospf_pid_area_cmds[] = {
	{ "<0-2147483647>", CLI_INT, 0, 0, do_vlan_ipv6_ospf_pid_area_id, no_vlan_ipv6_ospf_pid_area_id, NULL, CLI_END_FLAG | CLI_END_NO, 0, 2147483647,
		"OSPF area ID as a decimal value", "OSPF 区域号数值" },
	{ CMDS_END }
};

/* interface vlan: ipv6 rip sub command */
static struct cmds interface_vlan_ipv6_rip_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_vlan_ipv6_rip_name, no_vlan_ipv6_rip_name, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"User selected string identifying this RIP process", "用户选择 RIP 进程名" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_rip_name_cmds[] = {
	{ "enable", CLI_CMD, 0, 0, do_vlan_ipv6_rip_name_enable , NULL, NULL, CLI_END_FLAG, 0, 0,
		"Enable/disable RIP routing", "开启/关闭 RIP 路由" },
	{ CMDS_END }
};

/* interface vlan: ipv6 router sub command */
static struct cmds interface_vlan_ipv6_router_cmds[] = {
	{ "isis", CLI_CMD, 0, 0, do_vlan_ipv6_router_isis, no_vlan_ipv6_router_isis, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IS-IS Routing for IPv6", "IPv6 IS-IS 路由" },
	{ CMDS_END }
};

/* interface vlan: ipv6 isis sub command */
static struct cmds interface_vlan_ipv6_isis_cmds[] = {
	{ "circuit-type", CLI_CMD, 0, 0, do_vlan_ipv6_isis_circuit, no_vlan_ipv6_isis_circuit, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Configure circuit type for interface", "配置接口电流类型" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_isis_circuit_cmds[] = {
	{ "level-1", CLI_CMD, 0, 0, do_vlan_ipv6_isis_circuit_level_1, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Level-1 only adjacencies are formed", "Level-1" },
	{ "level-1-2", CLI_CMD, 0, 0, do_vlan_ipv6_isis_circuit_level_1_2, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Level-1-2 adjacencies are formed", "Level-1-2" },
	{ "level-2-only", CLI_CMD, 0, 0, do_vlan_ipv6_isis_circuit_level_2_o, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Level-2 only adjacencies are formed", "Level-2-only" },
	{ CMDS_END }
};

/* interface vlan: ipv6 traffic sub command */
static struct cmds interface_vlan_ipv6_traffic_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_vlan_ipv6_traffic_name, no_vlan_ipv6_traffic_name, NULL, CLI_END_NONE, 0, 0,
		"Access-list name", "ACL 名称" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_traffic_name_cmds[] = {
	{ "in", CLI_CMD, 0, 0, do_vlan_ipv6_traffic_name_in, no_vlan_ipv6_traffic_name_in, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"inbound packets", "带内数据" },
	{ "out", CLI_CMD, 0, 0, do_vlan_ipv6_traffic_name_out, no_vlan_ipv6_traffic_name_out, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"outbound packets", "带外数据" },
	{ CMDS_END }
};

/* interface vlan: ipv6 mld sub command */
static struct cmds interface_vlan_ipv6_mld_cmds[] = {
	{ "join-group", CLI_CMD, 0, 0, do_vlan_ipv6_mld_join, no_vlan_ipv6_mld_join, NULL, CLI_END_NONE, 0, 0,
		"MLD join group", "MLD 加入组" },
	{ "querier-timeout", CLI_CMD, 0, 0, do_vlan_ipv6_mld_querier, no_vlan_ipv6_mld_querier, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"MLD querier timeout", "MLD 查询超时时间" },
	{ "query-interval", CLI_CMD, 0, 0, do_vlan_ipv6_mld_query, no_vlan_ipv6_mld_query, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"MLD query interval", "MLD 查询间隔" },
	{ "static-group", CLI_CMD, 0, 0, do_vlan_ipv6_mld_static, no_vlan_ipv6_mld_static, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"MLD query interval", "MLD 查询间隔" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_mld_join_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_vlan_ipv6_mld_join_addr, no_vlan_ipv6_mld_join_addr, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"MLD join group address", "MLD 加入组地址" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_mld_join_addr_cmds[] = {
	{ "include", CLI_CMD, 0, 0, do_vlan_ipv6_mld_join_addr_in, no_vlan_ipv6_mld_join_addr_in, NULL, CLI_END_NONE, 0, 0,
		"MLD join group include source address", "MLD 加入组包含源地址" },
	{ "exclude", CLI_CMD, 0, 0, do_vlan_ipv6_mld_join_addr_ex, no_vlan_ipv6_mld_join_addr_ex, NULL, CLI_END_NONE, 0, 0,
		"MLD join group exclude source address", "MLD 加入组不包含源地址" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_mld_join_addr_in_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_vlan_ipv6_mld_join_addr_in_src, no_vlan_ipv6_mld_join_addr_in_src, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"MLD join group address include source address", "MLD 加入组包含源地址" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_mld_join_addr_ex_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_vlan_ipv6_mld_join_addr_ex_src, no_vlan_ipv6_mld_join_addr_ex_src, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"MLD join group address exclude source address", "MLD 加入组不包含源地址" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_mld_querier_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_vlan_ipv6_mld_querier_time, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"MLD querier timeout", "MLD 查询超时时间" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_mld_query_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_vlan_ipv6_mld_query_time, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"MLD query interval", "MLD 查询间隔" },
	{ CMDS_END }
};

static struct cmds vlan_ipv6_mld_static_cmds[] = {
	{ "all", CLI_CMD, 0, 0, do_vlan_ipv6_mld_static_all, no_vlan_ipv6_mld_static_all, NULL, CLI_END_FLAG, 0, 0,
		"MLD static group address", "配置 MLD 静态组地址" },
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_vlan_ipv6_mld_static_group, no_vlan_ipv6_mld_static_group, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"MLD join group include source address", "配置 MLD 组播组包括源地址" },
		{ CMDS_END  }
};

static struct cmds vlan_ipv6_mld_static_all_cmds[] =
{
	{ "include", CLI_CMD, 0, 0, do_vlan_ipv6_mld_static_all_in, no_vlan_ipv6_mld_static_all_in, NULL, CLI_END_NONE, 0, 0,
		"MLD static group include source address", "配置 MLD 静态组包括源地址" },
	{ CMDS_END  }
};

static struct cmds vlan_ipv6_mld_static_group_cmds[] =
{
	{ "include", CLI_CMD, 0, 0, do_vlan_ipv6_mld_static_group_in, no_vlan_ipv6_mld_static_group_in, NULL, CLI_END_NONE, 0, 0,
		"MLD static group include source address", "配置 MLD 静态组包括源地址" },
	{ CMDS_END  }
};

static struct cmds vlan_ipv6_mld_static_all_in_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_vlan_ipv6_mld_static_all_in_src, no_vlan_ipv6_mld_static_all_in_src, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"MLD static group include source address", "配置 MLD 静态组包括源地址" },
	{ CMDS_END  }
};

static struct cmds vlan_ipv6_mld_static_group_in_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_vlan_ipv6_mld_static_group_in_src, no_vlan_ipv6_mld_static_group_in_src, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"MLD static group include source address", "配置 MLD 静态组包括源地址" },
	{ CMDS_END  }
};

/* interface vlan: vrrp sub command */
static struct cmds interface_vlan_vrrp_cmds[] = {
	{ "<1-255>", CLI_INT, 0, 0, do_vlan_vrrp_num, no_vlan_vrrp_num, NULL, CLI_END_NONE, 1, 255,
		"Group number", "组号" },
	{ CMDS_END }
};

/* interface vlan: vrrp num sub command */
static struct cmds interface_vlan_vrrp_num_cmds[] = {
	{ "associate", CLI_CMD, 0, 0, do_vlan_vrrp_num_ip, no_vlan_vrrp_num_ip, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Enable Virtual Router Redundancy Protocol (VRRP) for IP", "使能此IP上 VRRP 协议" },
	{ "timer", CLI_CMD, 0, 0, do_vlan_vrrp_timer, no_vlan_vrrp_timer, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Enable delay of Virtual Router timer", "抢占延迟" },
	{ "preempt", CLI_CMD, 0, 0, do_vlan_vrrp_num_preempt, no_vlan_vrrp_num_preempt, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Enable preemption of lower priority Master", "使能低优先级 Master" },
	{ "priority", CLI_CMD, 0, 0, do_vlan_vrrp_num_priority, no_vlan_vrrp_num_priority, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Priority of this VRRP group", "VRRP 组优先级" },
	{ "authentication", CLI_CMD, 0, 0, do_vlan_vrrp_auth, no_vlan_vrrp_auth, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Group specific description", "组描述" },
	{ CMDS_END }
};

/* interface vlan: vrrp num desc sub command */
static struct cmds interface_vlan_vrrp_num_desc_cmds[] = {
	{ "WORD", CLI_WORD,0, 0, do_vlan_vrrp_num_desc_line, NULL, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"auth passwd", "认证密码" },
	{ CMDS_END }
};

/* interface vlan: vrrp num ip sub command */
static struct cmds interface_vlan_vrrp_num_ip_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_vlan_vrrp_num_ip_addr, no_vlan_vrrp_num_ip_addr, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"VRRP group IP address", "VRRP 组 IP 地址" },
	{ CMDS_END }
};

/* interface vlan: vrrp num priority sub command */
static struct cmds interface_vlan_vrrp_num_priority_cmds[] = {
	{ "<1-254>", CLI_INT, 0, 0, do_vlan_vrrp_num_priority_level, NULL, NULL, CLI_END_FLAG, 1, 254,
		"Priority level", "优先级" },
	{ CMDS_END }
};

/* interface vlan: vrrp num priority sub command */
static struct cmds interface_vlan_vrrp_num_timer_cmds[] = {
	{ "<1-10>", CLI_INT, 0, 0, do_vlan_vrrp_num_timer, NULL, NULL, CLI_END_FLAG, 1, 10,
		"Time Delay", "抢占延时" },
	{ CMDS_END }
};

/* interface vlan: arp timeout sub command */
static struct cmds interface_vlan_arp_cmds[] = {
	{ "timeout", CLI_CMD, 0, 0, do_vlan_arp_timeout, no_vlan_arp_timeout, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"arp timeout", "ARP 超时时间" },
	{ "send-gratuitous", CLI_CMD, 0, 0, do_vlan_arp_send, no_vlan_arp_send, NULL, CLI_END_NONE, 0, 0,
		"arp timeout", "ARP 超时时间" },
	{ CMDS_END }
};

static struct cmds interface_vlan_arp_timeout_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_vlan_arp_timeout_sec, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"arp timeout (seconds)", "ARP 超时时间（秒）" },
	{ CMDS_END }
};

static struct cmds interface_vlan_arp_send_cmds[] = {
	{ "interval", CLI_CMD, 0, 0, do_vlan_arp_send_interval, no_vlan_arp_send_interval, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"arp send interval", "ARP 发送间隔" },
	{ CMDS_END }
};

static struct cmds interface_vlan_arp_send_interval_cmds[] = {
	{ "<5-3600>", CLI_INT, 0, 0, do_vlan_arp_send_interval_sec, NULL, NULL, CLI_END_FLAG, 5, 3600,
		"arp send interval (seconds)", "ARP 发送间隔（秒）" },
	{ CMDS_END }
};

/* interface vlan: ip address sub command */
static struct cmds interface_vlan_ip_igmp_cmds[] = {
	{ "query-max-response-time", CLI_CMD, 0, 0, do_interface_vlan_ip_igmp_querier, no_interface_vlan_ip_igmp_querier, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"IGMP max response time", "配置 IGMP 请求超时" },
	{ "query-interval", CLI_CMD, 0, 0, do_interface_vlan_ip_igmp_query, no_interface_vlan_ip_igmp_query, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"IGMP querier interval", "配置 IGMP 请求超时" },
	{ "static-group", CLI_CMD, 0, 0, do_interface_vlan_ip_igmp_static, no_interface_vlan_ip_igmp_static, NULL, CLI_END_NONE, 0, 0,
		"IGMP static group", "配置 IGMP 静态组" },
	{ "version", CLI_CMD, 0, 0, do_interface_vlan_ip_igmp_version, no_interface_vlan_ip_igmp_version, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"IGMP version", "配置 IGMP 版本" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ip_igmp_querier_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_interface_vlan_ip_igmp_querier_time, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"IGMP querier timeout", "配置 IGMP 请求超时" },
	{ CMDS_END  }
};

static struct cmds interface_vlan_ip_igmp_query_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_interface_vlan_ip_igmp_query_time, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"IGMP querier timeout", "配置 IGMP 请求超时" },
	{ CMDS_END  }
};

static struct cmds interface_vlan_ip_igmp_static_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_interface_vlan_ip_igmp_static_ip, no_interface_vlan_ip_igmp_static_ip, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IGMP IP address", "组播 IP 地址" },
	{ CMDS_END  }
};

static struct cmds interface_vlan_ip_igmp_static_ip_cmds[] = {
	{ "include", CLI_CMD, 0, 0, do_interface_vlan_ip_igmp_static_ip_in, NULL, NULL, CLI_END_NONE, 0, 0,
		"IGMP IP address", "组播 IP 地址" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ip_igmp_static_ip_in_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_interface_vlan_ip_igmp_static_ip_in_source, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IGMP IP address", "组播 IP 地址" },
	{ CMDS_END  }
};

static struct cmds interface_vlan_ip_igmp_version_cmds[] = {
	{ "1", CLI_CMD, 0, 0, do_interface_vlan_ip_igmp_version_1, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IGMP version", "IGMP 版本s" },
	{ "2", CLI_CMD, 0, 0, do_interface_vlan_ip_igmp_version_2, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IGMP version", "IGMP 版本s" },
	{ "3", CLI_CMD, 0, 0, do_interface_vlan_ip_igmp_version_3, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IGMP version", "IGMP 版本s" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ip_pim_cmds[] = {
	{ "dr-priority", CLI_CMD, 0, 0, do_vlan_ip_pim_dr, no_vlan_ip_pim_dr, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"dr priority", "dr 优先级" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ip_pim_dr_cmds[] =
{
	{ "<1-65535>", CLI_INT, 0, 0, do_vlan_pim_dr_priority, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"dr priority", "配置 dr 优先级" },
	{ CMDS_END  }
};

static struct cmds interface_vlan_ipv6_pim_cmds[] = {
	{ "bsr-border", CLI_CMD, 0, 0, do_vlan_ipv6_pim_bsr, no_vlan_ipv6_pim_bsr, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"dr priority", "dr 优先级" },
	{ "dr-priority", CLI_CMD, 0, 0, do_vlan_ipv6_pim_dr, no_vlan_ipv6_pim_dr, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"dr priority", "dr 优先级" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ipv6_pim_dr_cmds[] =
{
	{ "<1-65535>", CLI_INT, 0, 0, do_vlan_ipv6_pim_dr_priority, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"dr priority", "配置 dr 优先级" },
	{ CMDS_END  }
};

static struct cmds interface_vlan_vrrp_num_associate_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_vlan_vrrp_num_associate_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Priority level", "优先级" },
	{ CMDS_END }
};

static struct cmds interface_vlan_vrrp_num_auth_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_vlan_vrrp_num_auth_str, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Priority level", "优先级" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ip_rip_cmds[] = {
	{ "bfd", CLI_CMD, 0, 0, do_interface_vlan_ip_rip_bfd, no_interface_vlan_ip_rip_bfd, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"RIP BFD", "配置 RIP BFD 应用" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ip_ospf_cmds[] = {
	{ "ospf", CLI_CMD, 0, 0, do_interface_vlan_ip_ospf_bfd, no_interface_vlan_ip_ospf_bfd, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"OSPF BFD", "配置 OSPF BFD 应用" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ip_bgp_cmds[] = {
	{ "bgp", CLI_CMD, 0, 0, do_interface_vlan_ip_bgp_bfd, no_interface_vlan_ip_bgp_bfd, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"BGP BFD", "配置 BGP BFD 应用" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ip_isis_cmds[] = {
	{ "isis", CLI_CMD, 0, 0, do_interface_vlan_ip_isis_bfd, no_interface_vlan_ip_isis_bfd, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IS-IS BFD", "配置 IS-IS BFD 应用" },
	{ CMDS_END }
};

static struct cmds interface_vlan_router_isis_cmds[] = {
	{ "isis", CLI_CMD, 0, 0, do_interface_vlan_router_isis, no_interface_vlan_router_isis, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IS-IS BFD", "配置 IS-IS BFD 应用" },
	{ CMDS_END }
};

static struct cmds interface_vlan_ip_static_cmds[] = {
	{ "static", CLI_CMD, 0, 0, do_interface_vlan_ip_static_bfd, no_interface_vlan_ip_static_bfd, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"static BFD", "配置 static BFD 应用" },
	{ CMDS_END }
};

static struct cmds interface_vlan_vrrp_num_bfd_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_vlan_vrrp_num_bfd_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"VRRP BFD IP address", "VRRP BFD IP 地址" },
	{ CMDS_END }
};

static struct cmds interface_vlan_bfd_cmds[] = {
	{ "interval", CLI_CMD, 0, 0, do_vlan_bfd_int, no_vlan_bfd_int, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"BFD interval", "BFD 间隔时间" },
//	{ "authentication-mode", CLI_CMD, 0, 0, do_vlan_bfd_auth, no_vlan_bfd_auth, NULL, CLI_END_NONE, 0, 0,
//		"BFD authentication mode", "BFD 认证模式" },
	{ CMDS_END }
};

static struct cmds interface_vlan_bfd_int_cmds[] = {
	{ "<200-30000>", CLI_INT, 0, 0, do_vlan_bfd_int_time, NULL, NULL, CLI_END_NONE, 200, 30000,
		"BFD interval", "BFD 间隔时间" },
	{ CMDS_END }
};

static struct cmds interface_vlan_bfd_int_time_cmds[] = {
	{ "min_rx", CLI_CMD, 0, 0, do_vlan_bfd_int_time_rx, NULL, NULL, CLI_END_NONE, 0, 0,
		"BFD min rx time", "BFD 最小接收时间" },
	{ CMDS_END }
};

static struct cmds interface_vlan_bfd_int_time_rx_cmds[] = {
	{ "<200-30000>", CLI_INT, 0, 0, do_vlan_bfd_int_time_rx_time, NULL, NULL, CLI_END_NONE, 200, 30000,
		"BFD min rx time", "BFD 最小接收时间" },
	{ CMDS_END }
};

static struct cmds interface_vlan_bfd_int_time_rx_time_cmds[] = {
	{ "multiplier", CLI_CMD, 0, 0, do_vlan_bfd_int_time_rx_time_plier, NULL, NULL, CLI_END_NONE, 0, 0,
		"BFD multiplier", "BFD 检测倍数" },
	{ CMDS_END }
};

static struct cmds interface_vlan_bfd_int_time_rx_time_plier_cmds[] = {
	{ "<1-20>", CLI_INT, 0, 0, do_vlan_bfd_int_time_rx_time_plier_val, NULL, NULL, CLI_END_FLAG, 1, 20,
		"BFD multiplier", "BFD 检测倍数" },
	{ CMDS_END }
};

static struct cmds interface_vlan_bfd_auth_cmds[] = {
	{ "md5", CLI_CMD, 0, 0, do_vlan_bfd_auth_md5, no_vlan_bfd_auth_md5, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"BFD authentication md5 mode", "BFD md5 认证" },
	{ "simple", CLI_CMD, 0, 0, do_vlan_bfd_auth_simple, no_vlan_bfd_auth_simple, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"BFD authentication simple mode", "BFD 简单认证" },
	{ CMDS_END }
};

static struct cmds interface_vlan_bfd_auth_md5_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_vlan_bfd_auth_md5_key, NULL, NULL, CLI_END_FLAG, 0, 0,
		"BFD authentication md5 key", "BFD BFD md5 秘钥" },
	{ CMDS_END }
};

static struct cmds interface_vlan_bfd_auth_simple_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_vlan_bfd_auth_simple_key, NULL, NULL, CLI_END_FLAG, 0, 0,
		"BFD authentication simple key", "BFD BFD 简单明文" },
	{ CMDS_END }
};

static struct cmds ip_helper_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_helper_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP address", "IP 地址" },
	{ CMDS_END  }
};


static int do_multicast_vlan(int argc, char *argv[], struct users *u)
{
    int retval = -1;

	retval = sub_cmdparse(multicast_vlan_id_cmds, argc, argv, u);

	return retval;
}

static int do_multicast_vlan_enable(int argc, char *argv[], struct users *u)
{
    int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	    nvram_set("multicast_vlan_enable","1");	
		nvram_commit();
	}
	
	return retval;
}
static int no_multicast_vlan_enable(int argc, char *argv[], struct users *u)
{
    int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
	    nvram_set("multicast_vlan_enable","0");
		nvram_commit();
		//system("rc erps restart");
	}	
	return retval;
}


static int no_multicast_vlan(int argc, char *argv[], struct users *u)
{
    int retval = -1;

	retval = sub_cmdparse(multicast_vlan_id_cmds, argc, argv, u);

	return retval;
}
static int do_multicast_vlan_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(multicast_vlan_subvlan_cmds, argc, argv, u);

	return retval;
}


/*
 *  Function:  do_vlan
 *  Purpose:  vlan topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char vlan_id[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_INT_MULTI;
	param.name = "1-4094";
	param.ylabel = "VLAN IDs(1-4094), such as(1,3,5,7) or (1,3-5,7) or (1-7)";
	param.hlabel = "类似(1,3,5,7) 或 (1,3-5,7) 或 (1-7)表示的VLAN 范围表(1-4094)";
	param.min = 1;
	param.max = 4094;
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		cli_param_get_string(DYNAMIC_PARAM, 0, vlan_id, u);
		
		if(0 > func_vlan(u))
			return retval;
		
		if(strpbrk(vlan_id, ",-") == NULL)
		{	
			if((retval = change_con_level(VLAN_TREE, u)) == 0)
			{	
				memset(u->promptbuf, '\0', sizeof(u->promptbuf));
				sprintf(u->promptbuf, "vlan%s", vlan_id);
			}
		}
	}
		
	return retval;
}
static int do_multicast_subvlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char vlan_id[MAX_ARGV_LEN] = {'\0'};
	char szbuff[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	int muti_vlan = 0;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_INT_MULTI;
	param.name = "1-4094";
	param.ylabel = "VLAN IDs(1-4094), such as(1,3,5,7) or (1,3-5,7) or (1-7)";
	param.hlabel = "类似(1,3,5,7) 或 (1,3-5,7) 或 (1-7)表示的VLAN 范围表(1-4094)";
	param.min = 1;
	param.max = 4094;
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
	 	
		cli_param_get_int(STATIC_PARAM, 0, &muti_vlan, u);

		cli_param_get_string(DYNAMIC_PARAM, 0, vlan_id, u);
		
		sprintf(szbuff,"%d,%s;",muti_vlan,vlan_id);
		nvram_set("multicast_vlan",szbuff);
		nvram_commit();
		
	}
		
	return retval;
}
/*
 *  Function:  no_vlan
 *  Purpose:  vlan topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_INT_MULTI;
	param.name = "1-4094";
	param.ylabel = "VLAN IDs(1-4094), such as(1,3,5,7) or (1,3-5,7) or (1-7)";
	param.hlabel = "类似(1,3,5,7) 或 (1,3-5,7) 或 (1-7)表示的VLAN 范围表(1-4094)";
	param.min = 1;
	param.max = 4094;
	param.flag = CLI_END_NO;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
	
	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan(u);
	}
	
	return retval;
}

/*
 *  Function:  do_gvrp
 *  Purpose:  GVRP topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/18
 */

static int do_gvrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_gvrp(u);
	}

	return retval;

}

/*
 *  Function:  no_gvrp
 *  Purpose:  GVRP topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/18
 */

static int no_gvrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_gvrp(u);
	}

	return retval;

}

/*
 *  Function:  do_vlan_name
 *  Purpose:  vlan name topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "The ascii name of VLAN(max length is 32)";
	param.hlabel = "配置当前vlan的名称(不能超过32个字符)";
	param.min = 1;
	param.max = 32;
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vname(u);
	}
	
	return retval;
}

static int no_vlan_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vname(u);
	}

	return retval;

}
/*
 *  Function:  do_private_vlan
 *  Purpose:  private vlan topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  dawei.hu
 *  Date:     2011/11/18
 */

static int do_private_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_private_vlan(u);
	}

	return retval;

}
/*
 *  Function:  do_vlan_ip
 *  Purpose:  intreface vlan ip topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_cmds, argc, argv, u);
	
	return retval;
}

/*
 *  Function:  no_vlan_ip
 *  Purpose:  intreface vlan ip topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_cmds, argc, argv, u);
	
	return retval;
}

/*
 *  Function:  do_vlan_ipv6
 *  Purpose:  intreface vlan ipv6 topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_cmds, argc, argv, u);
	
	return retval;
}

/*
 *  Function:  no_vlan_ipv6
 *  Purpose:  intreface vlan ipv6 topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_cmds, argc, argv, u);
	
	return retval;
}

/*
 *  Function:  do_vlan_shutdown
 *  Purpose:  intreface vlan shutdown topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int do_vlan_shutdown(int argc, char *argv[], struct users *u)
{	
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_shutdown(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_shutdown
 *  Purpose:  no intreface vlan shutdown topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int no_vlan_shutdown(int argc, char *argv[], struct users *u)
{	
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_shutdown(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ip_access_group
 *  Purpose:  intreface vlan ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ip_access_group(int argc, char *argv[], struct users *u)
{		
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Access-list name";
	param.hlabel = "访问列表名";
	param.flag = CLI_END_NONE;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	retval = sub_cmdparse(interface_vlan_ip_access_group_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_vlan_ip_access_group
 *  Purpose:  intreface vlan ip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ip_access_group(int argc, char *argv[], struct users *u)
{		
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Access-list name";
	param.hlabel = "访问列表名";
	param.flag = CLI_END_NONE;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);
	retval = sub_cmdparse(interface_vlan_ip_access_group_cmds, argc, argv, u);

	return retval;
}

static int do_vlan_ip_access_group_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_access_in(u);
	}
	return retval;
}

static int no_vlan_ip_access_group_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ip_access_in(u);
	}
	return retval;
}

static int do_vlan_ip_access_group_out(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_access_out(u);
	}
	return retval;
}

static int no_vlan_ip_access_group_out(int argc, char *argv[], struct users *u)
{
	int retval = -1;
		
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ip_access_out(u);
	}
	return retval;
}

/*
 *  Function:  do_vlan_ip_address
 *  Purpose:  intreface vlan ip address subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ip_address(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_address_cmds, argc, argv, u);
	
	return retval;
}

/*
 *  Function:  no_vlan_ip_address
 *  Purpose:  no intreface vlan ip address parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ip_address(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ip_adress(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ip_proxy_arp
 *  Purpose:  do intreface vlan ip proxy-arp parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ip_proxy_arp(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_proxy_arp(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ip_proxy_arp
 *  Purpose:  no intreface vlan ip proxy-arp parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ip_proxy_arp(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ip_proxy_arp(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ip_igmp
 *  Purpose:  intreface vlan ip igmp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ip_igmp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if(argc == 1)
	    func_ip_igmp(u);
	else    
	    retval = sub_cmdparse(interface_vlan_ip_igmp_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_ip_igmp_querier(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_igmp_querier_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_ip_igmp_querier_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ip_igmp_querier_time(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ip_igmp
 *  Purpose:  intreface vlan ip igmp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ip_igmp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if(argc == 1)
	    nfunc_ip_igmp(u);
	else   
	    retval = sub_cmdparse(interface_vlan_ip_igmp_cmds, argc, argv, u);
	
	return retval;
}

static int no_interface_vlan_ip_igmp_querier(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ip_igmp_querier_time(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ip_igmp_query
 *  Purpose:  intreface vlan ip igmp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_interface_vlan_ip_igmp_query(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_igmp_query_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_ip_igmp_query_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_igmp_query_time(u);
	}

	return retval;
}

/*
 *  Function:  no_interface_vlan_ip_igmp_query
 *  Purpose:  intreface vlan ip igmp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_interface_vlan_ip_igmp_query(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ip_igmp_query_time(u);
	}

	return retval;
}

/*
 *  Function:  do_interface_vlan_ip_igmp_static
 *  Purpose:  intreface vlan ip igmp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_interface_vlan_ip_igmp_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_igmp_static_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_ip_igmp_static_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_igmp_static_ip_cmds, argc, argv, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_igmp_static_group(u);
	}
	
	return retval;
}

static int do_interface_vlan_ip_igmp_static_ip_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_igmp_static_ip_in_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_ip_igmp_static_ip_in_source(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_igmp_static_group_source(u);
	}

	return retval;
}

/*
 *  Function:  no_interface_vlan_ip_igmp_static
 *  Purpose:  intreface vlan ip igmp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_interface_vlan_ip_igmp_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_igmp_static_cmds, argc, argv, u);
	
	return retval;
}

static int no_interface_vlan_ip_igmp_static_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ip_igmp_static_group(u);
	}

	return retval;
}

/*
 *  Function:  do_interface_vlan_ip_igmp_version
 *  Purpose:  intreface vlan ip igmp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_interface_vlan_ip_igmp_version(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_igmp_version_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_ip_igmp_version_1(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_igmp_version_1(u);
	}

	return retval;
}

static int do_interface_vlan_ip_igmp_version_2(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_igmp_version_2(u);
	}

	return retval;
}

static int do_interface_vlan_ip_igmp_version_3(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_igmp_version_3(u);
	}

	return retval;
}

/*
 *  Function:  no_interface_vlan_ip_igmp_version
 *  Purpose:  intreface vlan ip igmp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_interface_vlan_ip_igmp_version(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ip_igmp_version(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ipv6_address
 *  Purpose:  intreface vlan ipv6 address subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_address(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_address_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_dhcp(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_dhcp_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_dhcp(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(interface_no_vlan_ipv6_dhcp_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_dhcp_realy(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_dhcp_realy_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_dhcp_relay(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_dhcp_realy(u);
	}

	return retval;
}

static int do_vlan_ipv6_dhcp_realy_address (int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_dhcp_realy_address(u);
	}

	return retval;

}
/*
 *  Function:  no_vlan_ipv6_address
 *  Purpose:  no intreface vlan ipv6 address parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_address(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_no_vlan_ipv6_addr_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_address_global(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ipv6_adress(u);
	}

	return retval;
}











/*
 *  Function:  do_vlan_ipv6_enable
 *  Purpose:  intreface vlan ipv6 enable subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_enable(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_enable(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ipv6_enable
 *  Purpose:  no intreface vlan ipv6 enable parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_enable(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_enable(u);
	}

	return retval;
}


/*
 *  Function:  do_vlan_ipv6_ospf
 *  Purpose:  intreface vlan ipv6 ospf subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_ospf(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_ospf_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_ospf_pid(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_ospf_pid_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_ospf_pid_area(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_ospf_pid_area_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_ospf_pid_area_id(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_ospf(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ipv6_ospf
 *  Purpose:  no intreface vlan ipv6 ospf subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_ospf_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_ospf_pid(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_ospf_pid_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_ospf_pid_area(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_ospf_pid_area_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_ospf_pid_area_id(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_ospf(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ipv6_rip
 *  Purpose:  intreface vlan ipv6 rip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_rip_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_rip_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_rip_name_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_rip_name_enable(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_rip(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ipv6_rip
 *  Purpose:  no intreface vlan ipv6 rip parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_rip_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_rip_name(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_rip(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ipv6_router
 *  Purpose:  intreface vlan ipv6 router subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_router(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_router_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_router(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ipv6_router
 *  Purpose:  no intreface vlan ipv6 router parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_router(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_router_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_router_isis(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_router(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ipv6_isis
 *  Purpose:  intreface vlan ipv6 isis subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_isis_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_isis_circuit(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_isis_circuit_cmds, argc, argv, u);
	
	return retval;
}


static int do_vlan_ipv6_isis_circuit_level_1(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_isis_circuit_level_1(u);
	}

	return retval;
}

static int do_vlan_ipv6_isis_circuit_level_1_2(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_isis_circuit_level_1_2(u);
	}

	return retval;
}

static int do_vlan_ipv6_isis_circuit_level_2_o(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_isis_circuit_level_2_o(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ipv6_isis
 *  Purpose:  no intreface vlan ipv6 isis subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_isis_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_isis_circuit(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_isis(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ipv6_traffic
 *  Purpose:  intreface vlan ipv6 traffic topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_traffic(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_traffic_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_traffic_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_traffic_name_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_traffic_name_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_traffic_name_in(u);
	}

	return retval;
}

static int do_vlan_ipv6_traffic_name_out(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_traffic_name_out(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ipv6_traffic
 *  Purpose:  intreface vlan ipv6 traffic topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_traffic(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_traffic_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_traffic_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_traffic_name_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_traffic_name_in(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_traffic_name_in(u);
	}

	return retval;
}

static int no_vlan_ipv6_traffic_name_out(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_traffic_name_out(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ipv6_mld
 *  Purpose:  intreface vlan ipv6 mld topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_mld(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_mld_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_mld_join(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_mld_join_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_mld_join_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_mld_join_addr(u);
	} else
		retval = sub_cmdparse(interface_vlan_ipv6_mld_join_addr_cmds, argc, argv, u);

	return retval;
}

static int do_vlan_ipv6_mld_join_addr_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_mld_join_addr_in_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_mld_join_addr_ex(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_mld_join_addr_ex_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_mld_join_addr_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_mld_join_addr_in_src(u);
	}

	return retval;
}

static int do_vlan_ipv6_mld_join_addr_ex_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_mld_join_addr_ex_src(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ipv6_mld
 *  Purpose:  intreface vlan ipv6 mld topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_mld(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_mld_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_mld_join(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_mld_join_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_mld_join_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_mld_join_addr(u);
	} else
		retval = sub_cmdparse(interface_vlan_ipv6_mld_join_addr_cmds, argc, argv, u);

	return retval;
}

static int no_vlan_ipv6_mld_join_addr_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_mld_join_addr_in_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_mld_join_addr_ex(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_mld_join_addr_ex_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_mld_join_addr_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_mld_join_addr_in_src(u);
	}

	return retval;
}

static int no_vlan_ipv6_mld_join_addr_ex_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_mld_join_addr_ex_src(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ipv6_mld_querier
 *  Purpose:  intreface vlan ipv6 mld topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_mld_querier(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_mld_querier_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_mld_querier_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_mld_querier(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ipv6_mld_querier
 *  Purpose:  intreface vlan ipv6 mld topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_mld_querier(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_mld_querier(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ipv6_mld_query
 *  Purpose:  intreface vlan ipv6 mld topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_mld_query(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ipv6_mld_query_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_mld_query_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_mld_query(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ipv6_mld_query
 *  Purpose:  intreface vlan ipv6 mld topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_mld_query(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_mld_query(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ipv6_mld_static
 *  Purpose:  intreface vlan ipv6 mld static topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_mld_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(vlan_ipv6_mld_static_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_ipv6_mld_static_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_mld_static_all(u);
	} else
		retval = sub_cmdparse(vlan_ipv6_mld_static_all_cmds, argc, argv, u);

	return retval;
}

static int do_vlan_ipv6_mld_static_all_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(vlan_ipv6_mld_static_all_in_cmds, argc, argv, u);

	return retval;
}

static int do_vlan_ipv6_mld_static_all_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_vlan_ipv6_mld_static_all_in(u);
	}

	return retval;
}

static int do_vlan_ipv6_mld_static_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_mld_static_group(u);
	} else
		retval = sub_cmdparse(vlan_ipv6_mld_static_group_cmds, argc, argv, u);

	return retval;
}

static int do_vlan_ipv6_mld_static_group_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(vlan_ipv6_mld_static_group_in_cmds, argc, argv, u);

	return retval;
}

static int do_vlan_ipv6_mld_static_group_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_vlan_ipv6_mld_static_group_in(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ipv6_mld_static
 *  Purpose:  intreface vlan ipv6 mld static topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_mld_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(vlan_ipv6_mld_static_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_ipv6_mld_static_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_mld_static_all(u);
	} else
		retval = sub_cmdparse(vlan_ipv6_mld_static_all_cmds, argc, argv, u);

	return retval;
}

static int no_vlan_ipv6_mld_static_all_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(vlan_ipv6_mld_static_all_in_cmds, argc, argv, u);

	return retval;
}

static int no_vlan_ipv6_mld_static_all_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_vlan_ipv6_mld_static_all_in(u);
	}

	return retval;
}

static int no_vlan_ipv6_mld_static_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_mld_static_group(u);
	} else
		retval = sub_cmdparse(vlan_ipv6_mld_static_group_cmds, argc, argv, u);

	return retval;
}

static int no_vlan_ipv6_mld_static_group_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(vlan_ipv6_mld_static_group_in_cmds, argc, argv, u);

	return retval;
}

static int no_vlan_ipv6_mld_static_group_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_vlan_ipv6_mld_static_group_in(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_vrrp
 *  Purpose:  intreface vlan vrrp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_vrrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_cmds, argc, argv, u);
	
	return retval;
}

/*
 *  Function:  no_vlan_vrrp
 *  Purpose:  intreface vlan vrrp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_vrrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_cmds, argc, argv, u);
	
	return retval;
}

/*
 *  Function:  do_vlan_vrrp_num
 *  Purpose:  intreface vlan vrrp num topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_vrrp_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_num_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_vrrp_auth(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_num_desc_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_vrrp_num_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_num_ip_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_vrrp_num_preempt(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_vrrp_num_preempt(u);
	}

	return retval;
}

static int do_vlan_vrrp_num_priority(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_num_priority_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_vrrp_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_num_timer_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_vrrp_num_desc_line(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_vrrp_num_desc_line(u);
	}

	return retval;
}

static int do_vlan_vrrp_num_ip_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_vrrp_num_ip_addr(u);
	}

	return retval;
}

static int do_vlan_vrrp_num_priority_level(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_vrrp_num_priority_level(u);
	}

	return retval;
}

static int do_vlan_vrrp_num_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_vlan_vrrp_num_timer(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_vrrp_num
 *  Purpose:  intreface vlan vrrp num topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_vrrp_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_num_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_vrrp_num_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

    if(2 == argc)	
	    retval = sub_cmdparse(interface_vlan_vrrp_num_ip_cmds, argc, argv, u);
    else if(1 == argc)
	    nfunc_vlan_vrrp_num_ip_addr(u);
	    
	return retval;
}

static int no_do_vlan_vrrp_vip(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_vrrp_num_desc(u);
	}

	return retval;
}

static int no_vlan_vrrp_num_ip_addr(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_vrrp_num_ip_addr(u);
	}

	return retval;
}

static int no_vlan_vrrp_num_preempt(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_vrrp_num_preempt(u);
	}

	return retval;
}

static int no_vlan_vrrp_num_priority(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_vrrp_num_priority(u);
	}

	return retval;
}

static int no_vlan_vrrp_timer(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_vrrp_num_timer(u);
	}

	return retval;
}

static no_vlan_vrrp_auth(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_vrrp_num_auth(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_arp
 *  Purpose:  intreface vlan arp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_arp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_arp_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_arp_timeout(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_arp_timeout_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_arp_timeout_sec(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_arp_timeout(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_arp
 *  Purpose:  intreface vlan arp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_arp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_arp_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_arp_timeout(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_arp_timeout(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_arp_send
 *  Purpose:  intreface vlan arp send topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_arp_send(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_arp_send_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_arp_send_interval(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_arp_send_interval_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_arp_send_interval_sec(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_arp_send_interval(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_arp_send
 *  Purpose:  intreface vlan arp send topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_arp_send(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_arp_send_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_arp_send_interval(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_arp_send_interval(u);
	}

	return retval;
}



/*
 *  Function:  do_vlan_ip_address_dhcp
 *  Purpose:  intreface vlan ip address dhcp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/7
 */
static int do_vlan_ip_address_dhcp(int argc, char *argv[], struct users *u)
{	
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_adress_dhcp(u);
	}
	
	return retval;
}


/*
 *  Function:  do_vlan_ip_address_static
 *  Purpose:  intreface vlan ip address A.B.C.D subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ip_address_static(int argc, char *argv[], struct users *u)
{		
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_IPV4_MASK;
	param.name = "A.B.C.D";
	param.ylabel = "IP netmask";
	param.hlabel = "IP 网络掩码";
	param.flag = CLI_END_FLAG;
		
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);
			
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{		
		/* Do application function */
		func_ip_adress_static(u);
	}
	
	return retval;
}


/*
 *  Function:  do_vlan_ipv6_address_global
 *  Purpose:  intreface vlan ipv6 address global subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_address_global(int argc, char *argv[], struct users *u)
{		
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_IPV6_MASK;
	param.name = "X:X:X:X::X/<0-128>";
	param.ylabel = "IPv6 global address";
	param.hlabel = "IPv6 全局地址";
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ipv6_global(u);
	}
	
	return retval;
}

/*
 *  Function:  do_vlan_ipv6_address_local
 *  Purpose:  intreface vlan ipv6 address local-link subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_address_local(int argc, char *argv[], struct users *u)
{		
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_IPV6_NOMASK;
	param.name = "X:X:X:X::X";
	param.ylabel = "IPv6 local-link address";
	param.hlabel = "IPv6 本地地址";
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ipv6_local(u);
	}
	
	return retval;
}
static int no_vlan_ipv6_address_local(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_address_local();
	}
	
	return retval;


}

/*
 *  Function:  do_vlan_ip_pim
 *  Purpose:  do intreface vlan ip pim-dm parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ip_pim(int argc, char *argv[], struct users *u)
{	
	int retval = -1;

    if(argc == 1)
	{
		/* Do application */
		func_vlan_ip_pim(u);
	}else
	    retval = sub_cmdparse(interface_vlan_ip_pim_cmds, argc, argv, u);

	return retval;
}

static int do_vlan_ip_pim_dr(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_pim_dr_cmds, argc, argv, u);

	return retval;
}


static int do_vlan_pim_dr_priority(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ip_pim_dr(u);
	}

	return retval;
}
/*
 *  Function:  no_vlan_ip_pim
 *  Purpose:  no intreface vlan ip pim-dm parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ip_pim(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

    if(argc == 1)
	{
		/* Do application */
		nfunc_vlan_ip_pim(u);
	}else
	    retval = sub_cmdparse(interface_vlan_ip_pim_cmds, argc, argv, u);

	return retval;
}

static int no_vlan_ip_pim_dr(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ip_pim_dr(u);
	}

	return retval;
}

static int do_vlan_ip_pim_sm(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ip_pim_sm(u);
	}

	return retval;
}

static int no_vlan_ip_pim_sm(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ip_pim_sm(u);
	}

	return retval;
}
/*
 *  Function:  do_vlan_ipv6_pim
 *  Purpose:  intreface vlan ipv6 pim topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_ipv6_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_vlan_ipv6_pim(u);
	} else
		retval = sub_cmdparse(interface_vlan_ipv6_pim_cmds, argc, argv, u);

	return retval;
}

static int do_vlan_ipv6_pim_bsr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_vlan_ipv6_pim_bsr(u);
	}
	
	return retval;
}

static int do_vlan_ipv6_pim_dr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(interface_vlan_ipv6_pim_dr_cmds, argc, argv, u);

	return retval;
}

static int do_vlan_ipv6_pim_dr_priority(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_vlan_ipv6_pim_dr_priority(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ipv6_pim
 *  Purpose:  intreface vlan ipv6 pim topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_ipv6_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ipv6_pim(u);
	}

	return retval;
}

static int no_vlan_ipv6_pim_bsr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_vlan_ipv6_pim_bsr(u);
	}
	
	return retval;
}

static int no_vlan_ipv6_pim_dr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_vlan_ipv6_pim_dr_priority(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_vrrp_num_associate
 *  Purpose:  intreface vlan vrrp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_vrrp_num_associate(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_num_associate_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_vrrp_num_associate_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_vrrp_num_associate_ip(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_vrrp_num_associate
 *  Purpose:  intreface vlan vrrp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_vrrp_num_associate(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_vrrp_num_associate_ip(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_vrrp_num_auth
 *  Purpose:  intreface vlan vrrp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_vrrp_num_auth(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_num_auth_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_vrrp_num_auth_str(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_vrrp_num_auth(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_vrrp_num_auth
 *  Purpose:  intreface vlan vrrp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_vrrp_num_auth(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_vrrp_num_auth(u);
	}

	return retval;
}


/*
 *  Function:  no_vlan_vrrp_num_timer
 *  Purpose:  intreface vlan vrrp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_vrrp_num_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_num_timer_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_vrrp_num_timer_adver(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_vrrp_num_timer(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ip_rip
 *  Purpose:  intreface vlan ip rip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ip_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_rip_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_ip_rip_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ip_rip_bfd(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ip_rip
 *  Purpose:  intreface vlan ip rip subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ip_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_rip_cmds, argc, argv, u);
	
	return retval;
}

static int no_interface_vlan_ip_rip_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ip_rip_bfd(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ip_ospf
 *  Purpose:  intreface vlan ip ospf subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ip_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_ospf_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_ip_ospf_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ip_ospf_bfd(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ip_ospf
 *  Purpose:  intreface vlan ip ospf subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ip_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_ospf_cmds, argc, argv, u);
	
	return retval;
}

static int no_interface_vlan_ip_ospf_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ip_ospf_bfd(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ip_bgp
 *  Purpose:  intreface vlan ip bgp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ip_bgp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_bgp_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_ip_bgp_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ip_bgp_bfd(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ip_bgp
 *  Purpose:  intreface vlan ip bgp subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ip_bgp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_bgp_cmds, argc, argv, u);
	
	return retval;
}

static int no_interface_vlan_ip_bgp_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ip_bgp_bfd(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ip_isis
 *  Purpose:  intreface vlan ip isis subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ip_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_isis_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_ip_isis_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ip_isis_bfd(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ip_isis
 *  Purpose:  intreface vlan ip isis subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ip_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_isis_cmds, argc, argv, u);
	
	return retval;
}

static int no_interface_vlan_ip_isis_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ip_isis_bfd(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_ip_static
 *  Purpose:  intreface vlan ip static subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int do_vlan_ip_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_static_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_ip_static_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_ip_static_bfd(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_ip_static
 *  Purpose:  intreface vlan ip static subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_ip_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_ip_static_cmds, argc, argv, u);
	
	return retval;
}

static int no_interface_vlan_ip_static_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_ip_static_bfd(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_vrrp_num_bfd
 *  Purpose:  intreface vlan vrrp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_vrrp_num_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_vrrp_num_bfd_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_vrrp_num_bfd_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_vrrp_num_bfd(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_vrrp_num_bfd
 *  Purpose:  intreface vlan vrrp topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_vrrp_num_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_vrrp_num_bfd(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_bfd
 *  Purpose:  intreface vlan bfd topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_bfd_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_bfd_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_bfd_int_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_bfd_int_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_bfd_int_time_cmds, argc, argv, u);
	
	return retval;
}


static int do_vlan_bfd_int_time_rx(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_bfd_int_time_rx_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_bfd_int_time_rx_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_bfd_int_time_rx_time_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_bfd_int_time_rx_time_plier(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_bfd_int_time_rx_time_plier_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_bfd_int_time_rx_time_plier_val(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_bfd(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_bfd
 *  Purpose:  intreface vlan bfd topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_bfd_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_bfd_int(int argc, char *argv[], struct users *u)
{			
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_bfd(u);
	}

	return retval;
}

/*
 *  Function:  do_vlan_bfd_auth
 *  Purpose:  intreface vlan bfd topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_vlan_bfd_auth(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_bfd_auth_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_bfd_auth_md5(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_bfd_auth_md5_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_bfd_auth_md5_key(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_bfd_auth_md5(u);
	}

	return retval;
}

static int do_vlan_bfd_auth_simple(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_bfd_auth_simple_cmds, argc, argv, u);
	
	return retval;
}

static int do_vlan_bfd_auth_simple_key(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_vlan_bfd_auth_simple(u);
	}

	return retval;
}

/*
 *  Function:  no_vlan_bfd_auth
 *  Purpose:  intreface vlan bfd topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_vlan_bfd_auth(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_bfd_auth_cmds, argc, argv, u);
	
	return retval;
}

static int no_vlan_bfd_auth_md5(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_bfd_auth_md5(u);
	}

	return retval;
}

static int no_vlan_bfd_auth_simple(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_bfd_auth_simple(u);
	}

	return retval;
}

static int do_vlan_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_router_isis_cmds, argc, argv, u);
	
	return retval;
}

static int do_interface_vlan_router_isis(int argc, char *argv[], struct users *u)
{	int retval = -1;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_INT;
	param.name = "<1-65535>";
	param.ylabel = "isis-id";
	param.hlabel = "IS-IS号";
	param.flag = CLI_END_FLAG;
	param.min = 1;
	param.max = 65535;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(func_vlan_router_isis(u) < 0)
			return -1;
	}

	return retval;
}

/*
 *  Function:  no_vlan_router_isis
 *  Purpose:  intreface vlan ip isis subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  guiqin.li
 *  Date:     2011/11/8
 */
static int no_vlan_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(interface_vlan_router_isis_cmds, argc, argv, u);
	
	return retval;
}

static int no_interface_vlan_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_vlan_router_isis(u);
	}

	return retval;
}

static int do_supervlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		func_supervlan(u);
	}
	
	return retval;
}

static int no_supervlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		nfunc_supervlan(u);
	}
	
	return retval;
}

static int do_subvlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(vlan_subvlan, argc, argv, u);
	
	return retval;
}

static int no_subvlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		nfunc_subvlan(u);
	}
	
	return retval;
}

static int do_vlan_subvlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		func_subvlan(u);
	}
	
	return retval;
}


/*
 *  Function:  do_ip_helper
 *  Purpose:   do_ip_helper command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_helper(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_helper_cmds, argc, argv, u);
	return retval;
}

/*
 *  Function:  no_ip_helper
 *  Purpose:   no_ip_helper command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_helper(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_helper_ip(u);
	}

	return retval;
}


/*
 *  Function:  do_ip_helper_ip
 *  Purpose:   do_ip_helper_ip command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_helper_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_helper_ip(u);
	}

	return retval;
}

int init_cli_vlan(void)
{
	int retval = -1;

	retval = registerncmd(vlan_topcmds, (sizeof(vlan_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(interface_vlan_topcmds, (sizeof(interface_vlan_topcmds)/sizeof(struct topcmds) - 1));
    	retval += registerncmd(multicast_vlan_topcmds, (sizeof(multicast_vlan_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1,"init_cli_vlan retval = %d\n", retval);

	return retval;
}

