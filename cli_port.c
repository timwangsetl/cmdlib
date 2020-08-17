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

#include "cli_port_func.h"
#include "acl_utils.h"
#include "cli_port.h"
#include "../bcmutils/bcmutils.h"

/*
 *	interface port top command struct
 *
 *	Author:  peng.liu
 *	Date:    2011/11/17
 */

static struct topcmds interface_port_topcmds[] = {
	{ "aggregator-group", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_interface_trunk, no_interface_trunk, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Aggregation configuration", "聚合配置" },
//	{ "arp", 0, IF_PORT_TREE|IF_GPORT_TREE, do_interface_arp, NULL, NULL, CLI_END_NONE, 0, 0,
//		"ARP parameters", "设置ARP" },
	{ "cos", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_inter_cos, NULL, NULL, CLI_END_NONE, 0, 0,
		"Configure cos", "配置COS" },
	{ "description", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_inter_port_description, no_do_inter_port_description, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Set the interface description", "设置接口的描述" },
	{ "description", 0, IF_TRUNK_TREE, do_inter_port_trunk_description, no_do_inter_port_trunk_description, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Set the aggregation port description", "设置汇聚口的描述" },
	{ "duplex", 0, IF_PORT_TREE|IF_GPORT_TREE, do_duplex, no_do_duplex, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Configure duplex operation", "配置双工模式" },
	{ "dot1x", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_interface_dot1x, no_interface_dot1x, NULL, CLI_END_NONE, 0, 0,
		"IEEE 802.1X port configuration", "IEEE 802.1X 端口配置" },
	{ "dhcp", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_inter_port_dhcp, no_inter_port_dhcp, NULL, CLI_END_NONE, 0, 0,
		"DHCP parameters", "DHCP 配置" },
	{ "flow-control", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_inter_port_flo_control, NULL, NULL,CLI_END_NONE, 0, 0,
		"Configure interface flowcontrol", "配置端口流控" },
	{ "ip", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_inter_port_ip, no_inter_port_ip, NULL, CLI_END_NONE, 0, 0,
		"IP configuration commands", "IP 配置命令" },
	{ "ipv6", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_inter_port_ipv6, NULL, NULL, CLI_END_NONE, 0, 0,
		"IPv6 configuration commands", "IPv6 配置命令" },
	{ "mac", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_inter_port_mac, NULL, NULL, CLI_END_NONE, 0, 0,
		"MAC configuration subcommands", "MAC配置命令" },
	{ "mtu", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_TRUNK_TREE|IF_XPORT_TREE, do_port_mtu, no_port_mtu, NULL, CLI_END_NONE, 0, 0,
		"l2protocol tunnel protocol", "MTU Jumbo配置命令" },
	{ "qos", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_inter_qos, NULL, NULL, CLI_END_NONE, 0, 0,
		"Config port qos", "配置端口qos" },
//	{ "rmon", 0, IF_PORT_TREE|IF_GPORT_TREE, do_inter_port_rmon, NULL, NULL, CLI_END_NONE, 0, 0,
//		"Configure Remote Monitoring on an interface", "在接口上配置远程监控" },
	{ "speed", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_speed, no_do_speed, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Configure speed operation", "配置工作速率" },
	{ "shutdown", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_TRUNK_TREE|IF_XPORT_TREE, do_shutdown, no_do_shutdown, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Shutdown the selected interface", "停用当前接口" },
	{ "spanning-tree", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_stp_int, NULL, NULL, CLI_END_NONE, 0, 0,
		"Config spanning-tree protocol on port", "配置 spanning-tree 协议" },
//	{ "switchport", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_TRUNK_TREE, do_switchport, NULL, NULL, CLI_END_NONE, 0, 0,
	{ "switchport", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_switchport, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set port switching characteristics", "设置端口的交换属性" },
	{ "storm-control", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_inter_port_storm_control, NULL, NULL, CLI_END_NONE, 0, 0,
		"Storm control configuration", "配置风暴控制" },
	{ "gvrp", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_TRUNK_TREE|IF_XPORT_TREE, do_inter_port_gvrp, no_inter_port_gvrp, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"GVRP protocol", "GVRP 协议" },
//	{ "garp", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_TRUNK_TREE, do_inter_port_garp, no_inter_port_garp, NULL, CLI_END_NONE, 0, 0,
//		"GVRP protocol", "GVRP 协议" },
	{ "gmrp", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_TRUNK_TREE|IF_XPORT_TREE, do_inter_port_gmrp, no_inter_port_gmrp, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Config GMRP protocol", "GMRP 协议" },
	{ "lldp", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_TRUNK_TREE|IF_XPORT_TREE, do_inter_port_lldp, no_inter_port_lldp, NULL, CLI_END_NONE, 0, 0,
		"LLDP protocol", "LLDP 协议" },
	{ "l2protocol-tunnel", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_TRUNK_TREE|IF_XPORT_TREE, do_inter_port_tunnel, no_inter_port_tunnel, NULL, CLI_END_NONE, 0, 0,
		"l2protocol tunnel protocol", "二层隧道协议" },
	{ "vlan", 0, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE, do_vlan_mapping, NULL, NULL, CLI_END_NONE, 0, 0,
		"VLAN module", "VLAN 模块" },
	{ TOPCMDS_END }
};

/*
 *	interface port cmd  struct
 *
 *	Author:     peng.liu
 *	Date:	  2011/11/18
 */

//----------------------------------------------------------------------------------------
//aggregator-group


static struct cmds interface_trunk_group_cmds[] = {
	{ "<1-6>", CLI_INT, 0, 0, do_interface_trunk_group, NULL, NULL, CLI_END_NONE, 1, 6,
		"Aggregator group number", "端口聚合组号" },
	{ CMDS_END }
};

static struct cmds interface_trunk_mode_cmds[] = {
	{ "mode", CLI_CMD, 0, 0, do_interface_trunk_mode, NULL, NULL, CLI_END_NONE, 0, 0,
		"Port aggregation Mode of the interface", "端口下的端口聚合模式" },
	{ CMDS_END }
};

static struct cmds interface_trunk_mode_sel_cmds[] = {
	{ "lacp", CLI_CMD, 0, 0, do_interface_trunk_mode_lacp, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Enable lacp protocol negotiate", "LACP 协商的端口聚合配置" },
	{ "static", CLI_CMD, 0, 0, do_interface_trunk_mode_static, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Static port aggregate to aggregator", "静态端口聚合配置" },
	{ CMDS_END }
};

//----------------------------------------------------------------------------------------
//arp

static struct cmds interface_arp_cmds[] = {
	{ "inspection", CLI_CMD, 0, 0, do_arp_inspection, NULL, NULL, 0, 0, 0,
		"Configure ARP inspection", "配置ARP 侦测" },
	{ CMDS_END }
};

static struct cmds arp_inspection_cmds[] = {
	{ "trust", CLI_CMD, 0, 0, do_inspection_trust, no_inspection_trust, NULL, CLI_END_NO|CLI_END_FLAG, 0, 0,
		"Configure DHCP Snooping trust interface", "配置DHCP Snooping信任端口" },
	{ CMDS_END }
};


//----------------------------------------------------------------------------------------
//cos

static struct cmds inter_cos_cmds[] = {
	{ "default", CLI_CMD, 0, 0, do_inter_cos_default, no_inter_cos_default, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Config default cos value", "配置缺省cos 值" },
	{ CMDS_END }
};


//----------------------------------------------------------------------------------------
//description
static struct cmds inter_port_description[] = {
	{ "LINE", CLI_LINE, 0, 0, do_inter_port_description_line, NULL, NULL, CLI_END_FLAG, 0, 0,
		"The interface description", "字符参数" },
	{ CMDS_END }
};

static struct cmds inter_port_trunk_description[] = {
	{ "LINE", CLI_LINE, 0, 0, do_inter_port_trunk_description_line, NULL, NULL, CLI_END_FLAG, 0, 0,
		"The interface description", "字符参数" },
	{ CMDS_END }
};


//----------------------------------------------------------------------------------------
//flow_control
static struct cmds inter_port_flo_control[] = {
	{ "on", CLI_CMD, 0, 0, do_inter_port_flo_control_on, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Open interface flowcontrol", " 打开端口流控功能" },
	{ "off", CLI_CMD, 0, 0, do_inter_port_flo_control_off, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Close interface flowcontrol", "关闭端口流控功能" },
	{ CMDS_END }
};
/*---------------------------------------------------ipv6---------------------------*/

static struct cmds inter_port_ipv6[] = {
	{ "access_group", CLI_CMD, 0, 0, do_inter_port_ipv6_acc_grp, no_do_inter_port_ipv6_acc_grp, NULL, CLI_END_NONE, 0, 0,
		"Apply access-list", "应用访问列表" },
//	{ "dhcp", CLI_CMD, 0, 0, do_inter_port_ipv6_dhcp, NULL, NULL, CLI_END_NONE, 0, 0,
//		"Configure DHCP parameters for this interface", "配置 dhcp" },
	{ "nd", CLI_CMD, 0, 0, do_inter_port_ipv6_nd, no_inter_port_ipv6_nd, NULL, CLI_END_NONE, 0, 0,
		"Configure IPv6 neighbor parameters for this interface", "配置邻居发现协议" },
//	{ "router", CLI_CMD, 0, 0, do_inter_port_ipv6_router, no_inter_port_ipv6_router, NULL, CLI_END_NONE, 0, 0,
//		"Configure IPv6 router parameters for this interface", "配置路由协议" },
	{ CMDS_END }
};

static struct cmds inter_port_ipv6_dhcp[] = {
	{ "snooping", CLI_CMD, 0, 0, do_inter_port_ipv6_dhcp_sno, NULL, NULL, CLI_END_NONE, 0, 0,
		"DHCP Snooping", "配置 DHCP Snooping" },
		{ CMDS_END }
};

static struct cmds inter_port_ipv6_dhcp_sno[] = {
	{ "trust", CLI_CMD, 0, 0, do_inter_port_ipv6_dhcp_sno_trus, no_do_inter_port_ipv6_dhcp_sno_trus, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"DHCP Snooping trust config", "开启DHCP Snooping的信任配置" },
		{ CMDS_END }
};

static struct cmds inter_port_ipv6_nd_cmds[] = {
	{ "cache", CLI_CMD, 0, 0, do_inter_port_ipv6_nd_cache, no_inter_port_ipv6_nd_cache, NULL, CLI_END_NONE, 0, 0,
		"IPv6 neighbor cache", "配置 IPv6 邻居缓存" },
		{ CMDS_END }
};

static struct cmds inter_port_ipv6_nd_cache_cmds[] = {
	{ "expire", CLI_CMD, 0, 0, do_inter_port_ipv6_nd_cache_expire, no_inter_port_ipv6_nd_cache_expire, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"IPv6 neighbor cache expire", "配置 IPv6 邻居缓存" },
		{ CMDS_END }
};

static struct cmds inter_port_ipv6_nd_cache_expire_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_inter_port_ipv6_nd_cache_expire_sec, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"IPv6 neighbor cache expire time", "配置 IPv6 邻居缓存时间（秒）" },
		{ CMDS_END }
};

/* IPv6 router */
static struct cmds inter_port_ipv6_router_cmds[] = {
	{ "ospf", CLI_CMD, 0, 0, do_inter_port_ipv6_router_ospf, no_inter_port_ipv6_router_ospf, NULL, CLI_END_NONE, 0, 0,
		"IPv6 router ospf", "配置 IPv6 OSPF 路由协议" },
	{ "rip", CLI_CMD, 0, 0, do_inter_port_ipv6_router_rip, no_inter_port_ipv6_router_rip, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IPv6 router rip", "配置 IPv6 RIP 路由协议" },
	{ "isis", CLI_CMD, 0, 0, do_inter_port_ipv6_router_isis, no_inter_port_ipv6_router_isis, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"IPv6 router IS-IS", "配置 IPv6 IS-IS 路由协议" },
		{ CMDS_END }
};

static struct cmds inter_port_ipv6_router_ospf_cmds[] = {
	{ "area", CLI_CMD, 0, 0, do_inter_port_ipv6_router_ospf_area, no_inter_port_ipv6_router_ospf_area, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"IPv6 router ospf", "配置 IPv6 OSPF 路由协议" },
		{ CMDS_END }
};

static struct cmds inter_port_ipv6_router_ospf_area_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_inter_port_ipv6_router_ospf_area_id, NULL, NULL, CLI_END_NONE, 1, 65535,
		"IPv6 router ospf", "配置 IPv6 OSPF 路由协议" },
		{ CMDS_END }
};

static struct cmds inter_port_ipv6_router_ospf_area_id_cmds[] = {
	{ "tag", CLI_CMD, 0, 0, do_inter_port_ipv6_router_ospf_area_id_tag, NULL, NULL, CLI_END_NONE, 0, 0,
		"IPv6 router ospf", "配置 IPv6 OSPF 路由协议" },
		{ CMDS_END }
};

static struct cmds inter_port_ipv6_router_ospf_area_id_tag_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_inter_port_ipv6_router_ospf_area_id_tag_tag, NULL, NULL, CLI_END_NONE, 0, 0,
		"IPv6 router ospf", "配置 IPv6 OSPF 路由协议" },
		{ CMDS_END }
};

static struct cmds inter_port_ipv6_router_ospf_area_id_tag_tag_cmds[] = {
	{ "instance-id", CLI_CMD, 0, 0, do_inter_port_ipv6_router_ospf_area_id_tag_tag_instance, NULL, NULL, CLI_END_NONE, 0, 0,
		"IPv6 router ospf", "配置 IPv6 OSPF 路由协议" },
		{ CMDS_END }
};

static struct cmds inter_port_ipv6_router_ospf_area_id_tag_tag_instance_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_inter_port_ipv6_router_ospf_area_id_tag_tag_instance_id, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"IPv6 router ospf", "配置 IPv6 OSPF 路由协议" },
		{ CMDS_END }
};

static struct cmds inter_port_ipv6_router_isis_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_inter_port_ipv6_router_isis_id, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"IPv6 router IS-IS", "配置 IPv6 IS-IS 路由协议" },
		{ CMDS_END }
};

//----------------------------------------------------------------------------------------
//ip
static struct cmds inter_port_ip[] = {
	{ "access_group", CLI_CMD, 0, 0, do_inter_port_ip_acc_grp, no_do_inter_port_ip_acc_grp, NULL, CLI_END_NONE, 0, 0,
		"Apply access-list", "应用访问列表" },
	//{ "arp", CLI_CMD, 0, 0, do_inter_port_ip_arp, NULL, NULL, CLI_END_NONE, 0, 0,
		//"Configure ARP features", "配置 arp" },
	{ "dhcp", CLI_CMD, 0, 0, do_inter_port_ip_dhcp, NULL, NULL, CLI_END_NONE, 0, 0,
		"Configure DHCP parameters for this interface", "配置 dhcp" },
//	{ "router", CLI_CMD, 0, 0, do_inter_port_ip_router, no_inter_port_ip_router, NULL, CLI_END_NONE, 0, 0,
//		"Configure router parameters for this interface", "配置 router" },
	{ "igmp", CLI_CMD, 0, 0, do_inter_port_ip_igmp, no_inter_port_ip_igmp, NULL, CLI_END_NONE, 0, 0,
		"Configure igmp parameters for this interface", "配置 igmp" },
//	{ "pim-sm", CLI_CMD, 0, 0, do_inter_port_ip_pim, no_inter_port_ip_pim, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
//		"Configure pim-sm parameters for this interface", "配置 pim-sm" },
		{ CMDS_END }
};

static struct cmds inter_port_ip_dhcp[] = {
	{ "snooping", CLI_CMD, 0, 0, do_inter_port_ip_dhcp_sno, NULL, NULL, CLI_END_NONE, 0, 0,
		"DHCP Snooping", "配置 DHCP Snooping" },
		{ CMDS_END }
};

static struct cmds inter_port_ip_dhcp_sno[] = {
	{ "trust", CLI_CMD, 0, 0, do_inter_port_ip_dhcp_sno_trus, no_do_inter_port_ip_dhcp_sno_trus, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"DHCP Snooping trust config", "开启DHCP Snooping的信任配置" },
		{ CMDS_END }
};

static struct cmds inter_port_ip_router[] = {
	{ "isis", CLI_CMD, 0, 0, do_inter_port_ip_router_isis, no_inter_port_ip_router_isis, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Router IS-IS", "配置 Router IS-IS" },
		{ CMDS_END }
};

static struct cmds inter_port_ip_router_isis[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_inter_port_ip_router_isis_id, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"Router IS-IS ID", "配置 Router IS-IS 号" },
		{ CMDS_END }
};

static struct cmds inter_port_ip_arp[] = {
	{ "inspection", CLI_CMD, 0, 0, do_inter_port_ip_arp_inspect, NULL, NULL, CLI_END_NONE, 0, 0,
		"ARP Inspection configuration", "配置 arp inspection" },
		{ CMDS_END }
};

static struct cmds inter_port_ip_arp_inspect[] = {
	{ "trust", CLI_CMD, 0, 0, do_inter_port_ip_arp_inspect_trust, no_do_inter_port_ip_arp_inspect_trust, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Configure Trust state", "配置信任统计" },
	{ "limit", CLI_CMD, 0, 0, do_inter_port_ip_arp_inspect_limit, no_do_inter_port_ip_arp_inspect_limit, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Configure Rate limit of incoming ARP packets", "配置传入的ARP数据包的速率限制" },
		{ CMDS_END }
};

static struct cmds inter_port_ip_arp_inspect_limit[] = {
	{ "rate", CLI_CMD, 0, 0, do_inter_port_ip_arp_inspect_limit_rate, NULL, NULL, CLI_END_NONE, 0, 0,
		"Rate Limit", "速率限制" },
		{ CMDS_END }
};

static struct cmds inter_port_ip_igmp_cmds[] = {
	{ "join-group", CLI_CMD, 0, 0, do_inter_port_ip_igmp_join, no_inter_port_ip_igmp_join, NULL, CLI_END_NONE, 0, 0,
		"IGMP join group", "配置 IGMP 加入组" },
	/*{ "querier-timeout", CLI_CMD, 0, 0, do_inter_port_ip_igmp_querier, no_inter_port_ip_igmp_querier, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"IGMP querier timeout", "配置 IGMP 请求超时" },
	{ "last-member-query-interval", CLI_CMD, 0, 0, do_inter_port_ip_igmp_last_query, no_inter_port_ip_igmp_last_query, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"IGMP last member query interval", "配置 IGMP 最后一个组成员查询时间" },
	{ "query-interval", CLI_CMD, 0, 0, do_inter_port_ip_igmp_query, no_inter_port_ip_igmp_query, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"IGMP last member query interval", "配置 IGMP 最后一个组成员查询时间" },
	{ "static-group", CLI_CMD, 0, 0, do_inter_port_ip_igmp_static, no_inter_port_ip_igmp_static, NULL, CLI_END_NONE, 0, 0,
		"IGMP static group", "配置 IGMP 静态组" },
	{ "version", CLI_CMD, 0, 0, do_inter_port_ip_igmp_version, no_inter_port_ip_igmp_version, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"IGMP join group", "配置 IGMP 加入组" },*/
		{ CMDS_END }
};

static struct cmds inter_port_ip_igmp_join_cmds[] = {
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_inter_port_ip_igmp_join_group, no_inter_port_ip_igmp_join_group, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IGMP join group address", "配置 IGMP 组播组地址" },
		{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_join_group_cmds[] =
{
	{ "include", CLI_CMD, 0, 0, do_inter_port_ip_igmp_join_group_in, no_inter_port_ip_igmp_join_group_in, NULL, CLI_END_NONE, 0, 0,
		"IGMP join group include source address", "配置 IGMP 组播组包括源地址" },
	{ "exclude", CLI_CMD, 0, 0, do_inter_port_ip_igmp_join_group_ex, no_inter_port_ip_igmp_join_group_ex, NULL, CLI_END_NONE, 0, 0,
		"IGMP join group exclude source address", "配置 IGMP 组播组不包括源地址" },
	{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_join_group_in_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_inter_port_ip_igmp_join_group_in_src, no_inter_port_ip_igmp_join_group_in_src, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IGMP join group include source address", "配置 IGMP 组播组包括源地址" },
	{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_join_group_ex_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_inter_port_ip_igmp_join_group_ex_src, no_inter_port_ip_igmp_join_group_ex_src, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IGMP join group exclude source address", "配置 IGMP 组播组不包括源地址" },
	{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_querier_cmds[] =
{
	{ "<1-65535>", CLI_INT, 0, 0, do_inter_port_ip_igmp_querier_time, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"IGMP querier timeout", "配置 IGMP 请求超时" },
	{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_last_query_cmds[] =
{
	{ "<1-65535>", CLI_INT, 0, 0, do_inter_port_ip_igmp_last_query_time, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"IGMP last member query interval", "配置 IGMP 最后一个组成员查询时间" },
	{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_query_cmds[] =
{
	{ "<1-65535>", CLI_INT, 0, 0, do_inter_port_ip_igmp_query_time, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"IGMP query interval", "配置 IGMP 查询时间" },
	{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_static_cmds[] = {
	{ "all", CLI_CMD, 0, 0, do_inter_port_ip_igmp_static_all, no_inter_port_ip_igmp_static_all, NULL, CLI_END_FLAG, 0, 0,
		"IGMP static group address", "配置 IGMP 静态组地址" },
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_inter_port_ip_igmp_static_group, no_inter_port_ip_igmp_static_group, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IGMP join group include source address", "配置 IGMP 组播组包括源地址" },
		{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_static_all_cmds[] =
{
	{ "include", CLI_CMD, 0, 0, do_inter_port_ip_igmp_static_all_in, no_inter_port_ip_igmp_static_all_in, NULL, CLI_END_NONE, 0, 0,
		"IGMP static group include source address", "配置 IGMP 静态组包括源地址" },
	{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_static_group_cmds[] =
{
	{ "include", CLI_CMD, 0, 0, do_inter_port_ip_igmp_static_group_in, no_inter_port_ip_igmp_static_group_in, NULL, CLI_END_NONE, 0, 0,
		"IGMP static group include source address", "配置 IGMP 静态组包括源地址" },
	{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_static_all_in_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_inter_port_ip_igmp_static_all_in_src, no_inter_port_ip_igmp_static_all_in_src, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IGMP static group include source address", "配置 IGMP 静态组包括源地址" },
	{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_static_group_in_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_inter_port_ip_igmp_static_group_in_src, no_inter_port_ip_igmp_static_group_in_src, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IGMP static group include source address", "配置 IGMP 静态组包括源地址" },
	{ CMDS_END  }
};

static struct cmds inter_port_ip_igmp_version_cmds[] =
{
	{ "1", CLI_CMD, 0, 0, do_inter_port_ip_igmp_version_1, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IGMP version", "配置 IGMP 版本" },
	{ "2", CLI_CMD, 0, 0, do_inter_port_ip_igmp_version_2, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IGMP version", "配置 IGMP 版本" },
	{ "3", CLI_CMD, 0, 0, do_inter_port_ip_igmp_version_3, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IGMP version", "配置 IGMP 版本" },
	{ CMDS_END  }
};

//----------------------------------------------------------------------------------------
//dot1x
static struct cmds interface_dot1x_cmds[] = {
#ifdef CLI_AAA_MODULE
	{ "forbid", CLI_CMD, 0, NO_FORBID, do_dot1x_forbid, NULL, NULL, CLI_END_NO|CLI_END_FLAG, 0, 0,
		"Enabled IEEE 802.1X specil forbid control", "启动802.1x的特殊禁止功能" },
	{ "authentication", CLI_CMD, 0, NO_AUTHENTICATION, do_dot1x_authentication, NULL, NULL, 0, 0, 0,
		"Select 802.1x authenticate characteristics on interface", "选择端口下的802.1x认证属性" },
#endif
	{ "port-control", CLI_CMD, 0, NO_PORT_CONTROL, do_dot1x_portcontrol, NULL, NULL, CLI_END_NO, 0, 0,
		"Control port authentication", "选择端口下的802.1x模式" },
	{ "max-user", CLI_CMD, 0, 0, do_dot1x_maxuser,no_dot1x_maxuser, NULL, CLI_END_NO|CLI_END_FLAG, 0, 0,
		"Control the max number access in port", "配置认证端口下的最大用户数" },
	{ "guest-vlan", CLI_CMD, 0, 0, do_dot1x_guest_vlan,no_dot1x_guest_vlan, NULL, CLI_END_NO|CLI_END_FLAG, 0, 0,
		"Create a guest vlan", "创建一个guest-vlan" },
	{ CMDS_END }
};

static int do_dot1x_guest_vlan(int argc, char *argv[], struct users *u)
{
	int vlan_id,retval = -1;
	char str[20] = {0};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-4096>";
	param.ylabel = "The vlan number";
	param.min = 0;
	param.max = 0;
	param.flag = 1;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);
	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		cli_param_get_int(DYNAMIC_PARAM, 0, &vlan_id, u);
		sprintf(str,"%d",vlan_id);
		func_set_guest_vlan_id(str,u);
	}
	return retval;
}


static int no_dot1x_guest_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_set_guest_vlan(u);

	}

	return retval;
}

static struct cmds forbid_cmds[] = {
	{ "multi-network-adapter", CLI_CMD, 0, 0, do_forbid_multinetworkadapter, NULL, NULL, CLI_END_NO|CLI_END_FLAG, 0, 0,
		"Forbid client use multi network adapter", "禁止客户端使用多网卡" },
	{ CMDS_END }
};

static struct cmds authentication_cmds[] = {
	{ "type", CLI_CMD, 0, 0, do_authentication_type, NULL, NULL, CLI_END_NONE, 0, 0,
		"Select 802.1x authenticate type", "选择802.1x端口认证类型" },
	{ "method", CLI_CMD, 0, 0, do_authentication_method, NULL, NULL, CLI_END_NONE, 0, 0,
		"Select 802.1x authenticate method", "选择802.1x端口认证方法" },
	
	{ CMDS_END }
};

static struct cmds type_cmds[] = {
	{ "chap", CLI_CMD, 0, 0, do_type_chap, NULL, NULL, 1, 0, 0,
		"Select 802.1x chap authenticate type", "选择802.1x端口认证类型为chap" },
	{ "eap", CLI_CMD, 0, 0, do_type_eap, NULL, NULL, 1, 0, 0,
		" Select 802.1x eap authenticate type", "选择802.1x端口认证方法为eap" },
	{ CMDS_END }
};

static struct cmds port_control_cmds[] = {
	{ "auto", CLI_CMD, 0, 0, do_portcontrol_auto, NULL, NULL, 1, 0, 0,
		"Authenticate automatically", "Auto认证模式" },
	{ "force-authorized", CLI_CMD, 0, 0, do_portcontrol_forceauthorized, NULL, NULL, 1, 0, 0,
		"Force port to authorized state", "强制端口认证通过模式" },
	{ "force-unauthorized", CLI_CMD, 0, 0, do_portcontrol_forceunauthorized, NULL, NULL, 1, 0, 0,
		"Force port to unauthorized state", "强制端口认证不通过模式" },
	{ CMDS_END }
};

//----------------------------------------------------------------------------------------
//mac
static struct cmds inter_port_mac[] = {
	{ "access-group", CLI_CMD, 0, 0, do_inter_port_mac_acc_grp, no_do_inter_port_mac_acc_grp, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Named access-list", "配置访问列表" },
	{ "max-limit", CLI_CMD, 0, 0, do_mac_learn_limit, no_mac_learn_limit, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"mac learn limit", "mac学习限制" },
	{ CMDS_END }
};

//----------------------------------------------------------------------------------------
//qos

static struct cmds inter_qos_cmds[] = {
	{ "policy", CLI_CMD, 0, 0, do_inter_qos_policy, no_inter_qos_policy, NULL, CLI_END_NONE, 0, 0,
		"Config port policy map", "配置端口QOS 策略" },
	{ CMDS_END }
};

static struct cmds inter_qos_policy_cmds[] = {
	{ "ingress", CLI_CMD, 0, 0, do_inter_qos_policy_ingress, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Config port policy map ingress", "配置入端口QOS 策略" },
	{ CMDS_END }
};


//----------------------------------------------------------------------------------------
//storm_control
static struct cmds inter_port_storm_control[] = {
	{ "broadcast", CLI_CMD, 0, 0, do_inter_port_storm_contr_broad, NULL, NULL, CLI_END_NONE, 0, 0,
		"Broadcast address storm control", "广播报文风暴控制" },
	{ "multicast", CLI_CMD, 0, 0, do_inter_port_storm_contr_mul, NULL, NULL, CLI_END_NONE, 0, 0,
		"Multicast address storm control", "多播报文风暴控制" },
	{ "unicast", CLI_CMD, 0, 0, do_inter_port_storm_contr_unicast, NULL, NULL, CLI_END_NONE, 0, 0,
		"Unicast address storm control", "单播报文风暴控制" },
		{ CMDS_END }
};

static struct cmds inter_port_storm_contr_broad[] = {
	{ "threshold", CLI_CMD, 0, 0, do_inter_port_storm_contr_broad_thresd, no_do_inter_port_storm_contr_broad_thresd, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Enter Integer part of storm suppression threshold", "配置风暴控制的级阀值" },
		{ CMDS_END }
};

static struct cmds inter_port_storm_contr_mul[] = {
	{ "threshold", CLI_CMD, 0, 0, do_inter_port_storm_contr_mul_thresd, no_do_inter_port_storm_contr_mul_thresd, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Enter Integer part of storm suppression threshold", "配置风暴控制的级阀值" },
		{ CMDS_END }
};

static struct cmds inter_port_storm_contr_uni[] = {
	{ "threshold", CLI_CMD, 0, 0, do_inter_port_storm_contr_uni_thresd, no_do_inter_port_storm_contr_uni_thresd, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Enter Integer part of storm suppression threshold", "配置风暴控制的级阀值" },
		{ CMDS_END }
};

//----------------------------------------------------------------------------------------
//rmon
static struct cmds inter_port_rmon[] = {
	{ "collection", CLI_CMD, 0, 0, do_inter_port_rmon_collet, NULL, NULL, CLI_END_NONE, 0, 0,
		"Configure Remote Monitoring Collection on an interface", "在接口上使能RMON功能" },
		{ CMDS_END }
};

static struct cmds inter_port_rmon_collet[] = {
	{ "history", CLI_CMD, 0, 0, do_inter_port_rmon_collet_histy, NULL, NULL, CLI_END_NONE, 0, 0,
		"Configure history", "配置RMON历史组" },
	{ "stats", CLI_CMD, 0, 0, do_inter_port_rmon_collet_stats, NULL, NULL, CLI_END_NONE, 0, 0,
		"Configure statistics", "配置RMON统计组" },
		{ CMDS_END }
};

static struct cmds inter_port_rmon_collet_stats[] = {
	{ "owner", CLI_CMD, 0, 0, do_inter_port_rmon_collet_stats_own, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set the owner of this RMON collection", "指定本条记录的所有者" },
		{ CMDS_END }
};

static struct cmds inter_port_rmon_collet_stats_own[] = {
	{ "buckets", CLI_CMD, 0, 0, do_inter_port_rmon_collet_stats_own_bucket, NULL, NULL, CLI_END_NONE, 0, 0,
		"Requested buckets of intervals. Default is 50 buckets", "本统计控制表容纳的最大取样数量.默认值是50" },
		{ CMDS_END }
};

static struct cmds inter_port_rmon_collet_histy[] = {
	{ "buckets", CLI_CMD, 0, 0, do_inter_port_rmon_collet_histy_bucket, NULL, NULL, CLI_END_NONE, 0, 0,
		"Requested buckets of intervals. Default is 50 buckets", "本历史控制表容纳的最大取样数量. 默认值是50" },
	{ "interval", CLI_CMD, 0, 0, do_inter_port_rmon_collet_histy_intev, NULL, NULL, CLI_END_NONE, 0, 0,
		"Interval to sample data for each bucket. Default is 1800 seconds", "取样数据的间隔时间,默认值是1800秒(半小时)" },
		{ CMDS_END }
};

static struct cmds inter_port_rmon_collet_histy_intev[] = {
	{ "buckets", CLI_CMD, 0, 0, do_inter_port_rmon_collet_histy_intev_bucket, NULL, NULL, CLI_END_NONE, 0, 0,
		"Requested buckets of intervals. Default is 50 buckets", "本统计控制表容纳的最大取样数量.默认值是50" },
		{ CMDS_END }
};

static struct cmds inter_port_rmon_collet_histy_bucket[] = {
	{ "owner", CLI_CMD, 0, 0, do_inter_port_rmon_collet_histy_bucket_own, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set the owner of this RMON collection", "指定本条记录的所有者" },
	{ "interval", CLI_CMD, 0, 0, do_inter_port_rmon_collet_histy_bucket_intev, NULL, NULL, CLI_END_NONE, 0, 0,
		"Interval to sample data for each bucket. Default is 1800 seconds", "取样数据的间隔时间,默认值是1800秒(半小时)" },
		{ CMDS_END }
};

static struct cmds inter_port_rmon_collet_histy_intev_bucket[] = {
	{ "owner", CLI_CMD, 0, 0, do_inter_port_rmon_collet_histy_intev_bucket_own, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set the owner of this RMON collection", "指定本条记录的所有者" },
		{ CMDS_END }
};

static struct cmds inter_port_rmon_collet_histy_bucket_intev[] = {
	{ "owner", CLI_CMD, 0, 0, do_inter_port_rmon_collet_histy_bucket_intev_own, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set the owner of this RMON collection", "指定本条记录的所有者" },
		{ CMDS_END }
};


//----------------------------------------------------------------------------------------
//spanning-tree

static struct cmds stp_int_cmds[] = {
#if (ERR_DISABLE_RSTP)
{ "bpdufilter", CLI_CMD, 0, 0, do_stp_int_bpduf, no_do_stp_int_bpduf, NULL, CLI_END_NO, 0, 0,
  "Don't send or receive BPDUs on this interface", "禁止该端口的BPDU包收发" },
{ "bpduguard", CLI_CMD, 0, 0, do_stp_int_bpdug, no_do_stp_int_bpdug, NULL, CLI_END_NO, 0, 0,
  "Don't accept BPDUs on this interface", "禁止该端口接收BPDU包" },
#endif
{ "cost", CLI_CMD, 0, 0, do_stp_int_cost, no_do_stp_int_cost, NULL, CLI_END_NO, 0, 0,
  "Change an interface's spanning tree port path cost", "改变一个端口的生成树路径开销" },
#if (ERR_DISABLE_RSTP)
{ "guard", CLI_CMD, 0, 0, do_stp_int_guard, no_do_stp_int_guard, NULL, CLI_END_NO, 0, 0,
  "Change an interface's spanning tree guard mode", "改变一个端口的生成树防护模式" },
#endif
{ "link-type", CLI_CMD, 0, 0, do_stp_int_link, no_do_stp_int_link, NULL, CLI_END_NO, 0, 0,
  "Specify a link type for spanning tree protocol use", "指定生成树协议使用的链接类型" },
{ "port-priority", CLI_CMD, 0, 0, do_stp_int_portp, no_do_stp_int_portp, NULL, CLI_END_NO, 0, 0,
  "Change an interface's spanning tree port priority", "改变一个端口的生成树优先级" },
//#if (ERR_DISABLE_RSTP)
{ "portfast", CLI_CMD, 0, 0, do_stp_int_portf, no_do_stp_int_portf, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
  "Enable an interface to move directly to forwarding on link up", "使端口从down直接进入fowarding状态" },
//#endif
{ CMDS_END }
};

static struct cmds stp_int_bpduf_cmds[] = {
{ "disable", CLI_CMD, 0, 0, do_stp_int_bpduf_dis, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Disable BPDU filtering for this interface", "关闭bpdufilter功能" },
{ "enable", CLI_CMD, 0, 0, do_stp_int_bpduf_en, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Enable BPDU filtering for this interface", "开启bpdufilter功能" },
{ CMDS_END }
};

static struct cmds stp_int_bpdug_cmds[] = {
{ "disable", CLI_CMD, 0, 0, do_stp_int_bpdug_dis, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Disable BPDU guard for this interface", "关闭bpduguard功能" },
{ "enable", CLI_CMD, 0, 0, do_stp_int_bpdug_en, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Enable BPDU guard for this interface", "开启bpduguard功能" },
{ CMDS_END }
};

static struct cmds stp_int_guard_cmds[] = {
{ "none", CLI_CMD, 0, 0, do_stp_int_guard_none, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Set guard mode to none", "设置防护模式为none" },
{ "root", CLI_CMD, 0, 0, do_stp_int_guard_root, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Set guard mode to root guard on interface", "设置防护模式为root" },
{ CMDS_END }
};

static struct cmds stp_int_link_cmds[] = {
{ "point-to-point", CLI_CMD, 0, 0, do_stp_int_link_point, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Consider the interface as point-to-point", "设置生成树端口的链接类型为point-to-point" },
{ "shared", CLI_CMD, 0, 0, do_stp_int_link_shared, NULL, NULL, CLI_END_FLAG, 0, 0,
  "Consider the interface as shared", "设置生成树端口的链接类型为shared" },
{ CMDS_END }
};


/*
 *  sub command struct
 *  
 *  Author:   peng.liu
 *  Date:     2011/11/18
 */
static struct cmds speed[] = {
	{ "10", CLI_CMD, 0, 0, do_speed_ten, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 10, 10,
		"Force 10 Mbps operation", "设置工作速率为10Mbps" },
	{ "100", CLI_CMD, 0, 0, do_speed_hundred, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 100, 100,
		"Force 100 Mbps operation", "设置工作速率为100Mbps" },
	{ "1000", CLI_CMD, 0, 0, do_speed_giga, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 1000, 1000,
		"Force 1000 Mbps operation", "设置工作速率为1000Mbps" },
	{ "auto", CLI_CMD, 0, 0, do_speed_auto, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Enable AUTO speed configuration", "打开速率自动配置" },
	{ CMDS_END }
};

static struct cmds duplex[] = {
	{ "auto", CLI_CMD, 0, 0, do_duplex_auto, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Enable AUTO duplex configuration", "自动双工配置" },
	{ "full", CLI_CMD, 0, 0, do_duplex_full, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Force full duplex operation", "全双工模式" },
	{ "half", CLI_CMD, 0, 0, do_duplex_half, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Force half-duplex operation", "半双工模式" },
	{ CMDS_END }
};

static struct cmds switchport[] = {
	{ "block", CLI_CMD, 0, NO_BLOCK, do_sw_block, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set block mode of interface", "配置接口阻塞类型" },
	{ "loopback-detected", CLI_CMD, 0, NO_LOOPBACK, do_sw_loop, no_do_sw_loop, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Loopback detected config", "配置端口的回环检测" },
	{ "dot1q-translating-tunnel", CLI_CMD, 0, 0, do_sw_qinq, no_do_sw_qinq, NULL, CLI_END_FLAG |CLI_END_NO, 0, 0,
		"QinQ config", "配置端口的QinQ" },
	{ "mode", CLI_CMD, 0, 0, do_sw_mode, no_do_sw_mode, NULL, CLI_END_NONE |CLI_END_NO, 0, 0,
		"Select switching mode of the port", "选择端口的交换模式" },
	{ "port-security", CLI_CMD, 0, NO_PORTSEC, do_sw_portsec, NULL, NULL, CLI_END_NONE, 0, 0,
		"Security port config", "配置安全端口" },
	{ "protected", CLI_CMD, 0, NO_PROTECTED, do_sw_pro, no_do_sw_pro, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Protected port config", "配置保护端口" },
	{ "pvid", CLI_CMD, 0, 0, do_vlan, no_do_vlan, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"The pvid vlan of the port", "设置端口的 PVID" },
	{ "rate-limit", CLI_CMD, 0, NO_RATELIMIT, do_rate_limit, NULL, NULL, CLI_END_NONE, 0, 0,
		" Rate-limit", "端口限速" },
	{ "trunk", CLI_CMD, 0, 0, do_trunk, NULL, NULL, CLI_END_NONE, 0, 0,
		"The trunk characteristics when port is trunk mode", "设置端口的是中继端口时的交换属性" },
	{ "ring", CLI_CMD, 0, 0, do_ring, no_ring, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"The RING of the port", "设置端口的环网" },
	{ CMDS_END }
};

static struct cmds vlan_mapping[] = {
	{ "block", CLI_CMD, 0, NO_BLOCK, do_sw_block, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set block mode of interface", "配置接口阻塞类型" },
	
	{ CMDS_END }
};


static struct cmds switch_qinq[] = {
	{ "mode", CLI_CMD, 0, 0, do_sw_mode_qinq, no_do_sw_mode_qinq, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Select switching mode of the port", "选择端口的交换模式" },
	{ "translate", CLI_CMD, 0, 0, do_sw_trans_qinq, no_do_sw_trans_qinq, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Select switching mode of the port", "选择端口的交换模式" },
	{ CMDS_END }
};

static struct cmds switch_qinq_mode_type[] = {
	{ "qinq", CLI_CMD, 0, 0, do_sw_mode_qinq_type, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Select switching mode as QinQ", "选择端口的交换模式" },
	{ "flat", CLI_CMD, 0, 0, do_sw_mode_flat_type, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Select switching mode as Valn Translate", "选择端口的交换模式" },
	{ "uplink", CLI_CMD, 0, 0, do_sw_mode_qinquplink, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Double tag uplink mode", "双标签上联口模式" },
	{ CMDS_END }
};

static struct cmds switch_qinq_translate[] = {
	{ "WORD", CLI_WORD, 0, 0, do_switch_qinq_translate, NULL, NULL, CLI_END_NO, 0, 0,
		"VLAN IDs such as (1,3,5,7) Or (1,3-5,7) Or (1-7)", "类似(1,3,5,7) 或 (1,3-5,7) 或 (1-7)表示的VLAN 范围表" },
	{ CMDS_END }
};

static struct cmds switch_qinq_translate_new[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_switch_qinq_translate_new, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"VLAN IDs(1-4094), such as 1000", "VLAN范围1-4094，如 1000" },
	{ CMDS_END }
};

static struct cmds rate_limit[] = {
	{ "egress", CLI_CMD, 0, 0, do_rate_limit_egr, no_do_rate_limit_egr, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Config port rate-limit egress", "出口" },
	{ "ingress", CLI_CMD, 0, 0, do_rate_limit_ing, no_do_rate_limit_ing, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Config port rate-limit ingress", "入口" },
	{ CMDS_END }
};

static struct cmds sw_block[] = {
	{ "broadcast", CLI_CMD, 0, 0, do_sw_block_broad, no_do_sw_block_broad, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Set broadcast block", "设置不转发广播报文" },
	{ "multicast", CLI_CMD, 0, 0, do_sw_block_mul, no_do_sw_block_mul, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Set multicast block", "设置不转发多播报文" },
	{ "unicast", CLI_CMD, 0, 0, do_sw_block_uni, no_do_sw_block_uni, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Set unkown unicast block", "设置不转发未知单播报文" },
	{ CMDS_END }
};

static struct cmds sw_mode[] = {
	{ "access", CLI_CMD, 0, 0, do_sw_mode_acc, do_sw_mode_acc, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Access mode", "访问模式" },
#ifdef CLI_PRIVATE_VLAN
	{ "private-vlan", CLI_CMD, 0, 0, do_sw_mode_pri_vlan, NULL, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Private-vlan mode", "私有vlan模式" },
#endif
	{ "trunk", CLI_CMD, 0, 0, do_sw_mode_tru, do_sw_mode_acc, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Trunk mode", "中继模式" },
	{ CMDS_END }
};

static struct cmds sw_mode_pri_vlan[] = {
	{ "host", CLI_CMD, 0, 0, do_sw_mode_pri_vlan_host, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set host port", "配置主机端口" },
	{ "promiscuous", CLI_CMD, 0, 0, do_sw_mode_pri_vlan_pro, NULL, NULL, CLI_END_NONE, 0, 0,
		"Set promiscuous port", "配置混合端口" },
	{ CMDS_END }
};

static struct cmds sw_mode_pri_vlan_pro[] = {
	{ "add", CLI_CMD, 0, 0, do_sw_mode_pri_vlan_pro_add, NULL, NULL, CLI_END_NONE, 0, 0,
		"Add VLANs to the current list", "对当前的列表添加vlan ID" },
	{ CMDS_END }
};

static struct cmds sw_portsec[] = {
	{ "dynamic", CLI_CMD, 0, 0, do_sw_portsec_dy, no_do_sw_portsec_dy, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Security port dynamic config", "安全端口动态配置" },
	{ "mode", CLI_CMD, 0, 0, do_sw_portsec_mo, no_do_sw_portsec_mo, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Security port mode", "安全端口模式" },
	{ CMDS_END }
};

static struct cmds sw_portsec_dy[] = {
	{ "maximum", CLI_CMD, 0, 0, do_sw_portsec_dy_max, NULL, NULL, CLI_END_NONE, 0, 0,
		"Protect mode", "Protect模式" },
	{ CMDS_END }
};

static struct cmds sw_portsec_mo[] = {
	{ "dynamic", CLI_CMD, 0, 0, do_sw_portsec_mo_dy, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Security port dynamic mode", "安全端口动态模式" },
	{ "static", CLI_CMD, 0, 0, do_sw_portsec_mo_sta, NULL, NULL, CLI_END_NONE, 0, 0,
		"Security port static mode", "安全端口静态模式" },
	{ CMDS_END }
};

static struct cmds sw_portsec_mo_sta[] = {
	{ "accept", CLI_CMD, 0, 0, do_sw_portsec_mo_sta_acc, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Accept mode", "接收模式" },
	{ CMDS_END }
};

static struct cmds trunk[] = {
	{ "vlan-allowed", CLI_CMD, 0, 0, do_trunk_vlan_allo, no_do_trunk_vlan_allo, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Set allowed VLANs when port is in trunking mode", "设置端口的是中继端口时端口的 VLAN 范围" },
	{ "vlan-untagged", CLI_CMD, 0, 0, do_tru_vlan_untagged, no_do_tru_vlan_untagged, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Set untagged VLANs when port is in trunking mode", "设置端口的是中继端口时端口发送报文为不带 Tag 的 VLAN 范围" },
	{ CMDS_END }
};


static struct cmds tru_vlan_allo[] = {
	{ "WORD", CLI_WORD, 0, 0, do_trunk_vlan_allo_word, NULL, NULL, CLI_END_FLAG, 0, 0,
		"VLAN IDs such as (1,3,5,7) Or (1,3-5,7) Or (1-7)", "类似(1,3,5,7) 或 (1,3-5,7) 或 (1-7)表示的VLAN 范围表" },
	{ CMDS_END }
};


static struct cmds tru_vlan_untagged[] = {
	{ "WORD", CLI_WORD, 0, 0, do_tru_vlan_untag_word, NULL, NULL, CLI_END_FLAG, 0, 0,
		"VLAN IDs such as (1,3,5,7) Or (1,3-5,7) Or (1-7)", "类似(1,3,5,7) 或 (1,3-5,7) 或 (1-7)表示的VLAN 范围表" },
	{ CMDS_END }
};
static struct cmds do_inter_port_dhcp_filter[] = {
	{ "packet-filter", CLI_CMD, 0, 0, do_inter_port_dhcp_filter_t, no_inter_port_dhcp_filter_t, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"filter dhcp packet by port", "端口下过滤 DHCP 包" },
	{ CMDS_END }
};
static struct cmds no_inter_port_dhcp_filter[] = {
	{ "packet-filter", CLI_CMD, 0, 0, NULL, no_inter_port_dhcp_filter_t, NULL,CLI_END_NO, 0, 0,
		"filter dhcp packet by port", "端口下过滤 DHCP 包" },
	{ CMDS_END }
};

/* garp */

static struct cmds inter_port_ip_pim_cmds[] = {
	{ "bsr-border", CLI_CMD, 0, 0, do_inter_port_ip_pim_bsr, no_inter_port_ip_pim_bsr, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"bsr border", "边界" },
	{ "dr-priority", CLI_CMD, 0, 0, do_inter_port_ip_pim_dr, no_inter_port_ip_pim_dr, NULL, CLI_END_NO, 0, 0,
		"dr priority", "DR 优先级" },
	{ CMDS_END }
};

static struct cmds inter_port_ip_pim_dr_cmds[] = {
	{ "<1-65536>", CLI_INT, 0, 0, do_inter_port_ip_pim_dr_int, NULL, NULL, CLI_END_FLAG, 1, 65536,
		"dr priority", "DR 优先级" },
	{ CMDS_END }
};

static struct cmds inter_port_lldp_cmds[] = {
	{ "transmit", CLI_CMD, 0, 0, do_inter_port_lldp_transmit, no_inter_port_lldp_transmit, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"LLDP transmit", "LLDP 报文发送" },
	{ "receive", CLI_CMD, 0, 0, do_inter_port_lldp_receive, no_inter_port_lldp_receive, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"LLDP receive", "LLDP 报文接收" },
	{ CMDS_END }
};

static struct cmds inter_port_tunnel_cmds[] = {
	{ "stp", CLI_CMD, 0, 0, do_inter_port_tunnel_stp, no_inter_port_tunnel_stp, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"l2protocol tunnel stp", "二层隧道 STP 协议" },
	{ CMDS_END }
};


static struct cmds inter_port_mtu_cmds[] = {
	{ "jumbo", CLI_CMD, 0, 0, do_port_mtu_jumbo, no_port_mtu_jumbo, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"jumbo mtu val", "二层隧道 STP 协议" },
	{ CMDS_END }
};

static struct cmds inter_port_mtu_int_cmds[] = {
	{ "<1500-13000>", CLI_INT, 0, 0, do_port_mtu_jumbo_int, NULL, NULL, CLI_END_FLAG, 1500, 13000,
		"max transmit packet length", "最大报文传输长度" },
	{ CMDS_END }
};

static struct cmds ring_cmds[] = {
	{ "<1-65536>", CLI_INT, 0, 0, do_ring_id, NULL, NULL, CLI_END_FLAG, 1, 65536,
		"RING id", "环网编号" },
	{ CMDS_END }
};

static struct cmds vlan_mapping_new[] = {
	{ "mapping", CLI_CMD, 0, 0, do_mapping_new, no_mapping, NULL, CLI_END_NONE, 0, 0,
		"VLAN mapping module", "Vlan 映射模块" },
	{ CMDS_END }
};

static struct cmds vlan_mapping_value[] = {
	{"<1-4094>", CLI_INT, 0, 0, do_mapping_value, NULL, NULL, CLI_END_NONE,  1, 4094,
		"VLAN IDs(1-4094), such as 1000", "VLAN范围1-4094，如 1000"},
	{ CMDS_END }
};

static struct cmds vlan_mapping_translate_new[] = {
	{ "translated-vlan", CLI_CMD, 0, 0, do_mapping_translate_new, no_do_trunk_vlan_allo, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Specify translated VLAN", "指定转换后的vlan" },
	{ "to", CLI_CMD, 0, 0, do_mapping_to_new, no_do_trunk_vlan_allo, NULL, CLI_END_NONE|CLI_END_NO, 0, 0,
		"Range of VLAN IDs", "设置vlan的范围" },
	{ CMDS_END }
};

static struct cmds vlan_mapping_to_value[] = {
	{"<1-4094>", CLI_INT, 0, 0, do_mapping_to_value, NULL, NULL, CLI_END_NONE,  1, 4094,
		"VLAN IDs(1-4094), such as 1000", "VLAN范围1-4094，如 1000"},
	{ CMDS_END }
};

static struct cmds vlan_mapping_to_translate_new[] = {
	{ "translated-vlan", CLI_CMD, 0, 0, do_mapping_translate_new, no_do_trunk_vlan_allo, NULL, CLI_END_NONE,  1, 4094,
		"Specify translated VLAN", "指定转换后的vlan" },
	{ CMDS_END }
};

static struct cmds map_translate_value[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_mapping_translate_value, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"VLAN IDs(1-4094), such as 1000", "VLAN范围1-4094，如 1000" },
	{ CMDS_END }
};


/*
 *	Function:  do_interface_trunk
 *	Purpose:  interface aggregator-group topcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:  guiqin.li	
 *	Date:	  2011/11/7
 */
static int do_interface_trunk(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(interface_trunk_group_cmds, argc, argv, u);

	return retval;
}

/*
 *	Function:  no_interface_trunk
 *	Purpose:  no interface aggregator-group topcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:  guiqin.li	
 *	Date:	  2011/11/7
 */
static int no_interface_trunk(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_remove_trunk_interface(u);
	}

	return retval;
}

/*
 *	Function:  do_interface_trunk_group
 *	Purpose:  interface aggregator	group number subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:  guiqin.li	
 *	Date:	  2011/11/7
 */
static int do_interface_trunk_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(interface_trunk_mode_cmds, argc, argv, u);

	return retval;
}

/*
 *	Function:  do_interface_trunk_mode
 *	Purpose:  interface aggregator	group mode subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:  guiqin.li	
 *	Date:	  2011/11/7
 */
static int do_interface_trunk_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(interface_trunk_mode_sel_cmds, argc, argv, u);

	return retval;
}


/*
 *	Function:  do_interface_trunk_mode_lacp
 *	Purpose:  interface aggregator-group mode lacp subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:  guiqin.li	
 *	Date:	  2011/11/7
 */
static int do_interface_trunk_mode_lacp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_interface_trunk_mode_lacp(u);
	}

	return retval;
}

/*
 *	Function:  do_interface_trunk_mode_static
 *	Purpose:  interface aggregator-group mode static subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:  guiqin.li	
 *	Date:	  2011/11/7
 */
static int do_interface_trunk_mode_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_interface_trunk_mode_static(u);
	}

	return retval;
}


/*
 *	Function:  do_interface_arp
 *	Purpose:   interface_arp topcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:  yunchangxuan
 *	Date:	  2011/11/7
 */
static int do_interface_arp(int argc, char *argv[], struct users *u)
{

	int retval = -1;

	retval = sub_cmdparse(interface_arp_cmds, argc, argv, u);

	return retval;

}

/*
 *	Function:  do_arp_inspection
 *	Purpose:   arp_inspection subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_arp_inspection(int argc, char *argv[], struct users *u)
{

	int retval = -1;

	retval = sub_cmdparse(arp_inspection_cmds, argc, argv, u);

	return retval;

}

/*
 *	Function:  do_inspection_trust
 *	Purpose:   inspection_trust subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_inspection_trust(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_if_arp_inspection(u);
	}

	return retval;
}

/*
 *	Function:  no_inspection_trust
 *	Purpose:   no inspection_trust subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int no_inspection_trust(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_if_arp_inspection(u);
	}

	return retval;
}

/*
 *	Function:  do_inter_cos
 *	Purpose:  interface cos parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/7
 */
static int do_inter_cos(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(inter_cos_cmds, argc, argv, u);

	return retval;
}

/*
 *	Function:  do_inter_cos_default
 *	Purpose:  interface cos default subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/7
 */
static int do_inter_cos_default(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<0-7>";
	param.ylabel = "Default CoS value";
	param.hlabel = "缺省cos 值";
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
		func_cos_default(u);
	}

	return retval;
}

/*
 *	Function:  no_inter_cos_default
 *	Purpose:  no interface cos default subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/7
 */
static int no_inter_cos_default(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application function */
		nfunc_inter_cos_default(u);
	}

	return retval;
}


static int no_do_inter_port_description(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_inter_port_description(u);
	}
	return retval;
}

static int no_do_inter_port_trunk_description(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_inter_port_trunk_description(u);
	}
	return retval;
}

/*
 *  Function: interface_description 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  
 *     argv 
 *      u 
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */
static int do_inter_port_description(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_description, argc, argv, u);
	
	return retval;
}

/*
 *  Function: interface_description 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  
 *     argv 
 *      u 
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/12/28
 */
static int do_inter_port_trunk_description(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_trunk_description, argc, argv, u);
	
	return retval;
}

static int do_inter_port_description_line(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_inter_port_description_line(u);       
	}
	
	return retval;
}

static int do_inter_port_trunk_description_line(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_inter_port_trunk_description_line(u);       
	}
	
	return retval;
}

/*
 *  Function: interface_dhcp
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  
 *     argv 
 *     u 
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */
static int do_inter_port_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(do_inter_port_dhcp_filter, argc, argv, u);
	
	return retval;
}

static int no_inter_port_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(no_inter_port_dhcp_filter, argc, argv, u);
	
	return retval;
}


/*
 *  Function: interface_flow_control
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  
 *     argv 
 *     u   
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */
static int do_inter_port_flo_control(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_flo_control, argc, argv, u);
	
	return retval;
}

static int do_inter_port_flo_control_on(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_flo_con_on(u);
	}	
	
	return retval;
}

static int do_inter_port_flo_control_off(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_flo_con_off(u);
	}	
	
	return retval;
}


/*
 *  Function: interface_mac
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *       u  
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */
static int do_inter_port_mac(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_mac, argc, argv, u);
	
	return retval;
}

static int do_inter_port_mac_acc_grp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "access-list name";
	param.hlabel = "访问列表名";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_mac_acc_grp(u);
	}

	return retval;

}

static int no_do_inter_port_mac_acc_grp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Access-list name";
	param.hlabel = "访问列表名";
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_mac_acc_grp(u);
	}

	return retval;

}

static int do_mac_learn_limit(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "Value";
	param.ylabel = "Port mac limit learn max value";
	param.hlabel = "端口MAC学习的最大数值";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_mac_learn_limit_set(u);
	}

	return retval;
}

static int no_mac_learn_limit(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_mac_learn_limit_del(u);
	}

	return retval;
}



/*
 *	Function:  do_inter_qos
 *	Purpose:  interface qos parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/7
 */
static int do_inter_qos(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(inter_qos_cmds, argc, argv, u);

	return retval;
}

/*
 *	Function:  do_inter_qos_policy
 *	Purpose:  interface qos policy subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/7
 */
static int do_inter_qos_policy(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "policy-map name";
	param.hlabel = "QOS 策略名称";
	param.flag = CLI_END_NONE;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	if((retval = cli_param_set(DYNAMIC_PARAM, &param, u)) != 0)
		return retval;
#if 0
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application function */
		do_test_param(argc, argv, u);
	}
#endif
	retval = sub_cmdparse(inter_qos_policy_cmds, argc, argv, u);

	return retval;
}

/*
 *	Function:  do_inter_qos_policy_ingress
 *	Purpose:  interface qos policy ingress subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/7
 */
static int do_inter_qos_policy_ingress(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application function */
		func_inter_qos_policy_ingress(u);
	}

	return retval;
}
static int do_inter_port_dhcp_filter_t(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application function */
		func_inter_port_dhcp_filter(u);
	}

	return retval;
}

//static int do_dhcp_rate(int argc, char *argv[], struct users *u)
//{
//	int retval = -1;

	/* Check command end or not */
//	if((retval = cmdend2(argc, argv, u)) == 0)
	//{
		/* Do application function */
//		do_dhcp_rate_num(argc, argv, u);
//	}

//	return retval;
//}


static int no_inter_port_dhcp_filter_t(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application function */
		nfunc_inter_port_dhcp_filter(u);
	}

	return retval;
}

/*
 *	Function:  no_inter_qos_policy
 *	Purpose:  no interface qos policy subcmd parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/7
 */
static int no_inter_qos_policy(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "policy-map name";
	param.hlabel = "QOS 策略名称";
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
		nfunc_inter_qos_policy(u);
	}

	return retval;
}


/*
 *  Function: interface_shutdown
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */
static int do_shutdown(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_inter_shutdown(u);
	}
	
	return retval;
}

static int no_do_shutdown(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_inter_shutdown(u);
	}
	
	return retval;
}
/*
 *  Function: interface_storm_control
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */

static int do_inter_port_storm_control(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_storm_control, argc, argv, u);
	
	return retval;
}

static int do_inter_port_storm_contr_broad(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(inter_port_storm_contr_broad, argc, argv, u);
	
	return retval;
}

static int do_inter_port_storm_contr_mul(int argc, char *argv[], struct users *u)
{
	int retval = -1;
  
 
	retval = sub_cmdparse(inter_port_storm_contr_mul, argc, argv, u);
	
	return retval;
}

static int do_inter_port_storm_contr_unicast(int argc, char *argv[], struct users *u)
{
	int retval = -1;
 
	retval = sub_cmdparse(inter_port_storm_contr_uni, argc, argv, u);
	
	return retval;
}

static int do_inter_port_storm_contr_broad_thresd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-1000>";
	param.min  = 1;
	param.max  = 1000;
	param.ylabel = "input packet storm control(units: pps)";
	param.hlabel = "输入报文风暴控制(单位: pps)";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
//		  do_test_param(argc, argv, u);
		func_storm_contr_broad(u);
	}

	return retval;

}

static int do_inter_port_storm_contr_mul_thresd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-1000>";
	param.min  = 1;
	param.max  = 1000;
	param.ylabel = "input packet storm control(units: pps)";
	param.hlabel = "输入报文风暴控制(单位: pps)";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
//		  do_test_param(argc, argv, u);
		func_storm_contr_mul(u);
	}

	return retval;

}

static int do_inter_port_storm_contr_uni_thresd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-1000>";
	param.min  = 1;
	param.max  = 1000;
	param.ylabel = "input packet storm control(units: pps)";
	param.hlabel = "输入报文风暴控制(单位: pps)";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_storm_contr_uni(u);
	}

	return retval;

}

static int no_do_inter_port_storm_contr_broad_thresd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_storm_contr_broad(u);
	}
	
	return retval;
}

static int no_do_inter_port_storm_contr_mul_thresd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_storm_contr_mul(u);
	}
	
	return retval;
}

static int no_do_inter_port_storm_contr_uni_thresd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_storm_contr_uni(u);
	}
	
	return retval;
}

/*
 *  Function: interface_ip
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */

static int do_inter_port_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip, argc, argv, u);
	
	return retval;
}

static int no_inter_port_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6, argc, argv, u);
	
	return retval;
}
static int do_inter_port_ip_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_dhcp, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_router(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_router, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_router_isis, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_router_isis_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_ip_router_isis(u);
	}
	
	return retval;
}

static int no_inter_port_ip_router(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_router, argc, argv, u);
	
	return retval;
}

static int no_inter_port_ip_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_ip_router_isis(u);
	}
	
	return retval;
}

/*
 *  Function: do_inter_port_ip_igmp
 *  Purpose:  ip igmp subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */

static int do_inter_port_ip_igmp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_igmp_join(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_join_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_igmp_join_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_port_ip_igmp_join_group(u);
	} else
		retval = sub_cmdparse(inter_port_ip_igmp_join_group_cmds, argc, argv, u);

	return retval;
}

static int do_inter_port_ip_igmp_join_group_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_join_group_in_cmds, argc, argv, u);

	return retval;
}

static int do_inter_port_ip_igmp_join_group_ex(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_join_group_ex_cmds, argc, argv, u);

	return retval;
}

static int do_inter_port_ip_igmp_join_group_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_port_ip_igmp_join_group_in(u);
	}

	return retval;
}

static int do_inter_port_ip_igmp_join_group_ex_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_port_ip_igmp_join_group_ex(u);
	}

	return retval;
}

static int do_inter_port_ip_igmp_querier(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_querier_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_igmp_querier_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_port_ip_igmp_querier_time(u);
	}

	return retval;
}

static int do_inter_port_ip_igmp_last_query(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_last_query_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_igmp_last_query_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_port_ip_igmp_last_query_time(u);
	}

	return retval;
}

static int do_inter_port_ip_igmp_query(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_query_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_igmp_query_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_port_ip_igmp_query_time(u);
	}

	return retval;
}

static int do_inter_port_ip_igmp_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_static_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_igmp_static_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_port_ip_igmp_static_all(u);
	} else
		retval = sub_cmdparse(inter_port_ip_igmp_static_all_cmds, argc, argv, u);

	return retval;
}

static int do_inter_port_ip_igmp_static_all_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_static_all_in_cmds, argc, argv, u);

	return retval;
}

static int do_inter_port_ip_igmp_static_all_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_port_ip_igmp_static_all_in(u);
	}

	return retval;
}

static int do_inter_port_ip_igmp_static_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_port_ip_igmp_static_group(u);
	} else
		retval = sub_cmdparse(inter_port_ip_igmp_static_group_cmds, argc, argv, u);

	return retval;
}

static int do_inter_port_ip_igmp_static_group_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_static_group_in_cmds, argc, argv, u);

	return retval;
}

static int do_inter_port_ip_igmp_static_group_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_port_ip_igmp_static_group_in(u);
	}

	return retval;
}

static int do_inter_port_ip_igmp_version(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_version_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_igmp_version_1(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_port_ip_igmp_version_1(u);
	}

	return retval;
}

static int do_inter_port_ip_igmp_version_2(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_port_ip_igmp_version_2(u);
	}

	return retval;
}

static int do_inter_port_ip_igmp_version_3(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_port_ip_igmp_version_3(u);
	}

	return retval;
}

/*
 *  Function: no_inter_port_ip_igmp
 *  Purpose:  ip igmp subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */

static int no_inter_port_ip_igmp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_cmds, argc, argv, u);
	
	return retval;
}

static int no_inter_port_ip_igmp_join(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_join_cmds, argc, argv, u);
	
	return retval;
}

static int no_inter_port_ip_igmp_join_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_port_ip_igmp_join_group(u);
	} else
		retval = sub_cmdparse(inter_port_ip_igmp_join_group_cmds, argc, argv, u);

	return retval;
}

static int no_inter_port_ip_igmp_join_group_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_join_group_in_cmds, argc, argv, u);

	return retval;
}

static int no_inter_port_ip_igmp_join_group_ex(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_join_group_ex_cmds, argc, argv, u);

	return retval;
}

static int no_inter_port_ip_igmp_join_group_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_port_ip_igmp_join_group_in(u);
	}

	return retval;
}

static int no_inter_port_ip_igmp_join_group_ex_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_port_ip_igmp_join_group_ex(u);
	}

	return retval;
}

static int no_inter_port_ip_igmp_querier(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_port_ip_igmp_querier_time(u);
	}

	return retval;
}

static int no_inter_port_ip_igmp_last_query(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_port_ip_igmp_last_query_time(u);
	}

	return retval;
}

static int no_inter_port_ip_igmp_query(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_port_ip_igmp_query_time(u);
	}

	return retval;
}

static int no_inter_port_ip_igmp_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_static_cmds, argc, argv, u);
	
	return retval;
}

static int no_inter_port_ip_igmp_static_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_port_ip_igmp_static_all(u);
	} else
		retval = sub_cmdparse(inter_port_ip_igmp_static_all_cmds, argc, argv, u);

	return retval;
}

static int no_inter_port_ip_igmp_static_all_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_static_all_in_cmds, argc, argv, u);

	return retval;
}

static int no_inter_port_ip_igmp_static_all_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_port_ip_igmp_static_all_in(u);
	}

	return retval;
}

static int no_inter_port_ip_igmp_static_group(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_port_ip_igmp_static_group(u);
	} else
		retval = sub_cmdparse(inter_port_ip_igmp_static_group_cmds, argc, argv, u);

	return retval;
}

static int no_inter_port_ip_igmp_static_group_in(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_igmp_static_group_in_cmds, argc, argv, u);

	return retval;
}

static int no_inter_port_ip_igmp_static_group_in_src(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_port_ip_igmp_static_group_in(u);
	}

	return retval;
}

static int no_inter_port_ip_igmp_version(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_port_ip_igmp_version(u);
	}

	return retval;
}

/*
 *  Function: do_inter_port_ip_pim
 *  Purpose:  ip pim-sm subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */
static int do_inter_port_ip_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		func_port_ip_pim(u);
	} else
		retval = sub_cmdparse(inter_port_ip_pim_cmds, argc, argv, u);


	return retval;
}

static int do_inter_port_ip_pim_bsr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_port_ip_pim_bsr(u);
	}
	
	return retval;
}

static int do_inter_port_ip_pim_dr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_pim_dr_cmds, argc, argv, u);

	return retval;
}

static int do_inter_port_ip_pim_dr_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_port_ip_pim_dr(u);
	}
	
	return retval;
}

/*
 *  Function: no_inter_port_ip_pim
 *  Purpose:  ip pim-sm subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */
static int no_inter_port_ip_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_port_ip_pim(u);
	}
	
	return retval;
}

static int do_inter_port_ipv6_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_dhcp, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_dhcp_sno(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_dhcp_sno, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_dhcp_sno(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_dhcp_sno, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_dhcp_sno_trus(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_ip_dhcp_sno_trus(u);
	}
	
	return retval;
}

/*
 *  Function: no_inter_port_ip_pim_bsr
 *  Purpose:  ip pim-sm subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */
static int no_inter_port_ip_pim_bsr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_port_ip_pim_bsr(u);
	}
	
	return retval;
}

static int no_inter_port_ip_pim_dr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_port_ip_pim_dr(u);
	}
	
	return retval;
}

/*
 *  Function: do_inter_port_ipv6_dhcp_sno_trus
 *  Purpose:  ipv6 dhcp subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/18
 */
static int do_inter_port_ipv6_dhcp_sno_trus(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_ipv6_dhcp_sno_trus(u);
	}
	
	return retval;
}

static int no_do_inter_port_ipv6_dhcp_sno_trus(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_ipv6_dhcp_sno_trus(u);
	}
	
	return retval;
}

static int do_inter_port_ip_acc_grp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "IP access-list name";
	param.hlabel = "访问列表名";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_acc_grp(u);
	}
	return retval;

}

static int do_inter_port_ipv6_acc_grp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "IP access-list name";
	param.hlabel = "访问列表名";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ipv6_acc_grp(u);
	}
	return retval;

}

static int no_do_inter_port_ipv6_acc_grp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "IP access-list name";
	param.hlabel = "访问列表名";
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ipv6_acc_grp(u);
	}
	return retval;

}

static int do_inter_port_ip_arp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_arp, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_arp_inspect(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_arp_inspect, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_arp_inspect_limit(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ip_arp_inspect_limit, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ip_arp_inspect_limit_rate(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<64-64000>";
	param.min  = 64;
	param.max  = 64000;
	param.ylabel = "Enter KPS number of storm suppression level";
	param.hlabel = "进入KPS 风暴抑制水平的数量";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_arp_inspect_limit_rate(u);
	}

	return retval;
}

static int do_inter_port_ip_arp_inspect_trust(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_ip_arp_inspect_trust(u);
	}
	
	return retval;
}

static int no_do_inter_port_ip_acc_grp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "IPACL name";
	param.hlabel = "IPACL 名";
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ip_acc_grp(u);
	}
	return retval;

}

static int no_do_inter_port_ip_arp_inspect_trust(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_ip_arp_inspect_trust(u);
	}
	
	return retval;
}

static int no_do_inter_port_ip_arp_inspect_limit(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_ip_arp_inspect_limit(u);
	}
	
	return retval;
}

static int no_do_inter_port_ip_dhcp_sno_trus(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_ip_dhcp_sno_trus(u);
	}
	return retval;
}



/*
 *	Function:  do_interface_dot1x
 *	Purpose:   do_interface_dot1x parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_interface_dot1x(int argc, char *argv[], struct users *u)
{

	int retval = -1;

	retval = sub_cmdparse(interface_dot1x_cmds, argc, argv, u);

	return retval;

}


/*
 *	Function:  no_interface_dot1x
 *	Purpose:   do_interface_dot1x parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   peng.liu
 *	Date:	 2011/12/13
 */
static int no_interface_dot1x(int argc, char *argv[], struct users *u)
{

	int retval = -1;

	SET_CMD_MSKBIT(u, NO_FORBID);
	SET_CMD_MSKBIT(u, NO_AUTHENTICATION);
	SET_CMD_MSKBIT(u, NO_PORT_CONTROL);

	retval = sub_cmdparse(interface_dot1x_cmds, argc, argv, u);

	return retval;

}


/*
 *	Function:  do_dot1x_forbid
 *	Purpose:   do_dot1x_forbid parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_dot1x_forbid(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
//		do_test_param(argc, argv, u);
		vty_output("The command doesn't support in this version !\n");
		return retval;
	}
	retval = sub_cmdparse(forbid_cmds, argc, argv, u);

	return retval;
}

/*
 *	Function:  do_forbid_multinetworkadapter
 *	Purpose:   do_forbid_multinetworkadapter parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_forbid_multinetworkadapter(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		vty_output("The command doesn't support in this version !\n");

	}

	return retval;
}

/*
 *	Function:  do_dot1x_authentication
 *	Purpose:   do_dot1x_authentication parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_dot1x_authentication(int argc, char *argv[], struct users *u)
{

	int retval = -1;

	retval = sub_cmdparse(authentication_cmds, argc, argv, u);

	return retval;

}

/*
 *	Function:  do_authentication_type
 *	Purpose:   do_authentication_type parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_authentication_type(int argc, char *argv[], struct users *u)
{

	int retval = -1;

	retval = sub_cmdparse(type_cmds, argc, argv, u);

	return retval;

}

/*
 *	Function:  do_type_chap
 *	Purpose:   do_type_chap parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_type_chap(int argc, char *argv[], struct users *u)
{

	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		vty_output("The command doesn't support in this version !\n");

	}

	return retval;

}

/*
 *	Function:  do_type_eap
 *	Purpose:   do_type_eap parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_type_eap(int argc, char *argv[], struct users *u)
{

	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		vty_output("The command doesn't support in this version !\n");

	}

	return retval;

}

/*
 *	Function:  do_authentication_method
 *	Purpose:   do_authentication_method parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_authentication_method(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "AAA authentication method name";
	param.hlabel = "AAA 认证方法";
	param.min = 0;
	param.max = 0;
	param.flag = 1;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(STATIC_PARAM, &param, u);
	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		vty_output("The command doesn't support in this version !\n");
	}

	return retval;
}

/*
 *	Function:  do_dot1x_portcontrol
 *	Purpose:   do_dot1x_portcontrol parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_dot1x_portcontrol(int argc, char *argv[], struct users *u)
{

	int retval = -1;

	retval = sub_cmdparse(port_control_cmds, argc, argv, u);

	return retval;

}

/*
 *	Function:  do_portcontrol_auto
 *	Purpose:   do_portcontrol_auto parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_portcontrol_auto(int argc, char *argv[], struct users *u)
{

	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */	
			func_set_dot1x_port_control("2",u);
		

	}

	return retval;

}

/*
 *	Function:  do_portcontrol_forceauthorized
 *	Purpose:   do_portcontrol_forceauthorized parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_portcontrol_forceauthorized(int argc, char *argv[], struct users *u)
{

	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		
			func_set_dot1x_port_control("1",u);

	}

	return retval;

}

/*
 *	Function:  do_portcontrol_forceunauthorized
 *	Purpose:   do_portcontrol_forceunauthorized parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_portcontrol_forceunauthorized(int argc, char *argv[], struct users *u)
{

	int retval = -1;
	
	retval = cmdend2(argc, argv, u);
	
	if(retval == 0) 
	{
		/* Do application function */
			func_set_dot1x_port_control("3",u);
		
	}

	return retval;

}

/*
 *	Function:  do_dot1x_maxuser
 *	Purpose:   do_dot1x_maxuser parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int do_dot1x_maxuser(int argc, char *argv[], struct users *u)
{
	int max_user,retval = -1;
	char str[20] = {0};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-4096>";
	param.ylabel = "The max number";
	param.min = 0;
	param.max = 0;
	param.flag = 1;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);
	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		cli_param_get_int(DYNAMIC_PARAM, 0, &max_user, u);
		sprintf(str,"%d",max_user);
		func_set_dot1x_max_user(str,u);
	}

	return retval;
}

/*
 *	Function:  no_dot1x_maxuser
 *	Purpose:   no_dot1x_maxuser parse function
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   yunchang.xuan
 *	Date:	 2011/11/7
 */
static int no_dot1x_maxuser(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		nfunc_set_max_user(u);

	}

	return retval;
}


/*
 *  Function: interface_rmon
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:     2011/11/18
 */

static int do_inter_port_rmon(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_rmon, argc, argv, u);
	
	return retval;
}

static int do_inter_port_rmon_collet(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_rmon_collet, argc, argv, u);
	
	return retval;
}

static int do_inter_port_rmon_collet_histy(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-65535>";
	param.min  = 1;
	param.max  = 65535;
	param.ylabel = "Set RMON history control index";
	param.flag = CLI_END_NONE;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_collet_histy(u);
	}

	retval = sub_cmdparse(inter_port_rmon_collet_histy, argc, argv, u);

	return retval;
}

static int do_inter_port_rmon_collet_histy_intev_bucket(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-65535>";
	param.min  = 1;
	param.max  = 65535;
	param.ylabel = "Interval in seconds to sample data for each bucket";
	param.flag = CLI_END_NONE;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_collet_histy(u);
	}

	retval = sub_cmdparse(inter_port_rmon_collet_histy_intev_bucket, argc, argv, u);

	return retval;
}

static int do_inter_port_rmon_collet_histy_intev_bucket_own(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Set the owner of this RMON collection";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_collet_histy(u);
	}

	return retval;

}

static int do_inter_port_rmon_collet_histy_bucket_intev(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-3600>";
	param.min  = 1;
	param.max  = 3600;
	param.ylabel = "Interval in seconds to sample data for each bucket";
	param.flag = CLI_END_NONE;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	  func_rmon_collet_histy(u);
	}

	retval = sub_cmdparse(inter_port_rmon_collet_histy_bucket_intev, argc, argv, u);

	return retval;
}

static int do_inter_port_rmon_collet_histy_bucket_own(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Set the owner of this RMON collection";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_collet_histy(u);
	}

	return retval;

}

static int do_inter_port_rmon_collet_histy_bucket_intev_own(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Set the owner of this RMON collection";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	  func_rmon_collet_histy(u);
	}

	return retval;

}

static int do_inter_port_rmon_collet_stats(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-65535>";
	param.min  = 1;
	param.max  = 65535;
	param.ylabel = "Set RMON statistics control index";
	param.flag = CLI_END_NONE;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	    func_rmon_collet_stats(u);
	}

	retval = sub_cmdparse(inter_port_rmon_collet_stats, argc, argv, u);

	return retval;
}

static int do_inter_port_rmon_collet_stats_own(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "RMON collection owner";
	param.flag = CLI_END_NONE;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_collet_stats(u);
	}

	retval = sub_cmdparse(inter_port_rmon_collet_stats_own, argc, argv, u);

	return retval;

}

static int do_inter_port_rmon_collet_stats_own_bucket(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-65535>";
	param.min  = 1;
	param.max  = 65535;
	param.ylabel = "Requested buckets of intervals";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_collet_histy(u);
	}

	return retval;
}

static int do_inter_port_rmon_collet_histy_intev(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-3600>";
	param.min  = 1;
	param.max  = 3600;
	param.ylabel = "Interval in seconds to sample data for each bucket";
	param.flag = CLI_END_NONE;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_collet_histy(u);
	}

	retval = sub_cmdparse(inter_port_rmon_collet_histy_intev, argc, argv, u);

	return retval;
}

static int do_inter_port_rmon_collet_histy_bucket(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-65535>";
	param.min  = 1;
	param.max  = 65535;
	param.ylabel = "Requested buckets of intervals";
	param.flag = CLI_END_NONE;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rmon_collet_histy(u);
	}

	retval = sub_cmdparse(inter_port_rmon_collet_histy_bucket, argc, argv, u);

	return retval;
}



/*
 *  Function: interface_speed 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv 
 *      u 
 *  Returns:
 *  Author:  jiajie.gu
 *  Date:     2011/11/9
 *  modify:  peng.liu
 *  Date:     2011/11/18 
 */
static int do_speed(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(speed, argc, argv, u);
	
	return retval;
}

static int do_speed_ten(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_speed_ten(u);
	}
	
	return retval;
}

static int do_speed_hundred(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_speed_hundred(u);
	}
	
	return retval;
}

static int do_speed_giga(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_speed_giga(u);
	}
	
	return retval;
}

static int do_speed_auto(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_speed_auto(u);
	}
	
	return retval;
}

static int no_do_speed(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_speed(u);
	}
	
	return retval;
}

/*
 *  Function: interface_duplex
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv 
 *      u 
 *  Returns:
 *  Author:  jiajie.gu
 *  Date:     2011/11/9
 *  modify:  peng.liu
 *  Date:     2011/11/18 
 */
static int do_duplex(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(duplex, argc, argv, u);
	
	return retval;
}

static int do_duplex_auto(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_duplex_auto(u);
	}
	
	return retval;
}

static int do_duplex_half(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_duplex_half(u);
	}
	
	return retval;
}

static int do_duplex_full(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_duplex_full(u);
	}
	return retval;
}

static int no_do_duplex(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_duplex(u);
	}
	
	return retval;
}

/*
 *  Function: interface_switchport
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv 
 *      u 
 *  Returns:
 *  Author:  jiajie.gu
 *  Date:     2011/11/9
 *  modify:  peng.liu
 *  Date:     2011/11/18 
 */

static int no_do_sw_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_sw_mode(u);
	}else
	    retval = sub_cmdparse(sw_mode, argc, argv, u);
	
	return retval;
}

static int no_do_sw_portsec_dy(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_sw_portsec_dy(u);
	}
	
	return retval;
}

static int no_do_sw_portsec_mo(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_sw_portsec_mo(u);
	}
	
	return retval;
}

/*
 *  Function: do_switchport 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/9
 */
static int do_switchport(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char *port_str = NULL;

	port_str = u->promptbuf;
	if (port_str[0] == 'p') {
		SET_CMD_MSKBIT(u, NO_BLOCK);
		SET_CMD_MSKBIT(u, NO_LOOPBACK);
		SET_CMD_MSKBIT(u, NO_PORTSEC);
		SET_CMD_MSKBIT(u, NO_PROTECTED);
		SET_CMD_MSKBIT(u, NO_RATELIMIT);
	}
		
	retval = sub_cmdparse(switchport, argc, argv, u);
	
	return retval;
}


/*
 *  Function: do_switchport 
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:     2011/11/9
 */
static int do_vlan_mapping(int argc, char *argv[], struct users *u)
{
	int retval = -1;

    retval = sub_cmdparse(vlan_mapping_new, argc, argv, u);
	
	return retval;
}



/*
 *  Function: do_sw_block
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_sw_block(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(sw_block, argc, argv, u);
	
	return retval;
}

static int do_sw_block_broad(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_sw_block(u);
	}
	
	return retval;
}

static int do_sw_block_mul(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_sw_block(u);
	}
	
	return retval;
}

static int do_sw_block_uni(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_sw_block(u);
	}
	
	return retval;
}

static int no_do_sw_block_broad(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_sw_block(u);
	}
	
	return retval;
}

static int no_do_sw_block_mul(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_sw_block(u);
	}
	
	return retval;
}

static int no_do_sw_block_uni(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_sw_block(u);
	}
	
	return retval;
}

static int do_sw_loop(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char *port_str = NULL;
	port_str = u->promptbuf;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_sw_loop(u, port_str);
	}
	
	return retval;
}

static int no_do_sw_loop(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_sw_loop(u);
	}
	
	return retval;
}
/*
 *  Function: do_sw_mode
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv 
 *      u
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_sw_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(sw_mode, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_sw_portsec
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv 
 *      u
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_sw_portsec(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(sw_portsec, argc, argv, u);
	
	return retval;
}

static int do_sw_pro(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_sw_pro(u);
	}
	
	return retval;
}

/*
 *  Function: do_sw_portsec_dy
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv 
 *      u
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_sw_portsec_dy(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(sw_portsec_dy, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_sw_portsec_mo_sta
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_sw_portsec_mo_sta(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(sw_portsec_mo_sta, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_sw_portsec_mo_sta_acc
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv 
 *      u 
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:    2011/11/18
 */
static int do_sw_portsec_mo_sta_acc(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(NULL, argc, argv, u);
	
	if(retval == 0)
	{
		func_sw_portsec_mo_sta_acc(u);
	}
	
	return retval;
}

/*
 *  Function: do_sw_portsec_mo
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_sw_portsec_mo(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(sw_portsec_mo, argc, argv, u);
	
	return retval;
}

/*
 *  Function: do_trunk
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_trunk(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(trunk, argc, argv, u);
	
	return retval;
}

/*
 *  Function: trunk_vlan
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_trunk_vlan_allo(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(tru_vlan_allo, argc, argv, u);
	
	return retval;
}

static int do_tru_vlan_untagged(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(tru_vlan_untagged, argc, argv, u);
	
	return retval;
}

static int do_tru_vlan_untag_word(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		func_tru_vlan_untag(u);
	}
	
	return retval;
}

static int do_trunk_vlan_allo_word(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		func_tru_vlan_allo(u);
	}
	
	return retval;
}


static int no_do_trunk_vlan_allo(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_tru_vlan_allo(u);
  	}
	return retval;
}

static int no_do_tru_vlan_untagged(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_tru_vlan_untag(u);
  	}
	
	return retval;
}

/*
 *  Function: do_sw_portsec_mo_dy
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv 
 *      u
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:    2011/11/18
 */

static int do_sw_portsec_mo_dy(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(NULL, argc, argv, u);
	
	if(retval == 0)
	{
		func_sw_portsec_mo_dy(u);
	}
	
	return retval;
}

/*
 *  Function: do_sw_portsec_dy_max
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv 
 *     u 
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_sw_portsec_dy_max(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_INT;
	param.name = "<1-8191>";
	param.ylabel = "Configure interface maximum address";
	param.hlabel = "配置安全端口最大地址数";
	param.min = 1;
	param.max = 8191;
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
	
	cli_param_set(DYNAMIC_PARAM, &param, u);	
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_sw_portsec_dy_max(u);
	}
	
	return retval;
}

/*
 *  Function: do_vlan
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc
 *     argv
 *      u  
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_INT;
	param.name = "<1-4094>";
	param.ylabel = "VLAN ID of the VLAN";
	param.hlabel = "VLAN 的 vlan 标识";
	param.min = 1;
	param.max = 4094;
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;
	
	cli_param_set(DYNAMIC_PARAM, &param, u);	
	
	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_inter_vlan(u);
	}
	
	return retval;
}

static int no_do_sw_pro(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_sw_pro(u);
	}
	
	return retval;
}

static int no_do_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_inter_vlan(u);
	}
	
	return retval;
}

static int do_sw_mode_acc(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		func_sw_mode_acc(u);
	}
	
	return retval;
}
static int do_sw_mode_tru(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_sw_mode_tru(u);
	}
	
	return retval;
}

static int do_sw_mode_pri_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(sw_mode_pri_vlan, argc, argv, u);
	
	return retval;
}

static int do_sw_mode_pri_vlan_host(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-4094>";
	param.min  = 1;
	param.max  = 4094;
	param.ylabel = "VLAN ID";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_sw_mode_pri_vlan(u);
	}

	return retval;
}

static int do_sw_mode_pri_vlan_pro(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(sw_mode_pri_vlan_pro, argc, argv, u);
	
	return retval;
}

static int do_sw_mode_pri_vlan_pro_add(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */

	param.type = CLI_INT;
	param.name = "<1-4094>";
	param.min  = 1;
	param.max  = 4094;
	param.ylabel = "VLAN ID";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_sw_mode_pri_vlan(u);
	}

	return retval;
}


/*
 *  Function: interface_rate_limit
 *  Purpose:  subcmd parse function
 *  Parameters:
 *     argc 
 *     argv 
 *      u
 *  Returns:
 *  
 *  Author:  peng.liu
 *  Date:    2011/11/18
 */

static int do_rate_limit(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char * intf = u->promptbuf;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	if('g' == *intf)
	    param.name = "<64-1000000>";
	else    
	    param.name = "<64-100000>";
	param.min  = 64;
	if('g' == *intf)
	    param.max  = 1000000;
	else    
	    param.max  = 100000;
	param.ylabel = "Limit the rate of port(Kbps)";
	param.hlabel = "配置带宽(步长: pps)";
	param.flag = CLI_END_NONE;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_rate_limit(u);
	}
	retval = sub_cmdparse(rate_limit, argc, argv, u);

	return retval;
}


static int do_rate_limit_egr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_rate_limit_egr(u);
	}
	
	return retval;
}

static int do_rate_limit_ing(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		func_rate_limit_ing(u);
	}
	
	return retval;
}

static int no_do_rate_limit_egr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_rate_limit_egr(u);
	}
	
	return retval;
}

static int no_do_rate_limit_ing(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_rate_limit_ing(u);
	}
	
	return retval;
}



/*
 *	Function:  do_stp_int
 *	Purpose:  topcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(stp_int_cmds, argc, argv, u);
	
	return retval;
}

/*
 *	Function:  do_stp_int_bpduf
 *	Purpose:  stp bpdufilter subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_bpduf(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(stp_int_bpduf_cmds, argc, argv, u);
	
	return retval;
}

/*
 *	Function:  no_do_stp_int_bpduf
 *	Purpose:  no stp bpdufilter subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int no_do_stp_int_bpduf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	   nfunc_stp_int_bpduf(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_bpdug
 *	Purpose:  stp bpduguard subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_bpdug(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(stp_int_bpdug_cmds, argc, argv, u);
	
	return retval;
}

/*
 *	Function:  no_do_stp_int_bpdug
 *	Purpose:  no stp bpduguard subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int no_do_stp_int_bpdug(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	   nfunc_stp_int_bpdug(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_guard
 *	Purpose:  stp guard subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_guard(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(stp_int_guard_cmds, argc, argv, u);
	
	return retval;
}

/*
 *	Function:  no_do_stp_int_guard
 *	Purpose:  no stp guard subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int no_do_stp_int_guard(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	   nfunc_stp_int_guard(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_link
 *	Purpose:  stp link-type subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_link(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(stp_int_link_cmds, argc, argv, u);
	
	return retval;
}

/*
 *	Function:  no_do_stp_int_link
 *	Purpose:  no stp link-type subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int no_do_stp_int_link(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	  nfunc_stp_int_link(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_bpduf_dis
 *	Purpose:  stp bpdufilter disable subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_bpduf_dis(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_stp_int_bpduf_dis(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_bpduf_en
 *	Purpose:  stp bpdufilter enable subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_bpduf_en(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_stp_int_bpduf_en(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_bpdug_dis
 *	Purpose:  stp bpduguard disable subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_bpdug_dis(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	   func_stp_int_bpdug_dis(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_bpdug_en
 *	Purpose:  stp bpduguard enable subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_bpdug_en(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_stp_int_bpdug_en(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_cost
 *	Purpose:  stp cost subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_cost(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<1-200000000>";
	param.ylabel = "port path cost";
	param.hlabel = "端口路径开销";
	param.min = 1;
	param.max = 200000000;
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
	   func_stp_int_cost(u);
	}

	return retval;
}

/*
 *	Function:  no_do_stp_int_cost
 *	Purpose:  no stp cost subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int no_do_stp_int_cost(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	  nfunc_stp_int_cost(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_guard_none
 *	Purpose:  stp guard none subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_guard_none(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_stp_int_guard_none(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_guard_root
 *	Purpose:  stp guard root subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_guard_root(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_stp_int_guard_root(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_link_point
 *	Purpose:  stp link-type point-to-point subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_link_point(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	   func_stp_int_link_point(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_link_shared
 *	Purpose:  stp link-type shared subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_link_shared(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	   func_stp_int_link_shared(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_portp
 *	Purpose:  stp port-priority subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_portp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_INT;
	param.name = "<0-255>";
	param.ylabel = "port priority";
	param.hlabel = "端口优先级";
	param.min = 0;
	param.max = 255;
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
	   func_stp_int_portp(u);
	}

	return retval;
}

/*
 *	Function:  no_do_stp_int_portp
 *	Purpose:  no stp port-priority subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int no_do_stp_int_portp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
	   nfunc_stp_int_portp(u);
	}
	return retval;
}

/*
 *	Function:  do_stp_int_portf
 *	Purpose:  stp portfast subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int do_stp_int_portf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_stp_int_portf(u);
	}
	return retval;
}

/*
 *	Function:  no_do_stp_int_portf
 *	Purpose:  no stp portfast subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   chunli.wu
 *	Date:	 2011/11/07
 */
static int no_do_stp_int_portf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_stp_int_portf(u);
	}
	return retval;
}

/*
 *	Function:  do_inter_port_gvrp
 *	Purpose:  interface port gvrp subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int do_inter_port_gvrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_gvrp(u);
	}
	return retval;
}

/*
 *	Function:  no_inter_port_gvrp
 *	Purpose:  no interface port gvrp subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int no_inter_port_gvrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_gvrp(u);
	}
	return retval;
}

/*
 *	Function:  do_inter_port_gmrp
 *	Purpose:  interface port gmrp subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int do_inter_port_gmrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_gmrp(u);
	}
	return retval;
}

/*
 *	Function:  no_inter_port_gmrp
 *	Purpose:  no interface port gmrp subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int no_inter_port_gmrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_gmrp(u);
	}
	return retval;
}

/*
 *	Function:  do_inter_port_ipv6_nd
 *	Purpose:  do interface port neighbor subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int do_inter_port_ipv6_nd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_nd_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_nd_cache(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_nd_cache_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_nd_cache_expire(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_nd_cache_expire_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_nd_cache_expire_sec(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_ipv6_nd_cache_expire(u);
	}
	return retval;
}

/*
 *	Function:  no_inter_port_ipv6_nd
 *	Purpose:  no interface port neighbor subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int no_inter_port_ipv6_nd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_nd_cmds, argc, argv, u);
	
	return retval;
}

static int no_inter_port_ipv6_nd_cache(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_nd_cache_cmds, argc, argv, u);
	
	return retval;
}

static int no_inter_port_ipv6_nd_cache_expire(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_ipv6_nd_cache_expire(u);
	}
	return retval;
}

/*
 *	Function:  do_inter_port_ipv6_router
 *	Purpose:  do interface port router subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int do_inter_port_ipv6_router(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_router_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_router_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_router_ospf_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_router_ospf_area(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_router_ospf_area_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_router_ospf_area_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_router_ospf_area_id_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_router_ospf_area_id_tag(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_router_ospf_area_id_tag_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_router_ospf_area_id_tag_tag(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_router_ospf_area_id_tag_tag_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_router_ospf_area_id_tag_tag_instance(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_router_ospf_area_id_tag_tag_instance_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_router_ospf_area_id_tag_tag_instance_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_ipv6_router_ospf_area(u);
	}
	return retval;
}

/*
 *	Function:  no_inter_port_ipv6_router
 *	Purpose:  no interface port router subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int no_inter_port_ipv6_router(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_router_cmds, argc, argv, u);
	
	return retval;
}

static int no_inter_port_ipv6_router_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_router_ospf_cmds, argc, argv, u);
	
	return retval;
}

static int no_inter_port_ipv6_router_ospf_area(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_ipv6_router_ospf_area(u);
	}
	return retval;
}

/*
 *	Function:  do_inter_port_ipv6_router_rip
 *	Purpose:  do interface port router subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int do_inter_port_ipv6_router_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_ipv6_router_rip(u);
	}
	return retval;
}

/*
 *	Function:  no_inter_port_ipv6_router_rip
 *	Purpose:  no interface port router subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int no_inter_port_ipv6_router_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_ipv6_router_rip(u);
	}
	return retval;
}

/*
 *	Function:  do_inter_port_ipv6_router_isis
 *	Purpose:  do interface port router subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int do_inter_port_ipv6_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_ipv6_router_isis_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_ipv6_router_isis_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_ipv6_router_isis(u);
	}
	return retval;
}

/*
 *	Function:  no_inter_port_ipv6_router_isis
 *	Purpose:  no interface port router subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int no_inter_port_ipv6_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_ipv6_router_isis(u);
	}
	return retval;
}


/*
 *	Function:  do_inter_port_lldp
 *	Purpose:  interface port lldp subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int do_inter_port_lldp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_lldp_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_lldp_transmit(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_lldp_transmit(u);
	}
	return retval;
}

static int do_inter_port_lldp_receive(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_lldp_receive(u);
	}
	return retval;
}

/*
 *	Function:  no_inter_port_lldp
 *	Purpose:  interface port lldp subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int no_inter_port_lldp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_lldp_cmds, argc, argv, u);
	
	return retval;
}

static int no_inter_port_lldp_transmit(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_lldp_transmit(u);
	}
	return retval;
}

static int no_inter_port_lldp_receive(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_lldp_receive(u);
	}
	return retval;
}

/*
 *	Function:  do_inter_port_tunnel
 *	Purpose:  interface port tunnel subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int do_inter_port_tunnel(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_tunnel_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_tunnel_stp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_tunnel_stp(u);
	}
	return retval;
}

/*
 *	Function:  no_inter_port_tunnel
 *	Purpose:  interface port tunnel subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int no_inter_port_tunnel(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_tunnel_cmds, argc, argv, u);
	
	return retval;
}

static int no_inter_port_tunnel_stp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_tunnel_stp(u);
	}
	return retval;
}

/*
 *	Function:  do_port_mtu
 *	Purpose:  interface port tunnel subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int do_port_mtu(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_mtu_cmds, argc, argv, u);
	
	return retval;
}

static int do_port_mtu_jumbo(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_mtu_int_cmds, argc, argv, u);
	
	return retval;
}

static int do_port_mtu_jumbo_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_mtu(u);
	}
	return retval;
}

/*
 *	Function:  no_inter_port_tunnel
 *	Purpose:  interface port tunnel subcmd parse function in interface mode
 *	Parameters:
 *	   argc  -	Param count
 *	   argv  -	Param value
 *	Returns:
 *	
 *	Author:   xi.chen
 *	Date:	 2011/11/07
 */
static int no_port_mtu(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_mtu_cmds, argc, argv, u);
	
	return retval;
}

static int no_port_mtu_jumbo(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_mtu(u);
	}
	
	return retval;
}

/*
 *  Function: do_ring
 *  Purpose:  ring subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int do_ring(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ring_cmds, argc, argv, u);
	
	return retval;
}

static int do_ring_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_sw_ring(u);
	}
	return retval;
}

/*
 *  Function: no_ring
 *  Purpose:  ring subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  jiajie.gu
 *  Date:    2011/11/9
 */
static int no_ring(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_sw_ring(u);
	}
	return retval;
}


static int do_sw_qinq(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(switch_qinq, argc, argv, u);
	
	return retval;
}

static int no_do_sw_qinq(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(switch_qinq, argc, argv, u);
	
	return retval;
}


static int do_sw_mode_qinq(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(switch_qinq_mode_type, argc, argv, u);
	
	return retval;
}

static int no_do_sw_mode_qinq(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_sw_qinq_mode(u, 1);
	}
	return retval;
}


static int do_sw_mode_qinq_type(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_sw_qinq_mode(u, 1);
	}
	return retval;
}

static int do_sw_mode_flat_type(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_sw_qinq_mode(u, 3);
	}
	return retval;
}


static int do_sw_mode_qinquplink(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_sw_mode_qinq_uplink(u, 2);
	}
	
	return retval;
}

static int do_sw_trans_qinq(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(switch_qinq_translate, argc, argv, u);
	
	return retval;
}

static int no_do_sw_trans_qinq(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_sw_qinq_trans(u);
	}
	return retval;
}


static int do_switch_qinq_translate(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(switch_qinq_translate_new, argc, argv, u);
	
	return retval;
}

static int do_switch_qinq_translate_new(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_sw_qinq_trans(u);
	}
	return retval;
}

static int do_mapping_new(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(vlan_mapping_value, argc, argv, u);
	
	return retval;
}

static int do_mapping_to_new(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(vlan_mapping_to_value, argc, argv, u);
	
	return retval;
}


static int do_mapping_value(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		//func_tru_vlan_allo(u);
		;
	}
	
    retval = sub_cmdparse(vlan_mapping_translate_new, argc, argv, u);
	return retval;
}

static int do_mapping_to_value(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if ((retval = cmdend2(argc, argv, u)) == 0) {
		//func_tru_vlan_allo(u);
		;
	}
	
    retval = sub_cmdparse(vlan_mapping_to_translate_new, argc, argv, u);
	return retval;
}


static int do_mapping_translate_new(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(map_translate_value, argc, argv, u);
	
	return retval;
}

static int do_mapping_translate_value(int argc, char *argv[], struct users *u)
{
	int retval = 0;
		
		/* Do application function */
	if ((retval = cmdend2(argc, argv, u)) == 0) {
		;
		//func_mapping_trans(u);
	}
		func_mapping_trans(u);
	return retval;
}

static int no_mapping(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = nfunc_mapping_trans(u);
	
	return retval;
}


/*
 *  Function:  init_cli_port
 *  Purpose:  Register port_topcmds[]
 *  Parameters:
 *     void
 *  Returns:
 *     retval  -  The number of registered successfully
 *  Author:  jiajie.gu
 *  Date:     2011/11/8
 */
int init_cli_port(void)
{
	int retval = -1;

	retval = registerncmd(interface_port_topcmds, (sizeof(interface_port_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1,"init_cli_port retval = %d\n", retval);

	return retval;
}
