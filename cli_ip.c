/*
 * Copyright 2016 by Kuaipao Corporation
 *
 * All Rights Reserved
 *
 * File name  : cli_ip.c
 * Function   : ip command function
 * Auther     : limin.hua
 * Version    : 1.0
 * Date       : 2011/11/9
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

#include "cli_ip.h"
#include "cli_ip_func.h"
#include "cli_router.h"
#include "cli_router_func.h"

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


static struct topcmds ip_topcmds[] = {
	{ "ip", 0, CONFIG_TREE, do_ip, NULL, NULL,CLI_END_NONE, 0, 0,
		"IPv4 configuration commands", "ip配置命令" },
	{ "ipv6", 0, CONFIG_TREE, do_ipv6, NULL, NULL, CLI_END_NONE, 0, 0,
		"IPv6 configuration commands", "ipv6配置命令" },
	{ "cos", 0, CONFIG_TREE, do_cos, NULL, NULL, CLI_END_NONE, 0, 0,
		"Configure cos", "配置 cos" },
	{ "dscp", 0, CONFIG_TREE, do_dscp, NULL, NULL,CLI_END_NONE, 0, 0,
		"Differentiated Services Code Point", "配置DSCP" },
	{ "garp", 0, CONFIG_TREE, do_garp, no_garp, NULL,CLI_END_NONE, 0, 0,
		"GARP protocol", "配置 GARP" },
	{ "gmrp", 0, CONFIG_TREE, do_gmrp, no_gmrp, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"GMRP protocol", "配置 GMRP" },
	{ "bfd", 0, CONFIG_TREE, do_bfd, no_bfd, NULL, CLI_END_NONE, 0, 0,
		"BFD protocol", "配置 BFD" },
	{ TOPCMDS_END }
};

static struct cmds ip_cmds[] = {
	{ "access-list", CLI_CMD, 0, 0, do_ip_acl, NULL, NULL,CLI_END_NONE, 0, 0,
		"Named access-list", "配置访问列表" },
	{ "address", CLI_CMD, 0, 0, do_ip_set, NULL, NULL,CLI_END_NONE, 0, 0,
		"Configure IP address", "配置IP地址" },
	//{ "arp", CLI_CMD, 0, 0, do_arp, NULL, NULL,CLI_END_NONE, 0, 0,
		//"IP ARP global configuration", "arp 参数设置" },
	{ "dhcp", CLI_CMD, 0, 0, do_dhcp, no_dhcp, NULL,CLI_END_NONE, 0, 0,
		"Configure DHCP server and relay parameters", "配置 DHCP 参数" },
	{ "http", CLI_CMD, 0, 0, do_http, NULL, NULL,CLI_END_NONE, 0, 0,
		"HTTP server configuration", "配置 http 参数" } ,
	{ "dns", CLI_CMD, 0, 0, do_dns, no_dns, NULL,CLI_END_NONE, 0, 0,
		"Configure DNS server and relay parameters", "配置 DNS 参数" },
	{ "igmp-snooping", CLI_CMD, 0, 0, do_igmp_snooping, no_igmp_snooping, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0 ,
		"Config igmp-snooping", "配置 igmp-snooping" } ,
//	{ "dhcpd", CLI_CMD, 0, 0, do_dhcpd, no_dhcpd, NULL,CLI_END_NONE|CLI_END_NO, 0, 0 ,
//		"Config dhcp server", "配置DHCP服务器" } ,
	{ "source", CLI_CMD, 0, 0, do_source, NULL, NULL,CLI_END_NONE, 0, 0 ,
		"IP source", "ip 源地址配置" } ,
	{ "forward-protocol", CLI_CMD, 0, 0, do_ip_forward, no_ip_forward, NULL, CLI_END_NONE, 0, 0 ,
		"IP forward protocol", "IP 转发协议" } ,
	{ "route", CLI_CMD, 0, 0, do_ip_route, no_ip_route, NULL, CLI_END_NONE, 0, 0 ,
		"Configure static routes", "安装静态路由" } ,
	{ "mroute", CLI_CMD, 0, 0, do_ip_mroute, no_ip_mroute, NULL, CLI_END_NONE, 0, 0 ,
		"Configure mroute", "安装组播路由" } ,
	{ "multicast-routing", CLI_CMD, 0, 0, do_ip_multi_routing, no_ip_multi_routing, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0 ,
		"Configure mroute", "安装组播路由" } ,	
	{ "igmp", CLI_CMD, 0, 0, do_ip_igmp, no_ip_igmp, NULL, CLI_END_NONE, 0, 0 ,
		"Configure igmp", "配置 IGMP" } ,	
	{ "pim-sm", CLI_CMD, 0, 0, do_ip_pim, no_ip_pim, NULL, CLI_END_NONE, 0, 0,
		"pim-sm", "pim-sm" },
//	{ "pim-dm", CLI_CMD, 0, 0, do_ip_pim_dm, no_ip_pim_dm, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
//		"pim-dm", "pim-dm" },
	{ CMDS_END  }
} ;


static struct cmds ip_acl_mode_cmds[] =
{
	{ "extended", CLI_CMD, 0, 0, do_ip_acl_mode,no_ip_acl_mode, NULL,CLI_END_NONE, 0, 0 ,
		"Extended Access List", "扩展访问列表" } ,
	{ "standard", CLI_CMD, 0, 0, do_ip_acl_mode_s,no_ip_acl_mode_s, NULL,CLI_END_NONE, 0, 0 ,
		"Standard Access List", "标准访问列表" } ,
	{ CMDS_END  }
} ;

static struct cmds ip_dhcpd_cmds[] =
{
	{ "enable", CLI_CMD, 0, 0, do_ip_dhcpd_start, NULL, NULL, CLI_END_FLAG, 0, 0 ,
		"Enable DHCP Servers", "开启DHCP服务器" } ,
	{ CMDS_END  }
};

static struct cmds no_dhcpd_cmds[] =
{
	{ "enable", CLI_CMD, 0, 0, NULL, no_ip_dhcpd_start, NULL, CLI_END_FLAG, 0, 0 ,
		"Disable DHCP Servers", "关闭DHCP服务器" } ,
	{ CMDS_END  }
};

static struct cmds ip_dhcp_cmds[] =
{
	//{ "realy", CLI_CMD, 0, 0, do_ip_dhcp_realy, NULL, NULL, CLI_END_FLAG, 0, 0 ,
	//	"DHCP Relay", "中继参数设置" } ,
	{ "snooping", CLI_CMD, 0, 0, do_ip_dhcp_snooping, NULL, NULL, CLI_END_FLAG, 0, 0 ,
		"DHCP Snooping", "配置 DHCP snooping参数" } ,
	{ "pool", CLI_CMD, 0, 0, do_ip_dhcp_pool, NULL, NULL, CLI_END_NONE, 0, 0 ,
		"DHCP pool", "配置 DHCP 地址池" } ,	
	{ CMDS_END  }
};

static struct cmds no_dhcp_cmds[] =
{
	{ "binding", CLI_CMD, 0, 0,NULL, no_ip_dhcp_bind, NULL, CLI_END_NO, 0, 0 ,
		"Clear DHCP Snooping binding table", "清除 DHCP Snooping 绑定表" } ,
	{ "snooping", CLI_CMD, 0, 0, NULL, no_ip_dhcp_snooping, NULL, CLI_END_NO|CLI_END_FLAG, 0, 0 ,
		"Configure DHCP Snooping parameters", "配置 DHCP snooping参数" } ,
	{ "pool", CLI_CMD, 0, 0, NULL, no_ip_dhcp_pool, NULL, CLI_END_NO, 0, 0 ,
		"DHCP pool", "配置 DHCP 地址池" } ,	
	{ CMDS_END  }
};

static struct cmds ip_dns_cmds[] =
{
	{ "server", CLI_CMD, 0, 0, do_name_server, no_name_server, NULL,CLI_END_NONE|CLI_END_NO, 0, 0 ,
		"Specify IP DNS server", "指定系统使用的域名服务器的 ip 地址" } ,
//	{ "dynamic-host", CLI_CMD, 0, 0, do_ip_dhcp_pool, NULL, NULL, CLI_END_NONE, 0, 0 ,
//		"DHCP pool", "配置 DHCP 地址池" } ,	
	{ "proxy", CLI_CMD, 0, 0, do_ip_dns_proxy, no_ip_dns_proxy, NULL, CLI_END_NO|CLI_END_FLAG, 0, 0 ,
		"DHCP pool", "配置 DHCP 地址池" } ,	
	{ CMDS_END  }
};

static struct cmds do_dhcpv6_cmds[] =
{
	{ "pool", CLI_CMD, 0, 0, do_ipv6_dhcp_pool, no_ipv6_dhcp_pool, NULL, CLI_END_NONE, 0, 0 ,
		"DHCP pool", "配置 DHCP 地址池" } ,	
	{ "Client", CLI_CMD, 0, 0, do_ipv6_dhcp_client, no_ipv6_dhcp_client, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0 ,
		"DHCP Client", "开启 DHCP 客户端" } , 

	{ CMDS_END  }
};

static struct cmds ip_arp_cmds[] =
{
	{ "inspection", CLI_CMD, 0, 0, do_ip_arp_mode,no_ip_arp_mode, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0 ,
		"ARP Inspection configuration", "配置 ARP Inspection" } ,
	{ CMDS_END  }
};

static struct cmds ip_forward_cmds[] =
{
	{ "udp", CLI_CMD, 0, 0, do_ip_forward_udp, no_ip_forward_udp, NULL, CLI_END_NONE, 0, 0 ,
		"forward udp protocol", "转发 UDP 协议" } ,
	{ CMDS_END  }
};

static struct cmds ip_forward_udp_cmds[] =
{
	{ "bootps", CLI_CMD, 0, 0, do_ip_forward_udp_bootps, no_ip_forward_udp_bootps, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0 ,
		"forward dhcp protocol", "转发 DHCP 协议" } ,
	{ CMDS_END  }
};

static struct cmds ip_route_cmds[] =
{
	{ "default", CLI_CMD, 0, 0, do_ip_route_default, no_ip_route_default, NULL, CLI_END_NONE | CLI_END_NO, 0, 0 ,
		"default gateway IP address", "默认网关 IP 地址" } ,
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_route_ip, no_ip_route_ip, NULL, CLI_END_NONE, 0, 0,
		"gateway IP address", "网关 IP 地址" },
	{ CMDS_END  }
};

static struct cmds ip_route_default_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_route_default_ip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"default gateway IP address", "默认网关 IP 地址" },
	{ CMDS_END  }
};

static struct cmds ip_route_ip_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4_MASK, 0, 0, do_ip_route_ip_mask, no_ip_route_ip_mask, NULL, CLI_END_NONE, 0, 0,
		"IP netmask", "IP 网络掩码" },
	{ CMDS_END  }
};

static struct cmds ip_mask_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_and_mask, NULL, NULL, CLI_END_NONE, 0, 0,
		"IP address", "IP 地址" },
	{ CMDS_END  }
};

static struct cmds no_ip_route_ip_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4_MASK, 0, 0, do_ip_route_ip_mask, no_ip_route_ip_mask, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"IP netmask", "IP 网络掩码" },
	{ CMDS_END  }
};

static struct cmds ip_route_ip_mask_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_route_ip_mask_next, no_ip_route_ip_mask_next, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"next loop IP address", "下一跳 IP 地址" },
	{ CMDS_END  }
};

static struct cmds ip_mroute_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_mroute_ip, no_ip_mroute_ip, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"source IP address", "网关 IP 地址" },
	{ CMDS_END  }
};

static struct cmds ip_mroute_ip_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_mroute_ip_mask, no_ip_mroute_ip_mask, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"group IP address", "IP 网络掩码" },
	{ CMDS_END  }
};

//static struct cmds ip_mroute_ip_mask_cmds[] =
//{
//	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_mroute_ip_mask_rpf, NULL, NULL, CLI_END_NONE, 0, 0,
//		"default gateway IP address", "默认网关 IP 地址" },
//	{ CMDS_END  }
//};

static struct cmds ip_mroute_ip_mask_rpf_cmds[] =
{
	{ "interface", CLI_CMD, 0, 0, do_ip_mroute_ip_mask_rpf_int, NULL, NULL,CLI_END_NONE, 0, 0,
		"Binding interface", "绑定接口" },
	{ CMDS_END }
};

static struct cmds ip_mroute_interface[] =
{
	{ "vlan", CLI_CMD_UNUSAL, 0, IP_IF_FAST_PORT, do_ip_mroute_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"vlan interface", "虚拟VLAN接口" },
	{ CMDS_END }
};

/* interface vlan */
static struct cmds ip_mroute_interface_num_cmds[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_ip_mroute_interface_num, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"VLAN interface number", "VLAN 序号" },
	{ CMDS_END }
};

static struct cmds ip_mroute_interface_slash_cmds[] = {
	{ "/", CLI_CHAR_NO_BLANK, 0, 0, do_ip_mroute_interface_slash, NULL, NULL, CLI_END_NONE, 0, 0,
		"Slash", "斜杠" },
	{ CMDS_END }
};
static struct cmds ip_mroute_interface_port_cmds[] = {
	{ "<x-x>", CLI_INT, 0, 0, do_ip_mroute_interface_port, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Port number", "端口号" },
	{ CMDS_END }
};

static struct cmds ip_igmp_cmds[] =
{
	{ "querier-timeout", CLI_CMD, 0, 0, do_ip_igmp_querier, no_ip_igmp_querier, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"IGMP querier timeout", "配置 IGMP 请求超时" },
	{ CMDS_END  }
};

static struct cmds ip_igmp_querier_cmds[] =
{
	{ "<1-65535>", CLI_INT, 0, 0, do_ip_igmp_querier_time, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"IGMP querier timeout", "配置 IGMP 请求超时" },
	{ CMDS_END  }
};

static struct cmds ip_pim_cmds[] =
{
	{ "bsr-candidate", CLI_CMD, 0, 0, do_ip_pim_bsr, no_ip_pim_bsr, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"bsr-candidate", "配置 bsr-candidate" },
//	{ "dr-priority", CLI_CMD, 0, 0, do_ip_pim_dr, no_ip_pim_dr, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
//		"dr-priority", "配置 dr-priority" },
	{ "rp-address", CLI_CMD, 0, 0, do_ip_pim_rp, no_ip_pim_rp, NULL, CLI_END_NONE, 0, 0,
		"rp-address", "配置 rp-address" },
	{ "rp-candidate", CLI_CMD, 0, 0, do_ip_pim_can, no_ip_pim_can, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"rp-candidate", "配置 rp-candidate" },
	{ CMDS_END  }
};

static struct cmds ip_pimdm_cmds[] =
{
	{ "dr-priority", CLI_CMD, 0, 0, do_ip_pim_dr, no_ip_pim_dr, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"dr-priority", "配置 dr-priority" },
	{ CMDS_END  }
};

static struct cmds ip_pim_dr_cmds[] =
{
	{ "<1-65535>", CLI_INT, 0, 0, do_ip_pim_dr_priority, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"dr priority", "配置 dr 优先级" },
	{ CMDS_END  }
};

static struct cmds ip_pim_bsr_cmds[] =
{
	{ "priority", CLI_CMD, 0, 0, do_ip_pim_sm_priority, NULL, NULL, CLI_END_NONE, 1, 65535,
		"bsr-candidate priority", "配置 BSR 优先级" },
	{ CMDS_END  }
};

static struct cmds ip_pim_bsr_int_cmds[] =
{
	{ "<1-65535>", CLI_INT, 0, 0, do_ip_pim_bsr_pri, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"dr priority", "配置 dr 优先级" },
	{ CMDS_END  }
};


static struct cmds ip_pim_rp_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_pim_rp_add, no_ip_pim_rp_add, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Static rendez-vous point IP address", "静态RP地址" },
	{ CMDS_END  }
};

static struct cmds ip_pim_rp_add_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_pim_rp_add_netmask, NULL, NULL, CLI_END_NONE, 0, 0,
		"Multicast IP address", "多播IP 地址" },
	{ CMDS_END  }
};

static struct cmds ip_pim_rp_add_netmask_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4_MASK, 0, 0, do_ip_route_pimsm_mask, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP netmask", "IP 网络掩码" },
	{ CMDS_END  }
};

static struct cmds ip_pim_time_cmds[] =
{
	{ "time", CLI_CMD, 0, 0, do_pim_sm_cantime, NULL, NULL, CLI_END_NONE, 1, 65535,
		"rp-candidate time", "配置RP轮训时间" },
	{ CMDS_END  }
};

static struct cmds ip_pim_time_int_cmds[] =
{
	{ "<1-65535>", CLI_INT, 0, 0, do_pim_sm_cantime_int, NULL, NULL, CLI_END_NONE, 1, 65535,
		"rp-candidate time", "配置RP轮训时间" },
	{ CMDS_END  }
};

static struct cmds ip_pim_time_priority_cmds[] =
{
	{ "priority", CLI_CMD, 0, 0, do_pim_sm_priority, NULL, NULL, CLI_END_NONE, 1, 65535,
		"rp-candidate priority", "配置RP候选优先级" },
	{ CMDS_END  }
};

static struct cmds ip_pim_time_priority_int_cmds[] =
{
	{ "<1-65535>", CLI_INT, 0, 0, do_pim_sm_priority_int, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"rp-candidate priority", "配置RP候选优先级" },
	{ CMDS_END  }
};

static struct cmds do_ipv6_func[] =
{
	{ "access-list", CLI_CMD, 0, 0, do_ipv6_acl, NULL, NULL,CLI_END_NONE, 0, 0,
		"Named access-list", "配置访问列表" },
	{ "address", CLI_CMD, 0, 0, do_ipv6_set, no_ipv6_set, NULL,CLI_END_NONE|CLI_END_NO, 0, 0,
			"Configure IPv6 address", "配置IPv6地址" },

	//{ "dhcp", CLI_CMD, 0, 0, do_dhcpv6, no_dhcpv6, NULL, CLI_END_NONE, 0, 0,
	//	"Configure DHCPv6 parameters", "配置 dhcpv6 参数" },
	//{ "name-server", CLI_CMD, 0, 0, do_ipv6_name_server, no_ipv6_name_server, NULL, CLI_END_NONE|CLI_END_NO, 0, 0 ,
	//	"Specify IP DNS server", "指定 IP DNS 服务" } ,
	//{ "nd", CLI_CMD, 0, 0, do_ipv6_nd, no_ipv6_nd, NULL, CLI_END_NONE, 0, 0,
	//	"Configure IPv6 ND", "配置 IPv6 ND" },
	{ "default-gateway", CLI_CMD, 0, 0, do_ipv6_default_gateway, no_ipv6_default_gateway, NULL, CLI_END_NONE|CLI_END_NO, 0, 0 ,
		"Specify default gateway (if not routing IP)", "指定路径， 如果没有得到TP" } ,
	//{ "route", CLI_CMD, 0, 0, do_ipv6_route, no_ipv6_route, NULL, CLI_END_NONE, 0, 0 ,
	//	"Configure static routes", "安装静态路由" } ,
//	{ "router", CLI_CMD, 0, 0, do_ipv6_router, no_ipv6_router, NULL, CLI_END_NONE, 0, 0 ,
//		"Enable an IPV6 routing process", "使能 IPv6 路由进程" } ,	
	//{ "mld", CLI_CMD, 0, 0, do_ipv6_mld, no_ipv6_mld, NULL, CLI_END_NONE, 0, 0 ,
	//	"Global MLD Snooping enable for Catalyst Vlan", "为vlan设定全球MLD包" } ,
	//{ "dhcp-server", CLI_CMD, 0, 0, do_ipv6_dhcp, NULL, NULL, CLI_END_NONE, 0, 0 ,
	//	"Configure DHCPv6 server", "设置DHCPV6 服务器" } ,
	//{ "unicast-routing", CLI_CMD, 0, 0, do_ipv6_unicast, no_ipv6_unicast, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0 ,
	//	"Enable unicast routing", "使能单播路由" } ,
	//{ "pim", CLI_CMD, 0, 0, do_ipv6_pim, no_ipv6_pim, NULL, CLI_END_NONE, 0, 0,
	//	"pim-sm", "pim-sm" },
	{ CMDS_END  }
};

static struct cmds ipv6_acl_mode_cmds[] =
{
	{ "standard", CLI_CMD, 0, 0, do_ipv6_acl_mode_s,no_ipv6_acl_mode_s, NULL,CLI_END_NONE, 0, 0 ,
		"Standard Access List", "标准访问列表" } ,
	{ CMDS_END  }
} ;

static struct cmds ipv6_address_cmds[] =
{
	{ "X:X:X:X::X/<0-128>", CLI_IPV6, 0, 0, do_ipv6_addr, NULL, NULL,CLI_END_FLAG, 0, 0 ,
		"config IPv6 global address", "配置IPV6全局地址" } ,
	{ CMDS_END  }
};


static struct cmds do_ipv6_server[] =
{
	{ "X:X:X:X::X/<0-128>", CLI_IPV6, 0, 0, do_ipv6_name, NULL, NULL,CLI_END_FLAG, 0, 0 ,
		"default IPv6 nameserver's global address", "默认IPV6全局地址" } ,
	{ CMDS_END  }
};

/* ipv6 nd sub command */
static struct cmds do_ipv6_nd_cmds[] = {
	{ "cache", CLI_CMD, 0, 0, do_ipv6_nd_cache, no_ipv6_nd_cache, NULL, CLI_END_NONE, 0, 0,
		"Cache entry", "缓存队列" },
	{ CMDS_END }
};

static struct cmds do_ipv6_nd_cache_cmds[] = {
	{ "expire", CLI_CMD, 0, 0, do_ipv6_nd_cache_expire, no_ipv6_nd_cache_expire, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Expiry time for ND entries", "ND 队列时间" },
	{ CMDS_END }
};

static struct cmds do_ipv6_nd_cache_expire_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_ipv6_nd_cache_expire_time, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"Expiry time (seconds)", "时间（秒）" },
	{ CMDS_END }
};

/* ipv6 router sub command */
static struct cmds do_ipv6_router_cmds[] = {
	{ "ospf", CLI_CMD, 0, 0, do_ipv6_router_ospf, no_ipv6_router_ospf, NULL, CLI_END_NONE, 0, 0,
		"Open Shortest Path First (OSPF)", "OSPF 协议" },
	{ "rip", CLI_CMD, 0, 0, do_ipv6_router_rip, no_ipv6_router_rip, NULL, CLI_END_NONE, 0, 0,
		"IPv6 Routing Information Protocol (RIPv6)", "RIPv6 协议" },
	{ "bgp", CLI_CMD, 0, 0, do_router_bgp, no_router_bgp, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Border Gateway Protocol (BGP)", "BGP 协议" },
	{ "isis", CLI_CMD, 0, 0, do_router_isis, no_router_isis, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"ISO IS-IS", "ISO IS-IS" },
	{ CMDS_END }
};

static struct cmds do_ipv6_router_ospf_cmds[] = {
	{ "<1-65535>", CLI_INT, 0, 0, do_ipv6_router_ospf_pid, no_ipv6_router_ospf_pid, NULL, CLI_END_FLAG | CLI_END_NO, 1, 65535,
		"Process ID", "进程号" },
	{ CMDS_END }
};

static struct cmds do_ipv6_router_rip_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_ipv6_router_rip_str, no_ipv6_router_rip_str, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"User selected string identifying this process", "用户选择进程描述" },
	{ CMDS_END }
};

/*prefix can be configured network segment,so CLI_WORD*/
static struct cmds do_ipv6_route_cmds[] =
{
	{ "X:X:X:X::X/<0-128>", CLI_WORD, 0, 0, do_ipv6_route_ipv6, NULL, NULL,CLI_END_NONE, 0, 0 ,
		"IPv6 prefix", "IPv6前缀" } ,
	{ CMDS_END  }
};

static struct cmds do_ipv6_route_ipv6_cmds[] =
{
	{ "X:X:X:X::X", CLI_IPV6_NOMASK, 0, 0, do_ipv6_route_ipv6_next, NULL, NULL,CLI_END_FLAG, 0, 0 ,
		"IPv6 address of next-hop", "IPv6下一跳" } ,
	{ CMDS_END  }
};

static struct cmds no_ipv6_route_cmds[] =
{
	{ "X:X:X:X::X/<0-128>", CLI_WORD, 0, 0, NULL, no_ipv6_route_ipv6, NULL,CLI_END_NO, 0, 0 ,
		"IPv6 prefix", "IPv6前缀" } ,
	{ "all", CLI_CMD, 0, 0, NULL, no_ipv6_route_all, NULL,CLI_END_NO, 0, 0 ,
		"all static routes", "所有静态路由" } ,
	{ CMDS_END  }
};

static struct cmds do_ipv6_mld_snooping_cmds[] =
{
	{ "snooping", CLI_CMD, 0, 0, do_ipv6_mld_snooping, no_ipv6_mld_snooping, NULL,CLI_END_FLAG|CLI_END_NO, 0, 0 ,
		"Global MLD Snooping enable for Catalyst Vlan", "为vlan设定全球MLD包" } ,
	{ CMDS_END  }
};

static struct cmds do_ipv6_dhcp_snooping_cmds[] =
{
	{ "snooping", CLI_CMD, 0, 0, do_ipv6_dhcp_snooping, no_ipv6_dhcp_snooping, NULL,CLI_END_FLAG|CLI_END_NO, 0, 0 ,
		"DHCPv6 snooping", "侦测DHCPv6" } ,
	{ CMDS_END  }
};

static struct cmds do_ipv6_default[] =
{
	{ "X:X:X:X::X", CLI_IPV6_NOMASK, 0, 0, do_ipv6_default_g, NULL, NULL,CLI_END_FLAG, 0, 0 ,
		"default IPv6 gateway's global address", "缺省IPV6全局地址" } ,
	{ CMDS_END  }
};
static struct cmds do_cos_map[] =
{
	{ "map", CLI_CMD, 0, 0, do_cos_map_n, no_cos_num_n, NULL,CLI_END_NONE|CLI_END_NO, 0, 0 ,
		"Config the cos priority queue", "设置cos 优先级队列" } ,
	{ CMDS_END  }
};
static struct cmds do_cos_map_num[] =
{
	{ "<1-8>", CLI_INT, 0, 0, do_cos_num, NULL, NULL,CLI_END_NONE, 1, 8 ,
		"queue number", "队列号" } ,
	{ CMDS_END  }
};
static struct cmds do_cos_num1[] =
{
	{ "<0-7>", CLI_INT, 0, 0, do_cos_num_n, NULL, NULL,CLI_END_FLAG, 0, 7 ,
		"priority cos value", "优先级cos值" } ,
	{ CMDS_END  }
};
static struct cmds no_cos_map[] =
{
	{ "map", CLI_CMD, 0, 0, no_cos_num_n, NULL, NULL,CLI_END_NO, 0, 0 ,
		"Config the cos priority queue", "优先级队列号" } ,
	{ CMDS_END  }
};
#if 0
static struct cmds ip_dhcp_snooping_vlan[] =
{
	{ "vlan", CLI_CMD, 0, 0, do_ip_dhcp_snooping_vlan, NULL, NULL,CLI_END_NONE, 0, 0 ,
		"DHCP Snooping vlan", "配置DHCP SNOOPING VLAN接口" } ,
	{ CMDS_END  }
};
#endif
static struct cmds ip_arp_mode_cmds[] =
{
	{ "vlan", CLI_CMD, 0, 0, do_ip_arp_ins, NULL, NULL,CLI_END_NONE, 0, 0 ,
		"Enable/Disable ARP Inspection on vlans", "开启/关闭 ARP Inspection" } ,
	{ CMDS_END  }
};
static struct cmds ip_http_server[] =
{
	{ "server", CLI_CMD, 0, 0, do_http_server, no_http_server, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0 ,
		"Enable http server", "开启 http server" } ,
	{ CMDS_END }
};
static struct cmds ip_igmp_snooping[] =
{
	{ "querier", CLI_CMD, 0, 0,do_igmp_snooping_querier,NULL, NULL, CLI_END_FLAG, 0, 0,
		"IGMP querier configuration", "配置 igmp 查询功能" },
	{ "timer", CLI_CMD, 0, 0,do_igmp_snooping_timer,NULL, NULL,CLI_END_NONE, 0, 0,
		"Config igmp-snooping timer", "配置 igmp-snooping 时间参数" },
	//{ "vlan", CLI_CMD, 0, 0,do_igmp_snooping_vlan,no_igmp_snooping_vlan, NULL,CLI_END_FLAG, 0, 0,
	//	"igmp_snooping vlan", "igmp 侦听的VLAN" },
	{ CMDS_END }
};
static struct cmds ip_no_igmp_snooping_timer[] =
{
	{ "querier", CLI_CMD, 0, 0,NULL,no_igmp_snooping_querier, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"IGMP querier configuration", "配置 igmp query 报文的特征" },
	{ "timer", CLI_CMD, 0, 0,NULL,no_igmp_snooping_timer, NULL,CLI_END_NONE, 0, 0,
		"Config igmp-snooping timer", "配置 igmp-snooping timer" },
	{ CMDS_END }
};
static struct cmds ip_igmp_snooping_timer[] =
{
	{ "querier", CLI_CMD, 0, 0,do_igmp_snooping_timer_querier,NULL, NULL,CLI_END_NONE, 0, 0,
		"Config igmp-snooping querier interval", "igmp-snooping querier 间隔信息" },
	{ "survival", CLI_CMD, 0, 0,do_igmp_snooping_timer_survival, NULL, NULL,CLI_END_NONE, 0, 0,
		"Config survival time of group members", "配置 igmp-snooping 时间 " },
	{ CMDS_END }
};
static struct cmds no_igmp_snoop_timer_qs[] =
{
	{ "querier", CLI_CMD, 0, 0,NULL,no_igmp_snooping_timer_querier_q, NULL,CLI_END_NO, 0, 0,
		"Config igmp-snooping querier interval", "igmp-snooping querier 间隔信息" },
	{ "survival", CLI_CMD, 0, 0,NULL,no_igmp_snooping_timer_s, NULL,CLI_END_NO, 0, 0,
		"Config survival time of group members", "配置残存时间信息 " },
	{ CMDS_END }
};

	static struct cmds source_bind[] =
{
	{ "binding", CLI_CMD, 0, 0,do_ip_source_bind, no_ip_source_bind, NULL,CLI_END_NONE, 0, 0,
		"Static IP binding", "绑定静态 ip " },
	{ CMDS_END }
};
static struct cmds do_source_bind[] =
{
	{ "HH:HH:HH:HH:HH:HH", CLI_MAC, 0, 0,do_source_bind_mac,no_source_mac, NULL,CLI_END_NONE|CLI_END_NO, 0, 0,
		"48 bit mac address", "48位 mac 地址" },
	{ CMDS_END }
};


static struct cmds do_source_mac_ip[] =
{
	{ "mac", CLI_CMD, 0, 0,do_ip_source_bind, NULL, NULL,CLI_END_NONE, 0, 0,
		"mac address in binding table", "绑定 mac 地址表" },
	{ "ip", CLI_CMD, 0, 0,no_ip_source_vlan, NULL, NULL,CLI_END_NONE, 0, 0,
		"IP address in binding table", "绑定 ip 地址表" },
	{ CMDS_END }
};
static struct cmds source_vlan_num[] =
{
	{ "<1-4094>", CLI_INT, 0, 0,do_source_vlan_ip, NULL, NULL,CLI_END_NONE, 1, 4094,
		"Binding VLAN number", "绑定 vlan 号" },
	{ CMDS_END }
};
static struct cmds do_source_mac_vlan[] =
{
	{ "vlan", CLI_CMD, 0, 0,do_ip_source_vlan,NULL, NULL,CLI_END_NONE, 0, 0,
		"Binding vlan", "绑定 vlan " },
	{ CMDS_END }
};
static struct cmds source_vlan_ip[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0,do_source_bind_vlan, no_source_bind_vlan, NULL,CLI_END_NONE|CLI_END_NO, 0, 0,
		"Binding IP address", "绑定 ip 号" },
	{ CMDS_END }
};
static struct cmds do_source_vlan_num[] =
{
	{ "interface", CLI_CMD, 0, 0,do_source_bind_vlan_ip, NULL, NULL,CLI_END_NONE, 0, 0,
		"Binding interface", "绑定接口" },
	{ CMDS_END }
};

static struct cmds source_vlan_interface[] =
{
#if (XPORT==0)
	{ "FastEthernet", CLI_CMD_UNUSAL, 0, IP_IF_FAST_PORT, do_source_vlan_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"FastEthernet interface", "快速以太网接口" },
#endif
	{ "GigaEthernet", CLI_CMD_UNUSAL, 0, IP_IF_GIGA_PORT, do_source_vlan_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"GigaEthernet interface", "千兆以太网端口" },
#if (XPORT==1)
	{ "TenGigaEthernet", CLI_CMD_UNUSAL, 0, IP_IF_XE_PORT, do_source_vlan_interface_ethernet, NULL, NULL, CLI_END_NONE, 0, 0,
		"TenGigaEthernet interface", "万兆以太网端口" },
#endif
	{ CMDS_END }
};

/* interface fast port */
static struct cmds source_vlan_interface_num_cmds[] = {
	{ "<0-0>", CLI_CHAR_NO_BLANK, 0, 0, do_source_vlan_interface_num, NULL, NULL, CLI_END_NONE, 0x30, 0x30,
		"Interface number", "槽号" },
	{ CMDS_END }
};
static struct cmds source_vlan_interface_slash_cmds[] = {
	{ "/", CLI_CHAR_NO_BLANK, 0, 0, do_source_vlan_interface_slash, NULL, NULL, CLI_END_NONE, 0, 0,
		"Slash", "斜杠" },
	{ CMDS_END }
};
static struct cmds source_vlan_interface_port_cmds[] = {
	{ "<x-x>", CLI_INT, 0, 0, do_source_vlan_interface_port, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Port number", "端口号" },
	{ CMDS_END }
};
static struct cmds do_dscp_n[] =
{
	/*{ "enable", CLI_CMD, 0, 0,do_dscp_enable, NULL, NULL,CLI_END_FLAG, 0, 0,
		"enable dscp", "开启dscp" },*/
	{ "map", CLI_CMD, 0, 0,do_dscp_map, no_dscp_map_n, NULL,CLI_END_NO, 0, 0,
		"Config the dscp priority", "设置dscp优先级" },
	{ CMDS_END }
};
static struct cmds do_dscp_map_n[] =
{
	{ "<1-8>", CLI_INT, 0, 0, do_dscp_id, NULL, NULL,CLI_END_NONE, 1, 8,
		"enter the queue id", "进入的队列号" } ,
	{ CMDS_END  }
};
static struct cmds do_dscp_range[] =
{
	{ "<0-63>", CLI_INT_MULTI, 0, 0, do_dscp_value, NULL, NULL,CLI_END_FLAG, 0, 63,
		"differenttiated services codepoint value range.format like<p,m-n> ", "输入范围" } ,
	{ CMDS_END  }
};

#if 0
static struct cmds no_ip_dhcp_snooping_vlan[] =
{
	{ "vlan", CLI_CMD, 0, 0, NULL, no_ip_dhcp_snooping_vlan_num, NULL,CLI_END_NO, 0, 0,
		"delete num of the vlan", "删除vlan号" } ,
	{ CMDS_END  }
};
#endif

static struct cmds garp_cmds[] =
{
	{ "timer", CLI_CMD, 0, 0, do_garp_timer, no_garp_timer, NULL, CLI_END_NONE, 0, 0,
		"Config GARP timer", "设置 GARP 定时器" },
	{ CMDS_END }
};

static struct cmds garp_timer_cmds[] =
{
	{ "hold", CLI_CMD, 0, 0, do_inter_port_garp_timer_hold, no_inter_port_garp_timer_hold, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"garp hold timer", "GVRP hold 定时器" },
	{ "join", CLI_CMD, 0, 0, do_inter_port_garp_timer_join, no_inter_port_garp_timer_join, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"garp join timer", "GVRP join 定时器" },
	{ "leave", CLI_CMD, 0, 0, do_inter_port_garp_timer_leave, no_inter_port_garp_timer_leave, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"garp leave timer", "GVRP leave 定时器" },
	{ "leaveall", CLI_CMD, 0, 0, do_garp_timer_leaveall, no_garp_timer_leaveall, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Config GARP timer leaveall", "设置 GARP leaveall 定时器" },
	{ CMDS_END }
};


static struct cmds inter_port_garp_timer_hold_cmds[] = {
	{ "<1-3276>", CLI_INT, 0, 0, do_inter_port_garp_timer_hold_value, NULL, NULL, CLI_END_FLAG, 1, 3276,
		"garp hold timer", "GVRP hold 定时器" },
	{ CMDS_END }
};

static struct cmds inter_port_garp_timer_join_cmds[] = {
	{ "<1-3276>", CLI_INT, 0, 0, do_inter_port_garp_timer_join_value, NULL, NULL, CLI_END_FLAG, 1, 3276,
		"garp join timer", "GVRP join 定时器" },
	{ CMDS_END }
};

static struct cmds inter_port_garp_timer_leave_cmds[] = {
	{ "<1-3276>", CLI_INT, 0, 0, do_inter_port_garp_timer_leave_value, NULL, NULL, CLI_END_FLAG, 1, 3276,
		"garp leave timer", "GVRP leave 定时器" },
	{ CMDS_END }
};

static struct cmds garp_timer_leaveall_cmds[] =
{
	{ "<10-32765>", CLI_INT, 0, 0, do_garp_timer_leaveall_value, NULL, NULL, CLI_END_FLAG, 10, 32765,
		"Config GARP timer leaveall", "设置 GARP leaveall 定时器" },
	{ CMDS_END }
};

static struct cmds ipv6_pim_cmds[] =
{
	{ "bsr-candidate", CLI_CMD, 0, 0, do_ipv6_pim_bsr, no_ipv6_pim_bsr, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"bsr-candidate", "配置 bsr-candidate" },
	{ "rp-address", CLI_CMD, 0, 0, do_ipv6_pim_rp, no_ipv6_pim_rp, NULL, CLI_END_NONE, 0, 0,
		"rp-address", "配置 rp-address" },
	{ "rp-candidate", CLI_CMD, 0, 0, do_ipv6_pim_can, no_ipv6_pim_can, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"rp-candidate", "配置 rp-candidate" },
	{ CMDS_END  }
};

static struct cmds ipv6_pim_dr_cmds[] =
{
	{ "<1-65535>", CLI_INT, 0, 0, do_ipv6_pim_dr_priority, NULL, NULL, CLI_END_FLAG, 1, 65535,
		"dr priority", "配置 dr 优先级" },
	{ CMDS_END  }
};

static struct cmds ipv6_pim_rp_cmds[] =
{
	{ "rp-add", CLI_CMD, 0, 0, do_ipv6_pim_rp_add, no_ipv6_pim_rp_add, NULL, CLI_END_NONE, 0, 0,
		"rp-add", "配置添加" },
	{ CMDS_END  }
};

static struct cmds ipv6_pim_rp_add_cmds[] =
{
	{ "override", CLI_CMD, 0, 0, do_ipv6_pim_rp_add_over, no_ipv6_pim_rp_add_over, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"override", "覆盖" },
	{ "acl-name", CLI_CMD, 0, 0, do_ipv6_pim_rp_add_acl, no_ipv6_pim_rp_add_acl, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"acl-name", "ACL 名称" },
	{ CMDS_END  }
};

static struct cmds bfd_cmds[] =
{
	{ "enable", CLI_CMD, 0, 0, do_bfd_enable, no_bfd_enable, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"Config BFD enable", "设置 BFD 使能" },
//	{ "all-interface", CLI_CMD, 0, 0, do_bfd_all, no_bfd_all, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
//		"Config all BFD enable", "设置所有端口 BFD 使能" },
	{ CMDS_END }
};

/*
 *  Function:  do_ip
 *  Purpose:  entry ip command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/7
 */
static int do_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_cmds, argc, argv, u);
	return retval;
}
/*
 *  Function:  do_ipv6
 *  Purpose:  entry ip command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/7
 */
static int do_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_ipv6_func, argc, argv, u);
	return retval;
}

static int do_ipv6_acl(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ipv6_acl_mode_cmds, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_ipv6_acl_mode_s
 *  Purpose:   do_ipv6_acl_mode_s command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:     2012/2/27
 */
static int do_ipv6_acl_mode_s(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_WORD;
	param.name = " WORD";
	param.ylabel = "Standard Access-list name";
	param.hlabel = "标准列表名";
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(func_ipv6_acl_std_name(u) < 0)
			return -1;

		if((retval = change_con_level(IPV6_ACL_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			cli_param_get_string(DYNAMIC_PARAM, 0, buff, u);
			sprintf(u->promptbuf, "std_");
			strcat(u->promptbuf, buff);

			DEBUG_MSG(1, "u->promptbuf=%s\n", u->promptbuf);
		}
	}

	return retval;
}

/*
 *  Function:  no_ipv6_acl_mode_s
 *  Purpose:   no_ipv6_acl_mode_s command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:     2012/2/27
 */
static int no_ipv6_acl_mode_s(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_WORD;
	param.name = " WORD";
	param.ylabel = "Standard Access-list name";
	param.hlabel = "标准列表名";
	param.flag = CLI_END_NO;


	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Negative Application */
		nfunc_ipv6_acl_std_name(u);
	}
	return retval;
}

static int do_ipv6_name_server(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_ipv6_server, argc, argv, u);
	return retval;
}

static int no_ipv6_name_server(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)

	{
		nfunc_ipv6_name_server();
	}

	return retval;
}
static int do_ipv6_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2( argc, argv, u)) == 0)

	{
		func_ipv6_name(u);
	}

	return retval;
}
static int do_ipv6_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2( argc, argv, u)) == 0)
	{
		func_ipv6_addr(u);
	}

	return retval;
}

static int no_ipv6_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_ipv6_addr(u);
	}

	return retval;
}


/*
 *  Function:  do_ipv6_nd
 *  Purpose:  ipv6 nd subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_ipv6_nd(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(do_ipv6_nd_cmds, argc, argv, u);
	
	return retval;
}

static int do_ipv6_nd_cache(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(do_ipv6_nd_cache_cmds, argc, argv, u);
	
	return retval;
}

static int do_ipv6_nd_cache_expire(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(do_ipv6_nd_cache_expire_cmds, argc, argv, u);
	
	return retval;
}

static int do_ipv6_nd_cache_expire_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)

	{
		func_ipv6_nd(u);
	}

	return retval;
}

/*
 *  Function:  no_ipv6_nd
 *  Purpose:  no ipv6 nd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_ipv6_nd(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(do_ipv6_nd_cmds, argc, argv, u);
	
	return retval;
}

static int no_ipv6_nd_cache(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(do_ipv6_nd_cache_cmds, argc, argv, u);
	
	return retval;
}

static int no_ipv6_nd_cache_expire(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ipv6_nd(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_router
 *  Purpose:  ipv6 router subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_ipv6_router(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(do_ipv6_router_cmds, argc, argv, u);
	
	return retval;
}

static int do_ipv6_router_ospf(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(do_ipv6_router_ospf_cmds, argc, argv, u);
	
	return retval;
}

static int do_ipv6_router_rip(int argc, char *argv[], struct users *u)
{			
	int retval = -1;
	
	retval = sub_cmdparse(do_ipv6_router_rip_cmds, argc, argv, u);
	
	return retval;
}

static int do_ipv6_router_ospf_pid(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)

	{
		func_ipv6_router_ospf(u);
	}

	return retval;
}

static int do_ipv6_router_rip_str(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)

	{
		func_ipv6_router_rip(u);
	}

	return retval;
}

static int do_ipv6_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)

	{
		func_ipv6_router_isis(u);
	}

	return retval;
}

/*
 *  Function:  no_ipv6_router
 *  Purpose:  no ipv6 router parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_ipv6_router(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(do_ipv6_router_cmds, argc, argv, u);
	
	return retval;
}

static int no_ipv6_router_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(do_ipv6_router_ospf_cmds, argc, argv, u);
	
	return retval;
}

static int no_ipv6_router_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(do_ipv6_router_rip_cmds, argc, argv, u);
	
	return retval;
}

static int no_ipv6_router_ospf_pid(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ipv6_router_ospf(u);
	}

	return retval;
}

static int no_ipv6_router_rip_str(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ipv6_router_rip(u);
	}

	return retval;
}


static int no_ipv6_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ipv6_router_isis(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_unicast
 *  Purpose:  ipv6 unicast subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int do_ipv6_unicast(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)

	{
		func_ipv6_unicast(u);
	}

	return retval;
}

/*
 *  Function:  no_ipv6_unicast
 *  Purpose:  no ipv6 unicast parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:  xi.chen
 *  Date:     2011/11/8
 */
static int no_ipv6_unicast(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_ipv6_unicast(u);
	}

	return retval;
}














static int do_ipv6_default_gateway(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_ipv6_default, argc, argv, u);
	return retval;
}
static int do_ipv6_default_g(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2( argc, argv, u)) == 0)
	{
		func_ipv6_default_g(u);
	}

	return retval;
}
static int no_ipv6_default_gateway(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)

	{
		nfunc_ipv6_default_gateway();
	}

	return retval;
}
/*
 *  Function:  do_dhcp
 *  Purpose:  entry dhcp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/7
 */
static int do_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_dhcp_cmds, argc, argv, u);
	return retval;
}


/*
 *  Function:  no_dhcp
 *  Purpose:  no dhcp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/7
 */
static int no_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(no_dhcp_cmds, argc, argv, u);
	return retval;
}

static int do_dns(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_dns_cmds, argc, argv, u);
	return retval;
}


/*
 *  Function:  no_dhcp
 *  Purpose:  no dhcp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/7
 */
static int no_dns(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_dns_cmds, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_dhcpv6
 *  Purpose:  entry dhcpv6 command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_dhcpv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_dhcpv6_cmds, argc, argv, u);
	return retval;
}


/*
 *  Function:  no_dhcpv6
 *  Purpose:  no dhcpv6 command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/7
 */
static int no_dhcpv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_dhcpv6_cmds, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_arp
 *  Purpose:  entry arp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/7
 */
static int do_arp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_arp_cmds, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_http
 *  Purpose:  entry http command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/7
 */
static int do_http(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_http_server, argc, argv, u);
	return retval;
}
/*
 *  Function:  do_igmp_snooping
 *  Purpose:  entry igmp_snooping or do igmp snooping
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_igmp_snooping(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
 	{
		func_set_igmp_snooping_enable();
	}
	retval = sub_cmdparse(ip_igmp_snooping, argc, argv, u);
	return retval;
}
/*
 *  Function:  no_igmp_snooping
 *  Purpose:   no igmp_snooping or entry no igmp snooping command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */

static int no_igmp_snooping(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
 	{
		nfunc_igmp_snooping();
	}
	retval = sub_cmdparse(ip_no_igmp_snooping_timer, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_igmp_snooping_timer
 *  Purpose:   entry  igmp snooping timer command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_igmp_snooping_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_igmp_snooping_timer, argc, argv, u);
	return retval;
}

static int do_igmp_snooping_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_INT;
	param.name = "1-4094";
	param.ylabel = "VLAN num";
	param.hlabel = "VLAN 号";
	param.flag = CLI_END_FLAG;
	param.min = 1;
	param.max = 4094;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Negative Application */
		func_igmp_snooping_vlan(u);
	}

	return retval;

}

static int no_igmp_snooping_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_igmp_snooping_vlan();
	}

	return retval;

}

/*
 *  Function:  no_igmp_snooping_timer
 *  Purpose:   entry  no igmp snooping timer command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_igmp_snooping_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(no_igmp_snoop_timer_qs, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_source
 *  Purpose:   entry  do source command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_source(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(source_bind, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_ip_source_bind
 *  Purpose:   entry  do source bind command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_ip_source_bind(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_source_bind, argc, argv, u);
	return retval;
}

/*
 *  Function:  no_ip_source_bind
 *  Purpose:   entry no source bind command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_ip_source_bind(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_source_mac_ip, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_source_bind_mac
 *  Purpose:   entry source bind mac
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_source_bind_mac(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_source_mac_vlan, argc, argv, u);
	return retval;
}

/*
 *  Function:  no_source_mac
 *  Purpose:   no source bind mac
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_source_mac(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)

	{
		nfunc_mac_source_binding(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_source_vlan
 *  Purpose:   entry do_ip_source_vlan
 *  Parameters:
 *    void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_ip_source_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(source_vlan_num, argc, argv, u);
	return retval;
}

/*
 *  Function:  no_ip_source_vlan
 *  Purpose:   entry no_ip_source_vlan
 *  Parameters:
 *    void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_ip_source_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(source_vlan_ip, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_source_vlan_ip
 *  Purpose:   entry do_source_vlan_ip command
 *  Parameters:
 *    void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_source_vlan_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(source_vlan_ip, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_source_bind_vlan
 *  Purpose:   entry do_source_vlan command
 *  Parameters:
 *    void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_source_bind_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_source_vlan_num, argc, argv, u);
	return retval;
}
/*
 *  Function:  no_source_bind_vlan
 *  Purpose:   do no_source_vlan command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_source_bind_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)

	{
		nfunc_ip_source_binding(u);
	}

	return retval;
}

/*
 *  Function:  do_source_bind_vlan_ip
 *  Purpose:   entry do_source_bind_vlan_ip command
 *  Parameters:
 *     void
 *
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_source_bind_vlan_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(source_vlan_interface, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_ip_acl_mode
 *  Purpose:   do no_source_vlan command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_ip_acl_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_WORD;
	param.name = " WORD";
	param.ylabel = "Extended Access-list name";
	param.hlabel = "拓展列表名";
	param.flag = CLI_END_FLAG;


	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(func_ip_acl_ext_name(u) < 0)
			return -1;

		if((retval = change_con_level(IP_ACL_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			cli_param_get_string(DYNAMIC_PARAM, 0, buff, u);
			sprintf(u->promptbuf, "ext_");
			strcat(u->promptbuf, buff);

			DEBUG_MSG(1, "u->promptbuf=%s\n", u->promptbuf);
		}
	}

	return retval;
}
/*
 *  Function:  no_ip_acl_mode
 *  Purpose:   do no_source_vlan command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_ip_acl_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_WORD;
	param.name = " WORD";
	param.ylabel = "Extended Access-list name";
	param.hlabel = "拓展列表名";
	param.flag = CLI_END_NO;


	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Negative Application */
		nfunc_ip_acl_ext_name(u);
	}
	return retval;
}

/*
 *  Function:  do_ip_acl_mode_s
 *  Purpose:   do_ip_acl_mode_s command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_ip_acl_mode_s(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_WORD;
	param.name = " WORD";
	param.ylabel = "Standard Access-list name";
	param.hlabel = "标准列表名";
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(func_ip_acl_std_name(u) < 0)
			return -1;

		if((retval = change_con_level(IP_ACL_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			cli_param_get_string(DYNAMIC_PARAM, 0, buff, u);
			sprintf(u->promptbuf, "std_");
			strcat(u->promptbuf, buff);

			DEBUG_MSG(1, "u->promptbuf=%s\n", u->promptbuf);
		}
	}

	return retval;
}

/*
 *  Function:  no_ip_acl_mode_s
 *  Purpose:   no_ip_acl_mode_s command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_ip_acl_mode_s(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_WORD;
	param.name = " WORD";
	param.ylabel = "Standard Access-list name";
	param.hlabel = "标准列表名";
	param.flag = CLI_END_NO;


	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Negative Application */
		nfunc_ip_acl_std_name(u);
	}
	return retval;
}

/*
 *  Function:  do_ip_arp_ins
 *  Purpose:   do_ip_arp_ins command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_ip_arp_ins(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "vlan range, example: 1,3-5,7,9-11";
	param.hlabel = "vlan 范围";
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval ;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		vty_output("  The command doesn't support in this version!!\n");
	}
	return retval;
}

/*
 *  Function:  do_name_server
 *  Purpose:   do_name_server command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_name_server(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "Domain name server's IP address";
	param.hlabel = "域名服务器的 ip 地址";
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		func_ip_name_server(u);
	}
	return retval;
}

/*
 *  Function:  do_name_server
 *  Purpose:   do_name_server command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_name_server(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_name_server();
	}
	return retval;
}

static int do_ip_dns_proxy(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		func_ip_dns_proxy(1);
	}
	
	return retval;
}

static int no_ip_dns_proxy(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		func_ip_dns_proxy(0);
	}
	
	return retval;
}
/*
 *  Function:  do_default_gateway
 *  Purpose:   do_default_gateway command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_default_gateway(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "default gateway's IPv4 address";
	param.hlabel = "配置默认网关";
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		func_set_default_gateway(u);
	}
	return retval;
}

/*
 *  Function:  no_default_gateway
 *  Purpose:   no_default_gateway command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_default_gateway(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_default_gateway();
	}
	return retval;
}
/* cos */
static int do_cos(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_cos_map, argc, argv, u);
	return retval;
}
static int do_cos_map_n(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_cos_map_num, argc, argv, u);
	return retval;
}
static int do_cos_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(do_cos_num1, argc, argv, u);
	return retval;
}
static int do_cos_num_n(int argc, char *argv[], struct users *u)
{
	int retval = -1, cnt = 0;

	cli_param_get_int(DYNAMIC_PARAM, 13, &cnt, u);
	cli_param_set_int(DYNAMIC_PARAM, 13, ++cnt, u);

	if((retval = cmdend2(argc, argv, u)) == NULL)
	{
		func_cos_num(u);
	}

	if(cnt < 8)
		retval = sub_cmdparse(do_cos_num1, argc, argv, u);
	return retval;
}
 static int no_cos(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_cos();
	}
	retval = sub_cmdparse(no_cos_map, argc, argv, u);
	return retval;
}
static int no_cos_num_n(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_cos_map();
	}
	return retval;
}
/*
 *  Function:  do_igmp_snooping_querier
 *  Purpose:   do_igmp_snooping_querier command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_igmp_snooping_querier(int argc, char *argv[], struct users *u)
{
	int retval = -1;


	if((retval = cmdend2( argc, argv, u)) == 0)
	{
		func_set_igmp_snooping_querier();

	}

	return retval;
}

/*
 *  Function:  no_igmp_snooping_querier
 *  Purpose:   no_igmp_snooping_querier command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_igmp_snooping_querier(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_igmp_snooping_querier();
	}
	return retval;
}

/*
 *  Function:  do_igmp_snooping_timer_querier
 *  Purpose:   do_igmp_snooping_timer_querier command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_igmp_snooping_timer_querier(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_INT;
	param.name = "<60-1000>";
	param.ylabel = "Interval time in secends";
	param.hlabel = "间隔时间";
	param.flag =CLI_END_FLAG;
	param.min = 60;
	param.max = 1000;
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		func_igmp_snooping_timer_querier(u);
	}
	return retval;
}

/*
 *  Function:  no_igmp_snooping_timer_querier_q
 *  Purpose:   no_igmp_snooping_timer_querier_q command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_igmp_snooping_timer_querier_q(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2( argc, argv, u)) == 0)
	{
		nfunc_igmp_snooping_querier_timer();
	}

	return retval;
}

/*
 *  Function:  no_igmp_snooping_timer_s
 *  Purpose:   no_igmp_snooping_timer_s command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_igmp_snooping_timer_s(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_igmp_snooping_survival_timer();
	}

	return retval;
}

/*
 *  Function:  do_igmp_snooping_timer_survival
 *  Purpose:   do_igmp_snooping_timer_survival command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_igmp_snooping_timer_survival(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	param.type = CLI_INT;
	param.name = "<120-5000>";
	param.ylabel = "Survival time in secends";
	param.hlabel = "幸存时间";
	param.flag =CLI_END_FLAG;
	param.min = 120;
	param.max = 5000;
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		func_igmp_snooping_timer_survival(u);
	}
	return retval;
}

/*
 *  Function:  do_http_server
 *  Purpose:   do_http_server command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_http_server(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2( argc, argv, u)) == 0)
	{
		func_http_server();
	}

	return retval;
}


/*
 *  Function:  no_http_server
 *  Purpose:   no_http_server command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_http_server(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_http_server();
	}

	return retval;
}


/*
 *  Function:  do_ip_acl
 *  Purpose:   do_ip_acl command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_ip_acl(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_acl_mode_cmds, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_ip_set
 *  Purpose:   do_ip_set command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   liujh
 *  Date:    2019/05/08
 */

static int do_ip_set(int argc, char *argv[], struct users *u){
	int retval = -1;

	retval = sub_cmdparse(ip_mask_cmds, argc, argv, u);
	
	return retval;
}



/*
 *  Function:  do_ip_arp_mode
 *  Purpose:   do_ip_arp_mode command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_ip_arp_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		func_set_arp_inspection();

	}
#if 0
	retval = sub_cmdparse(ip_arp_mode_cmds, argc, argv, u);
#endif
	return retval;
}

/*
 *  Function:  no_ip_arp_mode
 *  Purpose:   no_ip_arp_mode command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_ip_arp_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)

	{
		nfunc_arp_inspection();
	}

	return retval;
}

/*
 *  Function:  do_ip_dhcp_realy
 *  Purpose:   do_ip_dhcp_realy command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_ip_dhcp_realy(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2( argc, argv, u)) == 0)
		{
			vty_output("  The command doesn't support in this version!!\n");
		}

	return retval;
}

/*
 *  Function:  do_ip_dhcp_snooping
 *  Purpose:   do_ip_dhcp_snooping or entey ip dhcp snooping command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_ip_dhcp_snooping(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2( argc, argv, u)) == 0)
 	{
		func_set_dhcp_snooping();

	}
//	retval = sub_cmdparse(do_ip_dhcp_snooping_vlan, argc, argv, u);
	return retval;
}


/*
 *  Function:  no_ip_dhcp_bind
 *  Purpose:   no_ip_dhcp_bind  command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_ip_dhcp_bind(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_dhcp_binding();
	}

	return retval;
}

/*
 *  Function:  no_ip_dhcp_snooping
 *  Purpose:   no_ip_dhcp_snooping  command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int no_ip_dhcp_snooping(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2( argc, argv, u)) == 0)
	{
		nfunc_dhcp_snooping();
	}
	//retval = sub_cmdparse(no_ip_dhcp_snooping_vlan, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_ip_dhcp_pool
 *  Purpose:   do_ip_dhcp_pool command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_dhcp_pool(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_WORD;
	param.name = " WORD";
	param.ylabel = "DHCP pool name";
	param.hlabel = "DHCP 地址池名";
	param.flag = CLI_END_FLAG;


	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(func_ip_dhcp_pool_name(u) < 0)
			return -1;

		if((retval = change_con_level(IP_DHCP_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			cli_param_get_string(DYNAMIC_PARAM, 0, buff, u);
			sprintf(u->promptbuf, "dhcp_");
			strcat(u->promptbuf, buff);

			DEBUG_MSG(1, "u->promptbuf=%s\n", u->promptbuf);
		}
	}

	return retval;
}

/*
 *  Function:  no_ip_dhcp_pool
 *  Purpose:   no_ip_dhcp_pool command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_dhcp_pool(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_WORD;
	param.name = " WORD";
	param.ylabel = "DHCP pool name";
	param.hlabel = "DHCP 地址池名";
	param.flag = CLI_END_NO;


	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Negative Application */
		nfunc_ip_dhcp_pool_name(u);
	}
	return retval;
}

/*
 *  Function:  do_ipv6_dhcp_pool
 *  Purpose:   do_ipv6_dhcp_pool command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ipv6_dhcp_pool(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_WORD;
	param.name = " WORD";
	param.ylabel = "DHCPv6 pool name";
	param.hlabel = "DHCPv6 地址池名";
	param.flag = CLI_END_FLAG;


	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(func_ip_dhcp_pool_name(u) < 0)
			return -1;

		if((retval = change_con_level(IP_DHCPv6_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			cli_param_get_string(DYNAMIC_PARAM, 0, buff, u);
			sprintf(u->promptbuf, "dhcpv6_");
			strcat(u->promptbuf, buff);

			DEBUG_MSG(1, "u->promptbuf=%s\n", u->promptbuf);
		}
	}

	return retval;
}

/*
 *  Function:  no_ipv6_dhcp_pool
 *  Purpose:   no_ipv6_dhcp_pool command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ipv6_dhcp_pool(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_WORD;
	param.name = " WORD";
	param.ylabel = "DHCPv6 pool name";
	param.hlabel = "DHCPv6 地址池名";
	param.flag = CLI_END_NO;


	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Negative Application */
		nfunc_ipv6_dhcp_pool_name(u);
	}
	return retval;
}
static int do_ipv6_dhcp_client(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2( argc, argv, u)) == 0)
	{
		func_ipv6_dhcp_client(u);
	}

	return retval;
}
static int no_ipv6_dhcp_client(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_ipv6_dhcp_client(u);
	}

	return retval;
}

static char port_num_start[MAX_ARGV_LEN] = {'\0'};

/* interface fast port */
static int do_source_vlan_interface_ethernet(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(source_vlan_interface_num_cmds, argc, argv, u);

	return retval;
}

static int do_source_vlan_interface_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(source_vlan_interface_slash_cmds, argc, argv, u);

	return retval;
}

static int do_source_vlan_interface_slash(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct cmds *cmds_ptr = source_vlan_interface_port_cmds;

	memset(port_num_start, '\0', sizeof(port_num_start));

	/* Change argcmin and argcmax according to interface type */
	if(ISSET_CMD_MSKBIT(u, IP_IF_FAST_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else if(ISSET_CMD_MSKBIT(u, IP_IF_GIGA_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, GNUM);
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = GNUM;
	}
	else
		sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

	/* Change name */
	cmds_ptr->name = port_num_start;

	retval = sub_cmdparse(source_vlan_interface_port_cmds, argc, argv, u);

	return retval;
}

static int do_source_vlan_interface_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_add_ip_source_binding(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_dhcp_snooping_vlan
 *  Purpose:   do_ip_dhcp_snooping_vlan  command
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
static int do_ip_dhcp_snooping_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_INT_RANGE;
	param.name = "1-4094";
	param.ylabel = "vlan num";
	param.hlabel = "vlan 号";
	param.flag = CLI_END_FLAG;
	param.min = 1;
	param.max = 4094;


	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval ;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		func_ip_dhcp_snooping_vlan(u);
	}
	return retval;
}
static int no_ip_dhcp_snooping_vlan_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_INT_RANGE;
	param.name = "1-4094";
	param.ylabel = "vlan num";
	param.hlabel = "vlan 号";
	param.flag = CLI_END_NO;
	param.min = 1;
	param.max = 4094;


	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval ;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_ip_dhcp_snooping_vlan_num(u);
	}
	return retval;
}


/*-----------------------------------------dscp------------------------------------------*/
static int do_dscp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(do_dscp_n, argc, argv, u);

	return retval;
}
static int do_dscp_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(do_dscp_range, argc, argv, u);

	return retval;
}
static int do_dscp_map(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(do_dscp_map_n, argc, argv, u);

	return retval;
}
static int do_dscp_enable(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_dscp_enable();
	}

	return retval;
}
static int do_dscp_value(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_dscp_value(u);
	}

	return retval;
}

static int no_dscp_map_n(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_dscp_map();
	}

	return retval;
}

static int do_ip_route(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_route_cmds, argc, argv, u);

	return retval;
}

static int no_ip_route(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_route_cmds, argc, argv, u);

	return retval;
}

static int do_ip_route_default(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_route_default_cmds, argc, argv, u);

	return retval;
}

static int do_ip_route_default_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_route_default(u);
	}

	return retval;
}

static int no_ip_route_default(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_route_default(u);
	}

	return retval;
}

static int do_ip_route_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_route_ip_cmds, argc, argv, u);

	return retval;
}

static int do_ip_route_ip_mask(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_route_ip_mask_cmds, argc, argv, u);

	return retval;
}

static int do_ip_and_mask(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char addr[32] = {0};	
	char addr_mask[32] = {0};
	struct in_addr ip;
	struct in_addr j;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "IP Mask";
	param.hlabel = "IP 掩码";
	param.flag = CLI_END_FLAG;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0)	{
		cli_param_get_ipv4(STATIC_PARAM, 0, &ip, addr, sizeof(addr), u);
		cli_param_get_ipv4(DYNAMIC_PARAM, 0, &j, addr_mask, sizeof(addr_mask), u);
		func_set_ip_and_mask(u,addr,addr_mask);
	}

	return retval;
}


static int do_ip_route_ip_mask_next(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_route_ip(u);
	}

	return retval;
}

static int no_ip_route_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(no_ip_route_ip_cmds, argc, argv, u);

	return retval;
}

static int no_ip_route_ip_mask(int argc, char *argv[], struct users *u)
{
	int retval = -1;

//	retval = sub_cmdparse(ip_route_ip_mask_cmds, argc, argv, u);
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_route_ip(u);
	}
	
	return retval;
}

static int no_ip_route_ip_mask_next(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_route_ip(u);
	}

	return retval;
}



static int do_ipv6_set(int argc, char *argv[], struct users *u){
	int retval = -1;

	retval = sub_cmdparse(ipv6_address_cmds, argc, argv, u);
	
	return retval;
}
static int no_ipv6_set(int argc, char *argv[], struct users *u){

	int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		nfunc_ipv6_addr(u);
	}

	return retval;
}



static int do_ipv6_route(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(do_ipv6_route_cmds, argc, argv, u);

	return retval;
}

static int no_ipv6_route(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(no_ipv6_route_cmds, argc, argv, u);

	return retval;
}


static int do_ipv6_mld(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(do_ipv6_mld_snooping_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(do_ipv6_dhcp_snooping_cmds, argc, argv, u);

	return retval;
}
static int no_ipv6_mld(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(do_ipv6_mld_snooping_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_route_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(do_ipv6_route_ipv6_cmds, argc, argv, u);

	return retval;
}

static int no_ipv6_route_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_route_ipv6(u);
	}

	return retval;
}

static int do_ipv6_route_ipv6_next(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_route_ipv6_next(u);
	}

	return retval;
}

static int no_ipv6_route_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_route_all(u);
	}

	return retval;

}

static int do_ipv6_mld_snooping(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_mld_snooping(u);
	}

	return retval;

}

static int do_ipv6_dhcp_snooping(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_dhcp_snooping();
	}

	return retval;

}

static int no_ipv6_dhcp_snooping(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_dhcp_snooping();
	}

	return retval;

}
static int no_ipv6_mld_snooping(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_mld_snooping(u);
	}

	return retval;

}

/*
 *  Function:  do_ip_forward
 *  Purpose:   do_ip_forward command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_forward(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_forward_cmds, argc, argv, u);
	return retval;
}

/*
 *  Function:  no_ip_forward
 *  Purpose:   no_ip_forward command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_forward(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_forward_cmds, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_ip_forward_udp
 *  Purpose:   do_ip_forward_udp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_forward_udp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_forward_udp_cmds, argc, argv, u);
	return retval;
}

/*
 *  Function:  no_ip_forward_udp
 *  Purpose:   no_ip_forward_udp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_forward_udp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	retval = sub_cmdparse(ip_forward_udp_cmds, argc, argv, u);
	return retval;
}

/*
 *  Function:  do_ip_forward_udp_bootps
 *  Purpose:   do_ip_forward_udp_bootps command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_forward_udp_bootps(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_forward_udp_bootps(u);
	}

	return retval;
}

/*
 *  Function:  no_ip_forward_udp_bootps
 *  Purpose:   no_ip_forward_udp_bootps command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_forward_udp_bootps(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_forward_udp_bootps(u);
	}

	return retval;
}

/*
 *  Function:  do_garp
 *  Purpose:   do_garp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_garp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(garp_cmds, argc, argv, u);

	return retval;
}

static int do_garp_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(garp_timer_cmds, argc, argv, u);

	return retval;
}

static int do_garp_timer_leaveall(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(garp_timer_leaveall_cmds, argc, argv, u);

	return retval;
}

static int do_garp_timer_leaveall_value(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_garp_timer_leaveall(u);
	}

	return retval;
}

/*
 *  Function:  no_garp
 *  Purpose:   no_garp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_garp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(garp_cmds, argc, argv, u);

	return retval;
}

static int no_garp_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(garp_timer_cmds, argc, argv, u);

	return retval;
}

static int no_garp_timer_leaveall(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_garp_timer_leaveall(u);
	}

	return retval;
}

/*
 *  Function:  do_gmrp
 *  Purpose:   do_gmrp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_gmrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_gmrp(u);
	}

	return retval;
}

/*
 *  Function:  no_gmrp
 *  Purpose:   no_gmrp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_gmrp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_gmrp(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_mroute
 *  Purpose:   do_ip_mroute command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_mroute(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_mroute_cmds, argc, argv, u);

	return retval;
}

static int do_ip_mroute_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_mroute_ip_cmds, argc, argv, u);

	return retval;
}

static int do_ip_mroute_ip_mask(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_mroute_ip_mask_rpf_cmds, argc, argv, u);

	return retval;
}

static int do_ip_mroute_ip_mask_rpf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_mroute_ip_mask_rpf_cmds, argc, argv, u);

	return retval;
}

static int do_ip_mroute_ip_mask_rpf_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_mroute_interface, argc, argv, u);

	return retval;
}

static int do_ip_mroute_interface_ethernet(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_mroute_interface_num_cmds, argc, argv, u);

	return retval;
}

static int do_ip_mroute_interface_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_mroute(u);
	}

	return retval;
}

static int do_ip_mroute_interface_slash(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct cmds *cmds_ptr = source_vlan_interface_port_cmds;

	memset(port_num_start, '\0', sizeof(port_num_start));

	/* Change argcmin and argcmax according to interface type */
	if(ISSET_CMD_MSKBIT(u, IP_IF_FAST_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, (PNUM-GNUM));
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = (PNUM-GNUM);
	}
	else if(ISSET_CMD_MSKBIT(u, IP_IF_GIGA_PORT))
	{
		sprintf(port_num_start, "<%d-%d>", 1, GNUM);
		cmds_ptr->argcmin = 1;
		cmds_ptr->argcmax = GNUM;
	}
	else
		sprintf(port_num_start, "<%d-%d>", cmds_ptr->argcmin, cmds_ptr->argcmax);

	/* Change name */
	cmds_ptr->name = port_num_start;

	retval = sub_cmdparse(ip_mroute_interface_port_cmds, argc, argv, u);

	return retval;
}

static int do_ip_mroute_interface_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_mroute(u);
	}

	return retval;
}

/*
 *  Function:  no_ip_mroute
 *  Purpose:   no_ip_mroute command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_mroute(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_mroute_cmds, argc, argv, u);

	return retval;
}

static int no_ip_mroute_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

    if(argc == 1)
	{
		/* Do application */
		nfunc_ip_allmroute(u);
	}else
	    retval = sub_cmdparse(ip_mroute_ip_cmds, argc, argv, u);

	return retval;
}

static int no_ip_mroute_ip_mask(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_mroute(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_multi_routing
 *  Purpose:   do_ip_multi_routing command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_multi_routing(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_multi_routing(u);
	}

	return retval;
}

/*
 *  Function:  no_ip_multi_routing
 *  Purpose:   no_ip_multi_routing command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_multi_routing(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_multi_routing(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_igmp
 *  Purpose:   do_ip_igmp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_igmp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_igmp_cmds, argc, argv, u);

	return retval;
}

static int do_ip_igmp_querier(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_igmp_querier_cmds, argc, argv, u);

	return retval;
}

static int do_ip_igmp_querier_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_igmp_querier_time(u);
	}

	return retval;
}

/*
 *  Function:  no_ip_igmp
 *  Purpose:   no_ip_igmp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_igmp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_igmp_cmds, argc, argv, u);

	return retval;
}

static int no_ip_igmp_querier(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_igmp_querier_time(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_pim
 *  Purpose:   do_ip_pim command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_cmds, argc, argv, u);

	return retval;
}

static int do_ip_pim_bsr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_bsr_cmds, argc, argv, u);

	return retval;
}

static int do_ip_pim_sm_priority(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_bsr_int_cmds, argc, argv, u);

	return retval;
}

static int do_ip_pim_bsr_pri(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_pim_bsr(u);
	}

	return retval;
}

static int do_ip_pim_dm(int argc, char *argv[], struct users *u)
{
	int retval = -1;

    if(argc == 2)
	{
		/* Do application */
		func_ip_pim_dm(1);
	}else
	    retval = sub_cmdparse(ip_pimdm_cmds, argc, argv, u);

	return retval;
}

static int no_ip_pim_dm(int argc, char *argv[], struct users *u)
{
	int retval = -1;

    if(argc == 3)
	{
		/* Do application */
		func_ip_pim_dm(0);
	}else
	    retval = sub_cmdparse(ip_pimdm_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_ip_pim
 *  Purpose:   no_ip_pim command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_cmds, argc, argv, u);

	return retval;
}

static int no_ip_pim_bsr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_pim_bsr(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_pim_dr
 *  Purpose:   do_ip_pim_dr command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_pim_dr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_dr_cmds, argc, argv, u);

	return retval;
}

static int do_ip_pim_dr_priority(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_pim_dr_priority(u);
	}

	return retval;
}

/*
 *  Function:  no_ip_pim_dr
 *  Purpose:   no_ip_pim_dr command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_pim_dr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_pim_dr(u);
	}
	return retval;
}

/*
 *  Function:  do_ip_pim_rp
 *  Purpose:   do_ip_pim_rp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_pim_rp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_rp_cmds, argc, argv, u);

	return retval;
}

static int do_ip_pim_rp_add(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_pim_rp_add_all(u);
	}
	else
	    retval = sub_cmdparse(ip_pim_rp_add_cmds, argc, argv, u);

	return retval;
}

static int do_ip_pim_rp_add_netmask(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_rp_add_netmask_cmds, argc, argv, u);

	return retval;
}

static int do_ip_route_pimsm_mask(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_pim_rp_add_over(u);
	}

	return retval;
}

static int do_ip_pim_rp_add_over(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_pim_rp_add_over(u);
	}

	return retval;
}

static int do_ip_pim_rp_add_acl(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_pim_rp_add_acl(u);
	}

	return retval;
}

/*
 *  Function:  no_ip_pim_rp
 *  Purpose:   no_ip_pim_rp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_pim_rp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_rp_cmds, argc, argv, u);

	return retval;
}

static int no_ip_pim_rp_add(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_pim_rp_add_over(u);
	}
	return retval;
}

static int no_ip_pim_rp_add_acl(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_pim_rp_add_acl(u);
	}
	return retval;
}

/*
 *  Function:  do_ip_pim_can
 *  Purpose:   do_ip_pim_can command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_pim_can(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_time_cmds, argc, argv, u);

	return retval;
}

static int do_pim_sm_cantime(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_time_int_cmds, argc, argv, u);

	return retval;
}


static int do_pim_sm_cantime_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_time_priority_cmds, argc, argv, u);

	return retval;
}


static int do_pim_sm_priority(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ip_pim_time_priority_int_cmds, argc, argv, u);

	return retval;
}

static int do_pim_sm_priority_int(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_pim_can(u);
	}
	return retval;
}

/*
 *  Function:  no_ip_pim_can
 *  Purpose:   no_ip_pim_can command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ip_pim_can(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_pim_can(u);
	}
	return retval;
}

/*
 *  Function:  do_ipv6_pim
 *  Purpose:   do_ipv6_pim command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ipv6_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_pim_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_pim_bsr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_pim_bsr(u);
	}

	return retval;
}

/*
 *  Function:  no_ipv6_pim
 *  Purpose:   no_ipv6_pim command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ipv6_pim(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_pim_cmds, argc, argv, u);

	return retval;
}

static int no_ipv6_pim_bsr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_pim_bsr(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_pim_rp
 *  Purpose:   do_ipv6_pim_rp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ipv6_pim_rp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_pim_rp_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_pim_rp_add(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_pim_rp_add_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_pim_rp_add_over(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_pim_rp_add_over(u);
	}

	return retval;
}

static int do_ipv6_pim_rp_add_acl(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_pim_rp_add_acl(u);
	}

	return retval;
}

/*
 *  Function:  no_ipv6_pim_rp
 *  Purpose:   no_ipv6_pim_rp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ipv6_pim_rp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_pim_rp_cmds, argc, argv, u);

	return retval;
}

static int no_ipv6_pim_rp_add(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(ipv6_pim_rp_add_cmds, argc, argv, u);

	return retval;
}

static int no_ipv6_pim_rp_add_over(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_pim_rp_add_over(u);
	}
	return retval;
}

static int no_ipv6_pim_rp_add_acl(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_pim_rp_add_acl(u);
	}
	return retval;
}

/*
 *  Function:  do_ipv6_pim_can
 *  Purpose:   do_ipv6_pim_can command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ipv6_pim_can(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_pim_can(u);
	}
	return retval;
}

/*
 *  Function:  no_ipv6_pim_can
 *  Purpose:   no_ipv6_pim_can command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ipv6_pim_can(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_pim_can(u);
	}
	return retval;
}

/*
 *  Function:  do_bfd
 *  Purpose:   do_bfd command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(bfd_cmds, argc, argv, u);

	return retval;
}

static int do_bfd_enable(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bfd_enable(u);
	}
	return retval;
}

static int do_bfd_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bfd_all(u);
	}
	return retval;
}

/*
 *  Function:  no_bfd
 *  Purpose:   no_bfd command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(bfd_cmds, argc, argv, u);

	return retval;
}

static int no_bfd_enable(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bfd_enable(u);
	}
	return retval;
}

static int no_bfd_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bfd_all(u);
	}
	return retval;
}

/*
 *  Function:  init_cli_ip
 *  Purpose:  Register ip function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   limin.hua
 *  Date:    2011/11/10
 */
int init_cli_ip(void)
{
	int retval = -1;

	retval = registerncmd(ip_topcmds, (sizeof(ip_topcmds)/sizeof(struct topcmds) - 1));

	DEBUG_MSG(1, "init_cli_ip retval = %d\n", retval);

	return retval;
}


static int do_inter_port_garp_timer_hold(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_garp_timer_hold_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_garp_timer_join(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_garp_timer_join_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_garp_timer_leave(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(inter_port_garp_timer_leave_cmds, argc, argv, u);
	
	return retval;
}

static int do_inter_port_garp_timer_hold_value(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_garp_timer_hold(u);
	}
	return retval;
}

static int do_inter_port_garp_timer_join_value(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_garp_timer_join(u);
	}
	return retval;
}

static int do_inter_port_garp_timer_leave_value(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_port_garp_timer_leave(u);
	}
	return retval;
}

static int no_inter_port_garp_timer_hold(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_garp_timer_hold(u);
	}
	return retval;
}

static int no_inter_port_garp_timer_join(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_garp_timer_join(u);
	}
	return retval;
}

static int no_inter_port_garp_timer_leave(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Check command end or not */
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nfunc_port_garp_timer_leave(u);
	}
	return retval;
}
