/*
 * Copyright 2016 by Kuaipao Corporation
 *
 * All Rights Reserved
 *
 * File name  : cli_dhcp.c
 * Function   : dhcp command function
 * Auther     : xi.chen
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

#include "cli_dhcp.h"
#include "cli_dhcp_func.h"

static struct topcmds dhcp_topcmds[] = {
	{ "service", 0, CONFIG_TREE, do_service, no_service, NULL, CLI_END_NONE, 0, 0,
		"service commands", "服务器命令" },
	{ TOPCMDS_END }
};

static struct cmds do_service_cmds[] =
{
	{ "dhcp", CLI_CMD, 0, 0, do_service_dhcp, no_service_dhcp, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"dhcp service", "DHCP 服务器" },
	{ "dhcpv6", CLI_CMD, 0, 0, do_service_dhcpv6, no_service_dhcpv6, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		"dhcpv6 service", "DHCPv6 服务器" },
	{ CMDS_END }
};

static struct topcmds ip_dhcp_topcmds[] = {
	{ "dns-server", 0, IP_DHCP_TREE, do_ip_dns, no_ip_dns, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"DNS Server configuration", "DNS 服务器配置" },
	{ "default-router", 0, IP_DHCP_TREE, do_ip_gateway, no_ip_gateway, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Default Router configuration", "默认网关配置" },
	{ "domain-name", 0, IP_DHCP_TREE, do_ip_domain, no_ip_domain, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Domain name configuration", "域名配置" },
	{ "lease", 0, IP_DHCP_TREE, do_ip_lease, no_ip_lease, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"lease time configuration", "域名配置" },
	{ "network", 0, IP_DHCP_TREE, do_ip_network, no_ip_network, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"network address configuration", "网络地址配置" },
	{ "range", 0, IP_DHCP_TREE, do_ip_range, no_ip_range, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"network address configuration", "网络地址配置" },
	{ "option", 0, IP_DHCP_TREE, do_ip_option, no_ip_option, NULL, CLI_END_NONE, 0, 0,
		"option configuration", "option 配置" },
	{ TOPCMDS_END }
};

static struct cmds do_ip_dns_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_dns_addr, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP address", "IP 地址" },
	{ CMDS_END }
};

static struct cmds do_ip_gateway_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_gateway_addr, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP address", "IP 地址" },
	{ CMDS_END }
};

static struct cmds do_ip_domain_cmds[] =
{
	{ "WORD", CLI_WORD, 0, 0, do_ip_domain_name, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Domain name", "域名" },
	{ CMDS_END }
};

static struct cmds do_ip_lease_cmds[] =
{
	{ "<0-365>", CLI_INT, 0, 0, do_ip_lease_days, NULL, NULL, CLI_END_FLAG, 0, 365,
		"days", "天数" },
	{ "infinite", CLI_CMD, 0, 0, do_ip_lease_infinite, NULL, NULL, CLI_END_FLAG, 0, 0,
		"infinite", "永久使用" },
	{ CMDS_END }
};

static struct cmds do_ip_lease_days_cmds[] =
{
	{ "<0-23>", CLI_INT, 0, 0, do_ip_lease_days_hours, NULL, NULL, CLI_END_FLAG, 0, 23,
		"hours", "小时数" },
	{ CMDS_END }
};

static struct cmds do_ip_lease_days_hours_cmds[] =
{
	{ "<0-59>", CLI_INT, 0, 0, do_ip_lease_days_hours_minutes, NULL, NULL, CLI_END_FLAG, 0, 59,
		"minutes", "分钟数" },
	{ CMDS_END }
};

static struct cmds do_ip_network_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_network_ip, NULL, NULL, CLI_END_NONE, 0, 0,
		"IP address", "IP 地址" },
	{ CMDS_END }
};


static struct cmds do_startip_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_startip, NULL, NULL, CLI_END_NONE, 0, 0,
		"DHCP Start IP address", "DHCP分配起始IP地址" },
	{ CMDS_END }
};

static struct cmds do_endip_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_endip, NULL, NULL, CLI_END_FLAG, 0, 0,
		"DHCP End IP address", "DHCP分配结束IP地址" },
	{ CMDS_END }
};

static struct cmds do_ip_network_ip_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4_MASK, 0, 0, do_ip_network_ip_mask, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP subnet mask", "IP 地址掩码" },
	{ CMDS_END }
};

static struct cmds do_ip_option_cmds[] =
{
	{ "<0-150>", CLI_INT, 0, 0, do_ip_option_code, no_ip_option_code, NULL, CLI_END_NONE | CLI_END_NO, 0, 150,
		"code", "网络参数的代码值" },
	{ CMDS_END }
};

static struct cmds do_ip_option_code_cmds[] =
{
	{ "ascii", CLI_CMD, 0, 0, do_ip_option_code_ascii, NULL, NULL, CLI_END_NONE, 0, 0,
		"code", "网络参数的代码值" },
	{ "hex", CLI_CMD, 0, 0, do_ip_option_code_hex, NULL, NULL, CLI_END_NONE, 0, 0,
		"code", "网络参数的代码值" },
	{ "ip", CLI_CMD, 0, 0, do_ip_option_code_ip, NULL, NULL, CLI_END_NONE, 0, 0,
		"code", "网络参数的代码值" },
	{ CMDS_END }
};

static struct cmds do_ip_option_code_ascii_cmds[] =
{
	{ "WORD", CLI_WORD, 0, 0, do_ip_option_code_ascii_str, NULL, NULL, CLI_END_FLAG, 0, 0,
		"ACSII String", "ACSII 字符串" },
	{ CMDS_END }
};

static struct cmds do_ip_option_code_hex_cmds[] =
{
	{ "WORD", CLI_WORD, 0, 0, do_ip_option_code_hex_hex, NULL, NULL, CLI_END_FLAG, 0, 0,
		"hex", "十六进制" },
	{ CMDS_END }
};

static struct cmds do_ip_option_code_ip_cmds[] =
{
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_option_code_ip_addr, NULL, NULL, CLI_END_FLAG, 0, 0,
		"IP address", "IP 地址" },
	{ CMDS_END }
};


static struct topcmds ipv6_dhcp_topcmds[] = {
	{ "dns-server", 0, IP_DHCPv6_TREE, do_ipv6_dns, no_ipv6_dns, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"DNS Server configuration", "DNS 服务器配置" },
	{ "domain-name", 0, IP_DHCPv6_TREE, do_ipv6_domain, no_ipv6_domain, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"Domain name configuration", "域名配置" },
	{ "lifetime", 0, IP_DHCPv6_TREE, do_ipv6_lifetime, no_ipv6_lifetime, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"lease time configuration", "域名配置" },
	{ "network-address", 0, IP_DHCPv6_TREE, do_ipv6_network, no_ipv6_network, NULL, CLI_END_NONE | CLI_END_NO, 0, 0,
		"network address configuration", "网络地址配置" },
	{ TOPCMDS_END }
};

static struct cmds do_ipv6_dns_cmds[] =
{
	{ "X:X:X:X::X/<0-128>", CLI_IPV6, 0, 0, do_ipv6_dns_addr, NULL, NULL, CLI_END_FLAG, 0, 0 ,
		"IPv6 address", "IPV6 地址" } ,
	{ CMDS_END }
};

static struct cmds do_ipv6_domain_cmds[] =
{
	{ "WORD", CLI_WORD, 0, 0, do_ipv6_domain_name, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Domain name", "域名" },
	{ CMDS_END }
};

static struct cmds do_ipv6_lifetime_cmds[] =
{
	{ "<0-31536000>", CLI_INT, 0, 0, do_ipv6_lifetime_time, NULL, NULL, CLI_END_NONE, 0, 31536000,
		"valid time (seconds)", "有效生存期（秒）" },
	{ "infinite", CLI_CMD, 0, 0, do_ipv6_lifetime_infinite, NULL, NULL, CLI_END_NONE, 0, 0,
		"infinite", "永久使用" },
	{ CMDS_END }
};

static struct cmds do_ipv6_lifetime_pre_cmds[] =
{
	{ "<0-31536000>", CLI_INT, 0, 0, do_ipv6_lifetime_pre_time, NULL, NULL, CLI_END_FLAG, 0, 31536000,
		"preferred time (seconds)", "优选生存期（秒）" },
	{ "infinite", CLI_CMD, 0, 0, do_ipv6_lifetime_pre_infinite, NULL, NULL, CLI_END_FLAG, 0, 0,
		"infinite", "永久使用" },
	{ CMDS_END }
};

static struct cmds do_ipv6_network_cmds[] =
{
	{ "X:X:X:X::X", CLI_IPV6_NOMASK, 0, 0, do_ipv6_network_start, NULL, NULL, CLI_END_NONE, 0, 0 ,
		"IPv6 pool start address", "IPV6 地址池开启地址" } ,
	{ CMDS_END }
};

static struct cmds do_ipv6_network_end_cmds[] =
{
	{ "X:X:X:X::X/<0-128>", CLI_IPV6, 0, 0, do_ipv6_network_end, NULL, NULL, CLI_END_FLAG, 0, 0 ,
		"IPv6 pool end address", "IPV6 地址池结束地址" } ,
	{ CMDS_END }
};

/*
 *  Function:  do_service
 *  Purpose:  service topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_service(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_service_cmds, argc, argv, u);

	return retval;
}

static int do_service_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_service_dhcp(u);
	}

	return retval;
}

static int do_service_dhcpv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_service_dhcpv6(u);
	}

	return retval;
}

/*
 *  Function:  no_service
 *  Purpose:  service topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_service(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_service_cmds, argc, argv, u);

	return retval;
}

static int no_service_dhcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_service_dhcp(u);
	}

	return retval;
}

static int no_service_dhcpv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_service_dhcpv6(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_dns
 *  Purpose:  ip dns topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_ip_dns(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_dns_cmds, argc, argv, u);

	return retval;
}

static int do_ip_gateway(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_gateway_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_ip_dns
 *  Purpose:  ip dns topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_ip_dns(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_gateway(u);
	}

	return retval;
}

static int no_ip_gateway(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_gateway(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_dns_addr
 *  Purpose:   ip dns command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_dns_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_dns_addr(u);
	}

	return retval;
}

static int do_ip_gateway_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_gateway_addr(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_domain
 *  Purpose:  ip domain topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_ip_domain(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_domain_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_ip_domain
 *  Purpose:  ip domain topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_ip_domain(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_domain(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_domain_addr
 *  Purpose:   ip domain command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_domain_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_domain_name(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_lease
 *  Purpose:  ip lease topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_ip_lease(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_lease_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_ip_lease
 *  Purpose:  ip lease topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_ip_lease(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_lease(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_lease_days
 *  Purpose:   ip lease command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_lease_days(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_lease_days(u);
	}

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_lease_days_cmds, argc, argv, u);

	return retval;
}

static int do_ip_lease_days_hours(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_lease_days_hours(u);
	}

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_lease_days_hours_cmds, argc, argv, u);

	return retval;
}

static int do_ip_lease_days_hours_minutes(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_lease_days_hours_minutes(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_lease_infinite
 *  Purpose:   ip lease infinite command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_lease_infinite(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_lease_infinite(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_network
 *  Purpose:  ip network topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_ip_network(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_network_cmds, argc, argv, u);

	return retval;
}

static int do_ip_range(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_startip_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_ip_network
 *  Purpose:  ip network topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_ip_network(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_network(u);
	}

	return retval;
}

static int no_ip_range(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_range(u);
	}

	return retval;
}
/*
 *  Function:  do_ip_network_ip
 *  Purpose:   ip network command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_network_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_network_ip_cmds, argc, argv, u);

	return retval;
}

static int do_ip_network_ip_mask(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_network_ip_mask(u);
	}

	return retval;
}


static int do_startip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_endip_cmds, argc, argv, u);

	return retval;
}

static int do_endip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_dhcp_range(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_option
 *  Purpose:  ip option topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_ip_option(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_option_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_ip_option
 *  Purpose:  ip option topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_ip_option(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_option_cmds, argc, argv, u);

	return retval;
}

static int no_ip_option_code(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ip_option_code(u);
	}

	return retval;
}

/*
 *  Function:  do_ip_option_code
 *  Purpose:   ip option command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ip_option_code(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_option_code_cmds, argc, argv, u);

	return retval;
}

static int do_ip_option_code_ascii(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_option_code_ascii_cmds, argc, argv, u);

	return retval;
}

static int do_ip_option_code_hex(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_option_code_hex_cmds, argc, argv, u);

	return retval;
}

static int do_ip_option_code_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ip_option_code_ip_cmds, argc, argv, u);

	return retval;
}

static int do_ip_option_code_ascii_str(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_option_code_ascii_str(u);
	}

	return retval;
}

static int do_ip_option_code_hex_hex(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_option_code_hex_hex(u);
	}

	return retval;
}

static int do_ip_option_code_ip_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ip_option_code_ip_addr(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_dns
 *  Purpose:  ipv6 dns topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_ipv6_dns(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ipv6_dns_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_ipv6_dns
 *  Purpose:  ipv6 dns topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_ipv6_dns(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_dns(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_dns_addr
 *  Purpose:   ipv6 dns command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ipv6_dns_addr(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_dns_addr(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_domain
 *  Purpose:  ipv6 domain topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_ipv6_domain(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ipv6_domain_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_ipv6_domain
 *  Purpose:  ipv6 domain topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_ipv6_domain(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_domain(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_domain_name
 *  Purpose:   ip domain command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ipv6_domain_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_domain_name(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_lifetime
 *  Purpose:  ipv6 lifetime topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_ipv6_lifetime(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ipv6_lifetime_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_ipv6_lifetime
 *  Purpose:  ipv6 lifetimetopcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_ipv6_lifetime(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_lifetime(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_lifetime_time
 *  Purpose:   ipv6 lifetime time command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ipv6_lifetime_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ipv6_lifetime_pre_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_lifetime_pre_time(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_lifetime_pre_time(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_lifetime_infinite
 *  Purpose:   ipv6 lifetime infinite command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ipv6_lifetime_infinite(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ipv6_lifetime_pre_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_lifetime_pre_infinite(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_lifetime_pre_infinite(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_network
 *  Purpose:  ipv6 network topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int do_ipv6_network(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ipv6_network_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_ipv6_network
 *  Purpose:  ipv6 network topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
static int no_ipv6_network(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ipv6_network(u);
	}

	return retval;
}

/*
 *  Function:  do_ipv6_network_start
 *  Purpose:   ip network command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ipv6_network_start(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(do_ipv6_network_end_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_network_end(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ipv6_network_addr(u);
	}

	return retval;
}

/*
 *  Function:  init_cli_ip_dhcp
 *  Purpose:  Register ip function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int init_cli_dhcp(void)
{
	int retval = -1;

	retval = registerncmd(dhcp_topcmds, (sizeof(dhcp_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(ip_dhcp_topcmds, (sizeof(ip_dhcp_topcmds)/sizeof(struct topcmds) - 1));

	DEBUG_MSG(1, "init_cli_dhcp retval = %d\n", retval);

	return retval;
}

