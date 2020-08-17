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

#include "cli_acl.h"
#include "acl_utils.h"
#include "cli_acl_func.h"

static char location_num[MAX_ARGV_LEN] = {'\0'};

static struct topcmds ip_acl_topcmds[] = {
	{ "deny", 0, IP_ACL_TREE, do_ip_acl_deny, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specify packets to reject", "指定访问拒绝报文" },
	{ "permit", 0, IP_ACL_TREE, do_ip_acl_permit, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specify packets to forward", "指定访问接受报文" },
	{ TOPCMDS_END }
};

static struct cmds ip_acl_ext_protocol_cmds[] = {
	{ "ip", CLI_CMD, 0, 0, do_ip_acl_ext_ip, NULL, NULL, CLI_END_NONE, 0, 0,
		"Internet Protocol", "IP协议" },
	{ "tcp", CLI_CMD, 0, 0, do_ip_acl_ext_tcp, NULL, NULL, CLI_END_NONE, 0, 0,
		"Transmission Control Protocol", "TCP协议" },
	{ "udp", CLI_CMD, 0, 0, do_ip_acl_ext_udp, NULL, NULL, CLI_END_NONE, 0, 0,
		"User Datagram Protocol", "UDP协议" },
	{ "<0-255>", CLI_INT, 0, 0, do_ip_acl_ext_protocol_num, NULL, NULL, CLI_END_NONE, 0, 0,
		"An IP protocol number", "IP协议号" },
	{ CMDS_END }
};

static struct cmds ip_acl_ext_src_cmds[] = {
	{ "any", CLI_CMD, 0, 0, do_ip_acl_ext_src_any, NULL, NULL, CLI_END_NONE, 0, 0,
		"Any source host", "任何源地址" },
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_acl_ext_src_ip, NULL, NULL, CLI_END_NONE, 0, 0,
		"Address to match", "IP地址" },
	{ CMDS_END }
};

static struct cmds ip_acl_ext_dst_cmds[] = {
	{ "eq", CLI_CMD, 0, IP_ACL_SRC_PORT_MSK, do_ip_acl_ext_src_port_eq, NULL, NULL, CLI_END_NONE, 0, 0,
		"Only this port number", "等于指定的服务端口" },
	{ "any", CLI_CMD, 0, 0, do_ip_acl_ext_dst_any, no_ip_acl_ext_dst_any, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Any destination host", "任何目的地址" },
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_acl_ext_dst_ip, no_ip_acl_ext_dst_ip, NULL, CLI_END_NONE, 0, 0,
		"Address to match", "IP地址" },
	{ CMDS_END }
};

static struct cmds ip_acl_ext_option_cmds[] = {
	{ "eq", CLI_CMD, 0, IP_ACL_DST_PORT_MSK, do_ip_acl_ext_dst_port_eq, no_ip_acl_ext_dst_port_eq, NULL, CLI_END_NONE, 0, 0,
		"Only this port number", "等于指定的服务端口" },
	{ "time-range", CLI_CMD, 0, IP_ACL_TIME_RANGE_MSK, do_ip_acl_ext_opt_time_range, no_ip_acl_ext_opt_time_range, NULL, CLI_END_NONE, 0, 0,
		"Specify a time-range", "指定时间范围" },
	{ "tos", CLI_CMD, 0, IP_ACL_TOS_MSK, do_ip_acl_ext_opt_tos, no_ip_acl_ext_opt_tos, NULL, CLI_END_NONE, 0, 0,
		"Match packets with given TOS value", "符合给定的 TOS 值" },
	{ "precedence", CLI_CMD, 0, IP_ACL_PRECEDENCE_MSK, do_ip_acl_ext_opt_precedence, no_ip_acl_ext_opt_precedence, NULL, CLI_END_NONE, 0, 0,
		"Match packets with given precedence value", "符合给定的 precedence 值" },
	{ "location", CLI_CMD, 0, IP_ACL_LOCATION_MSK, do_ip_acl_ext_opt_location, NULL, NULL, CLI_END_NONE, 0, 0,
		"Insert rule to the specify location", "插入规则到指定的num位置" },
	{ "vlan", CLI_CMD, 0, IP_ACL_VLAN_MSK, do_ip_acl_ext_opt_vlan, no_ip_acl_ext_opt_vlan, NULL, CLI_END_NONE, 0, 0,
		"Match packets with given VLAN value", "符合给定的 vlan 值" },
	{ CMDS_END }
};

static struct cmds ip_acl_std_src_cmds[] = {
	{ "any", CLI_CMD, 0, 0, do_ip_acl_std_src_any, no_ip_acl_std_src_any, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Any source host", "任何目的地址" },
	{ "A.B.C.D", CLI_IPV4, 0, 0, do_ip_acl_std_src_ip, no_ip_acl_std_src_ip, NULL, CLI_END_NONE, 0, 0,
		"Address to match", "IP地址" },
	{ CMDS_END }
};

static struct cmds ip_acl_std_option_cmds[] = {
	{ "location", CLI_CMD, 0, IP_ACL_LOCATION_MSK, do_ip_acl_std_opt_location, NULL, NULL, CLI_END_NONE, 0, 0,
		"Insert rule to the specify location", "插入规则到指定的num位置" },
	{ CMDS_END }
};

/*
 * flag=0: standard  ipv4 
 * flag=1: extendard ipv4 
 * flag=2: standard  ipv6
 */
int modify_acl_location(int flag)
{
	int num;
	IP_STANDARD_ACL_ENTRY entry1;
	IP_EXTENDED_ACL_ENTRY entry2;
	IPV6_STANDARD_ACL_ENTRY entry3;
	char *acl_name = nvram_safe_get("acl_name");
	
	if (0 == strlen(acl_name)) {
		free(acl_name);
		return -1;
	}
	
	memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
	memset(&entry3, '\0', sizeof(IPV6_STANDARD_ACL_ENTRY));
	
	/* standard ipv4*/
	if (0 == flag)
		num = ip_std_acl_set(acl_name, &entry1, ACL_ENTRY_NUM, -1, 0x00ULL);
	/* extended ipv4*/
	else if (1 == flag)
		num = ip_ext_acl_set(acl_name, &entry2, ACL_ENTRY_NUM, -1, 0x00ULL);
	/* standard ipv6 */
	else 
		num = ipv6_std_acl_set(acl_name, &entry3, ACL_ENTRY_NUM, -1, 0x00ULL);
		
	if (-1 == num) {
		free(acl_name);
		return 0;
	}
	
	if (0 == num)
		num = 1;
	
	free(acl_name);
	return num;
}

static int do_ip_acl_deny(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, ACL_MODE_POS, ACL_DENY, u);

	if(memcmp(u->promptbuf, "ext_", 4) == 0)
		retval = sub_cmdparse(ip_acl_ext_protocol_cmds, argc, argv, u);
	else if(memcmp(u->promptbuf, "std_", 4) == 0)
		retval = sub_cmdparse(ip_acl_std_src_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_permit(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, ACL_MODE_POS, ACL_PERMIT, u);
	
	if(memcmp(u->promptbuf, "ext_", 4) == 0)
		retval = sub_cmdparse(ip_acl_ext_protocol_cmds, argc, argv, u);
	else if(memcmp(u->promptbuf, "std_", 4) == 0)
		retval = sub_cmdparse(ip_acl_std_src_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_PRO_POS, IP_ACL_PRO_IP, u);
	
	SET_CMD_MSKBIT(u, (IP_ACL_SRC_PORT_MSK|IP_ACL_DST_PORT_MSK));
	
	retval = sub_cmdparse(ip_acl_ext_src_cmds, argc, argv, u);

	return retval;
}
static int do_ip_acl_ext_tcp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_PRO_POS, IP_ACL_PRO_TCP, u);
	
	retval = sub_cmdparse(ip_acl_ext_src_cmds, argc, argv, u);

	return retval;
}
static int do_ip_acl_ext_udp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_PRO_POS, IP_ACL_PRO_UDP, u);
	
	retval = sub_cmdparse(ip_acl_ext_src_cmds, argc, argv, u);

	return retval;
}
static int do_ip_acl_ext_protocol_num(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_PRO_POS, IP_ACL_PRO_NUM, u);
	
	retval = sub_cmdparse(ip_acl_ext_src_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_src_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, IP_ACL_SRC_ANY, u);

	retval = sub_cmdparse(ip_acl_ext_dst_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_src_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
//	param.type = CLI_IPV4_MASK;
	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "IP subnet mask";
	param.hlabel = "IP地址掩码";
	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, IP_ACL_SRC_IP, u);
	
	retval = sub_cmdparse(ip_acl_ext_dst_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_src_port_eq(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = "<0-65535>";
	param.ylabel = "Port number";
	param.hlabel = "端口号";
	param.min = 0;
	param.max = 65535;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_SRC_PORT_POS, param.value.v_int, u);

	retval = sub_cmdparse(ip_acl_ext_dst_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_dst_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_DST_POS, IP_ACL_DST_ANY, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_dst_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
//	param.type = CLI_IPV4_MASK;
	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "IP subnet mask";
	param.hlabel = "IP地址掩码";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_DST_POS, IP_ACL_DST_IP, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_dst_port_eq(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = "<0-65535>";
	param.ylabel = "Port number";
	param.hlabel = "端口号";
	param.min = 0;
	param.max = 65535;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_DST_PORT_POS, param.value.v_int, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_opt_time_range(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Time-range name";
	param.hlabel = "范围时间名";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_opt_tos(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = "<0-15>";
	param.ylabel = "Type of service value";
	param.hlabel = "符合给定的值";
	param.min = 0;
	param.max = 15;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_TOS_POS, param.value.v_int, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_opt_precedence(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = "<0-7>";
	param.ylabel = "Precedence value";
	param.hlabel = "优先值";
	param.min = 0;
	param.max = 7;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_PRECEDENCE_POS, param.value.v_int, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_opt_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = "<1-4094>";
	param.ylabel = "vlan value";
	param.hlabel = "vlan值";
	param.min = 1;
	param.max = 4094;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_VLAN_POS, param.value.v_int, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_ext_opt_location(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int num = 1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	memset(location_num, '\0', sizeof(location_num));

	num = modify_acl_location(1);
	sprintf(location_num, "<%d-%d>", 1, num);

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = location_num;
	param.ylabel = "Specify location";
	param.hlabel = "指定的位置";
	param.min = 1;
	param.max = num;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_LOCATION_POS, param.value.v_int, u);

	retval = cmdend2(argc, argv, u);
	if(retval == 0)
	{
		/* Do application function */
		func_ip_acl_ext(u);
	}

	return retval;
}

static int do_ip_acl_std_src_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, IP_ACL_SRC_ANY, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_acl_std(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_std_option_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_std_src_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
//	param.type = CLI_IPV4_MASK;
	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "IP subnet mask";
	param.hlabel = "IP地址掩码";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, IP_ACL_SRC_IP, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ip_acl_std(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_std_option_cmds, argc, argv, u);

	return retval;
}

static int do_ip_acl_std_opt_location(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int num = 1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	memset(location_num, '\0', sizeof(location_num));

	num = modify_acl_location(0);
	sprintf(location_num, "<%d-%d>", 1, num);

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = location_num;
	param.ylabel = "Specify location";
	param.hlabel = "指定位置";
	param.min = 1;
	param.max = num;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_LOCATION_POS, param.value.v_int, u);

	retval = cmdend2(argc, argv, u);
	if(retval == 0)
	{
		/* Do application function */
		func_ip_acl_std(u);
	}

	return retval;
}

static int no_ip_acl_ext_dst_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_DST_POS, IP_ACL_DST_ANY, u);

	SET_CMD_MSKBIT(u, IP_ACL_LOCATION_MSK);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Negative application */
		nfunc_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int no_ip_acl_ext_dst_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
//	param.type = CLI_IPV4_MASK;
	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "IP subnet mask";
	param.hlabel = "IP地址掩码";
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_DST_POS, IP_ACL_DST_IP, u);
	
	SET_CMD_MSKBIT(u, IP_ACL_LOCATION_MSK);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Negative application */
		nfunc_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int no_ip_acl_ext_dst_port_eq(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = "<0-65535>";
	param.ylabel = "Port number";
	param.hlabel = "端口号";
	param.min = 0;
	param.max = 65535;
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_DST_PORT_POS, param.value.v_int, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Negative application */
		nfunc_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int no_ip_acl_ext_opt_time_range(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "Time-range name";
	param.hlabel = "范围时间名";
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Negative application */
		nfunc_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int no_ip_acl_ext_opt_tos(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = "<0-15>";
	param.ylabel = "Type of service value";
	param.hlabel = "符合给定的值";
	param.min = 0;
	param.max = 15;
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_TOS_POS, param.value.v_int, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Negative application */
		nfunc_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int no_ip_acl_ext_opt_precedence(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = "<0-7>";
	param.ylabel = "Precedence value";
	param.hlabel = "优先值";
	param.min = 0;
	param.max = 7;
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_PRECEDENCE_POS, param.value.v_int, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Negative application */
		nfunc_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int no_ip_acl_ext_opt_vlan(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = "<1-4094>";
	param.ylabel = "VLAN value";
	param.hlabel = "VLAN值";
	param.min = 1;
	param.max = 4094;
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_VLAN_POS, param.value.v_int, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Negative application */
		nfunc_ip_acl_ext(u);
	
		return retval;
	}
	retval = sub_cmdparse(ip_acl_ext_option_cmds, argc, argv, u);

	return retval;
}

static int no_ip_acl_std_src_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, IP_ACL_SRC_ANY, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Negative application */
		nfunc_ip_acl_std(u);
	}

	return retval;
}

static int no_ip_acl_std_src_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
//	param.type = CLI_IPV4_MASK;
	param.type = CLI_IPV4;
	param.name = "A.B.C.D";
	param.ylabel = "IP subnet mask";
	param.hlabel = "IP 掩码";
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set(DYNAMIC_PARAM, &param, u);
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, IP_ACL_SRC_IP, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Negative application */
		nfunc_ip_acl_std(u);
	}

	return retval;
}



/***********************  IPv6 Access List  ******************************/
static struct topcmds ipv6_acl_topcmds[] = {
	{ "deny", 0, IPV6_ACL_TREE, do_ipv6_acl_deny, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specify packets to reject", "指定访问拒绝报文" },
	{ "permit", 0, IPV6_ACL_TREE, do_ipv6_acl_permit, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specify packets to forward", "指定访问接受报文" },
	{ TOPCMDS_END }
};

static struct cmds ipv6_acl_std_src_cmds[] = {
	{ "any", CLI_CMD, 0, 0, do_ipv6_acl_std_src_any, no_ipv6_acl_std_src_any, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Any source host", "任何目的地址" },
	{ "X:X:X:X::X/<1-128>", CLI_IPV6_MASK, 0, 0, do_ipv6_acl_std_src_ip, no_ipv6_acl_std_src_ip, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Address to match", "IP地址" },
	{ CMDS_END }
};

static struct cmds ipv6_acl_std_option_cmds[] = {
	{ "location", CLI_CMD, 0, IP_ACL_LOCATION_MSK, do_ipv6_acl_std_opt_location, NULL, NULL, CLI_END_NONE, 0, 0,
		"Insert rule to the specify location", "插入规则到指定的num位置" },
	{ CMDS_END }
};

static int do_ipv6_acl_deny(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, ACL_MODE_POS, ACL_DENY, u);

	if(memcmp(u->promptbuf, "std_", 4) == 0)
		retval = sub_cmdparse(ipv6_acl_std_src_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_acl_permit(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, ACL_MODE_POS, ACL_PERMIT, u);
	
	if(memcmp(u->promptbuf, "std_", 4) == 0)
		retval = sub_cmdparse(ipv6_acl_std_src_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_acl_std_src_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, IP_ACL_SRC_ANY, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ipv6_acl_std(u);
	
		return retval;
	}
	retval = sub_cmdparse(ipv6_acl_std_option_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_acl_std_src_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	/* add by gujiajie start */
	int srcSubnet_v6 = 0;
	int err_offset = 0, err_flag = 0, linelen = 0;
	char *linebuf = NULL;

	cli_param_get_int(STATIC_PARAM, 14, &srcSubnet_v6, u);
	if ((srcSubnet_v6 < 1) || (srcSubnet_v6 > 128)) {
		u->err_ptr = strchr(u->err_ptr, '/');
		if (u->err_ptr == NULL)
			return 0;
		u->err_ptr++;
		err_offset = u->err_ptr - u->linebuf;
		linelen = u->linelen;
		linebuf = u->linebuf;
		while(1) {
			vty_output("%-80.80s\n", linebuf);

			if(err_offset > 80)
				err_offset -= 80;
			else {
				if(err_flag == 0) {
					if(err_offset == 0)
						vty_output("^\n");
					else
						vty_output("\033[%dC^\n", err_offset);

					err_flag = 1;
				}
			}
			if(linelen > 80) {
				linebuf += 80;
				linelen -= 80;
			}
			else
				break;
		}
		if(ISSET_CMD_ST(u, CMD_ST_CN))
			vty_output("非法 acl IPv6 子网掩码!!\n");
		else
			vty_output("Invalid acl IPv6 Netmask!!\n");
		return 0;
	}
	/* add by gujiajie end */

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, IP_ACL_SRC_IP, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_ipv6_acl_std(u);
	
		return retval;
	}
	retval = sub_cmdparse(ipv6_acl_std_option_cmds, argc, argv, u);

	return retval;
}

static int do_ipv6_acl_std_opt_location(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	int num = 1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));
	memset(location_num, '\0', sizeof(location_num));

	num = modify_acl_location(2);
	sprintf(location_num, "<%d-%d>", 1, num);

	/* Init paramter struct */	
	param.type = CLI_INT;
	param.name = location_num;
	param.ylabel = "Specify location";
	param.hlabel = "指定位置";
	param.min = 1;
	param.max = num;
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_LOCATION_POS, param.value.v_int, u);

	retval = cmdend2(argc, argv, u);
	if(retval == 0)
	{
		/* Do application function */
		func_ipv6_acl_std(u);
	}

	return retval;
}

static int no_ipv6_acl_std_src_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, IP_ACL_SRC_ANY, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Negative application */
		nfunc_ipv6_acl_std(u);
	}

	return retval;
}

static int no_ipv6_acl_std_src_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	/* add by gujiajie start */
	int srcSubnet_v6 = 0;
	int err_offset = 0, err_flag = 0, linelen = 0;
	char *linebuf = NULL;

	cli_param_get_int(STATIC_PARAM, 14, &srcSubnet_v6, u);
	if ((srcSubnet_v6 < 85) || (srcSubnet_v6 > 128)) {
		u->err_ptr = strchr(u->err_ptr, '/');
		if (u->err_ptr == NULL)
			return 0;
		u->err_ptr++;
		err_offset = u->err_ptr - u->linebuf;
		linelen = u->linelen;
		linebuf = u->linebuf;
		while(1) {
			vty_output("%-80.80s\n", linebuf);

			if(err_offset > 80)
				err_offset -= 80;
			else {
				if(err_flag == 0) {
					if(err_offset == 0)
						vty_output("^\n");
					else
						vty_output("\033[%dC^\n", err_offset);

					err_flag = 1;
				}
			}
			if(linelen > 80) {
				linebuf += 80;
				linelen -= 80;
			}
			else
				break;
		}
		if(ISSET_CMD_ST(u, CMD_ST_CN))
			vty_output("非法 acl IPv6 子网掩码!!\n");
		else
			vty_output("Invalid acl IPv6 Netmask!!\n");
		return 0;
	}
	/* add by gujiajie end */

	cli_param_set_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, IP_ACL_SRC_IP, u);
	
	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Negative application */
		nfunc_ipv6_acl_std(u);
	}

	return retval;
}



/*---------------- MAC Access List ------------------------*/
static struct topcmds mac_acl_topcmds[] = {
	{ "deny", 0, MAC_ACL_TREE, do_mac_acl_deny, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specify packets to reject", "指定访问拒绝报文" },
	{ "permit", 0, MAC_ACL_TREE, do_mac_acl_permit, NULL, NULL, CLI_END_NONE, 0, 0,
		"Specify packets to forward", "指定访问接受报文" },
	{ TOPCMDS_END }
};

static struct cmds mac_acl_mode_src_cmds[] = {
	{ "any", CLI_CMD, 0, 0, do_mac_acl_src_any, NULL, NULL, CLI_END_NONE, 0, 0,
		"Any source MAC address", "任何源地址" },
	{ "host", CLI_CMD, 0, 0, do_mac_acl_src_host, NULL, NULL, CLI_END_NONE, 0, 0,
		"A single source host", "主机地址" },
	{ CMDS_END }
};

static struct cmds mac_acl_mode_dst_cmds[] = {
	{ "any", CLI_CMD, 0, 0, do_mac_acl_dst_any, no_mac_acl_dst_any, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"Any destination MAC address", "任何源地址" },
	{ "host", CLI_CMD, 0, 0, do_mac_acl_dst_host, no_mac_acl_dst_host, NULL, CLI_END_NONE, 0, 0,
		"A single destination host", "主机地址" },
	{ CMDS_END }
};

static struct cmds mac_acl_mode_host_ethertype_cmds[] = {
	{ "<1536-65535>", CLI_INT, 0, 0, do_mac_acl_ethertype, no_mac_acl_ethertype, NULL, CLI_END_FLAG|CLI_END_NO, 0, 0,
		"An arbitrary EtherType", "任意以太网字段" },
	{ CMDS_END }
};


static int do_mac_acl_deny(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, ACL_MODE_POS, ACL_DENY, u);
	
	
	retval = sub_cmdparse(mac_acl_mode_src_cmds, argc, argv, u);

	return retval;
}

static int do_mac_acl_permit(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	cli_param_set_int(DYNAMIC_PARAM, ACL_MODE_POS, ACL_PERMIT, u);
	
	retval = sub_cmdparse(mac_acl_mode_src_cmds, argc, argv, u);

	return retval;
}

static int do_mac_acl_src_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	cli_param_set_int(DYNAMIC_PARAM, MAC_ACL_SRC_POS, MAC_ACL_SRC_ANY, u);

	retval = sub_cmdparse(mac_acl_mode_dst_cmds, argc, argv, u);

	return retval;
}

static int do_mac_acl_src_host(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_MAC;
	param.name = "HH:HH:HH:HH:HH:HH";
	param.ylabel = "Source mac address";
	param.hlabel = "物理地址";
	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_string(DYNAMIC_PARAM, 0, param.value.v_string, u);
	
	cli_param_set_int(DYNAMIC_PARAM, MAC_ACL_SRC_POS, MAC_ACL_SRC_HOST, u);

	retval = sub_cmdparse(mac_acl_mode_dst_cmds, argc, argv, u);

	return retval;
}

static int do_mac_acl_dst_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	cli_param_set_int(DYNAMIC_PARAM, MAC_ACL_DST_POS, MAC_ACL_DST_ANY, u);
	
		if((retval = cmdend2(argc, argv, u)) == 0)
		{
			func_mac_acl(u);

		}
	
	retval = sub_cmdparse(mac_acl_mode_host_ethertype_cmds, argc, argv, u);

	return retval;
}

static int do_mac_acl_dst_host(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_MAC;
	param.name = "HH:HH:HH:HH:HH:HH";
	param.ylabel = "Destination mac address";
	param.hlabel = "MAC	地址的描述信息";
	param.flag = CLI_END_FLAG;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_string(DYNAMIC_PARAM, 1, param.value.v_string, u);

	cli_param_set_int(DYNAMIC_PARAM, MAC_ACL_DST_POS, MAC_ACL_DST_HOST, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_mac_acl(u);
	
		return retval;
	}
	retval = sub_cmdparse(mac_acl_mode_host_ethertype_cmds, argc, argv, u);

	return retval;
}

static int do_mac_acl_ethertype(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0)
	{
		/* Do application function */
		func_mac_acl(u);
	}

	return retval;
}

static int no_mac_acl_dst_any(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	cli_param_set_int(DYNAMIC_PARAM, MAC_ACL_DST_POS, MAC_ACL_DST_ANY, u);
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		
		nfunc_mac_acl(u);
		return retval;
	}
	retval = sub_cmdparse(mac_acl_mode_host_ethertype_cmds, argc, argv, u);

	return retval;
}

static int no_mac_acl_dst_host(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */	
	param.type = CLI_MAC;
	param.name = "HH:HH:HH:HH:HH:HH";
	param.ylabel = "Source mac address";
	param.hlabel = "源 MAC 地址";
	param.flag = CLI_END_NO;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_string(DYNAMIC_PARAM, 1, param.value.v_string, u);

	cli_param_set_int(DYNAMIC_PARAM, MAC_ACL_DST_POS, MAC_ACL_DST_HOST, u);

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		nfunc_mac_acl(u);
	
		return retval;
	}
	retval = sub_cmdparse(mac_acl_mode_host_ethertype_cmds, argc, argv, u);

	return retval;
}

static int no_mac_acl_ethertype(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if(retval == 0)
	{
		/* Do application function */
		nfunc_mac_acl(u);
	}

	return retval;
}

int init_cli_acl(void)
{
	int retval = -1;

	retval = registerncmd(ip_acl_topcmds, (sizeof(ip_acl_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(ipv6_acl_topcmds, (sizeof(ipv6_acl_topcmds)/sizeof(struct topcmds) - 1));
	retval += registerncmd(mac_acl_topcmds, (sizeof(mac_acl_topcmds)/sizeof(struct topcmds) - 1));
	
	DEBUG_MSG(1, "init_cli_acl retval = %d\n", retval);

	return retval;
}

