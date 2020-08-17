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

#include "cli_acl_func.h"
#include "acl_utils.h"
#include "bcmutils.h"

/* source port range string */
NUMBER_STR src_port_range_list[]= {
	{PORT_EQ,    "eq"},
	{PORT_GT,    "gt"},
	{PORT_LT,    "lt"},
	{PORT_NEQ,   "neq"},
	{PORT_RANGE, "src_portrange"},
	{-1,         NULL}
};

/* destination port range string */
NUMBER_STR dst_port_range_list[]= {
	{PORT_EQ,    "eq"},
	{PORT_GT,    "gt"},
	{PORT_LT,    "lt"},
	{PORT_NEQ,   "neq"},
	{PORT_RANGE, "dst_portrange"},
	{-1,         NULL}
};

NUMBER_STR ext_option_list[] = {
	{OPTION_SRC_PORT,    "src-port"},
	{OPTION_DST_PORT,    "dst-port"},
	{OPTION_TIME_RANGE,  "time-range"},
	{OPTION_TOS,         "tos"},
	{OPTION_PRECEDENCE,  "precedence"},
	{OPTION_VLAN,        "vlan"},
	{OPTION_LOCATION,    "location"},
	{-1,                  NULL}
};

/* 0:option  1:src port 2:dst port */
int get_number_by_str(char *str, int tag)
{
	NUMBER_STR *entry=NULL;
	
	if(0 == tag)
		entry = ext_option_list;
	else if(1 == tag)
		entry = src_port_range_list;
	else if(2 == tag)
		entry = dst_port_range_list;
	
	if(strlen(str))
	{
		for( ; entry->str != NULL; entry++)
		{
			if(0 == strncasecmp(str, entry->str, strlen(str)))
				return entry->number;
		}
	}
	
	return -1;
}

int ipInt2Str(uint32_t ip, char *ip_str)
{
    int i;
    uint32_t val = ip, temp=0;
    char str[17];
    
    memset(str, '\0', 17);
    
    for(i = 0; i < 4; i++)
    {
        temp = (val >> (8*(3-i))) & 0xFF;
        sprintf(str, "%s%u", str, temp);
        if(i < 3)
            sprintf(str, "%s.", str);
    }
    
    strcpy(ip_str, str);
    return 0;
}

int macstr_to_uint64(char *mac_str, uint64_t *mac_val)
{
	char temp[13], *p, *ptr;
	uint64_t mac=0x00ULL;
	
	memset(temp, '\0', 13);
	p = mac_str;
        
    while(strchr(p, ':') != NULL)
    {
        ptr = strchr(p , ':');
        strncat(temp, p, ptr-p);      
        p= ptr+1;
    }
    strcat(temp, p);    
    mac = str2mac(temp); 
      
    * ((uint64_t *)mac_val) = (uint64_t) mac; 
    
    return 0;
}

static int cli_set_ip_acl_ext(struct users *u)
{
	int protocol=0, res, i=0, action = -1, flag = 0, src_port_flag=-1, dst_port_flag=-1;
	int num1 = 0, num2 = 0;
	int src_port1=0, src_port2=0, dst_port1=0, dst_port2=0;
	int tos=0, precedence=0, vlan=0;
	int location=0;
	uint32_t src_ip=0, src_subnet=0, dst_ip=0, dst_subnet=0;
	char time_range[TIME_NAME_LEN], tmp[20];
	char *ip_acl, *acl_name, *p, *str;
	char name[ACL_NAME_LEN+3];
	IP_EXTENDED_ACL_ENTRY entry;
	POLICY_CLASSIFY classify;
		
	ip_acl  = nvram_safe_get("ip_ext_acl");
	acl_name = nvram_safe_get("acl_name");
	    	
	if(strlen(acl_name) == 0)
	{
        if (ip_acl)
		    free(ip_acl);
        if (acl_name)
		    free(acl_name);
		return -1;
	}

	int action_flag = 0;
	cli_param_get_int(DYNAMIC_PARAM, ACL_MODE_POS, &action_flag, u);
	if(action_flag == ACL_DENY)
		action = ACL_ACT_DENY;
	else if(action_flag == ACL_PERMIT)
		action = ACL_ACT_PERMIT;

	memset(time_range, '\0', sizeof(TIME_NAME_LEN));				

	/**buff[1]:protocol, buff[2]:src ip*/
	int protocol_num = 0;
	cli_param_get_int(DYNAMIC_PARAM, IP_ACL_PRO_POS, &protocol_num, u);
	switch(protocol_num)
	{
		/* ip */
		case IP_ACL_PRO_IP:
			protocol = ACL_IP;
			break;
		/* tcp */			
		case IP_ACL_PRO_TCP:
			protocol = ACL_TCP;
			break;
		/* udp */		
		case IP_ACL_PRO_UDP:
			protocol = ACL_UDP;
			break;
		/* <0-255> */		
		case IP_ACL_PRO_NUM:
			cli_param_get_int(STATIC_PARAM, 0, &protocol, u);
			break;
		default:
			break;
	}

	/* src ip :any   dst ip: any */
	struct in_addr s_addr, s_subnet, d_addr, d_subnet;
	int src_ip_flag = 0, dst_ip_flag = 0;
	char srcIp[MAX_ARGV_LEN] = {'\0'}, srcSubnet[MAX_ARGV_LEN] = {'\0'};
	char dstIp[MAX_ARGV_LEN] = {'\0'}, dstSubnet[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, &src_ip_flag, u);
	cli_param_get_int(DYNAMIC_PARAM, IP_ACL_DST_POS, &dst_ip_flag, u);

	if(src_ip_flag == IP_ACL_SRC_ANY)
		flag |= (0x01 << FLAG_SRC_IP);
	else if(src_ip_flag == IP_ACL_SRC_IP)
	{
		cli_param_get_ipv4(STATIC_PARAM, 0, &s_addr, srcIp, sizeof(srcIp), u);
		cli_param_get_ipv4(DYNAMIC_PARAM, 0, &s_subnet, srcSubnet, sizeof(srcSubnet), u);

		src_ip = s_addr.s_addr;
		src_subnet = s_subnet.s_addr;
	}

	if(dst_ip_flag == IP_ACL_DST_ANY)
		flag |= (0x01 << FLAG_DST_IP);
	else if(dst_ip_flag == IP_ACL_DST_IP)
	{
		if(src_ip_flag == IP_ACL_SRC_ANY)
		{
			cli_param_get_ipv4(STATIC_PARAM, 0, &d_addr, dstIp, sizeof(dstIp), u);
			cli_param_get_ipv4(DYNAMIC_PARAM, 0, &d_subnet, dstSubnet, sizeof(dstSubnet), u);
		}
		else
		{
			cli_param_get_ipv4(STATIC_PARAM, 1, &d_addr, dstIp, sizeof(dstIp), u);
			cli_param_get_ipv4(DYNAMIC_PARAM, 1, &d_subnet, dstSubnet, sizeof(dstSubnet), u);
		}
		
		dst_ip = d_addr.s_addr;
		dst_subnet = d_subnet.s_addr;
	}

	/* has more option */
	if(ISSET_CMD_MSKBIT(u, IP_ACL_SRC_PORT_MSK) && protocol_num != IP_ACL_PRO_IP)
	{
		src_port_flag = get_number_by_str("eq", 1); 
		flag |= (src_port_flag << FLAG_SRC_PORT_RANGE);
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_SRC_PORT_POS, &src_port1, u);
	}
	if(ISSET_CMD_MSKBIT(u, IP_ACL_DST_PORT_MSK) && protocol_num != IP_ACL_PRO_IP)
	{
		dst_port_flag = get_number_by_str("eq", 2); 
		flag |= (dst_port_flag << FLAG_DST_PORT_RANGE);
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_DST_PORT_POS, &dst_port1, u);
	}
	if(ISSET_CMD_MSKBIT(u, IP_ACL_TIME_RANGE_MSK))
	{
		flag |= (0x01 << FLAG_TIME_RANGE);
		cli_param_get_string(DYNAMIC_PARAM, IP_ACL_TIME_RANGE_POS, time_range, u);
	}
	if(ISSET_CMD_MSKBIT(u, IP_ACL_TOS_MSK))
	{
		flag |= (0x01 << FLAG_TOS);
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_TOS_POS, &tos, u);
	}
	if(ISSET_CMD_MSKBIT(u, IP_ACL_PRECEDENCE_MSK))
	{
		flag |= (0x01 << FLAG_PRECEDENCE);
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_PRECEDENCE_POS, &precedence, u);
	}
	if(ISSET_CMD_MSKBIT(u, IP_ACL_LOCATION_MSK))
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_LOCATION_POS, &location, u);
	
	if(ISSET_CMD_MSKBIT(u, IP_ACL_VLAN_MSK))
	{
		flag |= (0x01 << FLAG_VLAN);
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_VLAN_POS, &vlan, u);
	}
		
	memset(&entry, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));	
	entry.action = action;
	entry.protocol = protocol;
	entry.src_ip = src_ip;
	entry.src_subnet = src_subnet;
	entry.dst_ip = dst_ip;
	entry.dst_subnet = dst_subnet;
	entry.src_port1 = src_port1;
	entry.src_port2 = src_port2;
	entry.dst_port1 = dst_port1;
	entry.dst_port2 = dst_port2;
	if(strlen(time_range) > 0)
		strcpy(entry.time_range, time_range);
	entry.tos = tos;
	entry.precedence = precedence; 
	entry.vlan = vlan; 
	entry.flag = flag;   
	entry.next = NULL;	

	/* append the entry */
	if(0 == location)
		res = ip_ext_acl_set(acl_name, &entry, ACL_ENTRY_APPEND, -1, 0x00ULL);
	/* insert the entry */
	else
		res = ip_ext_acl_set(acl_name, &entry, ACL_ENTRY_INSERT, location, 0x00ULL);

	if(res == -1)
	{
		//vty_output("The rule has existed in the access list.\n");
		free(ip_acl);
		free(acl_name);
		return 0;
	}
	else if(res == -2)
	{
		vty_output("all ip extended acl entries number can not exceed %d!!!!\n", (SIP_ACL_NUM+1));//ynn 20170629 add total num = XX+1
		free(ip_acl);
		free(acl_name);
		return 0;
	}

	/* write policy start*/
//	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
//	classify.type_flag = CLASSIFY_TYPE_IP;
//	strcpy(classify.name, acl_name);
//	/* get policy classify num based on acl with the name */
//	num1 = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
//	if(num1)	
//	{		
//		/*
//		*  add code to check all policy entry num 
//		*/
//		num2 = policy_set("", &classify, POLICY_ACL_ENTRY_NUM, 0, 0x00ULL);
//		if(num2 > POLICY_NUM)
//			vty_output("Adding this rule, all policy entris number will exceed %d !\n", POLICY_NUM);
//		else
//			policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);
//	}
//	else
//		policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);
	/* write policy end*/

	/* modify nvram value */		
	memset(name, '\0', ACL_NAME_LEN+3);
	strcpy(name, acl_name);
	strcat(name, "|");
	p = strstr(ip_acl, name);

	if(NULL == p)
	{
		free(ip_acl);
		free(acl_name);
		return -1;
	}

	if(p != ip_acl)
	{
		memset(name, '\0', ACL_NAME_LEN+3);
		strcat(name, ";");
		strcat(name, acl_name);
		strcat(name, "|");
		p = strstr(ip_acl, name);
		
		if(NULL == p)
		{
			free(ip_acl);
			free(acl_name);
			return -1;
		}
		p++;
	}

	str = malloc(strlen(ip_acl) + 512);
	if(NULL == str)
	{
		free(ip_acl);
		free(acl_name);
		return -1;
	}
	memset(str, '\0', strlen(ip_acl) + 512);

	/* location:0---> no location (append entry),  oether: has location(insert entry)*/
	i = 0;
	while(*p != ';')
	{
		i++;
		p = strchr(p, '|') + 1;
		if((i == location) || (0 == location))
		{
			if(0 == location)
				p = strchr(p, ';');
			strncpy(str, ip_acl, p-ip_acl);		
				
			sprintf(str, "%s%d:%d:", str, action, protocol);
		
			/* src ip : any */
			if((flag >> FLAG_SRC_IP) & 0x01)
			{
				strcat(str, "any");
				strcat(str, "::");
			}
			else
			{
				/* src ip */
				memset(tmp, '\0', 20);
				ipInt2Str(src_ip, tmp);
				strcat(str, tmp);
				strcat(str, ":"); 
			
				/* src subnet */
				memset(tmp, '\0', 20);
				ipInt2Str(src_subnet, tmp);
				strcat(str, tmp);
				strcat(str, ":");
			}
		
			/* dst ip: any */
			if((flag >> FLAG_DST_IP) & 0x01)
			{
				strcat(str, "any");
				strcat(str, "::");
			}
			else
			{
				/* dst ip */
				memset(tmp, '\0', 20);
				ipInt2Str(dst_ip, tmp);
				strcat(str, tmp);
				strcat(str, ":");
			
				/* dst subnet */
				memset(tmp, '\0', 20);
				ipInt2Str(dst_subnet, tmp);
				strcat(str, tmp);
				strcat(str, ":");
			}
		
			/* src port range */
			if((res = ((flag >> FLAG_SRC_PORT_RANGE) & 0x07)))
			{
				sprintf(str, "%s%d", str, res);
				strcat(str, ":");
				sprintf(str, "%s%d", str, src_port1);
				strcat(str, ":");
				sprintf(str, "%s%d", str, src_port2);
				strcat(str, ":");
			}
			else
				strcat(str, ":::");
			
			/* dst port range */
			if((res = ((flag >> FLAG_DST_PORT_RANGE) & 0x07)))
			{
				sprintf(str, "%s%d", str, res);
				strcat(str, ":");
				sprintf(str, "%s%d", str, dst_port1);
				strcat(str, ":");
				sprintf(str, "%s%d", str, dst_port2);
				strcat(str, ":");
			}
			else
				strcat(str, ":::");
		
			/* time range */
			if(strlen(time_range))
				strcat(str,time_range);
			strcat(str, ":");
		
			/* tos */
			if((flag >> FLAG_TOS) & 0x01)
				sprintf(str, "%s%d", str, tos);
			strcat(str, ":");
			
			/* vlan */
			if((flag >> FLAG_VLAN) & 0x01)
					sprintf(str, "%s%d", str, vlan);		
			strcat(str, ":");
		
			/* precedence */
			if((flag >> FLAG_PRECEDENCE) & 0x01)
					sprintf(str, "%s%d", str, precedence);
			strcat(str, "|");					
			
			strcat(str, p);
		}
	}

	nvram_set("ip_ext_acl", str);

	free(str);
	free(ip_acl);
	free(acl_name); 	

	return 0;
}

static int cli_set_ip_acl_std(struct users *u)
{ 
	int action = -1, res, flag=0, i=0;
	int num1 = 0, num2 = 0;
	uint32_t srcIp=0, srcSubnet=0;
	char *ip_acl, *acl_name, *p, *str;
	char name[ACL_NAME_LEN+3];
	IP_STANDARD_ACL_ENTRY entry;
	POLICY_CLASSIFY classify;
		    
	/* get value from nvram */
	ip_acl  = nvram_safe_get("ip_std_acl");
	acl_name = nvram_safe_get("acl_name");
	    	
	if(strlen(acl_name) == 0){
        if (ip_acl)
		    free(ip_acl);
        if (acl_name)
		    free(acl_name);
		return -1;
    }   
	int action_flag = 0;
	cli_param_get_int(DYNAMIC_PARAM, ACL_MODE_POS, &action_flag, u);
	if(action_flag == ACL_DENY){
		action = ACL_ACT_DENY;		
	}
	else if(action_flag == ACL_PERMIT){
		action = ACL_ACT_PERMIT;
	}
	
	int src_ip_flag = -1;
	struct in_addr s_ip, s_subnet;
	char src_ip[MAX_ARGV_LEN] = {'\0'}, src_subnet[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, &src_ip_flag, u);
	if(src_ip_flag == IP_ACL_SRC_ANY)
		flag = 1;
	else
	{
		cli_param_get_ipv4(STATIC_PARAM, 0, &s_ip, src_ip, sizeof(src_ip), u);
		cli_param_get_ipv4(DYNAMIC_PARAM, 0, &s_subnet, src_subnet, sizeof(src_subnet), u);

		srcIp = s_ip.s_addr;
		srcSubnet = s_subnet.s_addr;
	}
		
	entry.action = action;
	entry.src_ip = srcIp;
	entry.src_subnet = srcSubnet;
	entry.flag = flag;   /* 1: any  0:other*/
	entry.next = NULL;

	/* append the entry */
	int location = -1;
	if(!ISSET_CMD_MSKBIT(u, IP_ACL_LOCATION_MSK))
		res = ip_std_acl_set(acl_name, &entry, ACL_ENTRY_APPEND, -1, 0x00ULL);
	else
	{
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_LOCATION_POS, &location, u);
		res = ip_std_acl_set(acl_name, &entry, ACL_ENTRY_INSERT, location, 0x00ULL);
	}

	if(res == -1)
	{
		vty_output("The rule has existed in the access list.\n");
		free(ip_acl);
		free(acl_name);
		return 0;
	}
	else if(res == -2)
	{
		vty_output("all ip standard acl entries number can not exceed %d!!!!\n", SIP_ACL_NUM);
		free(ip_acl);
		free(acl_name);
		return 0;
	}

	/* write policy start*/
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	classify.type_flag = CLASSIFY_TYPE_IP;
	strcpy(classify.name, acl_name);
	/* get policy classify num based on acl with the name */
	num1 = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
	if(num1)	
	{
		/*
		*  add code to check all policy entry num 
		*/
		num2 = policy_set("", &classify, POLICY_ACL_ENTRY_NUM, 0, 0x00ULL);
		if(num2 > POLICY_NUM)
			vty_output("Adding this rule, all policy entris number will exceed %d !\n", POLICY_NUM);
		else
			policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);
	}
	else
		policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);
	/* write policy end*/
		
	/* modify nvram value */		
	memset(name, '\0', ACL_NAME_LEN+3);
	strcpy(name, acl_name);
	strcat(name, "|");
	p = strstr(ip_acl, name);

	if(NULL == p)
	{
		free(ip_acl);
		free(acl_name);
		return -1;
	}

	if(p != ip_acl)
	{
		memset(name, '\0', ACL_NAME_LEN+3);
		strcat(name, ";");
		strcat(name, acl_name);
		strcat(name, "|");
		p = strstr(ip_acl, name);
		
		if(NULL == p)
		{
			free(ip_acl);
			free(acl_name);
			return -1;
		}
		p++;
	}

	str = malloc(strlen(ip_acl) + 64);
	if(NULL == str)
	{
		free(ip_acl);
		free(acl_name);
		return -1;
	}
	memset(str, '\0', strlen(ip_acl) + 64);

	/* append */
	if(!ISSET_CMD_MSKBIT(u, IP_ACL_LOCATION_MSK))
	{
		p = strchr(p, ';');
		strncpy(str, ip_acl, p-ip_acl);

		sprintf(str, "%s%d", str, action);
		strcat(str, ":");

		if(strlen(src_ip) > 0)
			strcat(str, src_ip);
		strcat(str, ":");
		
		if(strlen(src_subnet) > 0)
			strcat(str, src_subnet);
		strcat(str, "|");
		strcat(str, p);
	}
	/* insert */
	else
	{
		while(*p != ';')
		{
			i++;
			p = strchr(p, '|') + 1;
			if(i == location)
			{
				strncpy(str, ip_acl, p-ip_acl);
				
				sprintf(str, "%s%d", str, action);
				strcat(str, ":");
				
				if(strlen(src_ip) > 0)
					strcat(str, src_ip);
				strcat(str, ":");
				
				if(strlen(src_subnet) > 0)
					strcat(str, src_subnet);
				strcat(str, "|");
				
				strcat(str, p);
			}
		}
	}

	nvram_set("ip_std_acl", str);

	free(str);
	free(ip_acl);
	free(acl_name); 
	return 0;       
}

static int cli_set_ip_acl_ext_no(struct users *u)
{
	int protocol = 0, res, action = -1, flag = 0, src_port_flag=-1, dst_port_flag=-1;
	int src_port1=0, src_port2=0, dst_port1=0, dst_port2=0;
	int tos = 0, precedence = 0, vlan = 0;
	int location=0;
	uint32_t src_ip=0, src_subnet=0, dst_ip=0, dst_subnet=0;
	char time_range[TIME_NAME_LEN], tmp[20], entry_data[512], entry_tmp[512];
	char *ip_acl, *acl_name, *p, *ptr, *str;
	char name[ACL_NAME_LEN+3];
	IP_EXTENDED_ACL_ENTRY entry;
	POLICY_CLASSIFY classify;
		
	ip_acl  = nvram_safe_get("ip_ext_acl");
	acl_name = nvram_safe_get("acl_name");
	    	
	if(strlen(acl_name) == 0)
	{
        if (ip_acl)
		    free(ip_acl);
        if (acl_name)
		    free(acl_name);
		return -1;
	}

	/*	buff[1] : action */
	int action_flag = 0;
	cli_param_get_int(DYNAMIC_PARAM, ACL_MODE_POS, &action_flag, u);
	if(action_flag == ACL_DENY)
		action = ACL_ACT_DENY;
	else if(action_flag == ACL_PERMIT)
		action = ACL_ACT_PERMIT;
		
	memset(time_range, '\0', sizeof(TIME_NAME_LEN));				

	/* buff[2] : protocol */
	int protocol_num = 0;
	cli_param_get_int(DYNAMIC_PARAM, IP_ACL_PRO_POS, &protocol_num, u);
	switch(protocol_num)
	{
		/* ip */
		case IP_ACL_PRO_IP:
			protocol = ACL_IP;
			break;
		/* tcp */			
		case IP_ACL_PRO_TCP:
			protocol = ACL_TCP;
			break;
		/* udp */		
		case IP_ACL_PRO_UDP:
			protocol = ACL_UDP;
			break;
		/* <0-255> */		
		case IP_ACL_PRO_NUM:
			cli_param_get_int(STATIC_PARAM, 0, &protocol, u);
			break;
		default:
			break;
	}
	
	/* buff[3] :  src ip */
	/* src ip :any   dst ip: any */
	struct in_addr s_addr, s_subnet, d_addr, d_subnet;
	int src_ip_flag = 0, dst_ip_flag = 0;
	char srcIp[MAX_ARGV_LEN] = {'\0'}, srcSubnet[MAX_ARGV_LEN] = {'\0'};
	char dstIp[MAX_ARGV_LEN] = {'\0'}, dstSubnet[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, &src_ip_flag, u);
	cli_param_get_int(DYNAMIC_PARAM, IP_ACL_DST_POS, &dst_ip_flag, u);

	if(src_ip_flag == IP_ACL_SRC_ANY)
		flag |= (0x01 << FLAG_SRC_IP);
	else if(src_ip_flag == IP_ACL_SRC_IP)
	{
		cli_param_get_ipv4(STATIC_PARAM, 0, &s_addr, srcIp, sizeof(srcIp), u);
		cli_param_get_ipv4(DYNAMIC_PARAM, 0, &s_subnet,srcSubnet, sizeof(srcSubnet), u);

		src_ip = s_addr.s_addr;
		src_subnet = s_subnet.s_addr;
	}

	if(dst_ip_flag == IP_ACL_DST_ANY)
		flag |= (0x01 << FLAG_DST_IP);
	else if(dst_ip_flag == IP_ACL_DST_IP)
	{
		if(src_ip_flag == IP_ACL_SRC_ANY)
		{
			cli_param_get_ipv4(STATIC_PARAM, 0, &d_addr, dstIp, sizeof(dstIp), u);
			cli_param_get_ipv4(DYNAMIC_PARAM, 0, &d_subnet, dstSubnet, sizeof(dstSubnet), u);
		}
		else
		{
			cli_param_get_ipv4(STATIC_PARAM, 1, &d_addr, dstIp, sizeof(dstIp), u);
			cli_param_get_ipv4(DYNAMIC_PARAM, 1, &d_subnet, dstSubnet, sizeof(dstSubnet), u);
		}
		
		dst_ip = d_addr.s_addr;
		dst_subnet = d_subnet.s_addr;
	}
	
	/* has more option */
	if(ISSET_CMD_MSKBIT(u, IP_ACL_SRC_PORT_MSK) && protocol_num != IP_ACL_PRO_IP)
	{	
		src_port_flag = get_number_by_str("eq", 1); 
		flag |= (src_port_flag << FLAG_SRC_PORT_RANGE);
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_SRC_PORT_POS, &src_port1, u);
		
	}
	if(ISSET_CMD_MSKBIT(u, IP_ACL_DST_PORT_MSK) && protocol_num != IP_ACL_PRO_IP)
	{
		dst_port_flag = get_number_by_str("eq", 2); 
		flag |= (dst_port_flag << FLAG_DST_PORT_RANGE);
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_DST_PORT_POS, &dst_port1, u);

	}
	if(ISSET_CMD_MSKBIT(u, IP_ACL_TIME_RANGE_MSK))
	{
		flag |= (0x01 << FLAG_TIME_RANGE);
		cli_param_get_string(DYNAMIC_PARAM, IP_ACL_TIME_RANGE_POS, time_range, u);
	}
	if(ISSET_CMD_MSKBIT(u, IP_ACL_TOS_MSK))
	{
		flag |= (0x01 << FLAG_TOS);
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_TOS_POS, &tos, u);
	}
	if(ISSET_CMD_MSKBIT(u, IP_ACL_PRECEDENCE_MSK))
	{
		flag |= (0x01 << FLAG_PRECEDENCE);
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_PRECEDENCE_POS, &precedence, u);
	}
	if(ISSET_CMD_MSKBIT(u, IP_ACL_LOCATION_MSK))
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_LOCATION_POS, &location, u);
		
	if(ISSET_CMD_MSKBIT(u, IP_ACL_VLAN_MSK))
	{
		flag |= (0x01 << FLAG_VLAN);
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_VLAN_POS, &vlan, u);
	}
	
	memset(&entry, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));	
	entry.action = action;
	entry.protocol = protocol;
	entry.src_ip = src_ip;
	entry.src_subnet = src_subnet;
	entry.dst_ip = dst_ip;
	entry.dst_subnet = dst_subnet;
	entry.src_port1 = src_port1;
	entry.src_port2 = src_port2;
	entry.dst_port1 = dst_port1;
	entry.dst_port2 = dst_port2;
	if(strlen(time_range) > 0)
		strcpy(entry.time_range, time_range);
	entry.tos = tos;
	entry.precedence = precedence; 
	entry.vlan = vlan; 
	entry.flag = flag;   
	entry.next = NULL;	
	
	/* delete the entry */
	res = ip_ext_acl_set(acl_name, &entry, ACL_ENTRY_DELETE, -1, 0x00ULL);
	/* entry is not exist or the acl name is not exist */
	if(res == 0)
	{
		vty_output("The rule has not existed in the access list.\n");
		free(ip_acl);
		free(acl_name);
		return 0;
	}
	
	/* write policy start*/
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	classify.type_flag = CLASSIFY_TYPE_IP;
	strcpy(classify.name, acl_name);
	/* get policy classify num based on acl with the name */
	res = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
	//if(res)	
		policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);
	/* write policy end*/
	
	/* modify nvram value */
	memset(entry_data, '\0', 512);
	/* action:protocol:*/
	sprintf(entry_data, "%s%d:%d:", entry_data, action, protocol);
	
	/* src ip : any */
	if((flag >> FLAG_SRC_IP) & 0x01)
		strcat(entry_data, "any::");
	else
	{
		/* src ip */
		memset(tmp, '\0', 20);
		ipInt2Str(src_ip, tmp);
		strcat(entry_data, tmp);
		strcat(entry_data, ":"); 
		
		/* src subnet */
		memset(tmp, '\0', 20);
		ipInt2Str(src_subnet, tmp);
		strcat(entry_data, tmp);
		strcat(entry_data, ":");
	}
	
	/* dst ip: any */
	if((flag >> FLAG_DST_IP) & 0x01)
		strcat(entry_data, "any::");
	else
	{
		/* dst ip */
		memset(tmp, '\0', 20);
		ipInt2Str(dst_ip, tmp);
		strcat(entry_data, tmp);
		strcat(entry_data, ":"); 
		
		/* dst subnet */
		memset(tmp, '\0', 20);
		ipInt2Str(dst_subnet, tmp);
		strcat(entry_data, tmp);
		strcat(entry_data, ":");
	}
	
	/* src port range */
	if((res = ((flag >> FLAG_SRC_PORT_RANGE) & 0x07)))
	{
		sprintf(entry_data, "%s%d:", entry_data, res);
		sprintf(entry_data, "%s%d:", entry_data, src_port1);
		sprintf(entry_data, "%s%d:", entry_data, src_port2);
	}
	else
		strcat(entry_data, ":::");
	
	/* dst port range */
	if((res = ((flag >> FLAG_DST_PORT_RANGE) & 0x07)))
	{
		sprintf(entry_data, "%s%d:", entry_data, res);
		sprintf(entry_data, "%s%d:", entry_data, dst_port1);
		sprintf(entry_data, "%s%d:", entry_data, dst_port2);
	}
	else
		strcat(entry_data, ":::");
		
	/* time range */
	if(strlen(time_range))
		strcat(entry_data,time_range);
	strcat(entry_data, ":");
	
	/* tos */
	if((flag >> FLAG_TOS) & 0x01)
		sprintf(entry_data, "%s%d", entry_data, tos);
	strcat(entry_data, ":");
	
	/* vlan */
	if((flag >> FLAG_VLAN) & 0x01)
		sprintf(entry_data, "%s%d", entry_data, vlan);	
	strcat(entry_data, ":");
		
	/* precedence */
	if((flag >> FLAG_PRECEDENCE) & 0x01)
		sprintf(entry_data, "%s%d", entry_data, precedence);
	strcat(entry_data, "|");
				
	str = malloc(strlen(ip_acl));
	if(NULL == str)
	{
		free(ip_acl);
		free(acl_name);
		return -1;
	}
	memset(str, '\0', strlen(ip_acl));
			
	memset(name, '\0', ACL_NAME_LEN+3);
	strcpy(name, acl_name);
	strcat(name, "|");
	p = strstr(ip_acl, name);
	
	if(NULL == p)
	{
		free(str);
		free(ip_acl);
		free(acl_name);
		return -1;
	}
	
	if(p != ip_acl)
	{
		memset(name, '\0', ACL_NAME_LEN+3);
		strcat(name, ";");
		strcat(name, acl_name);
		strcat(name, "|");
		p = strstr(ip_acl, name);
		
		if(NULL == p)
		{
			free(str);
			free(ip_acl);
			free(acl_name);
			return -1;
		}
		p++;
	}
	
	ptr = strchr(p, '|');
	p = ptr + 1;
	
	while(*p != ';')
	{		
		memset(entry_tmp, '\0', 512);	
		ptr = strchr(p, '|')+1;
		strncpy(entry_tmp, p, ptr-p);
		if(0 == strcmp(entry_data, entry_tmp))
		{
			strncpy(str, ip_acl, p-ip_acl);
			strcat(str, ptr);
			nvram_set("ip_ext_acl", str);
			break;
		}
		p = ptr;
	}
		
	free(str);
	free(ip_acl);
	free(acl_name); 
    return 0;       
}

static int cli_set_ip_acl_std_no(struct users *u)
{
	int action = -1, res, flag=0;
	uint32_t srcIp=0, srcSubnet=0;
	char *ip_acl, *acl_name, *p, *ptr, *str, entry_data[64], temp[64];
	char name[ACL_NAME_LEN+3];
	IP_STANDARD_ACL_ENTRY entry;
	POLICY_CLASSIFY classify;
		    
	/* get value from nvram */
	ip_acl  = nvram_safe_get("ip_std_acl");
	acl_name = nvram_safe_get("acl_name");
	    	
	if(strlen(acl_name) == 0){
        if (ip_acl)
		    free(ip_acl);
        if (acl_name)
		    free(acl_name);
		return -1;
    }
	int action_flag = 0;
	cli_param_get_int(DYNAMIC_PARAM, ACL_MODE_POS, &action_flag, u);
	if(action_flag == ACL_DENY)
		action = ACL_ACT_DENY;
	else if(action_flag == ACL_PERMIT)
		action = ACL_ACT_PERMIT;
	
	int src_ip_flag = -1;
	struct in_addr s_ip, s_subnet;
	char src_ip[MAX_ARGV_LEN] = {'\0'}, src_subnet[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, &src_ip_flag, u);
	if(src_ip_flag == IP_ACL_SRC_ANY)
		flag = 1;
	else
	{
		cli_param_get_ipv4(STATIC_PARAM, 0, &s_ip, src_ip, sizeof(src_ip), u);
		cli_param_get_ipv4(DYNAMIC_PARAM, 0, &s_subnet, src_subnet, sizeof(src_subnet), u);
	
		srcIp = s_ip.s_addr;
		srcSubnet = s_subnet.s_addr;
	}
		
	entry.action = action;
	entry.src_ip = srcIp;
	entry.src_subnet = srcSubnet;
	entry.flag = flag;   /* 1: any  0:other*/
	entry.next = NULL;
	
	/* delete the entry */
	res = ip_std_acl_set(acl_name, &entry, ACL_ENTRY_DELETE, -1, 0x00ULL);
	/* entry is not exist or the acl name is not exist */
	if(res == 0)
	{
		vty_output("The rule has not existed in the access list.\n");
		free(ip_acl);
		free(acl_name);
		return 0;
	}
	
	/* write policy start*/
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	classify.type_flag = CLASSIFY_TYPE_IP;
	strcpy(classify.name, acl_name);
	/* get policy classify num based on acl with the name */
	res = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
	//if(res)	
		policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);
	/* write policy end*/
			
	/* modify nvram value */
	str = malloc(strlen(ip_acl));
	if(NULL == str)
	{
		free(ip_acl);
		free(acl_name);
		return -1;
	}
	memset(str, '\0', strlen(ip_acl));
		
	memset(entry_data, '\0', 64);
	sprintf(entry_data, "%d", action_flag);
	strcat(entry_data, ":");
	if(strlen(src_ip) > 0)
		strcat(entry_data, src_ip);
	strcat(entry_data, ":");
	if(strlen(src_subnet) > 0)
		strcat(entry_data, src_subnet);
	strcat(entry_data, "|");	
		
	memset(name, '\0', ACL_NAME_LEN+3);
	strcpy(name, acl_name);
	strcat(name, "|");
	p = strstr(ip_acl, name);
	
	if(NULL == p)
	{
		free(str);
		free(ip_acl);
		free(acl_name);
		return -1;
	}
	
	if(p != ip_acl)
	{
		memset(name, '\0', ACL_NAME_LEN+3);
		strcat(name, ";");
		strcat(name, acl_name);
		strcat(name, "|");
		p = strstr(ip_acl, name);
		
		if(NULL == p)
		{
			free(str);
			free(ip_acl);
			free(acl_name);
			return -1;
		}
		p++;
	}
	
	///////////////////
	ptr = strchr(p, '|');
	p = ptr + 1;
	
	while(*p != ';')
	{		
		memset(temp, '\0', 64);	
		ptr = strchr(p, '|')+1;
		strncpy(temp, p, ptr-p);
		if(0 == strcmp(entry_data, temp))
		{
			strncpy(str, ip_acl, p-ip_acl);
			strcat(str, ptr);
			nvram_set("ip_std_acl", str);
			break;
		}
		p = ptr;
	}
		
	free(str);
	free(ip_acl);
	free(acl_name); 
    return 0;       
}

static int cli_set_ipv6_acl_std(struct users *u)
{ 
	int action, res, flag=0, i=0, srcSubnet_v6=0;
	int num1 = 0, num2 = 0;
	struct in6_addr srcIPv6;
	char *ip_acl, *acl_name, *p, *str, buff[129];
	char name[ACL_NAME_LEN+3];
	IPV6_STANDARD_ACL_ENTRY entry;
	POLICY_CLASSIFY classify;
	
	/* get value from nvram */
	ip_acl  = nvram_safe_get("ipv6_std_acl");
	acl_name = nvram_safe_get("acl_name");

	if(strlen(acl_name) == 0){
        if (ip_acl)
		    free(ip_acl);
        if (acl_name)
		    free(acl_name);
		return -1;
    }
	int action_flag = 0;
	cli_param_get_int(DYNAMIC_PARAM, ACL_MODE_POS, &action_flag, u);
	if(action_flag == ACL_DENY)
		action = ACL_ACT_DENY;
	else if(action_flag == ACL_PERMIT)
		action = ACL_ACT_PERMIT;

	int src_ip_flag = -1;
	char src_ip[MAX_ARGV_LEN] = {'\0'};
	memset(&srcIPv6,0,sizeof(struct in6_addr));
	cli_param_get_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, &src_ip_flag, u);
	if(src_ip_flag == IP_ACL_SRC_ANY) {
		flag = 1;
	} else {
		cli_param_get_ipv6(STATIC_PARAM, 0, &srcIPv6, src_ip, sizeof(src_ip), u);
		cli_param_get_int(STATIC_PARAM, 14, &srcSubnet_v6, u);
		p = strchr(src_ip, '/');
		if(p != NULL) {
			*p = '\0';
		}
	}
	
	memset(&entry, '\0', sizeof(IPV6_STANDARD_ACL_ENTRY));	
	entry.action = action;
	memcpy(&entry.src_ipv6,&srcIPv6,sizeof(struct in6_addr));
	entry.src_subnet_v6 = srcSubnet_v6;
	entry.flag = flag;   /* 1: any  0:other*/
	entry.next = NULL;
	/*vty_output("acl:%x\n",sizeof(IPV6_STANDARD_ACL_ENTRY));

	for(i=0;i<16;i++){
		vty_output("%x \n", entry.src_ipv6.s6_addr[i]);
	}*/
		//buff[i]='\0';

	//vty_output("acl:%s\n", buff);//ynn 20170629 modify

	/* append the entry */
	int location = -1;
	if(!ISSET_CMD_MSKBIT(u, IP_ACL_LOCATION_MSK))
		res = ipv6_std_acl_set(acl_name, &entry, ACL_ENTRY_APPEND, -1, 0x00ULL);
	else
	{
		cli_param_get_int(DYNAMIC_PARAM, IP_ACL_LOCATION_POS, &location, u);
		res = ipv6_std_acl_set(acl_name, &entry, ACL_ENTRY_INSERT, location, 0x00ULL);
	}

	if(res == -1)
	{
		//vty_output("The rule has existed in the access list.\n");
		free(ip_acl);
		free(acl_name);
		return 0;
	}
	else if(res == -2)
	{
		vty_output("all ip standard acl entries number can not exceed %d!!!!\n", SIP_ACL_NUM+1);//ynn 20170629 modify
		free(ip_acl);
		free(acl_name);
		return 0;
	}

	/* write policy start*/
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	classify.type_flag = CLASSIFY_TYPE_IP;
	strcpy(classify.name, acl_name);
	/* get policy classify num based on acl with the name */
	num1 = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
	if(num1)	
	{
		/*
		*  add code to check all policy entry num 
		*/
		num2 = policy_set("", &classify, POLICY_ACL_ENTRY_NUM, 0, 0x00ULL);
		if(num2 >= POLICY_NUM)
			vty_output("Adding this rule, all policy entris number will exceed %d !\n", POLICY_NUM);
		else
			policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);
	}
	else
		policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);
	/* write policy end*/
		
	/* modify nvram value */		
	memset(name, '\0', ACL_NAME_LEN+3);
	strcpy(name, acl_name);
	strcat(name, "|");
	p = strstr(ip_acl, name);

	if(NULL == p)
	{
		free(ip_acl);
		free(acl_name);
		return -1;
	}

	if(p != ip_acl)
	{
		memset(name, '\0', ACL_NAME_LEN+3);
		strcat(name, ";");
		strcat(name, acl_name);
		strcat(name, "|");
		p = strstr(ip_acl, name);
		
		if(NULL == p)
		{
			free(ip_acl);
			free(acl_name);
			return -1;
		}
		p++;
	}

	str = malloc(strlen(ip_acl) + 128);
	if(NULL == str)
	{
		free(ip_acl);
		free(acl_name);
		return -1;
	}
	memset(str, '\0', strlen(ip_acl) + 128);

	/* append */
	if(!ISSET_CMD_MSKBIT(u, IP_ACL_LOCATION_MSK))
	{

        p = strchr(p, ';');
		strncpy(str, ip_acl, p-ip_acl);

		sprintf(str, "%s%d", str, action);
		strcat(str, ",");
	
		if(src_ip)
		{
			if(0 == strcmp(src_ip, "any"))
				strcat(str, src_ip);
			else
			{
				strcat(str, src_ip);
				sprintf(str, "%s/%d", str, srcSubnet_v6);
			}
		}
			
		strcat(str, "|");
		strcat(str, ";");
	}
	/* insert */
	else
	{//vty_output("ipv6 add insert\n");
		while(*p != ';')
		{
			i++;
			p = strchr(p, '|') + 1;
			if(i == location)
			{
				strncpy(str, ip_acl, p-ip_acl);
				
				sprintf(str, "%s%d", str, action);
				strcat(str, ",");
				
				if(src_ip)
				{
					if(0 == strcmp(src_ip, "any"))
						strcat(str, src_ip);
					else
					{
						strcat(str, src_ip);
						sprintf(str, "%s/%d", str, srcSubnet_v6);
					}
				}
				strcat(str, "|");
				
				strcat(str, p);
			}
		}
	}

	nvram_set("ipv6_std_acl", str);
//vty_output("ipv6 sta acl:%s\n", str);
	free(str);
	free(ip_acl);
	free(acl_name); 
	return 0;
}

static int cli_set_ipv6_acl_std_no(struct users *u)
{
	int action, res, flag=0, srcSubnet_v6=0;
	struct in6_addr srcIPv6;
	char *ip_acl, *acl_name, *p, *ptr, *str, entry_data[129], temp[129], buff[129];
	char name[ACL_NAME_LEN+3];
	IPV6_STANDARD_ACL_ENTRY entry;
	POLICY_CLASSIFY classify;
		    
	/* get value from nvram */
	ip_acl  = nvram_safe_get("ipv6_std_acl");
	acl_name = nvram_safe_get("acl_name");
	    	
	if(strlen(acl_name) == 0){
        if (ip_acl)
		    free(ip_acl);
        if (acl_name)
		    free(acl_name);
		return -1;
    }
	int action_flag = 0;
	cli_param_get_int(DYNAMIC_PARAM, ACL_MODE_POS, &action_flag, u);
	if(action_flag == ACL_DENY)
		action = ACL_ACT_DENY;
	else if(action_flag == ACL_PERMIT)
		action = ACL_ACT_PERMIT;
	
	int src_ip_flag = -1;
	struct in_addr s_ip, s_subnet;
	char src_ip[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_int(DYNAMIC_PARAM, IP_ACL_SRC_POS, &src_ip_flag, u);
	if(src_ip_flag == IP_ACL_SRC_ANY)
		flag = 1;
	else
	{
		cli_param_get_ipv6(STATIC_PARAM, 0, &srcIPv6, src_ip, sizeof(src_ip), u);
		cli_param_get_int(STATIC_PARAM, 14, &srcSubnet_v6, u);
		p = strchr(src_ip, '/');
		if(p != NULL) {
			*p = '\0';
		}
	}
		
	memset(&entry, '\0', sizeof(IPV6_STANDARD_ACL_ENTRY));	
	entry.action = action;
	entry.src_ipv6 = srcIPv6;
	entry.src_subnet_v6 = srcSubnet_v6;
	entry.flag = flag;   /* 1: any  0:other*/
	entry.next = NULL;
	
	/* delete the entry */
	res = ipv6_std_acl_set(acl_name, &entry, ACL_ENTRY_DELETE, -1, 0x00ULL);
	/* entry is not exist or the acl name is not exist */
	if(res == 0)
	{
		vty_output("The rule has not existed in the access list.\n");
		free(ip_acl);
		free(acl_name);
		return 0;
	}
	
	/* write policy start*/
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	classify.type_flag = CLASSIFY_TYPE_IP;
	strcpy(classify.name, acl_name);
	/* get policy classify num based on acl with the name */
	res = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
//	if(res)	
		policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);
	/* write policy end*/
			
	/* modify nvram value */
	str = malloc(strlen(ip_acl));
	if(NULL == str)
	{
		free(ip_acl);
		free(acl_name);
		return -1;
	}
	memset(str, '\0', strlen(ip_acl));
		
	memset(entry_data, '\0', sizeof(entry_data));
	sprintf(entry_data, "%d", action_flag);
	strcat(entry_data, ",");	
	if(src_ip)
	{
		if(0 == strcmp(src_ip, "any"))
			strcat(entry_data, src_ip);
		else
		{
			strcat(entry_data, buff);
			sprintf(entry_data, "%s/%d", entry_data, srcSubnet_v6);												
		}
	}	
	
	strcat(entry_data, "|");
		
	memset(name, '\0', ACL_NAME_LEN+3);
	strcpy(name, acl_name);
	strcat(name, "|");
	p = strstr(ip_acl, name);
	
	if(NULL == p)
	{
		free(str);
		free(ip_acl);
		free(acl_name);
		return -1;
	}
	
	if(p != ip_acl)
	{
		memset(name, '\0', ACL_NAME_LEN+3);
		strcat(name, ";");
		strcat(name, acl_name);
		strcat(name, "|");
		p = strstr(ip_acl, name);
		
		if(NULL == p)
		{
			free(str);
			free(ip_acl);
			free(acl_name);
			return -1;
		}
		p++;
	}
	
	ptr = strchr(p, '|');
	p = ptr + 1;
	
	while(*p != ';')
	{		
		memset(temp, '\0', sizeof(temp));	
		ptr = strchr(p, '|')+1;
		strncpy(temp, p, ptr-p);
		if(0 == strcmp(entry_data, temp))
		{
			strncpy(str, ip_acl, p-ip_acl);
			strcat(str, ptr);
			nvram_set("ipv6_std_acl", str);
			break;
		}
		p = ptr;
	}
		
	free(str);
	free(ip_acl);
	free(acl_name); 
    return 0;       
}

static int cli_set_mac_acl(struct users *u)
{ 
	int action = -1, res;
	int num1 = 0, num2 = 0;
	uint16_t etherType=0;
	uint64_t srcMac=0x00ULL, dstMac=0x00ULL;
	char *mac_acl, *acl_name, *p, *str;
	char name[ACL_NAME_LEN+3];
	MAC_ACL_ENTRY entry;
	POLICY_CLASSIFY classify;
	   
	/* get value from nvram */
	mac_acl  = nvram_safe_get("mac_acl");
	acl_name = nvram_safe_get("acl_name");
	    	
	if(strlen(acl_name) == 0){
        if (mac_acl)
		    free(mac_acl);
        if (acl_name)
		    free(acl_name);
		return -1;
    }
	int action_flag = 0;
	cli_param_get_int(DYNAMIC_PARAM, ACL_MODE_POS, &action_flag, u);

	if(action_flag == ACL_DENY)
		action = ACL_ACT_DENY;
	else if(action_flag == ACL_PERMIT)		
		action = ACL_ACT_PERMIT;

	int src_host_flag = 0, dst_host_flag = 0, ether_type_flag = 0;
	char src_mac[MAX_ARGV_LEN] = {'\0'}, dst_mac[MAX_ARGV_LEN] = {'\0'}, ether_type[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_int(DYNAMIC_PARAM, MAC_ACL_SRC_POS, &src_host_flag, u);
	cli_param_get_int(DYNAMIC_PARAM, MAC_ACL_DST_POS, &dst_host_flag, u);
	cli_param_get_int(STATIC_PARAM, 0, &ether_type_flag, u);

	if(src_host_flag == MAC_ACL_SRC_HOST)
	{
		cli_param_get_string(DYNAMIC_PARAM, 0, src_mac, u);
		macstr_to_uint64(src_mac, &srcMac);
	}
		
	if(dst_host_flag == MAC_ACL_DST_HOST)
	{
		cli_param_get_string(DYNAMIC_PARAM, 1, dst_mac, u);
		macstr_to_uint64(dst_mac, &dstMac);
	}

	if(ether_type_flag != 0)
	{
		ether_type_flag &= 0x0000ffff;
		etherType = ether_type_flag;;
		sprintf(ether_type, "%d", ether_type_flag);
	}
	
	entry.action = action;
	entry.src_mac = srcMac;
	entry.dst_mac = dstMac;
	entry.ether_type = etherType;
	entry.next = NULL;

	/* add the entry */
	res = mac_acl_set(acl_name, &entry, ACL_ENTRY_APPEND, -1, 0x00ULL);
	if(res == -1)
	{
		//vty_output("ma_permit fail, because the entry has be in the acl list, not to be write\n");
		vty_output("The rule has existed in the access list.\n");//ynn 20170622
		free(mac_acl);
		free(acl_name);
		return 0;
	}
	else if(res == -2)
	{
		vty_output("all mac acl entries number can not exceed %d!!!!\n", MAC_ACL_NUM+1);//ynn 20170629 modify
		free(mac_acl);
		free(acl_name);
		return 0;
	}

//	/* write policy start*/
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	classify.type_flag = CLASSIFY_TYPE_MAC;
	strcpy(classify.name, acl_name);
	/* get policy classify num based on acl with the name */
	num1 = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
	if(num1)	
	{		
		/*
		*  add code to check all policy entry num 
		*/
		num2 = policy_set("", &classify, POLICY_ACL_ENTRY_NUM, 0, 0x00ULL);
		if(num2 > POLICY_NUM)
			vty_output("Adding this rule, all policy entris number will exceed %d !\n", POLICY_NUM);
		else
			policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);
	}
	else
		policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);
	/* write policy end*/
		
	/* modify nvram value */		
	memset(name, '\0', ACL_NAME_LEN+3);
	strcpy(name, acl_name);
	strcat(name, "|");
	p = strstr(mac_acl, name);
	
	if(NULL == p)
	{
		free(mac_acl);
		free(acl_name);
		return -1;
	}
	
	if(p != mac_acl)
	{
		memset(name, '\0', ACL_NAME_LEN+3);
		strcat(name, ";");
		strcat(name, acl_name);
		strcat(name, "|");
		p = strstr(mac_acl, name);
		
		if(NULL == p)
		{
			free(mac_acl);
			free(acl_name);
			return -1;
		}
		p++;
	}
	
	str = malloc(strlen(mac_acl) + 64);
	if(NULL == str)
	{
		free(mac_acl);
		free(acl_name);
		return -1;
	}
	memset(str, '\0', strlen(mac_acl) + 64);
	
	p = strchr(p, ';');
	strncpy(str, mac_acl, p-mac_acl);
	
	sprintf(str, "%s%d", str, action);
	strcat(str, ":");
	
	if(strlen(src_mac) > 0)
		sprintf(str, "%s%04x%08x", str, (uint16_t)(srcMac>>32), (uint32_t)srcMac);
	strcat(str, ":");
		
	if(strlen(dst_mac) > 0)
		sprintf(str, "%s%04x%08x", str, (uint16_t)(dstMac>>32), (uint32_t)dstMac);
	strcat(str, ":");
		
	if(strlen(ether_type) > 0)
		strcat(str, ether_type);
	strcat(str, "|");
	
	strcat(str, p);
	
	nvram_set("mac_acl", str);
	
	free(str);
	free(mac_acl);
	free(acl_name); 
    return 0;       
}

static int nfunc_mac_acl_any_any(struct users *u)
{
	int action = -1, res;
	uint16_t etherType=0;
	uint64_t srcMac=0x00ULL, dstMac=0x00ULL;
	char *mac_acl, *acl_name, *p, *ptr, *str, entry_data[64], temp[64];
	char name[ACL_NAME_LEN+3];
	MAC_ACL_ENTRY entry;
	POLICY_CLASSIFY classify;
		    
	/* get value from nvram */
	mac_acl  = nvram_safe_get("mac_acl");
	acl_name = nvram_safe_get("acl_name");
	    	
	if(strlen(acl_name) == 0)
	{
        if (mac_acl)
		    free(mac_acl);
        if (acl_name)
		    free(acl_name);
		return -1;
	}
		
	int action_flag = 0;
	cli_param_get_int(DYNAMIC_PARAM, ACL_MODE_POS, &action_flag, u);
	if(action_flag == ACL_DENY)
		action = ACL_ACT_DENY;
	else if(action_flag == ACL_PERMIT)
		action = ACL_ACT_PERMIT;
	
	int src_host_flag = 0, dst_host_flag = 0, ether_type_flag = 0;
	char src_mac[MAX_ARGV_LEN] = {'\0'}, dst_mac[MAX_ARGV_LEN] = {'\0'}, ether_type[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_int(DYNAMIC_PARAM, MAC_ACL_SRC_POS, &src_host_flag, u);
	cli_param_get_int(DYNAMIC_PARAM, MAC_ACL_DST_POS, &dst_host_flag, u);
	cli_param_get_int(STATIC_PARAM, 0, &ether_type_flag, u);
	
	if(src_host_flag == MAC_ACL_SRC_HOST)
	{
		cli_param_get_string(DYNAMIC_PARAM, 0, src_mac, u);
		macstr_to_uint64(src_mac, &srcMac);
	}
	//vty_output("src_mac = %08x%08x\n", (uint32_t)(srcMac>>32), (uint32_t)(srcMac));
		
	if(dst_host_flag == MAC_ACL_DST_HOST)
	{
		cli_param_get_string(DYNAMIC_PARAM, 1, dst_mac, u);
		macstr_to_uint64(dst_mac, &dstMac);
	}
	//vty_output("dst_mac = %08x%08x\n", (uint32_t)(dstMac>>32), (uint32_t)(dstMac));

	if(ether_type_flag != 0)
	{
		ether_type_flag &= 0x0000ffff;
		etherType = (uint16_t)ether_type_flag;
		sprintf(ether_type, "%d", ether_type_flag);
	}
		
	entry.action = action;
	entry.src_mac = srcMac;
	entry.dst_mac = dstMac;
	entry.ether_type = etherType;
	entry.next = NULL;
	
	/* delete the entry */
	res = mac_acl_set(acl_name, &entry, ACL_ENTRY_DELETE, -1, 0x00ULL);
	/* entry is not exist or the acl name is not exist */
	if(res == 0)
	{
		vty_output("The rule has not existed in the access list.\n");
		free(mac_acl);
		free(acl_name);
		return 0;
	}
	
	/* write policy start*/
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	classify.type_flag = CLASSIFY_TYPE_MAC;
	strcpy(classify.name, acl_name);
	/* get policy classify num based on acl with the name */
	res = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
	//if(res)	
		policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);	
	/* write policy end*/
		
	/* modify nvram value */
	str = malloc(strlen(mac_acl));
	if(NULL == str)
	{
		free(mac_acl);
		free(acl_name);
		return -1;
	}
	memset(str, '\0', strlen(mac_acl));
		
	memset(entry_data, '\0', 64);
	sprintf(entry_data, "%d", action_flag);
	strcat(entry_data, ":");
	if(strlen(src_mac) > 0)
		sprintf(entry_data, "%s%04x%08x", entry_data, (uint16_t)(srcMac>>32), (uint32_t)(srcMac));
	strcat(entry_data, ":");
	if(strlen(dst_mac) > 0)
		sprintf(entry_data, "%s%04x%08x", entry_data, (uint16_t)(dstMac>>32), (uint32_t)(dstMac));
	strcat(entry_data, ":");
	if(strlen(ether_type) > 0)
		strcat(entry_data, ether_type);
	strcat(entry_data, "|");	
		
	memset(name, '\0', ACL_NAME_LEN+3);
	strcpy(name, acl_name);
	strcat(name, "|");
	p = strstr(mac_acl, name);
	
	if(NULL == p)
	{
		free(str);
		free(mac_acl);
		free(acl_name);
		return -1;
	}
	
	if(p != mac_acl)
	{
		memset(name, '\0', ACL_NAME_LEN+3);
		strcat(name, ";");
		strcat(name, acl_name);
		strcat(name, "|");
		p = strstr(mac_acl, name);
		
		if(NULL == p)
		{
			free(str);
			free(mac_acl);
			free(acl_name);
			return -1;
		}
		p++;
	}
	
	///////////////////
	ptr = strchr(p, '|');
	p = ptr + 1;
	
	while(*p != ';')
	{		
		memset(temp, '\0', 64);	
		ptr = strchr(p, '|')+1;
		strncpy(temp, p, ptr-p);
		if(0 == strcmp(entry_data, temp))
		{
			strncpy(str, mac_acl, p-mac_acl);
			strcat(str, ptr);
			nvram_set("mac_acl", str);
			break;
		}
		p = ptr;
	}
		
	free(str);
	free(mac_acl);
	free(acl_name); 
    return 0;       
}

int func_ip_acl_ext(struct users *u)
{
	int retval = -1;
	
	retval = cli_set_ip_acl_ext(u);

	return retval;
}

int func_ip_acl_std(struct users *u)
{
	int retval = -1;
	
	retval = cli_set_ip_acl_std(u);

	return retval;
}

int nfunc_ip_acl_ext(struct users *u)
{
	int retval = -1;
	
	retval = cli_set_ip_acl_ext_no(u);

	return retval;
}

int nfunc_ip_acl_std(struct users *u)
{
	int retval = -1;
	
	retval = cli_set_ip_acl_std_no(u);

	return retval;
}

int func_ipv6_acl_std(struct users *u)
{
	int retval = -1;
	
	retval = cli_set_ipv6_acl_std(u);

	return retval;
}

int nfunc_ipv6_acl_std(struct users *u)
{
	int retval = -1;
	
	retval = cli_set_ipv6_acl_std_no(u);

	return retval;
}

int func_mac_acl(struct users *u)
{
	int retval = -1;
	
	retval = cli_set_mac_acl(u);

	return retval;
}

int nfunc_mac_acl(struct users *u)
{
	int retval = -1;
	
	retval = nfunc_mac_acl_any_any(u);

	return retval;
}

