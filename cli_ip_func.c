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

#include "cli_ip_func.h"
#include "bcmutils.h"
#include "acl_utils.h"
#include "cli_dhcp_func.h"

#define ARP_CONFIG_FILE "/tmp/arp_config"

/*------------------------------------------ip acc_list---------------------*/
/* set extended acl */
static int cli_set_ext_acl(char *acl_name)
{
	char *ip_acl  = nvram_safe_get("ip_ext_acl");
	char *str;
	IP_STANDARD_ACL_ENTRY entry1;
	IP_EXTENDED_ACL_ENTRY entry2;
	MAC_ACL_ENTRY entry3;
	int res;

	//vty_output("set ip acl!!!!!\n");
	memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
	memset(&entry3, '\0', sizeof(MAC_ACL_ENTRY));

	/* check if name exists in standard acl list, -1:not exist, 0:exist */
	res = ip_std_acl_set(acl_name, &entry1, ACL_NAME_CHECK, -1, 0x00ULL);
	/* exist */
	if(0 == res)
	{
		free(ip_acl);
		printf("A named Standard IP access list with this name already exists\n");
		return -2;
	}

	/* check if name exists in mac list, -1:not exist, 0:exist */
	res = mac_acl_set(acl_name, &entry3, ACL_NAME_CHECK, -1, 0x00ULL);
	/* exist */
	if(0 == res)
	{
		free(ip_acl);
		printf("A named MAC access list with this name already exists!\n");
		return -2;
	}

	/* add name to acl struct */
	res = ip_ext_acl_set(acl_name, &entry2, ACL_LIST_ADD, -1, 0x00ULL);

	/* this name has be exist or malloc space fail for new node */
	if(res == -1){
		free(ip_acl);
		return -1;
	}

	/* name is not exist */
	str = malloc(strlen(ip_acl) + 64);
	if(NULL == str)
	{
		free(ip_acl);
		return -1;
	}
	memset(str, '\0', strlen(ip_acl) + 64);
	strcpy(str, ip_acl);
	strcat(str, acl_name);
	strcat(str, "|;");

	nvram_set("ip_ext_acl", str);

	free(str);
	free(ip_acl);
	return CLI_SUCCESS;
}

/* set standard acl */
static int cli_set_std_acl(char *acl_name)
{
	char *ip_acl  = nvram_safe_get("ip_std_acl");
	char *str;
	IP_STANDARD_ACL_ENTRY entry1;
	IP_EXTENDED_ACL_ENTRY entry2;
	MAC_ACL_ENTRY entry3;
	int res;

	//vty_output("set ip acl!!!!!\n");
	memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
	memset(&entry3, '\0', sizeof(MAC_ACL_ENTRY));

	/* check if name exists in extended acl list, -1:not exist, 0:exist */
	res = ip_ext_acl_set(acl_name, &entry2, ACL_NAME_CHECK, -1, 0x00ULL);
	/* exist */
	if(0 == res)
	{
		free(ip_acl);
		printf("A named Extended IP access list with this name already exists\n");
		return -2;
	}

	/* check if name exists in mac list, -1:not exist, 0:exist */
	res = mac_acl_set(acl_name, &entry3, ACL_NAME_CHECK, -1, 0x00ULL);
	/* exist */
	if(0 == res)
	{
		free(ip_acl);
		printf("A named MAC access list with this name already exists!\n");
		return -2;
	}

	/* add name to acl struct */
	res = ip_std_acl_set(acl_name, &entry1, ACL_LIST_ADD, -1, 0x00ULL);

	/* this name has be exist or malloc space fail for new node */
	if(res == -1){
		free(ip_acl);
		return -1;
	}
	/* name is not exist */
	str = malloc(strlen(ip_acl) + 64);
	if(NULL == str)
	{
		free(ip_acl);
		return -1;
	}
	memset(str, '\0', strlen(ip_acl) + 64);
	strcpy(str, ip_acl);
	strcat(str, acl_name);
	strcat(str, "|;");

	nvram_set("ip_std_acl", str);

	free(str);
	free(ip_acl);
	return CLI_SUCCESS;
}

/* delete ip extended acl list with specific name */
static int cli_delete_ip_ext_acl_list(char *name)
{
	int res, i, flag=0;
	IP_EXTENDED_ACL_ENTRY entry;
	char *acl_name, *ip_acl, *port_acl, *buff, *p, *ptr;
	char temp[ACL_NAME_LEN+3], port_acl_name[1024];
	POLICY_CLASSIFY classify;

	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	memset(&entry, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));

	/* check if acl name is exist */
	res = ip_ext_acl_set(name, &entry, ACL_NAME_CHECK, -1, 0x00ULL);
	if(res)
	{
		vty_output("Can not find IP Extended Access-List %s\n", name);
		return -1;
	}

	/* check if this acl is included in policy-map */
//	classify.type_flag = CLASSIFY_TYPE_IP;
//	strcpy(classify.name, name);
//	/* get policy classify num based on acl with the name */
//	res = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
//	if(res)
//	{
//		vty_output("IP Extended Access-List %s is included in policy-map, please delete it from policy-map first!\n", name);
//		return -1;
//	}

	/* delete this acl */
	ip_ext_acl_set(name, &entry, ACL_LIST_DEL, -1, 0x00ULL);

	/* following is to modify nvram value */
	acl_name = nvram_safe_get("acl_name");
	ip_acl  = nvram_safe_get("ip_ext_acl");
	//port_acl = nvram_safe_get("port_ip_acl");
	port_acl = cli_nvram_safe_get(CLI_PORT_ACL, "port_ip_acl");

	/* set acl_name */
	if(0 == strcmp(acl_name, name))
		nvram_set("acl_name","");

	/* set ip_acl */
	memset(temp, '\0', ACL_NAME_LEN+3);
	strcpy(temp, name);
	strcat(temp, "|");
	p = strstr(ip_acl, temp);

	if(NULL == p)
	{
		free(ip_acl);
		free(acl_name);
		free(port_acl);
		return -1;
	}

	if(p != ip_acl)
	{
		memset(temp, '\0', ACL_NAME_LEN+3);
		strcat(temp, ";");
		strcat(temp, name);
		strcat(temp, "|");
		p = strstr(ip_acl, temp);

		if(NULL == p)
		{
			free(ip_acl);
			free(acl_name);
			free(port_acl);
			return -1;
		}
		p++;
	}

	buff = malloc(strlen(ip_acl));
	if(NULL == buff)
	{
		free(ip_acl);
		free(acl_name);
		free(port_acl);
		return -1;
	}
	memset(buff, '\0', strlen(ip_acl));

	strncpy(buff, ip_acl, p-ip_acl);
	p = strchr(p, ';');
	p++;
	strcat(buff, p);

	nvram_set("ip_ext_acl", buff);

	/* set port_ip_acl */
	p = port_acl;
	memset(port_acl_name, '\0', 1024);
	for(i = 0; i < PNUM; i++)
	{
		memset(temp, '\0', ACL_NAME_LEN+3);
		ptr = strchr(p, ',');
		strncpy(temp, p, ptr-p);

		if(0 == strcmp(temp, name))
		{
			flag = 1;
			strcat(port_acl_name, ",");
		}
		else
		{
			strcat(port_acl_name, temp);
			strcat(port_acl_name, ",");
		}
		p = ptr+1;
	}

	if(flag)
		nvram_set("port_ip_acl", port_acl_name);

	free(buff);
	free(ip_acl);
	free(acl_name);
	free(port_acl);
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Deleted IP extended acl list with name %s, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

/* delete ip standard acl list with specific name */
static int cli_delete_ip_std_acl_list(char *name)
{
	int res, i, flag=0;
	IP_STANDARD_ACL_ENTRY entry;
	char *acl_name, *ip_acl, *port_acl, *buff, *p, *ptr;
	char temp[ACL_NAME_LEN+3], port_acl_name[1024];
	POLICY_CLASSIFY classify;

	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	memset(&entry, '\0', sizeof(IP_STANDARD_ACL_ENTRY));

	/* check if acl name is exist */
	res = ip_std_acl_set(name, &entry, ACL_NAME_CHECK, -1, 0x00ULL);
	if(res)
	{
		vty_output("Can not find IP Standard Access-List %s\n", name);
		return -1;
	}

	/* write policy start*/
//	classify.type_flag = CLASSIFY_TYPE_IP;
//	strcpy(classify.name, name);
//	/* get policy classify num based on acl with the name */
//	res = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
//	if(res)
//	{
//		vty_output("IP Standard Access-List %s is included in policy-map, please delete it from policy-map first!\n", name);
//		return -1;
//	}

	/* delete this ip acl */
	ip_std_acl_set(name, &entry, ACL_LIST_DEL, -1, 0x00ULL);

	/* following is to modify nvram value */
	acl_name = nvram_safe_get("acl_name");
	ip_acl  = nvram_safe_get("ip_std_acl");
	//port_acl = nvram_safe_get("port_ip_acl");
	port_acl = cli_nvram_safe_get(CLI_PORT_ACL, "port_ip_acl");

	/* set acl_name */
	if(0 == strcmp(acl_name, name))
		nvram_set("acl_name","");

	/* set ip_acl */
	memset(temp, '\0', ACL_NAME_LEN+3);
	strcpy(temp, name);
	strcat(temp, "|");
	p = strstr(ip_acl, temp);

	if(NULL == p)
	{
		free(ip_acl);
		free(acl_name);
		free(port_acl);
		return -1;
	}

	if(p != ip_acl)
	{
		memset(temp, '\0', ACL_NAME_LEN+3);
		strcat(temp, ";");
		strcat(temp, name);
		strcat(temp, "|");
		p = strstr(ip_acl, temp);

		if(NULL == p)
		{
			free(ip_acl);
			free(acl_name);
			free(port_acl);
			return -1;
		}
		p++;
	}

	buff = malloc(strlen(ip_acl));
	if(NULL == buff)
	{
		free(ip_acl);
		free(acl_name);
		free(port_acl);
		return -1;
	}
	memset(buff, '\0', strlen(ip_acl));

	strncpy(buff, ip_acl, p-ip_acl);
	p = strchr(p, ';');
	p++;
	strcat(buff, p);

	nvram_set("ip_std_acl", buff);

	/* set port_ip_acl */
	p = port_acl;
	memset(port_acl_name, '\0', 1024);
	for(i = 0; i < PNUM; i++)
	{
		memset(temp, '\0', ACL_NAME_LEN+3);
		ptr = strchr(p, ',');
		strncpy(temp, p, ptr-p);

		if(0 == strcmp(temp, name))
		{
			flag = 1;
			strcat(port_acl_name, ",");
		}
		else
		{
			strcat(port_acl_name, temp);
			strcat(port_acl_name, ",");
		}
		p = ptr+1;
	}

	if(flag)
		nvram_set("port_ip_acl", port_acl_name);

	free(buff);
	free(ip_acl);
	free(acl_name);
	free(port_acl);
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Deleted IP standard acl list with name %s, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int func_ip_acl_ext_name(struct users *u)
{
	char acl_name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(DYNAMIC_PARAM, 0, acl_name, u);

	if(cli_set_ext_acl(acl_name) == -2)
		return -1;

	nvram_set("acl_name", acl_name);
	syslog(LOG_NOTICE, "[CONFIG-5-IP]: The IP access list standard was set to %s, %s\n", acl_name, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

int func_ip_acl_std_name(struct users *u)
{
	char acl_name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(DYNAMIC_PARAM, 0, acl_name, u);

	if(cli_set_std_acl(acl_name) == -2)
		return -1;

	nvram_set("acl_name", acl_name);
	syslog(LOG_NOTICE, "[CONFIG-5-IP]: The IP access list standard was set to %s, %s\n", acl_name, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

int nfunc_ip_acl_ext_name(struct users *u)
{
	char acl_name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(DYNAMIC_PARAM, 0, acl_name, u);

	cli_delete_ip_ext_acl_list(acl_name);

	return 0;
}


int nfunc_ip_acl_std_name(struct users *u)
{
	char acl_name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(DYNAMIC_PARAM, 0, acl_name, u);

	cli_delete_ip_std_acl_list(acl_name);

	return 0;
}
/*------------------------------ipv6---------------------------------------------*/

/* set standard acl */
static int cli_set_std_ipv6_acl(char *acl_name)
{
	char *p, *ptr;
	char name[ACL_NAME_LEN+3];
	char *ip_acl  = nvram_safe_get("ipv6_std_acl");
	char *str;
	IP_STANDARD_ACL_ENTRY entry1;
	IP_EXTENDED_ACL_ENTRY entry2;
	IPV6_STANDARD_ACL_ENTRY entry3;
	int res;

	//printf("set ip acl!!!!!\n");
	memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
	memset(&entry3, '\0', sizeof(IPV6_STANDARD_ACL_ENTRY));

	/* check if name exists in extended acl list, -1:not exist, 0:exist */
	res = ip_std_acl_set(acl_name, &entry1, ACL_NAME_CHECK, -1, 0x00ULL);

	/* exist */
	if(0 == res)
	{
		free(ip_acl);
		printf("A named Standard IP access list with this name already exists\n");
		return -2;
	}
	else
	{
		res = ip_ext_acl_set(acl_name, &entry2, ACL_NAME_CHECK, -1, 0x00ULL);
		if(0 == res)
		{
			free(ip_acl);
			printf("A named Extended IP access list with this name already exists\n");
			return -2;
		}
	}

	/* add name to acl struct */
	res = ipv6_std_acl_set(acl_name, &entry3, ACL_LIST_ADD, -1, 0x00ULL);

	/* this name has be exist or malloc space fail for new node */
	if(res == -1){
		free(ip_acl);
		return -1;
	}
	/* name is not exist */
	str = malloc(strlen(ip_acl) + 64);
	if(NULL == str)
	{
		free(ip_acl);
		return -1;
	}
	memset(str, '\0', strlen(ip_acl) + 64);
	strcpy(str, ip_acl);
	strcat(str, acl_name);
	strcat(str, "|;");

	nvram_set("ipv6_std_acl", str);

	free(str);
	free(ip_acl);

	return 0;
}

/* delete ipv6 standard acl list with specific name */
static int cli_delete_ipv6_std_acl_list(char *name)
{
	int res, i, flag=0;
	IPV6_STANDARD_ACL_ENTRY entry;
	char *acl_name, *ip_acl, *port_acl, *buff, *p, *ptr;
	char temp[ACL_NAME_LEN+3], port_acl_name[1024];
	POLICY_CLASSIFY classify;

	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	memset(&entry, '\0', sizeof(IPV6_STANDARD_ACL_ENTRY));

	/* check if acl name is exist */
	res = ipv6_std_acl_set(name, &entry, ACL_NAME_CHECK, -1, 0x00ULL);
	if(res)
	{
		printf("Can not find IPV6 Standard Access-List %s\n", name);
		return -1;
	}

	/* check if this acl is included in policy-map */
//	classify.type_flag = CLASSIFY_TYPE_IP;
//	strcpy(classify.name, name);
//	/* get policy classify num based on acl with the name */
//	res = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
//	if(res)
//	{
//		printf("IPV6 Standard Access-List %s is included in policy-map, please delete it from policy-map first!\n", name);
//		return -1;
//	}

	/* delete this ip acl */
	ipv6_std_acl_set(name, &entry, ACL_LIST_DEL, -1, 0x00ULL);

	/* set policy map */
	policy_set("", &classify, POLICY_WRITE_REGS, 0, 0x00ULL);

	/* following is to modify nvram value */
	acl_name = nvram_safe_get("acl_name");
	ip_acl  = nvram_safe_get("ipv6_std_acl");
	//port_acl = nvram_safe_get("port_ip_acl");
	port_acl = cli_nvram_safe_get(CLI_PORT_ACL, "port_ipv6_acl");

	/* set acl_name */
	if(0 == strcmp(acl_name, name))
		nvram_set("acl_name","");

	/* set ip_acl */
	memset(temp, '\0', ACL_NAME_LEN+3);
	strcpy(temp, name);
	strcat(temp, "|");
	p = strstr(ip_acl, temp);

	if(NULL == p)
	{
		free(ip_acl);
		free(acl_name);
		free(port_acl);
		return -1;
	}

	if(p != ip_acl)
	{
		memset(temp, '\0', ACL_NAME_LEN+3);
		strcat(temp, ";");
		strcat(temp, name);
		strcat(temp, "|");
		p = strstr(ip_acl, temp);

		if(NULL == p)
		{
			free(ip_acl);
			free(acl_name);
			free(port_acl);
			return -1;
		}
		p++;
	}

	buff = malloc(strlen(ip_acl));
	if(NULL == buff)
	{
		free(ip_acl);
		free(acl_name);
		free(port_acl);
		return -1;
	}
	memset(buff, '\0', strlen(ip_acl));

	strncpy(buff, ip_acl, p-ip_acl);
	p = strchr(p, ';');
	p++;
	strcat(buff, p);

	nvram_set("ipv6_std_acl", buff);

	/* set port_ipv6_acl */
	p = port_acl;
	memset(port_acl_name, '\0', 1024);
	for(i = 0; i < PNUM; i++)
	{
		memset(temp, '\0', ACL_NAME_LEN+3);
		ptr = strchr(p, ',');
		strncpy(temp, p, ptr-p);

		if(0 == strcmp(temp, name))
		{
			flag = 1;
			strcat(port_acl_name, ",");
		}
		else
		{
			strcat(port_acl_name, temp);
			strcat(port_acl_name, ",");
		}
		p = ptr+1;
	}

	if(flag)
		nvram_set("port_ipv6_acl", port_acl_name);

	free(buff);
	free(ip_acl);
	free(acl_name);
	free(port_acl);
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Deleted IPV6 standard acl list with name %s, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int func_ipv6_acl_std_name(struct users *u)
{
	char acl_name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(DYNAMIC_PARAM, 0, acl_name, u);

	if(cli_set_std_ipv6_acl(acl_name) == -2)
		return -1;

	nvram_set("acl_name", acl_name);
	syslog(LOG_NOTICE, "[CONFIG-5-IP]: The IPv6 access list standard was set to %s, %s\n", acl_name, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

int nfunc_ipv6_acl_std_name(struct users *u)
{
	char acl_name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(DYNAMIC_PARAM, 0, acl_name, u);

	cli_delete_ipv6_std_acl_list(acl_name);

	return 0;
}

int func_ipv6_name(struct users *u)
{
	char *lan_ipv6dns = nvram_safe_get("lan_ipv6dns");
	
	struct in6_addr s_addr;
	char nameserver[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_ipv6(STATIC_PARAM, 0, &s_addr, nameserver, sizeof(nameserver), u);

	if(strcmp(lan_ipv6dns, nameserver)) 
	{
		scfgmgr_set("lan_ipv6dns", nameserver);
		SYSTEM("/usr/sbin/rc relay restart  > /dev/null 2>&1");
	}
	free(lan_ipv6dns);

	syslog(LOG_NOTICE, "[CONFIG-5-IPV6]:The IPv6 DNS was set to %s, %s\n", nameserver, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int nfunc_ipv6_name_server()
{
	char *lan_ipv6dns = nvram_safe_get("lan_ipv6dns");

	if(strlen(lan_ipv6dns) > 0) 
	{
		scfgmgr_set("lan_ipv6dns", "");
		SYSTEM("/usr/sbin/rc relay restart  > /dev/null 2>&1");
	}
	free(lan_ipv6dns);

	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set IPv6 DNS to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int func_ipv6_addr(struct users *u)
{
    char *ipv6_addr = nvram_safe_get(NVRAM_STR_L3_IPV6);

    struct in6_addr s_addr;
    char nameserver[MAX_ARGV_LEN] = {'\0'};
    cli_param_get_ipv6(STATIC_PARAM, 0, &s_addr, nameserver, sizeof(nameserver), u);
    //vty_output("%d ipv6_addr=%s nameserver=%s\n",__LINE__,ipv6_addr,nameserver);//tt
    scfgmgr_set(NVRAM_STR_L3_IPV6, nameserver);
    SYSTEM("/usr/sbin/rc lanv6 restart > /dev/null 2>&1");
    free(ipv6_addr);

    syslog(LOG_NOTICE, "[CONFIG-5-IPV6]:The IPv6 address was set to %s\n", nameserver);
    return 0;
}

int nfunc_ipv6_addr(struct users *u)
{
    char *ipv6_addr = nvram_safe_get(NVRAM_STR_L3_IPV6);
    //vty_output("%d ipv6_addr=%s \n",__LINE__,ipv6_addr);//tt
    if(strlen(ipv6_addr) >= 3) 
    {
        scfgmgr_set(NVRAM_STR_L3_IPV6, "");
        SYSTEM("/usr/sbin/rc lanv6 restart  > /dev/null 2>&1");

        syslog(LOG_NOTICE, "[CONFIG-5-IPV6]:Cancel IPv6 address %s\n", ipv6_addr);
    }else{
        vty_output("Ipv6 address not exist\n");
    }

    free(ipv6_addr);

    return 0;
}

int func_ipv6_default_g(struct users *u)
{
    struct in6_addr s_addr;
    char *ipv6_gw = nvram_safe_get(NVRAM_STR_IPV6_GW);
    char gateway[MAX_ARGV_LEN] = {'\0'};
    
    cli_param_get_ipv6(STATIC_PARAM, 0, &s_addr, gateway, sizeof(gateway), u);
    //vty_output("%d ipv6_gw=%s gateway=%s\n",__LINE__,ipv6_gw,gateway);//tt

    scfgmgr_set(NVRAM_STR_IPV6_GW, gateway);
    SYSTEM("/usr/sbin/rc lanv6 restart > /dev/null 2>&1");
    syslog(LOG_NOTICE, "[CONFIG-5-IPV6]: Default gateway was set to %s, %s\n", gateway, getenv("LOGIN_LOG_MESSAGE"));

    return;
}

int nfunc_ipv6_default_gateway()
{
    //	SYSTEM("/sbin/route -A inet6 del default dev %s > /dev/null 2>&1", IMP);
    scfgmgr_set(NVRAM_STR_IPV6_GW, "");
    SYSTEM("/usr/sbin/rc lanv6 restart > /dev/null 2>&1");

    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set gateway IPv6 address to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return 0;
}

/*------------------------------cos---------------------------------------------*/
static int cli_start_qos_8021p(void)
{
	system("rc qos start > /dev/null 2>&1");
	return 0;
}

static int cli_stop_qos_8021p(void)
{
	system("rc qos stop > /dev/null 2>&1");
	return 0;
}

int func_cos_num(struct users *u)
{
 	int skfd, i, j,map_num, cos_cnt = 0, cos_num = 0;
 	int cos_value[8] = {0};
    char tmp[20];
    char map_n[MAX_ARGV_LEN] = {'\0'};
    cli_param_get_int(DYNAMIC_PARAM, 13, &cos_cnt, u);
	cli_param_get_int(STATIC_PARAM, 0, &map_num, u);
	sprintf(map_n,"%d",map_num);
	for(j = 0;j < cos_cnt;j++)
	{
		cli_param_get_int(STATIC_PARAM, j+1, &cos_num, u);
		cos_value[j] = cos_num;
	}

    char *qos_8021p_cfg = nvram_safe_get("qos_802_1p_config");
	for(i = 0; i < cos_cnt; i++)
	{
		*(qos_8021p_cfg+cos_value[i]) = *map_n;
		sprintf(tmp, " %d",cos_value[i]);
	}

	scfgmgr_set("qos_802_1p_config", qos_8021p_cfg);
	system("rc qos start > /dev/null 2>&1");
    free(qos_8021p_cfg);

    syslog(LOG_NOTICE, "[CONFIG-5-COS]: Add the priority value %s to the queue %s ,%s\n", tmp , map_n, getenv("LOGIN_LOG_MESSAGE"));

    return CLI_SUCCESS;
}
int nfunc_cos()
{
	char *tos_dscp_enable = nvram_safe_get("tos_dscp_enable");
	if('0' == *tos_dscp_enable)
		scfgmgr_set("qos_enable", "0");
    scfgmgr_set("qos_8021p_enable", "0");
    scfgmgr_set("qos_port_enable", "0");

    cli_stop_qos_8021p();
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Disabled the tos DSCP function, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(tos_dscp_enable);
	return CLI_SUCCESS;

}
int nfunc_cos_map()
{
	char *cos_cfg = nvram_safe_get_def("qos_802_1p_config");
    scfgmgr_set("qos_802_1p_config", cos_cfg);
    cli_stop_qos_8021p();
    cli_start_qos_8021p();
    free(cos_cfg);
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set the COS to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return CLI_SUCCESS;

}


/*------------------------------------------ip arp---------------------------------*/
void func_set_arp_inspection(void)
{
	char *arp_enable = nvram_safe_get("arp_enable");
	char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	char *relay_enable = nvram_safe_get("relay_enable");

	if( ('1' == *arp_enable)||('1' == *snoop_enable)||('1' == *relay_enable) ) {
		scfgmgr_set("arp_enable", "1");
		cli_create_config(0);
		SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
	} else {
		scfgmgr_set("arp_enable", "1");
		cli_create_config(1);
		SYSTEM("/usr/sbin/arp_inspection -f /tmp/arp_config&");
	}

	free(arp_enable);
	free(snoop_enable);
	free(relay_enable);

	syslog(LOG_NOTICE, "[CONFIG-5-IP]: The ARP Inspection was enabled, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	return;
}

void func_set_ip_and_mask(struct users *u, char *lan_ipaddr, char *lan_netmask){
	unsigned long int ipaddr, netmask = 0, bipaddr, gateaddr,nipaddr;
	int i,ret=0,mask_num = 24;
	struct in_addr addr;
	char *lan_bipaddr ;
	char *manage_vlan = nvram_safe_get("manage_vlan");
	int vlan_id = atoi(manage_vlan);

	if(0 != vlan_id){
		if((vlan_id < 1)||(vlan_id > 4094))
			vlan_id = 1;
	}
	else{
		vlan_id = 1;
	}
	
	netmask = inet_addr(lan_netmask);
	ipaddr = inet_addr(lan_ipaddr);
	
	bipaddr = ipaddr | (~netmask);
	addr.s_addr = bipaddr;
	lan_bipaddr = inet_ntoa(addr);
		 
	SYSTEM("ifconfig %s.%d %s netmask %s broadcast %s",IMP,vlan_id,lan_ipaddr, lan_netmask, lan_bipaddr);
	//printf("ifconfig %s %s netmask %s broadcast %s",IMP,lan_ipaddr, ip_mask, lan_bipaddr);

	//if(strlen(lan_gateway) > 0)
		//SYSTEM("/sbin/route add default gw %s dev %s.%d > /dev/null 2>&1", lan_gateway, IMP,vlan_id);

	scfgmgr_set("lan_ipaddr", lan_ipaddr);
	scfgmgr_set("lan_netmask", lan_netmask);
	scfgmgr_set("ip_staticip_enable", "1");

	system("/bin/sleep 2; /usr/sbin/rc lan restart && /bin/rm /tmp/www && /usr/sbin/rc httpd restart");
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLAN]: Set the IP address of lan to %s,and the netmask to %s, %s\n", lan_ipaddr, lan_netmask, getenv("LOGIN_LOG_MESSAGE"));
	
	free(manage_vlan);
	return ret;
}

static void cli_create_config(int first_start)
{
	FILE *fp;
	char *arp_enable = nvram_safe_get("arp_enable");
	char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	char *relay_enable = nvram_safe_get("relay_enable");

	char *source_binding = nvram_safe_get("source_binding");

	char *arp_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "arp_trust_port");
	char *snoop_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "snoop_trust_port");

	char *p = NULL, *p1 = NULL;
	char tmp[64];

	if((fp=fopen(ARP_CONFIG_FILE,"w+")) != NULL) {

		fprintf(fp,"arp_enable=%c\n", *arp_enable);
		fprintf(fp,"arp_trust_port=%s\n", arp_trust_port);

		fprintf(fp,NVRAM_STR_SNOOP_ENABLE"=%c\n", *snoop_enable);
		fprintf(fp,"snoop_trust_port=%s\n", snoop_trust_port);

		fprintf(fp,"relay_enable=%c\n", *relay_enable);

		if(first_start) {
			p = source_binding;
			while((p1=strchr(p, ';')) != NULL)
			{
				memset(tmp, '\0', sizeof(tmp));
				memcpy(tmp, p, p1-p);
				fprintf(fp, "add=%s\n", tmp);
				p = p1+1;
			}
		}
		fclose(fp);
	}

	free(arp_enable);
	free(snoop_enable);
	free(relay_enable);
	free(source_binding);
	free(arp_trust_port);
	free(snoop_trust_port);

	return;
}
void nfunc_arp_inspection(void)
{
	char *arp_enable = nvram_safe_get("arp_enable");
	char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	char *relay_enable = nvram_safe_get("relay_enable");

	if('1' == *arp_enable) {
		if( ('1' == *snoop_enable)||('1' == *relay_enable) ) {
			scfgmgr_set("arp_enable", "0");
			cli_create_config(0);
			SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
		} else {
			scfgmgr_set("arp_enable", "0");
			SYSTEM("/usr/bin/killall arp_inspection > /dev/null 2>&1");
		}
	}

	free(arp_enable);
	free(snoop_enable);
	free(relay_enable);
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Stop the ARP inspection, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return;
}


/*------------------------------------------ip dhcp--------------------------------*/
void func_set_dhcp_snooping(void)
{
#if 1
    char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);

    if('1' == *snoop_enable) {
        //vty_output(" %d already enable\n",__LINE__);//tt
        return;
    } else {
        scfgmgr_set(NVRAM_STR_SNOOP_ENABLE, "1");
    }
    SYSTEM("/usr/sbin/rc dhcpsnoop restart > /dev/null 2>&1");
    free(snoop_enable);
#else
    char *arp_enable = nvram_safe_get("arp_enable");
    char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
    char *relay_enable = nvram_safe_get("relay_enable");

    if( ('1' == *arp_enable)||('1' == *snoop_enable)||('1' == *relay_enable) ) {
        scfgmgr_set(NVRAM_STR_SNOOP_ENABLE, "1");
        cli_create_config(0);
        SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
    } else {
        scfgmgr_set(NVRAM_STR_SNOOP_ENABLE, "1");
        cli_create_config(1);
        SYSTEM("/usr/sbin/arp_inspection -f /tmp/arp_config&");
    }

    free(arp_enable);
    free(snoop_enable);
    free(relay_enable);
#endif
    syslog(LOG_NOTICE, "[CONFIG-5-IP]: Open the DHCP snooping function, %s\n", getenv("LOGIN_LOG_MESSAGE"));

    return;
}

void nfunc_dhcp_snooping(void)
{
#if 1
    char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);

    if('0' == *snoop_enable) {
        //vty_output(" %d already disable\n",__LINE__);//tt
        return;
    } else {
        scfgmgr_set(NVRAM_STR_SNOOP_ENABLE, "0");
    }
    SYSTEM("/usr/sbin/rc dhcpsnoop restart > /dev/null 2>&1");
    free(snoop_enable);
#else
    char *arp_enable = nvram_safe_get("arp_enable");
    char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
    char *relay_enable = nvram_safe_get("relay_enable");

    if('1' == *snoop_enable) {
        if( ('1' == *arp_enable)||('1' == *relay_enable) ) {
            scfgmgr_set(NVRAM_STR_SNOOP_ENABLE, "0");
            cli_create_config(0);
            SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
        } else {
            scfgmgr_set(NVRAM_STR_SNOOP_ENABLE, "0");
            SYSTEM("/usr/bin/killall arp_inspection > /dev/null 2>&1");
        }
    }

    free(arp_enable);
    free(snoop_enable);
    free(relay_enable);
#endif
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Stop the DHCP snooping function, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return;
}
void nfunc_dhcp_binding(void)
{
	FILE *fp;
	char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);

	if('1' == *snoop_enable) {
		if((fp=fopen(ARP_CONFIG_FILE,"w+")) != NULL) {
			fprintf(fp,"clear_table=1\n");
			fclose(fp);
		}
		SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
	}

	free(snoop_enable);
 	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Clear DHCP snooping binding table, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return;
}

void func_ip_dhcp_snooping_vlan(struct users *u)
{
	char vlan_buff[MAX_ARGV_LEN] = {'\0'};
	//char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	char *ip_dhcp_snooping_vlan = nvram_safe_get("ip_dhcp_snooping_vlan");
	
	cli_param_get_string(DYNAMIC_PARAM, 0, vlan_buff, u);

	sprintf(vlan_buff,"%d;%s",vlan_buff,ip_dhcp_snooping_vlan);
	scfgmgr_set("ip_dhcp_snooping_vlan", vlan_buff);
    syslog(LOG_NOTICE, "[CONFIG-5-IP]:ip dhcp snooping vlan %s, %s \n",vlan_buff,getenv("LOGIN_LOG_MESSAGE"));
	free(ip_dhcp_snooping_vlan);
}
void nfunc_ip_dhcp_snooping_vlan_num(struct users *u)
{
	char vlan_buff[MAX_ARGV_LEN] = {'\0'};
	int vlan_num;
	char *ip_dhcp_snooping_vlan = nvram_safe_get("ip_dhcp_snooping_vlan");
	cli_param_get_int(DYNAMIC_PARAM, 0, &vlan_num, u);

	sprintf(vlan_buff,"%d",vlan_num);
	
	scfgmgr_set("delete_ip_dhcp_snooping_vlan_num", vlan_buff);
    syslog(LOG_NOTICE, "[CONFIG-5-IP]:ip dhcp snooping vlan %s, %s \n",vlan_buff,getenv("LOGIN_LOG_MESSAGE"));
	free(ip_dhcp_snooping_vlan);
}

int func_ip_dhcp_pool_name(struct users *u)
{
    char *p;
	int id, retval = 0;

	p = strstr(u->linebuf, "po");
	while(*p != ' ') p++;
	while(*p == ' ') p++;
	    
	id = atoi(p);   
	if((id > 32)||(id < 1))
	{
        vty_output("  Create dhcp server pool failed: too larger, pool 1-32!\n");
	    return -1;
	}    

	return retval;
}

int nfunc_ip_dhcp_pool_name(struct users *u)
{
    dhcpd_conf conf;
	int id, flag = 0;
    char *config,*p1, *p2, *p3, *p4, pool_name[16], subnet[32];
    char dhcp_conf[128], *dhcpd, *l3_dhcp, dhcp_str[8196];
    
    config = strstr(u->linebuf, "po");
	while(*config != ' ') config++;
	while(*config == ' ') config++;
	id = atoi(config);
//	printf("id %d\n", id);
	
	sprintf(pool_name,"dhcp_pool%d", id);
	config = nvram_safe_get(pool_name);
    if(strlen(config) > 4)
    {
        memset(&conf, '\0', sizeof(conf));
        get_parameter_dhcpd(config, conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, conf.name);

        if(strlen(conf.subnet) >= 7) 
        {       
            dhcpd = l3_dhcp = nvram_safe_get("l3_dhcp"); 
            memset(dhcp_str, '\0', sizeof(dhcp_str));
            ////l3_dhcp=eth1.5,192.168.19.2/24,192.168.19.100-192.168.19.149,86400,192.168.1.1/192.168.1.2,192.168.1.3; 
            while((*dhcpd != NULL) && (strlen(dhcpd) > 0))
            {     
                p1 = dhcpd;  
                p2 = strchr(p1, ';');
                memset(subnet, '\0', sizeof(subnet));
                memset(dhcp_conf, '\0', sizeof(dhcp_conf));
                memcpy(dhcp_conf, p1, p2-p1);
                p3 = strchr(dhcp_conf, ',')+1;
                p4 = strchr(p3, ',');
                memcpy(subnet, p3, p4-p3);
                fprintf(stderr, "dhcp_conf %s subnet %s\n", dhcp_conf, subnet);
                
                if(1 == isin_same_subnet(conf.subnet, subnet))  
                {
                    flag = 1;
                
                }else
                {
                    sprintf(dhcp_str, "%s%s;", dhcp_str, dhcp_conf);  
                }  
                
                dhcpd = p2+1;
            }
            free(l3_dhcp); 
        }
                  
        if(1 == flag)
        {
            scfgmgr_set("l3_dhcp", dhcp_str);
            system("rc dhcpd restart  > /dev/null 2>&1");  
            vty_output("  delete dhcp server pool %d success: stop this dhcpd server!\n", id);  
        }
        else
        {
            vty_output("  delete dhcp server pool %d success: only remove config!\n", id);
			free(config);
			return 0;
        }
        scfgmgr_set(pool_name, "");    
	}else
	{
		free(config);
        vty_output("  delete dhcp server pool %d failed: no this config!\n", id);
	    return -1;
	}    
	free(config);
	
	return 0;
}

int func_ipv6_dhcp_pool_name(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_ipv6_dhcp_pool_name here\n");

	return retval;
}

int nfunc_ipv6_dhcp_pool_name(struct users *u)
{
	int retval = -1;

	printf("do nfunc_ipv6_dhcp_pool_name here\n");

	return retval;
}

/*---------------------------------set/no ip http server---------------------*/
void func_http_server()
{
    scfgmgr_set("http_enable", "1");
    SYSTEM("rc httpd start");
    syslog(LOG_NOTICE, "[CONFIG-5-IP]: Enable ip http server, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return;
}
void nfunc_http_server()
{
    scfgmgr_set("http_enable", "0");
    SYSTEM("rc httpd stop");
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Disable ip http server, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return;
}

int func_ipv6_dhcp_client(struct users *u)
{
    scfgmgr_set("dhcp6_client", "1");
    SYSTEM("rc dhcpclient start");

    return 0;
}


int nfunc_ipv6_dhcp_client(struct users *u)
{
    scfgmgr_set("dhcp6_client", "0");
    SYSTEM("rc dhcpclient stop");

    return 0;
}


/*------------------------------set ip name server--------------------------*/
static int check_ipaddr(char *ip_buf)
{
	char *ip_head, *ip_add, *ip_two, *ip_thr;
	if ((strcmp(ip_buf,"127.0.0.1") == 0) || (strcmp(ip_buf,"127.1.1.1") == 0)) {
		return 1;
	}
	ip_add = ip_buf;
	ip_head = strsep(&ip_add,".");
	if ((224 <= atoi(ip_head)) && (atoi(ip_head) <= 239)) {
		return 1;
	}
	if ((atoi(ip_head)==0) || (atoi(ip_head) == 255)) {
		return 1;
	}
	ip_two = strsep(&ip_add, ".");
	ip_thr = strsep(&ip_add, ".");
	if (atoi(ip_add) == 255 || atoi(ip_add) == 0) {
		return 1;
	}	
	return 0;
}

int func_ip_name_server(struct users *u)
{
	int vaild;
	char *lan_dns;
	struct in_addr ip_addr;
	char ip_buf[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_ipv4(DYNAMIC_PARAM, 0, &ip_addr, ip_buf, sizeof(ip_buf), u);

	/* hualimin 2012.4.12*/
	vaild = check_ipaddr(ip_buf);
	if (vaild == 1) {
		vty_output("invalid ip address\n");
		return 0;
	}
	
	cli_param_get_ipv4(DYNAMIC_PARAM, 0, &ip_addr, ip_buf, sizeof(ip_buf), u);
	lan_dns = nvram_safe_get("lan_dns");
 	if(strcmp(lan_dns, ip_buf)) 
    {	
		scfgmgr_set("lan_dns", ip_buf);
		SYSTEM("/usr/sbin/rc relay restart  > /dev/null 2>&1");
	}
	free(lan_dns);

	syslog(LOG_NOTICE, "[CONFIG-5-IP]:The DNS IP address was set to %s, %s\n", ip_buf, getenv("LOGIN_LOG_MESSAGE"));
    return 0;
}

void nfunc_name_server(void)
{
	char *lan_dns = nvram_safe_get("lan_dns");
	
 	if(strlen(lan_dns) > 0) 
 	{
		scfgmgr_set("lan_dns", "");
		SYSTEM("/usr/sbin/rc relay restart  > /dev/null 2>&1");
	}
	free(lan_dns);

	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set DNS to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return;
}

/*------------------------------igmp_snooping--------------------------*/

static int cli_stop_igmp_snooping(void)
{
  	system("rc igmp stop > /dev/null 2>&1");
	return 0;
}
static int cli_start_igmp_snooping(void)
{
  	system("rc igmp start > /dev/null 2>&1");
 	return 0;
}

int func_set_igmp_snooping_enable()
{
	char *igmp_enable = nvram_safe_get("igmp_enable");

    if(*igmp_enable == '0'){
	    scfgmgr_set("igmp_enable", "1");
	    //cli_stop_igmp_snooping();
	    cli_start_igmp_snooping();
	    syslog(LOG_NOTICE, "[CONFIG-5-IP]: Enabled the igmp snooping, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	}
	free(igmp_enable);
    return CLI_SUCCESS;
}

void nfunc_igmp_snooping()
{
	char *igmp_enable = nvram_safe_get("igmp_enable");

    if(*igmp_enable == '1'){
		scfgmgr_set("igmp_enable", "0");
		scfgmgr_set("mld_enable", "0");
	    cli_stop_igmp_snooping();
	    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Diasble the IGMP snooping function, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	}
	free(igmp_enable);
	return CLI_SUCCESS;
}

int func_set_igmp_snooping_querier()
{
    char *igmp_querytime = nvram_safe_get("igmp_querytime");
    char *igmp_agetime = nvram_safe_get("igmp_agetime");

    scfgmgr_set("igmp_querytime", igmp_querytime);
    scfgmgr_set("igmp_agetime", igmp_agetime);

    scfgmgr_set("igmp_query_enable", "1");

    cli_stop_igmp_snooping();
    cli_start_igmp_snooping();

    free(igmp_querytime);
    free(igmp_agetime);

    syslog(LOG_NOTICE, "[CONFIG-5-IP]: The igmp snooping querier was enabled, %s\n", getenv("LOGIN_LOG_MESSAGE"));

    return CLI_SUCCESS;
}

int nfunc_igmp_snooping_querier()
{
    scfgmgr_set("igmp_query_enable", "0");

    cli_stop_igmp_snooping();
    cli_start_igmp_snooping();

    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Disable IGMP snooping querier, %s\n", getenv("LOGIN_LOG_MESSAGE"));

    return CLI_SUCCESS;
}

int func_igmp_snooping_timer_querier(struct users *u)
{
	int timer_q;
	char timer_querier[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_int(DYNAMIC_PARAM, 0, &timer_q, u);
	sprintf(timer_querier,"%d",timer_q);
	scfgmgr_set("igmp_querytime", timer_querier);
	cli_stop_igmp_snooping();
    cli_start_igmp_snooping();
	syslog(LOG_NOTICE, "[CONFIG-5-IP]: The IGMP snooping querier interval was set to %s, %s\n", timer_querier, getenv("LOGIN_LOG_MESSAGE"));
    return CLI_SUCCESS;
}

int nfunc_igmp_snooping_querier_timer()
{
	char *igmp_querytime = nvram_safe_get_def("igmp_querytime");

	scfgmgr_set("igmp_querytime", igmp_querytime);

	cli_stop_igmp_snooping();
    cli_start_igmp_snooping();

	free(igmp_querytime);
	return CLI_SUCCESS;
}
int func_igmp_snooping_timer_survival(struct users *u)
{
	int timer_s;
	char timer_survival[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_int(DYNAMIC_PARAM, 0, &timer_s, u);
	sprintf(timer_survival,"%d",timer_s);
	scfgmgr_set("igmp_agetime", timer_survival);
	cli_stop_igmp_snooping();
    cli_start_igmp_snooping();
	syslog(LOG_NOTICE, "[CONFIG-5-IP]: The survival time of group members was set to %s, %s\n", timer_survival, getenv("LOGIN_LOG_MESSAGE"));
    return CLI_SUCCESS;
}
int nfunc_igmp_snooping_survival_timer()
{
	char *igmp_agetime = nvram_safe_get_def("igmp_agetime");

	scfgmgr_set("igmp_agetime", igmp_agetime);

	cli_stop_igmp_snooping();
    cli_start_igmp_snooping();

	free(igmp_agetime);
    return CLI_SUCCESS;
}


int nfunc_igmp_snooping_vlan()
{
	//char *igmp_snooping_vlan = NULL;
	//igmp_snooping_vlan = nvram_safe_get("igmp_snooping_vlan");
	scfgmgr_set("igmp_snooping_vlan",'0');


	return CLI_SUCCESS;
}


int check_vid(int vid)
{

}

int func_igmp_snooping_vlan(struct users *u)
{
	char vlan_buf[MAX_ARGV_LEN] = {'\0'};
	char vlan_num[4] = {'\0'};
	char *enable_igmp_vlan_num = nvram_safe_get("enable_igmp_vlan_num");

	cli_param_get_int(DYNAMIC_PARAM, 0, &vlan_num, u);
	sprintf(vlan_buf,"%d,%s",vlan_num,enable_igmp_vlan_num);
	scfgmgr_set("enable_igmp_vlan_num",enable_igmp_vlan_num);
	free(enable_igmp_vlan_num);
	return CLI_SUCCESS;
}
int nfunc_igmp_snooping_vlan_num(struct users *u)
{
	char vlan_buf[MAX_ARGV_LEN] = {'\0'};
	char *disable_igmp_vlan_num = NULL;

	cli_param_get_int(DYNAMIC_PARAM, 0, &vlan_buf, u);

	disable_igmp_vlan_num = cli_nvram_safe_get(CLI_COMMA,"disable_igmp_vlan_num");
	scfgmgr_set("disable_igmp_vlan_num",disable_igmp_vlan_num);
	free(disable_igmp_vlan_num);
	return CLI_SUCCESS;
}

/*------------------------------------ip default gateway--------------------------*/
void func_set_default_gateway(struct users *u)
{
	return;
}
int nfunc_default_gateway()
{
    return 0;
}
/*-----------------------------------------source f--------------------------*/
int func_add_ip_source_binding(struct users *u)
{
	FILE *fp;
	char *arp_enable = nvram_safe_get("arp_enable");
	char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	char *relay_enable = nvram_safe_get("relay_enable");
	struct in_addr ip_addr;
	char ip_buf[MAX_ARGV_LEN] = {'\0'};
	int vlan = 0;
	int port = 0;
	char mac_addr[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(STATIC_PARAM, 0, mac_addr, u);
	cli_param_get_int(STATIC_PARAM, 0, &vlan, u);
	cli_param_get_ipv4(STATIC_PARAM, 0, &ip_addr, ip_buf, sizeof(ip_buf), u);
	cli_param_get_int(STATIC_PARAM, 1, &port, u);

	if(ISSET_CMD_MSKBIT(u, IP_IF_GIGA_PORT))
		port += (PNUM - GNUM);

	char *p = NULL, *p1 = NULL;
	unsigned char tmp_mac[6];
	char mac_string[13];
	cli_source_info_conf *p_source = NULL;
	cli_source_info_conf *t_source = NULL;
	memset(&cur_source_conf, 0, sizeof(cli_source_conf));
	cur_source_conf.cur_source_info = NULL;

	cli_nvram_conf_get(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);

	p_source = cur_source_conf.cur_source_info;
	t_source = cur_source_conf.cur_source_info;

	inet_pton(AF_INET, ip_buf, (void *)&ip_addr.s_addr);
	memset(tmp_mac, 0, sizeof(tmp_mac));

    memset(mac_string, '\0', sizeof(mac_string));
    p = mac_addr;
    while(strchr(p, ':') != NULL)
    {
        p1 = strchr(p , ':');
        strncat(mac_string, p, p1-p);
        p= p1+1;
    }
    strcat(mac_string, p);
	cli_str2mac(mac_string, tmp_mac);

	while(NULL != p_source)
	{
		if( (0 == memcmp(tmp_mac, p_source->mac_addr, sizeof(p_source->mac_addr)))||(ip_addr.s_addr == p_source->ip_addr.s_addr) )
		{
			vty_output("  IP Source binding entry is exist\n");
			cli_nvram_conf_free(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);
			
			free(arp_enable);
			free(snoop_enable);
			free(relay_enable);
			return CLI_FAILED;
		}
		t_source = p_source;
		p_source = p_source->next;
	}

	p_source = malloc(sizeof(cli_source_info_conf));
	if(NULL == p_source){
		cli_nvram_conf_free(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);
		free(arp_enable);
		free(snoop_enable);
		free(relay_enable);
		return -1;
	}
	memset(p_source, 0, sizeof(cli_source_info_conf));
	p_source->next = NULL;

	if(NULL == t_source) {
		cur_source_conf.cur_source_info = p_source;
	} else {
		if(NULL == t_source->next)
			t_source->next = p_source;
		else {
			p_source->next = t_source->next;
			t_source->next = p_source;
		}
	}
	cur_source_conf.source_count++;

	memcpy(p_source->mac_addr, tmp_mac, sizeof(p_source->mac_addr));
	p_source->ip_addr.s_addr = ip_addr.s_addr;
	p_source->port = port;
	p_source->vlan = vlan;
	p_source->type = 1;

	cli_nvram_conf_set(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);

	if( ('1' == *arp_enable)||('1' == *snoop_enable)||('1' == *relay_enable) )
	{

		if((fp=fopen(ARP_CONFIG_FILE,"w+")) != NULL)
		{
			fprintf(fp, "add=%s|%s|%d|%d|%d\n", mac_addr, ip_buf, port, vlan, 1);
			fclose(fp);
		}
		SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
	}

	cli_nvram_conf_free(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);

	free(arp_enable);
	free(snoop_enable);
	free(relay_enable);

	syslog(LOG_NOTICE, "[CONFIG-5-IP]: The port %d which was in vlan %d was added ,it's IP address is %s and MAC address is %s, %s\n", port,vlan, ip_buf, mac_addr, getenv("LOGIN_LOG_MESSAGE"));

	return CLI_SUCCESS;
}

int nfunc_mac_source_binding(struct users *u)
{
	int flag = 0;
	FILE *fp;
	char *arp_enable = nvram_safe_get("arp_enable");
	char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	char *relay_enable = nvram_safe_get("relay_enable");
	char mac_addr[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(STATIC_PARAM, 0, mac_addr, u);
	struct in_addr ip_addr;

	char *p = NULL, *p1 = NULL;
	unsigned char tmp_mac[6];
	char mac_string[13];
	cli_source_info_conf *p_source = NULL;
	cli_source_info_conf *t_source = NULL;

	memset(&cur_source_conf, 0, sizeof(cli_source_conf));
	cur_source_conf.cur_source_info = NULL;

	cli_nvram_conf_get(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);

	p_source = cur_source_conf.cur_source_info;

	memset(tmp_mac, 0, sizeof(tmp_mac));

    memset(mac_string, '\0', sizeof(mac_string));
    p = mac_addr;
    while(strchr(p, ':') != NULL)
    {
        p1 = strchr(p , ':');
        strncat(mac_string, p, p1-p);
        p= p1+1;
    }
    strcat(mac_string, p);

	cli_str2mac(mac_string, tmp_mac);

	while(NULL != p_source) {
		if( 0 == memcmp(tmp_mac, p_source->mac_addr, sizeof(p_source->mac_addr)) ) {
			flag = 1;
			break;
		}
		t_source = p_source;
		p_source = p_source->next;
	}

	if(flag) {
		if(NULL == t_source) {
			cur_source_conf.cur_source_info = p_source->next;
			free(p_source);
		} else {
			t_source->next = p_source->next;
			free(p_source);
		}

		cli_nvram_conf_set(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);

		if( ('1' == *arp_enable)||('1' == *snoop_enable)||('1' == *relay_enable) ) {
			if((fp=fopen(ARP_CONFIG_FILE,"w+")) != NULL) {
				fprintf(fp, "del_mac=%s\n", mac_string);
				fclose(fp);
			}
			SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
		}
	} else
		vty_output("  The mac address %s does not exist in source binding table\n", mac_addr);

	cli_nvram_conf_free(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);

	free(arp_enable);
	free(snoop_enable);
	free(relay_enable);
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Stop IP source binding with MAC address %s, %s\n", mac_addr, getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}

int nfunc_ip_source_binding(struct users *u)
{
	int flag = 0;
	FILE *fp;
	char *arp_enable = nvram_safe_get("arp_enable");
	char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	char *relay_enable = nvram_safe_get("relay_enable");
	struct in_addr ip_addr;
	char ip_buf[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_ipv4(STATIC_PARAM, 0, &ip_addr, ip_buf, sizeof(ip_buf), u);

	cli_source_info_conf *p_source = NULL;
	cli_source_info_conf *t_source = NULL;

	memset(&cur_source_conf, 0, sizeof(cli_source_conf));
	cur_source_conf.cur_source_info = NULL;

	cli_nvram_conf_get(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);

	p_source = cur_source_conf.cur_source_info;

	inet_pton(AF_INET, ip_buf, (void *)&ip_addr.s_addr);

	while(NULL != p_source) {
		if( ip_addr.s_addr == p_source->ip_addr.s_addr ) {
			flag = 1;
			break;
		}
		t_source = p_source;
		p_source = p_source->next;
	}

	if(flag) {
		if(NULL == t_source) {
			cur_source_conf.cur_source_info = p_source->next;
			free(p_source);
		} else {
			t_source->next = p_source->next;
			free(p_source);
		}

		cli_nvram_conf_set(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);

		if( ('1' == *arp_enable)||('1' == *snoop_enable)||('1' == *relay_enable) ) {
			if((fp=fopen(ARP_CONFIG_FILE,"w+")) != NULL) {
				fprintf(fp, "del_ip=%s\n", ip_buf);
				fclose(fp);
			}
			SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
		}
	} else
		vty_output("  The ip address %s does not exist in source binding table\n", ip_buf);

	cli_nvram_conf_free(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);

	free(arp_enable);
	free(snoop_enable);
	free(relay_enable);
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Stop IP source binding with IP address %s, %s\n", ip_buf, getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}
/*--------------------------------------dscp---------------------------------*/

/*change the whole function by jiangyaohui 20120309*/
static int cli_new_start_dscp(void)
{
	system("rc qos start > /dev/null 2>&1");
    return 0;	
}

int func_dscp_enable()
{
	scfgmgr_set("qos_enable", "1");
    scfgmgr_set("tos_dscp_enable", "1");

    system("rc qos start > /dev/null 2>&1");
    syslog(LOG_NOTICE, "[CONFIG-5-DSCP]: Enabled the dscp function, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return CLI_SUCCESS;
}
int func_dscp_value(struct users *u)
{
	char value[64][8],*p=NULL,*p1=NULL;
	char flag[64],i=0,j=0,k=0,min=0,max=0,count=0;
	int quene = 0;
	char flag_str[MAX_ARGV_LEN] = {'\0'};
	char quene_str[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_int(STATIC_PARAM, 0, &quene,u);
	sprintf(quene_str,"%d",quene);
	cli_param_get_string(STATIC_PARAM, 0,flag_str, u);
	memset(&value,'\0',sizeof(value));
	memset(&flag,'\0',sizeof(flag));
	p1 = flag_str;
/*take apart by ','*/
	while(1)
	{
		if((p = strchr(p1, ',')) != NULL)
		{
			memcpy(value[i], p1, p - p1);
			p1 = p+1;
			i++;

		}else
		{
			memcpy(value[i], p1, strlen(p1));
			break;
		}
	}
/*take apart by '-'*/
	for(j = 0; j <= i; j++)
   	{
		p = value[j];
		if((p = strchr(value[j], '-')) != NULL)
		{
			p++;
			min = atoi(value[j]);
			max = atoi(p);
        while(max - min >= 0)
				{
          flag[count++]=min;
					min++;
				}
		}
		else
		{
			flag[count++]=atoi(value[j]);
		}
   	}
    char *dscp_cfg = cli_nvram_safe_get(CLI_DSCP_CONFIG, "qos_dscp_config");

    for(i=0; i<count; i++)
	{
		*(dscp_cfg+flag[i]) = *quene_str;
	}
    scfgmgr_set("qos_dscp_config", dscp_cfg);

    /*cli_stop_dscp();
    cli_start_dscp();*/
    cli_new_start_dscp();

    free(dscp_cfg);
    syslog(LOG_NOTICE, "[CONFIG-5-DSCP]: set the queue %s 's differentiated services codepoint value to %s, %s\n", quene_str, flag_str, getenv("LOGIN_LOG_MESSAGE"));
    return CLI_SUCCESS;
}

int nfunc_dscp()
{
	char *qos_8021p_enable = nvram_safe_get("qos_8021p_enable");
	if('0' == *qos_8021p_enable)
		scfgmgr_set("qos_enable", "0");

    scfgmgr_set("tos_dscp_enable", "0");

    system("rc qos start > /dev/null 2>&1");
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Disable DSCP function, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(qos_8021p_enable);
    return CLI_SUCCESS;
}

int nfunc_dscp_map()
{
    char *dscp_cfg = cli_nvram_safe_get(CLI_DSCP_CONFIG, "qos_dscp_config");
    char *dscp_cfg_def = nvram_safe_get_def("qos_dscp_config");
	
	if(strcmp(dscp_cfg, dscp_cfg_def) != 0){
		scfgmgr_set("qos_dscp_config", dscp_cfg_def);
	    system("rc qos start > /dev/null 2>&1");
	}

    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Dscp map changed to be default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    free(dscp_cfg);
    free(dscp_cfg_def);
    return CLI_SUCCESS;
}

static void cli_enable_ipv6_mld_snooping(void)
{
    FILE *fp;
    pid_t pid=0;
    union sigval mysigval;
    char mld_buf[128]={'\0'};

    char *igmp_enable = nvram_safe_get("igmp_enable");
    if(*igmp_enable == '0'){
        printf("Please enable ip igmp-snooping first!\n");
        free(igmp_enable);
        return;
    }
    if((fp = fopen("/var/run/snoop.pid","r"))!=NULL){
        while(fgets(mld_buf, 128, fp)!=NULL){
            pid = (pid_t)atoi(mld_buf);
            //printf("pid = %d\n",atoi(mld_buf));
        }
        fclose(fp);
    }

    mysigval.sival_int = 1;
    if(sigqueue(pid,SIGRTMIN+2,mysigval)<0)
        printf("Send signal fail!\n");
    scfgmgr_set("mld_enable", "1");

    syslog(LOG_NOTICE, "[CONFIG-5-IP]: Enabled the ipv6 mld snooping, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    free(igmp_enable);
    return;
}


/*
 *  Function : cli_set_ipv6_route
 *  Purpose:
 *     set ipv6 route
 *  Parameters:ipv6_prefix ipv6_nexthop
 *
 *
 *  Author  : wuchunli 
 *  Date    :2011/12/08
 */
static void cli_set_ipv6_route(char *ipv6_prefix,char *ipv6_nexthop)
{
    struct in6_addr s6_ip;
    struct in6_addr s6_ip_nv;
    struct in6_addr s6_ip_global;
    struct in6_addr s6_ip_nexthop;
    char *p = NULL;
	char *p1 = NULL;
	char *p2 = NULL;
    char tmp[MAX_IPV6_ROUTE];
    char tmp_nv[MAX_IPV6_ROUTE];
    char tmp_global[MAX_IPV6_ROUTE];

    cli_ipv6_route_list *route_list = NULL;
    cli_nvram_conf_get(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
    route_list = cur_ipv6_route_conf.ipv6_route_list;

    char *lan_ipv6addr = nvram_safe_get("lan_ipv6addr");
	/*wuchunli 2012-4-1 12:33:02 begin*/
	if (NULL == (p = strstr(ipv6_prefix, "/"))) {
		vty_output("The prefix should need mask!\n");
        cli_nvram_conf_free(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
        free(lan_ipv6addr);
        return;	
	}
	else {
		memset(tmp, '\0', sizeof(tmp));
        memcpy(tmp, ipv6_prefix, p-ipv6_prefix);
		if(NULL == inet_pton(AF_INET6, tmp, (void *)&s6_ip)) {
			vty_output("Invalid IPv6 prefix!\n");
			cli_nvram_conf_free(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
            free(lan_ipv6addr);
            return;
		}
	}
	/*wuchunli 2012-4-1 12:33:18 end*/
    if((p2 = strstr(lan_ipv6addr, "/")) != NULL)
	{
        memset(tmp_global, '\0', sizeof(tmp_global));
        memcpy(tmp_global, lan_ipv6addr, p2-lan_ipv6addr);
        inet_pton(AF_INET6, tmp_global, (void *)&s6_ip_global);
        inet_pton(AF_INET6, ipv6_nexthop, (void *)&s6_ip_nexthop);
	
        if(0 == memcmp((char*)&s6_ip_global,(char*)&s6_ip_nexthop,sizeof(s6_ip_global)))
        {
            vty_output("The next hop shouldn't be equal to IPV6 global address!\n");
            cli_nvram_conf_free(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
            free(lan_ipv6addr);
			return;
        }
    }
    free(lan_ipv6addr);

    while(route_list != NULL)
    {
        /*"route_list->prefix" is ipv6 prefix in nvram*/
        p1 = strstr((char*)&(route_list->prefix), "/") ;

        memset(tmp_nv, '\0', sizeof(tmp_nv));
        memcpy(tmp_nv, (char*)&(route_list->prefix), p1-(char*)&(route_list->prefix));

        inet_pton(AF_INET6, tmp_nv, (void *)&s6_ip_nv);
        /*atoi(p+1) is mask and atoi(p1+1) is mask in nvram */
        if(0 == memcmp((char*)&s6_ip,(char*)&s6_ip_nv,sizeof(s6_ip))&&(atoi(p+1) == atoi(p1+1)))
        {
            vty_output("The IPV6 route has been exist!\n");
            cli_nvram_conf_free(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
            return;
        }

        if(!route_list->next)
        {
            break;
        }
        route_list = route_list->next;
    }

//    SYSTEM("/sbin/route -A inet6 add %s gw %s > /dev/null 2>&1",ipv6_prefix,ipv6_nexthop);
//	usleep(500000);
//    syslog(LOG_NOTICE, "[CONFIG-5-IPV6]: Add IPV6 route:%s %s, %s\n",ipv6_prefix,ipv6_nexthop, getenv("LOGIN_LOG_MESSAGE"));
    
    if(route_list)
    {
        route_list->next = malloc(sizeof(cli_ipv6_route_list));
        route_list=route_list->next;
    }
    else
    {
        route_list = malloc(sizeof(cli_ipv6_route_list));
        cur_ipv6_route_conf.ipv6_route_list=route_list;
    }
    memset(route_list, 0, sizeof(cli_ipv6_route_list));
    route_list->next = NULL;
    strcpy(route_list->prefix,ipv6_prefix);
    strcpy(route_list->nexthop,ipv6_nexthop);
    cur_ipv6_route_conf.ipv6_route_count++;
    cli_nvram_conf_set(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
    cli_nvram_conf_free(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
    system("rc route start");

    return;
}

static int cli_disable_mld_snooping(void)
{
	FILE *fp;
	pid_t pid=0;
	union sigval mysigval;
	char mld_buf[128]={'\0'};

	char *igmp_enable = nvram_safe_get("igmp_enable");
	if(*igmp_enable == '0'){
		scfgmgr_set("mld_enable", "0");
		free(igmp_enable);
		return 0;
	}
	if((fp = fopen("/var/run/snoop.pid","r"))!=NULL){
		while(fgets(mld_buf, 128, fp)!=NULL){
			pid = (pid_t)atoi(mld_buf);
		}
		fclose(fp);
	}

	mysigval.sival_int = 0;
	if(sigqueue(pid,SIGRTMIN+2,mysigval)<0)
		printf("Send signal fail!\n");
	scfgmgr_set("mld_enable", "0");
	free(igmp_enable);
	return 0;
}


/*
 *  Function : cli_no_ipv6_routes_all
 *  Purpose:
 *      remove all ipv6 routes
 *  Parameters:
 *  Returns:
 *     CLI_SUCCESS - Success
 *
 *  Author  : wuchunli
 *  Date    :2011/12/13
 */

int cli_no_ipv6_routes_all()
{
    cli_ipv6_route_list *route_list = NULL;

    cli_nvram_conf_get(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);

    route_list = cur_ipv6_route_conf.ipv6_route_list;

    while(route_list)
    {
//        SYSTEM("/sbin/route -A inet6 del %s",route_list->prefix);
        scfgmgr_set("ipv6_route_list", "");
        route_list = route_list->next;
    }
    cli_nvram_conf_free(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
    system("rc route start");

    return CLI_SUCCESS;
}


/*
 *  Function : cli_no_ipv6_route
 *  Purpose:
 *      remove one ipv6 route
 *  Parameters:
 *  Returns:
 *
 *  Author  : wuchunli
 *  Date    :2011/12/13
 */
int cli_no_ipv6_route(char *ipv6_prefix)
{
    struct in6_addr s6_ip;
    struct in6_addr s6_ip_nv;
    char *p,*p1;
    int flag=0;
    char tmp[MAX_IPV6_ROUTE];
    char tmp_nv[MAX_IPV6_ROUTE];
    cli_ipv6_route_list *p_route_list = NULL;
    cli_ipv6_route_list *t_route_list = NULL;
    cli_ipv6_route_list *k_route_list = NULL;

    cli_nvram_conf_get(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);

    p_route_list = cur_ipv6_route_conf.ipv6_route_list;
    t_route_list = cur_ipv6_route_conf.ipv6_route_list;
    k_route_list = cur_ipv6_route_conf.ipv6_route_list;

	/*wuchunli 2012-4-5 12:33:02 begin 
	  ipv6_prefix is CLI_WORD,so need check format*/
	if (NULL == (p = strstr(ipv6_prefix, "/"))) {
		vty_output("The prefix should need mask!\n");
        cli_nvram_conf_free(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
        return;	
	}
	else {
		memset(tmp, '\0', sizeof(tmp));
        memcpy(tmp, ipv6_prefix, p-ipv6_prefix);
		if(NULL == inet_pton(AF_INET6, tmp, (void *)&s6_ip)) {
			vty_output("Invalid IPv6 prefix!\n");
			cli_nvram_conf_free(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
            return;
		}
	}
	/*wuchunli 2012-4-5 12:33:18 end*/

    while(p_route_list)
    {
        /*"p_route_list->prefix" is ipv6 prefix in nvram*/
        p1 = strstr((char*)&(p_route_list->prefix), "/") ;

        memset(tmp_nv, '\0', sizeof(tmp_nv));
        memcpy(tmp_nv, (char*)&(p_route_list->prefix), p1-(char*)&(p_route_list->prefix));

        inet_pton(AF_INET6, tmp_nv, (void *)&s6_ip_nv);

        /*atoi(p+1) is mask and atoi(p1+1) is mask in nvram */
        if(0 == memcmp((char*)&s6_ip,(char*)&s6_ip_nv,sizeof(s6_ip))&&(atoi(p+1) == atoi(p1+1)))
        {
            flag = 1;
//            SYSTEM("/sbin/route -A inet6 del %s",ipv6_prefix);
            syslog(LOG_NOTICE, "[CONFIG-5-NO]: Remove IPV6 route: %s, %s\n",ipv6_prefix, getenv("LOGIN_LOG_MESSAGE"));
            break;
        }

        k_route_list = p_route_list;
        p_route_list = p_route_list->next;
    }

    if(flag)
    {
        if(p_route_list == t_route_list)
        {
            cur_ipv6_route_conf.ipv6_route_list = p_route_list->next;
            free(p_route_list);
        }
        else
        {
            k_route_list->next = p_route_list->next;
            free(p_route_list);
        }
    }
    else
    {
        printf(" The IPV6 route has not been exist!\n");
        cli_nvram_conf_free(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
        return 0;
    }

    cli_nvram_conf_set(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
    cli_nvram_conf_free(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
	system("rc route start");
    

    return 1;
}


int func_ipv6_mld_snooping(struct users *u)
{
	cli_enable_ipv6_mld_snooping();

	return 0;
}
int func_ipv6_dhcp_snooping()
{
	int portid, skfd;
	uint64_t trust_port;
	char *dhcp6_snoop_enable, *dhcp6_snoop_trust_port;

	dhcp6_snoop_enable = nvram_safe_get("dhcp6_snoop_enable");

	if('1' != *dhcp6_snoop_enable) {
		scfgmgr_set("dhcp6_snoop_enable", "1");
		SYSTEM("/usr/sbin/dhcp6snoop %s > /dev/null 2>&1", IMP);
	}

	syslog(LOG_NOTICE, "[CONFIG-5-IP]: The DHCPv6 snooping is enable, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	free(dhcp6_snoop_enable);

	return;

}
int nfunc_ipv6_dhcp_snooping()
{
	FILE *fp;
	int skfd;
	uint64_t trust_port;
	char *dhcp6_snoop_enable = nvram_safe_get("dhcp6_snoop_enable");

	if('1' == *dhcp6_snoop_enable) {
		unlink("/tmp/dhcp6_snooping");
		system("/usr/bin/killall dhcp6snoop> /dev/null 2>&1");
	}
	free(dhcp6_snoop_enable);

	scfgmgr_set("dhcp6_snoop_enable", "0");

	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Disable DHCPv6 snooping, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;

}

int nfunc_ipv6_route_ipv6(struct users *u)
{
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	/*wuchunli 2012-4-5 10:49:39 
	  ipv6_prefix is ipv6 address or network segment,so it is CLI_WORD*/
	cli_param_get_string(STATIC_PARAM,0,ipv6_str,u);
	cli_no_ipv6_route(ipv6_str);

	return 0;
}

int nfunc_ipv6_route_all(struct users *u)
{
	cli_no_ipv6_routes_all();
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Remove all IPV6 routes, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

/*modified by wuchunli 2012-4-1 12:31:21*/
int func_ipv6_route_ipv6_next(struct users *u)
{
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	char ipv6_str2[MAX_ARGV_LEN] = {'\0'};
	struct in6_addr s;
	/*prefix format is CLI_WORD*/
	cli_param_get_string(STATIC_PARAM,0,ipv6_str,u);
	cli_param_get_ipv6(STATIC_PARAM, 0, &s, ipv6_str2, sizeof(ipv6_str2), u);
	cli_set_ipv6_route(ipv6_str, ipv6_str2);

	return 0;

}

int nfunc_ipv6_mld_snooping(struct users *u)
{
	cli_disable_mld_snooping();

	return 0;
}



/*
 *  Function:  func_ipv6_nd
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_nd(struct users *u)
{
	printf("do func_ipv6_nd here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_nd
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_nd(struct users *u)
{
	printf("do nfunc_ipv6_nd here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_router_ospf
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_router_ospf(struct users *u)
{
	printf("do func_ipv6_router_ospf here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_router_rip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_router_rip(struct users *u)
{
	printf("do func_ipv6_router_rip here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_router_isis
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_router_isis(struct users *u)
{
	printf("do func_ipv6_router_isis here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_router_ospf
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_router_ospf(struct users *u)
{
	printf("do nfunc_ipv6_router_ospf here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_router_rip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_router_rip(struct users *u)
{
	printf("do nfunc_ipv6_router_rip here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_router_isis
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_router_isis(struct users *u)
{
	printf("do nfunc_ipv6_router_isis here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_unicast
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_unicast(struct users *u)
{
	printf("do func_ipv6_unicast here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_unicast
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_unicast(struct users *u)
{
	printf("do nfunc_ipv6_unicast here\n");

	return 0;
}

/*
 *  Function:  func_ip_forward_udp_bootps
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_forward_udp_bootps(struct users *u)
{
	scfgmgr_set("dhcp_relay", "1");
	return 0;
}

/*
 *  Function:  nfunc_ip_forward_udp_bootps
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_forward_udp_bootps(struct users *u)
{
	scfgmgr_set("dhcp_relay", "0");
	return 0;
}

/*
 *  Function:  func_ip_route_ip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_route_ip(struct users *u)
{
	int cnt = 0, flag = 0; 
	struct in_addr i;
	struct in_addr j;
	struct in_addr k;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
	char ip_gateway[MAX_ARGV_LEN] = {'\0'};
    struct in_addr addr;
	unsigned long int ipaddr, netmask, subnet;
    char *l3_st, *st, *p1, *pend, * lan_subnet;
	char st_str[8196];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &j, ip_mask, sizeof(ip_mask), u);
	cli_param_get_ipv4(STATIC_PARAM, 2, &k, ip_gateway, sizeof(ip_gateway), u);
		
//    DEBUG("[%s:%d] ip_str %s, ip_mask %s ip_gateway %s", __FUNCTION__, __LINE__, ip_str, ip_mask, ip_gateway);
    
    memset(st_str, '\0', sizeof(st_str));
    l3_st = nvram_safe_get("l3_st");  
    ipaddr = inet_addr(ip_str);
    netmask = inet_addr(ip_mask);
    subnet = ipaddr & netmask;
    addr.s_addr = subnet;
    lan_subnet = inet_ntoa(addr);
        
    sprintf(st_str, "%s%s:%s:%s:%d:eth1.%d;", l3_st, ip_str, ip_gateway, ip_mask, 10, 0); 
    free(l3_st);
    scfgmgr_set("l3_st", st_str);
    system("rc route restart > /dev/null 2>&1");
    
	return 0;
}

/*
 *  Function:  nfunc_ip_route_ip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_route_ip(struct users *u)
{
	int cnt = 0, found = 0; 
	struct in_addr i;
	struct in_addr j;
	struct in_addr k;
	STRLst strlst[128];
    struct in_addr addr;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
	char ip_gateway[MAX_ARGV_LEN] = {'\0'};
    char *l3_st, *st, *p1, *pend, * lan_subnet;
	char line[128], st_str[8196];
	unsigned long int ipaddr, netmask, subnet, ipaddr1, netmask1, subnet1;

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &j, ip_mask, sizeof(ip_mask), u);
//	cli_param_get_ipv4(STATIC_PARAM, 2, &k, ip_gateway, sizeof(ip_gateway), u);
	
    ipaddr1 = inet_addr(ip_str);
    netmask1 = inet_addr(ip_mask);
    subnet1 = ipaddr1 & netmask1;	

    //l3_st=0.0.0.0:192.168.10.2:255.255.255.0:20:eth1.1;192.168.11.0:192.168.16.2:255.255.255.0:20:eth1.3;
    memset(strlst, '\0', sizeof(strlst));
    memset(st_str, '\0', sizeof(st_str));

    l3_st = st = nvram_safe_get("l3_st");  
    while((*st != NULL) && (strlen(st) > 0))
    {
        memset(line, '\0', sizeof(line));
        
        p1 = st;// analysis this
        pend = strchr(st, ';'); 
        memcpy(line, p1, pend-p1);
        st = pend+1; //next one

        sscanf(line,"%[^:]:%[^:]:%[^:]:%d:eth1.%d", strlst[cnt].dst, strlst[cnt].gateway, strlst[cnt].mask, &strlst[cnt].metric, &strlst[cnt].dev);

        if(!strcmp(strlst[cnt].dst, "0.0.0.0"))
        {	
            sprintf(st_str, "%s%s:%s:%s:%d:eth1.%d;", st_str, strlst[cnt].dst, strlst[cnt].gateway, strlst[cnt].mask, strlst[cnt].metric, 0); 
        }        
        else
        {	
            ipaddr = inet_addr(strlst[cnt].dst);
	        netmask = inet_addr(strlst[cnt].mask);
	        subnet = ipaddr & netmask;
	        addr.s_addr = subnet;
	        lan_subnet = inet_ntoa(addr);
	        
	        if(subnet != subnet1)
	        {    
                sprintf(st_str, "%s%s;", st_str, line); 
            }else
            {
                found = 1;
            }    
        }
        
        cnt++;
    } 
    free(l3_st);
    
    if(1 == found)
    {
        scfgmgr_set("l3_st", st_str);
        system("rc route restart > /dev/null 2>&1");
    }    
    
	return 0;
}

/*
 *  Function:  func_ip_route_default
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_route_default(struct users *u)
{
	int cnt = 0, flag = 0; 
	struct in_addr i;
	STRLst strlst[128];
    struct in_addr addr;
	unsigned long int ipaddr, netmask, subnet;
    char *l3_st, *st, *p1, *pend, * lan_subnet;
	char line[128], ip_str[MAX_ARGV_LEN] = {'\0'}, st_str[8196];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
		
//    DEBUG("[%s:%d] ip_str %s", __FUNCTION__, __LINE__, ip_str);
    
    //l3_st=0.0.0.0:192.168.10.2:255.255.255.0:20:eth1.1;192.168.11.0:192.168.16.2:255.255.255.0:20:eth1.3;
    memset(strlst, '\0', sizeof(strlst));
    memset(st_str, '\0', sizeof(st_str));

    l3_st = st = nvram_safe_get("l3_st");  
    while((*st != NULL) && (strlen(st) > 0))
    {
        memset(line, '\0', sizeof(line));
        
        p1 = st;// analysis this
        pend = strchr(st, ';'); 
        memcpy(line, p1, pend-p1);
        st = pend+1; //next one

        sscanf(line,"%[^:]:%[^:]:%[^:]:%d:eth1.%d", strlst[cnt].dst, strlst[cnt].gateway, strlst[cnt].mask, &strlst[cnt].metric, &strlst[cnt].dev);

        if(!strcmp(strlst[cnt].dst, "0.0.0.0"))
        {	
            flag = 1; 
            strcpy(strlst[cnt].gateway, ip_str); 
            sprintf(st_str, "%s%s:%s:%s:%d:eth1.%d;", st_str, strlst[cnt].dst, strlst[cnt].gateway, strlst[cnt].mask, strlst[cnt].metric, 0); 
        }        
        else
        {	
            ipaddr = inet_addr(strlst[cnt].dst);
	        netmask = inet_addr(strlst[cnt].mask);
	        subnet = ipaddr & netmask;
	        addr.s_addr = subnet;
	        lan_subnet = inet_ntoa(addr);
            sprintf(st_str, "%s%s;", st_str, line); 
        }
        
        cnt++;
    } 
    free(l3_st);
    
    if(flag == 0)
    {
        sprintf(st_str, "%s%s:%s:%s:%d:eth1.%d;", st_str, "0.0.0.0", ip_str, "0.0.0.0", 10, 0); 
    }  
    scfgmgr_set("l3_st", st_str);
    system("rc route restart > /dev/null 2>&1");
    
	return 0;
}

/*
 *  Function:  nfunc_ip_route_default
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_route_default(struct users *u)
{
	FILE *fp;	
	int cnt = 0, found = 0; 
	struct in_addr i;
	STRLst strlst[128];
    struct in_addr addr;
	unsigned long int ipaddr, netmask, subnet;
    char *l3_st, *st, *p1, *pend, * lan_subnet;
	char line[128], ip_str[MAX_ARGV_LEN] = {'\0'}, st_str[8196];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
		
//    DEBUG("[%s:%d] ip_str %s", __FUNCTION__, __LINE__, ip_str);
    
    //l3_st=0.0.0.0:192.168.10.2:255.255.255.0:20:eth1.1;192.168.11.0:192.168.16.2:255.255.255.0:20:eth1.3;
    memset(strlst, '\0', sizeof(strlst));
    memset(st_str, '\0', sizeof(st_str));

    l3_st = st = nvram_safe_get("l3_st");  
    while((*st != NULL) && (strlen(st) > 0))
    {
        memset(line, '\0', sizeof(line));
        
        p1 = st;// analysis this
        pend = strchr(st, ';'); 
        memcpy(line, p1, pend-p1);
        st = pend+1; //next one

        sscanf(line,"%[^:]:%[^:]:%[^:]:%d:eth1.%d", strlst[cnt].dst, strlst[cnt].gateway, strlst[cnt].mask, &strlst[cnt].metric, &strlst[cnt].dev);

        if(!strcmp(strlst[cnt].dst, "0.0.0.0"))
        {	
            found = 1;
        }        
        else
        {	
            ipaddr = inet_addr(strlst[cnt].dst);
	        netmask = inet_addr(strlst[cnt].mask);
	        subnet = ipaddr & netmask;
	        addr.s_addr = subnet;
	        lan_subnet = inet_ntoa(addr);
            sprintf(st_str, "%s%s;", st_str, line); 
        }
        
        cnt++;
    } 
    free(l3_st);
    
    if(1 == found)
    {    
        scfgmgr_set("l3_st", st_str);
        system("rc route restart > /dev/null 2>&1"); 
    }
    
	return 0;
}

/*
 *  Function:  func_garp_timer_leaveall
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_garp_timer_leaveall(struct users *u)
{
    int time;
    char timestr[12];
    
    cli_param_get_int(STATIC_PARAM, 0, &time, u);
    
    memset(timestr, '\0', sizeof(timestr));
    sprintf(timestr, "%d", time);
	scfgmgr_set("garp_leaveall", timestr);
	system("killall -SIGUSR2 gvrpd  > /dev/null 2>&1 &");
	system("killall -SIGUSR2 gmrpd  > /dev/null 2>&1 &");
	
	return 0;
}

/*
 *  Function:  nfunc_garp_timer_leaveall
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_garp_timer_leaveall(struct users *u)
{
	scfgmgr_set("garp_leaveall", "10");
	system("killall -SIGUSR2 gvrpd  > /dev/null 2>&1 &");
	system("killall -SIGUSR2 gmrpd  > /dev/null 2>&1 &");
	return 0;
}

/*
 *  Function:  func_gmrp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_gmrp(struct users *u)
{
    char *gmrp_enable = nvram_safe_get("gmrp_enable");
	
 	//printf("func_gmrp gmrp_enable %s\n",gmrp_enable);
    //if( '1' != *gmrp_enable )
    {    
        scfgmgr_set("gmrp_enable", "1");
        COMMAND("rc gmrp restart > /dev/null 2>&1");
    }
    
    #if 0
    else
        system("killall -SIGUSR2 gmrpd >/dev/null 2>&1");
    #endif

	free(gmrp_enable);
	
	return 0;
}

/*
 *  Function:  nfunc_gmrp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_gmrp(struct users *u)
{
    char *gmrp_enable = nvram_safe_get("gmrp_enable");

    if( '0' != *gmrp_enable )
    {    
        scfgmgr_set("gmrp_enable", "0");
        system("rc gmrp stop >/dev/null 2>&1");
    }

	free(gmrp_enable);
	return 0;
}

/*
 *  Function:  func_ip_mroute
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_mroute(struct users *u)
{
    FILE * fp;
	struct in_addr i;
	struct in_addr j;
	int cnt = 0, found = 0, vlan_id; 
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char mip_str[MAX_ARGV_LEN] = {'\0'};
    char line[128], intf[8], sip[16], gip[16];
    char *p, *p1, smt_str[8196];
    char *ipmc = nvram_safe_get("ipmc_slist"); 
    char *ipmc_enable = nvram_safe_get("ipmc_enable"); 

    if(*ipmc_enable == '0')
    {    
        vty_output("Error: no multicast-routing enable, please run \"ip multicast-routing\" first!\n\n");    
        free(ipmc);  
        free(ipmc_enable);
        return 0;
    }
    
	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &j, mip_str, sizeof(mip_str), u);
	p = strstr(u->linebuf, "vlan")+strlen("vlan");
	while(*p == ' ')
	    p++;
	vlan_id = atoi(p);    
//    printf("[%s:%d] ip_str %s, mip_str %s vlan_id %d\n", __FUNCTION__, __LINE__, ip_str, mip_str, vlan_id);
    
    if(find_vlan_intf_exit(vlan_id) == 0)
    {    
        vty_output("Error: no this valid interface, please config vlan and ip first!\n\n");    
        free(ipmc);  
        free(ipmc_enable);
        return 0;
    }
    
    if((fp=fopen("/etc/ipmc","r")) != NULL)
    { 
        memset(line, '\0', sizeof(line));
    	while(fgets(line, sizeof(line), fp)!=NULL)
    	{		
            memset(intf, '\0', sizeof(intf));
            memset(sip, '\0', sizeof(sip));
            memset(gip, '\0', sizeof(gip));				
    		
            sscanf(line, "%[^,],%[^,],%s", intf, gip, sip); 
            if((atoi(intf) == vlan_id) && !strcmp(gip, mip_str) && !strcmp(ip_str, sip))
            {    
                found = 1;
                break;
            }    
    	}
    	fclose(fp);   
    } 
    
    if(0 == found)
    {
        if((fp=fopen("/etc/ipmc","a"))!=NULL)
        {
            fprintf(fp,"%s,%s,%s\n", p, mip_str, ip_str); 
            SYSTEM("/usr/sbin/smcroute -a %s.%d %s %s %s.%d > /dev/null 2>&1", IMP, vlan_id, ip_str, mip_str, IMP, vlan_id);
    	    fclose(fp);   
        }       
        memset(smt_str, '\0', sizeof(smt_str));
	    sprintf(smt_str, "%s%d,%s,%s;", ipmc, vlan_id, mip_str, ip_str);
	    scfgmgr_set("ipmc_slist", smt_str);
    }else
    {
        vty_output("Warning: the same item configure, no action!\n\n");    
    }
             
    free(ipmc);  
    free(ipmc_enable);  
	return 0;
}

/*
 *  Function:  nfunc_ip_mroute
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   eagles.zhou
 *  Date:    2011/11/26
 */
int nfunc_ip_allmroute(struct users *u)
{
    FILE * fp;
	struct in_addr i;
	struct in_addr j;
    struct in_addr addr;
	int cnt = 0, found = 0, vlan_id; 
	char ip_str[MAX_ARGV_LEN] = {'\0'};
    char line[128], intf[8], sip[16], gip[16];
    char smt_str[8196];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
//    printf("[%s:%d] ip_str %s\n", __FUNCTION__, __LINE__, ip_str);

    memset(smt_str, '\0', sizeof(smt_str));
    if((fp=fopen("/etc/ipmc","r")) != NULL)
    { 
        memset(line, '\0', sizeof(line));
    	while(fgets(line, sizeof(line), fp)!=NULL)
    	{		
            memset(intf, '\0', sizeof(intf));
            memset(sip, '\0', sizeof(sip));
            memset(gip, '\0', sizeof(gip));				
    		
            sscanf(line, "%[^,],%[^,],%s", intf, gip, sip); 
            if(!strcmp(ip_str, sip))
            {    
                found = 1;
            }else
                sprintf(smt_str, "%s%s,%s,%s;", smt_str, intf, gip, sip);    
    	}
    	fclose(fp);   
    } 
    
    if(0 == found)
    {
        vty_output("Warning: no any mroute item with this soure ip, no action!\n\n");  
	    return 0;
    }else
    {
        scfgmgr_set("ipmc_slist", smt_str);
	    system("rc mroute restart > /dev/null 2>&1 &");
    }
             
	return 0;
}

/*
 *  Function:  nfunc_ip_mroute
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_mroute(struct users *u)
{
    FILE * fp;
	struct in_addr i;
	struct in_addr j;
	int cnt = 0, found = 0, vlan_id; 
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char mip_str[MAX_ARGV_LEN] = {'\0'};
    char line[128], intf[8], sip[16], gip[16];
    char smt_str[8196];
    //char *ipmc = nvram_safe_get("ipmc_slist"); 
    //char *ipmc_enable = nvram_safe_get("ipmc_enable"); 

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &j, mip_str, sizeof(mip_str), u);
//    printf("[%s:%d] ip_str %s, mip_str %s\n", __FUNCTION__, __LINE__, ip_str, mip_str);

    if((fp=fopen("/etc/ipmc","r")) != NULL)
    { 
        memset(line, '\0', sizeof(line));
    	while(fgets(line, sizeof(line), fp)!=NULL)
    	{		
            memset(intf, '\0', sizeof(intf));
            memset(sip, '\0', sizeof(sip));
            memset(gip, '\0', sizeof(gip));				
    		
            sscanf(line, "%[^,],%[^,],%s", intf, gip, sip); 
            if(!strcmp(gip, mip_str)&& !strcmp(ip_str, sip))
            {    
                found = 1;
            } 
            else
                sprintf(smt_str, "%s%s,%s,%s;", smt_str, intf, gip, sip);     
    	}
    	fclose(fp);   
    } 
    
    if(0 == found)
    {
        vty_output("Warning: no any mroute item with this soure ip and greoup ip, no action!\n\n");  
	    return 0;
    }else
    {
        scfgmgr_set("ipmc_slist", smt_str);
	    system("rc mroute restart > /dev/null 2>&1 &");
    }
	return 0;
}

/*
 *  Function:  func_ip_multi_routing
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_multi_routing(struct users *u)
{
	scfgmgr_set("ipmc_enable", "1");
	system("rc mroute restart > /dev/null 2>&1");
	
	return 0;
}

/*
 *  Function:  nfunc_ip_multi_routing
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_multi_routing(struct users *u)
{
	scfgmgr_set("ipmc_enable", "0");
	scfgmgr_set("ipmc_slist", "");
	scfgmgr_set("igmp_config", "");
	
	system("rc mroute restart > /dev/null 2>&1");

	return 0;
}

/*
 *  Function:  func_ip_igmp_querier_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_igmp_querier_time(struct users *u)
{
	printf("do func_ip_igmp_querier_time here\n");

	return 0;
}

/*
 *  Function:  nfunc_ip_igmp_querier_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_igmp_querier_time(struct users *u)
{
	printf("do nfunc_ip_igmp_querier_time here\n");

	return 0;
}

/*
 *  Function:  func_ip_pim_bsr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_pim_bsr(struct users *u)
{
    char key[8];
	int priority = 0;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");
    char *pimsm_pri = nvram_safe_get("pimsm_pri");
	
    cli_param_get_int(STATIC_PARAM, 0, &priority, u);
//    fprintf(stderr, "[%s:%d] priority %d\n", __FUNCTION__, __LINE__, priority);
    
    if(*ipmc_enable == '1')
	{
	    if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
    	{    
    	    if(priority != atoi(pimsm_pri))
        	{
	            memset(key, '\0', sizeof(key));
        	    sprintf(key, "%d", priority);
                scfgmgr_set("pimsm_pri", key);
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else
            {
                vty_output("Warning: PIM-SM has the same configure, no change!\n"); 
            } 
    	}else
        {
            vty_output("Warning: PIM-SM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(ipmc_enable);
    free(ipmc_type);
    free(pimsm_pri);

	return 0;
}

/*
 *  Function:  nfunc_ip_pim_bsr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_pim_bsr(struct users *u)
{
	printf("do nfunc_ip_pim_bsr here\n");

	return 0;
}

/*
 *  Function:  func_ip_pim_dr_priority
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
 
int func_ip_pim_dm(int enable)
{
	printf("do func_ip_pim_dr_priority here\n");

	return 0;
}
 
int func_ip_pim_dr_priority(struct users *u)
{
	printf("do func_ip_pim_dr_priority here\n");

	return 0;
}

/*
 *  Function:  nfunc_ip_pim_dr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_pim_dr(struct users *u)
{
	printf("do nfunc_ip_pim_dr here\n");

	return 0;
}

/*
 *  Function:  func_ip_pim_rp_add_over
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_pim_rp_add_over(struct users *u)
{	
    int flag = 0, netmask, netmask1;
    char rp_str[MAX_ARGV_LEN] = {'\0'};
    char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
	struct in_addr i, j, k;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");
    char *pimsm_rp = nvram_safe_get("pimsm_rp");
    char *ip, *p1, line[256], pimstr[8192], ipaddr[3][32];
	
	cli_param_get_ipv4(STATIC_PARAM, 0, &i, rp_str, sizeof(rp_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &j, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 2, &k, ip_mask, sizeof(ip_mask), u);
	
	netmask = inet_addr(ip_str) & inet_addr(ip_mask);
//	fprintf(stderr, "[%s:%d] rp %s ip %s, mask %s netmask 0x%08x\n", __FUNCTION__, __LINE__, rp_str, ip_str, ip_mask, netmask);
	
    if(*ipmc_enable == '1')
	{
	    if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
    	{    
    	    ip = pimsm_rp;
		    while(strlen(ip) > 0)
		    {
		        memset(line, '\0', sizeof(line));
		        memset(ipaddr, '\0', sizeof(ipaddr));
		        p1 = strchr(ip, ';');
		        memcpy(line, ip, p1-ip);
		        
		        sscanf(line, "%[^:]:%[^:]:%[^:]", ipaddr[0], ipaddr[1], ipaddr[2]);
		        netmask1 = inet_addr(ipaddr[1]) & inet_addr(ipaddr[2]);
//		        fprintf(stderr, "[%s:%d] line: ipaddr %s  %s  %s netmask1 0x%08x\n", __FUNCTION__, __LINE__, ipaddr[0], ipaddr[1], ipaddr[2], netmask1);
		        
		        if((!strcmp(rp_str, ipaddr[0])) && (!strcmp(ip_str, ipaddr[1])) && (!strcmp(ip_mask, ipaddr[2])))
		        {
		            flag = 1;
		            break;
		        }   
		        
		        if((netmask == netmask1)&&(inet_addr(ip_mask) == inet_addr(ipaddr[2])))
		        {
		            flag = 2;
		            break;
		        }   
		        
		        ip = p1+1;
		    }  
    	    
        	if(0 == flag)
        	{
	            memset(pimstr, '\0', sizeof(pimstr));
        	    sprintf(pimstr, "%s%s:%s:%s;", pimsm_rp, rp_str, ip_str, ip_mask);
                scfgmgr_set("pimsm_rp", pimstr);
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else if(2 == flag)
            {
                vty_output("Error: PIM-SM has the conflict configure, please check!\n"); 
            } 
            else
            {
                vty_output("Warning: PIM-SM has the same configure, no change!\n"); 
            } 
    	}else
        {
            vty_output("Warning: PIM-SM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(ipmc_enable);
    free(ipmc_type);
    free(pimsm_rp);
    
	return 0;
}

int func_ip_pim_rp_add_all(struct users *u)
{	
    int flag = 0, netmask, netmask1;
    char rp_str[MAX_ARGV_LEN] = {'\0'};
    char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
	struct in_addr i, j, k;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");
    char *pimsm_rp = nvram_safe_get("pimsm_rp");
    char *ip, *p1, line[256], pimstr[8192], ipaddr[3][32];
	
	cli_param_get_ipv4(STATIC_PARAM, 0, &i, rp_str, sizeof(rp_str), u);
	netmask = inet_addr("240.0.0.0");
	
    if(*ipmc_enable == '1')
	{
	    if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
    	{    
    	    ip = pimsm_rp;
		    while(strlen(ip) > 0)
		    {
		        memset(line, '\0', sizeof(line));
		        memset(ipaddr, '\0', sizeof(ipaddr));
		        p1 = strchr(ip, ';');
		        memcpy(line, ip, p1-ip);
		        
		        sscanf(line, "%[^:]:%[^:]:%[^:]", ipaddr[0], ipaddr[1], ipaddr[2]);
		        netmask1 = inet_addr(ipaddr[1]) & inet_addr(ipaddr[2]);
//		        fprintf(stderr, "[%s:%d] line: ipaddr %s  %s  %s netmask1 0x%08x\n", __FUNCTION__, __LINE__, ipaddr[0], ipaddr[1], ipaddr[2], netmask1);
		        
		        if((netmask == netmask1) && (!strcmp(rp_str, ipaddr[0])))
		        {
		            flag = 1;
		            break;
		        }   
		        
		        if((netmask == netmask1)&&(inet_addr(ip_mask) == inet_addr(ipaddr[2])))
		        {
		            flag = 2;
		            break;
		        }   
		        
		        ip = p1+1;
		    }  
    	    
        	if(0 == flag)
        	{
	            memset(pimstr, '\0', sizeof(pimstr));
        	    sprintf(pimstr, "%s%s:%s:%s;", pimsm_rp, rp_str, "224.0.0.0", "240.0.0.0");
                scfgmgr_set("pimsm_rp", pimstr);
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else if(2 == flag)
            {
                vty_output("Error: PIM-SM has the conflict configure, please check!\n"); 
            } 
            else
            {
                vty_output("Warning: PIM-SM has the same configure, no change!\n"); 
            } 
    	}else
        {
            vty_output("Warning: PIM-SM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(ipmc_enable);
    free(ipmc_type);
    free(pimsm_rp);
    
	return 0;
}

/*
 *  Function:  nfunc_ip_pim_rp_add_over
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_pim_rp_add_over(struct users *u)
{
    int flag = 0, netmask, netmask1;
    char rp_str[MAX_ARGV_LEN] = {'\0'};
    char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
	struct in_addr i, j, k;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");
    char *pimsm_rp = nvram_safe_get("pimsm_rp");
    char *ip, *p1, line[256], pimstr[8192], ipaddr[3][32];
	
	cli_param_get_ipv4(STATIC_PARAM, 0, &i, rp_str, sizeof(rp_str), u);
	netmask = inet_addr("240.0.0.0");
	
    if(*ipmc_enable == '1')
	{
	    if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
    	{    
    	    ip = pimsm_rp;
	        memset(pimstr, '\0', sizeof(pimstr));
	        
		    while(strlen(ip) > 0)
		    {
		        memset(line, '\0', sizeof(line));
		        memset(ipaddr, '\0', sizeof(ipaddr));
		        p1 = strchr(ip, ';');
		        memcpy(line, ip, p1-ip);
		        
		        sscanf(line, "%[^:]:%[^:]:%[^:]", ipaddr[0], ipaddr[1], ipaddr[2]);
		        if(!strcmp(rp_str, ipaddr[0]))
		        {
		            flag = 1;
		        }
		        else
		        {
		            sprintf(pimstr, "%s%s;", pimstr, line);      
		        }   
		        
		        ip = p1+1;
		    }  
    	    
        	if(1 == flag)
        	{
                scfgmgr_set("pimsm_rp", pimstr);
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else
            {
                vty_output("Warning: PIM-SM has the no static rp configure, no change!\n"); 
            } 
    	}else
        {
            vty_output("Warning: PIM-SM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(ipmc_enable);
    free(ipmc_type);
    free(pimsm_rp);
    
	return 0;
}

/*
 *  Function:  func_ip_pim_rp_add_acl
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_pim_rp_add_acl(struct users *u)
{
	printf("do func_ip_pim_rp_add_acl here\n");

	return 0;
}

/*
 *  Function:  nfunc_ip_pim_rp_add_acl
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_pim_rp_add_acl(struct users *u)
{
	printf("do nfunc_ip_pim_rp_add_acl here\n");

	return 0;
}

/*
 *  Function:  func_ip_pim_can
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_pim_can(struct users *u)
{
    char *p1, key[32];
	int time = 0, priority = 0, om, op;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");
    char *pimsm_rpc = nvram_safe_get("pimsm_rpc");
	
    cli_param_get_int(STATIC_PARAM, 0, &time, u);
    cli_param_get_int(STATIC_PARAM, 1, &priority, u);

    if(*ipmc_enable == '1')
	{
	    if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
    	{
    	    if(atoi(pimsm_rpc) == 0)
    	        om = op = 0;
    	    else
    	    {
    	    fprintf(stderr, "[%s:%d]\n", __FUNCTION__, __LINE__);
    	        p1 = strchr(pimsm_rpc, ':')+1;
    	        om = atoi(pimsm_rpc);
    	        op = atoi(p1); 
    	    }  
    	    
    	    if((om != time) ||(op != priority)) 
        	{
	            memset(key, '\0', sizeof(key));
        	    sprintf(key, "%d:%d", time, priority);
                scfgmgr_set("pimsm_rpc", key);
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else
            {
                vty_output("PIM-SM has the same configure, no change!\n"); 
            } 
    	}else
        {
            vty_output("Warning: PIM-SM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(ipmc_enable);
    free(ipmc_type);
    free(pimsm_rpc);

	return 0;
}

/*
 *  Function:  nfunc_ip_pim_can
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_pim_can(struct users *u)
{
    char *p1, key[32];
	int time = 0, priority = 0, om, op;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");
    char *pimsm_rpc = nvram_safe_get("pimsm_rpc");
	
    cli_param_get_int(STATIC_PARAM, 0, &time, u);
    cli_param_get_int(STATIC_PARAM, 1, &priority, u);

    if(*ipmc_enable == '1')
	{
	    if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
    	{   
    	    if(atoi(pimsm_rpc) != 0)
        	{
                scfgmgr_set("pimsm_rpc", "");
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else
            {
                vty_output("Warning: PIM-SM hasn't be configured, no change!\n"); 
            } 
    	}else
        {
            vty_output("Warning: PIM-SM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(ipmc_enable);
    free(ipmc_type);
    free(pimsm_rpc);

	return 0;
}

/*
 *  Function:  func_ipv6_pim_rp_add_over
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_pim_rp_add_over(struct users *u)
{
	printf("do func_ipv6_pim_rp_add_over here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_pim_rp_add_over
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_pim_rp_add_over(struct users *u)
{
	printf("do nfunc_ipv6_pim_rp_add_over here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_pim_rp_add_acl
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_pim_rp_add_acl(struct users *u)
{
	printf("do func_ipv6_pim_rp_add_acl here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_pim_rp_add_acl
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_pim_rp_add_acl(struct users *u)
{
	printf("do nfunc_ipv6_pim_rp_add_acl here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_pim_can
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_pim_can(struct users *u)
{
	printf("do func_ipv6_pim_can here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_pim_can
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_pim_can(struct users *u)
{
	printf("do nfunc_ipv6_pim_can here\n");

	return 0;
}

/*
 *  Function:  func_bfd_enable
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_bfd_enable(struct users *u)
{
	char *bfd_enable = nvram_safe_get("bfd_enable");
	int enable = atoi(bfd_enable);

	if(1 != enable)
	{   
	    nvram_set("bfd_enable", "1");
	    system("rc bfd restart  > /dev/null 2>&1");
	    system("rc ospf restart  > /dev/null 2>&1");
	} 
	
	free(bfd_enable);
	return 0;
}

/*
 *  Function:  nfunc_bfd_enable
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_bfd_enable(struct users *u)
{
	char *bfd_enable = nvram_safe_get("bfd_enable");
	int enable = atoi(bfd_enable);

	if(0 != enable)
	{   
	    nvram_set("bfd_enable", "0");
	    system("rc bfd stop  > /dev/null 2>&1");
	} 
	
	free(bfd_enable);
	return 0;
}

/*
 *  Function:  func_bfd_all
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_bfd_all(struct users *u)
{
	printf("do func_bfd_all here\n");

	return 0;
}

/*
 *  Function:  nfunc_bfd_all
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_bfd_all(struct users *u)
{
	printf("do nfunc_bfd_all here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_pim_bsr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_pim_bsr(struct users *u)
{
	printf("do func_ipv6_pim_bsr here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_pim_bsr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_pim_bsr(struct users *u)
{
	printf("do nfunc_ipv6_pim_bsr here\n");

	return 0;
}

/*
 *  Function:  func_port_garp_timer_hold
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_garp_timer_hold(struct users *u)
{
    int time;
    char timestr[12];
    
    cli_param_get_int(STATIC_PARAM, 0, &time, u);
    
    memset(timestr, '\0', sizeof(timestr));
    sprintf(timestr, "%d", time);
	scfgmgr_set("garp_hold", timestr);
	
	system("killall -SIGUSR2 gvrpd  > /dev/null 2>&1 &");
	system("killall -SIGUSR2 gmrpd  > /dev/null 2>&1 &");
	
	return 0;
}

/*
 *  Function:  func_port_garp_timer_join
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_garp_timer_join(struct users *u)
{
    int time;
    char timestr[12];
    
    cli_param_get_int(STATIC_PARAM, 0, &time, u);
    
    memset(timestr, '\0', sizeof(timestr));
    sprintf(timestr, "%d", time);
    
	scfgmgr_set("garp_join", timestr);
	system("killall -SIGUSR2 gvrpd  > /dev/null 2>&1 &");
	system("killall -SIGUSR2 gmrpd  > /dev/null 2>&1 &");
	return 0;
}

/*
 *  Function:  func_port_garp_timer_leave
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_garp_timer_leave(struct users *u)
{
    int time;
    char timestr[12];
    
    cli_param_get_int(STATIC_PARAM, 0, &time, u);
    
    memset(timestr, '\0', sizeof(timestr));
    sprintf(timestr, "%d", time);
	scfgmgr_set("garp_leave", timestr);
	system("killall -SIGUSR2 gvrpd  > /dev/null 2>&1 &");
	system("killall -SIGUSR2 gmrpd  > /dev/null 2>&1 &");
	
	return 0;
}

/*
 *  Function:  nfunc_port_garp_timer_hold
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_garp_timer_hold(struct users *u)
{
	scfgmgr_set("garp_hold", "1");
	system("killall -SIGUSR2 gvrpd  > /dev/null 2>&1 &");
	system("killall -SIGUSR2 gmrpd  > /dev/null 2>&1 &");
	return 0;
}

/*
 *  Function:  nfunc_port_garp_timer_join
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_garp_timer_join(struct users *u)
{
	scfgmgr_set("garp_join", "1");
	system("killall -SIGUSR2 gvrpd  > /dev/null 2>&1 &");
	system("killall -SIGUSR2 gmrpd  > /dev/null 2>&1 &");
	return 0;
}

/*
 *  Function:  nfunc_port_garp_timer_leave
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_garp_timer_leave(struct users *u)
{
	scfgmgr_set("garp_leave", "6");
	system("killall -SIGUSR2 gvrpd  > /dev/null 2>&1 &");
	system("killall -SIGUSR2 gmrpd  > /dev/null 2>&1 &");
	return 0;
}


int func_ip_dns_proxy(int enable)
{
    int orig = 0;
	char val[8], *dns_proxy = nvram_safe_get("dns_proxy");
	
	if(*dns_proxy == '1')
	    orig = 1;    
	free(dns_proxy);    
	if(orig != enable) 
	{      
	    memset(val, '\0', sizeof(val));
	    val[0] = enable+'0';
	    
    	scfgmgr_set("dns_proxy", val);
		SYSTEM("/usr/sbin/rc relay restart  > /dev/null 2>&1");
    }
    
	return 0;
}

