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

#include "cli_dhcp_func.h"


int get_parameter_dhcpd(char *conf, char *subnet, char *gateway, char *range, char *lease, char *dns, char *name)
{
    char *p, *p1, *p2;
    
    p = strchr(conf, ',');
    memcpy(subnet, conf, p-conf);
    p++;
    
    p1 = strchr(p, ',');
    memcpy(gateway, p, p1-p);
    p1++;
    
    p = strchr(p1, ',');
    memcpy(range, p1, p-p1);
    p++;
    
    p1 = strchr(p, ',');
    memcpy(lease, p, p1-p);
    p1++;
    
    p = strchr(p1, ',');
    memcpy(dns, p1, p-p1);
    p++;
    
    strcpy(name, p);
    return 0;
}
/*
 *  Function:  func_service_dhcp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_service_dhcp(struct users *u)
{
    nvram_set("dhcpd_enable", "1");
	return 0;
}

/*
 *  Function:  func_service_dhcpv6
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_service_dhcpv6(struct users *u)
{
    nvram_set("dhcpdv6_enable", "1");
    
	return 0;
}

/*
 *  Function:  nfunc_service_dhcp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_service_dhcp(struct users *u)
{
    nvram_set("dhcpd_enable", "0");
    nvram_set("l3_dhcp", "");
	return 0;
}

/*
 *  Function:  nfunc_service_dhcpv6
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_service_dhcpv6(struct users *u)
{
	printf("do nfunc_service_dhcpv6 here\n");

	return 0;
}

/*
 *  Function:  nfunc_ip_dns
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_dns(struct users *u)
{
	printf("do nfunc_ip_dns here\n");

	return 0;
}

int nfunc_ip_gateway(struct users *u)
{
	printf("do nfunc_ip_dns here\n");

	return 0;
}

/*
 *  Function:  func_ip_dns_addr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_dns_addr(struct users *u)
{   
    int pool;
    dhcpd_conf conf;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	struct in_addr i;
    char *config, pool_name[16], pool_str[256];
	
	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	
	pool = atoi(u->promptbuf+5);
	sprintf(pool_name,"dhcp_pool%d", pool);
	
	config = nvram_safe_get(pool_name);
    
    //subnet/mask,gateway,range,lease,dns,name
    memset(pool_str, '\0', sizeof(pool_str));
    if(strlen(config) > 4)
    {
        memset(&conf, '\0', sizeof(conf));
        get_parameter_dhcpd(config,  conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, conf.name);
        sprintf(pool_str, "%s,%s,%s,%s,%s,%s", conf.subnet, conf.gateway, conf.range, conf.lease, ip_str, conf.name); 
    }else
    {
        sprintf(pool_str, ",,,,%s,", ip_str);
    }   
    
    nvram_set(pool_name, pool_str);    
    
    free(config);
    fun_set_dhcpd_enable(pool);   

	return 0;
}

int func_ip_gateway_addr(struct users *u)
{    
    int pool;
    dhcpd_conf conf;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	struct in_addr i;
    char *config, pool_name[16], pool_str[256];
	
	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	
	pool = atoi(u->promptbuf+5);
	sprintf(pool_name,"dhcp_pool%d", pool);
	
	config = nvram_safe_get(pool_name);
    
    //subnet/mask,gateway,range,lease,dns,name
    memset(pool_str, '\0', sizeof(pool_str));
    if(strlen(config) > 4)
    {
        memset(&conf, '\0', sizeof(conf));
        get_parameter_dhcpd(config,  conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, conf.name);
        sprintf(pool_str, "%s,%s,%s,%s,%s,%s", conf.subnet, ip_str, conf.range, conf.lease, conf.dns, conf.name); 
    }else
    {
        sprintf(pool_str, ",%s,,,,", ip_str);
    }   

    nvram_set(pool_name, pool_str);   
    free(config);
    fun_set_dhcpd_enable(pool);   

	return 0;
}
/*
 *  Function:  nfunc_ip_domain
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_domain(struct users *u)
{
	printf("do nfunc_ip_domain here\n");

	return 0;
}

/*
 *  Function:  func_ip_domain_name
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_domain_name(struct users *u)
{   
    int pool, lease_time;
    dhcpd_conf conf;	
    char *config, pool_name[16], doname_name[32], pool_str[256];
	
	cli_param_get_string(STATIC_PARAM, 0, doname_name, u);
	pool = atoi(u->promptbuf+5);
	sprintf(pool_name,"dhcp_pool%d", pool);
	
	config = nvram_safe_get(pool_name);
    
    //subnet/mask,gateway,range,lease,dns,name
    memset(pool_str, '\0', sizeof(pool_str));
    if(strlen(config) > 4)
    {
        memset(&conf, '\0', sizeof(conf));
        get_parameter_dhcpd(config,  conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, conf.name);
        sprintf(pool_str, "%s,%s,%s,%s,%s,%s", conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, doname_name); 
    }else
    {
        sprintf(pool_str, ",,,,,%s", doname_name);
    }
    nvram_set(pool_name, pool_str);    
    
    free(config);
    fun_set_dhcpd_enable(pool);   

	return 0;
}

/*
 *  Function:  nfunc_ip_lease
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_lease(struct users *u)
{
	printf("do nfunc_ip_lease here\n");

	return 0;
}

/*
 *  Function:  func_ip_lease_days
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_lease_days(struct users *u)
{    
    int pool, lease_time;
    dhcpd_conf conf;	
    int buffer1 = 0;
    char *config, pool_name[16], pool_str[256];
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer1, u);
    lease_time = buffer1*24*60*60;
	pool = atoi(u->promptbuf+5);
	sprintf(pool_name,"dhcp_pool%d", pool);
	
	config = nvram_safe_get(pool_name);
    
    //subnet/mask,gateway,range,lease,dns,name
    memset(pool_str, '\0', sizeof(pool_str));
    if(strlen(config) > 4)
    {
        memset(&conf, '\0', sizeof(conf));
        get_parameter_dhcpd(config,  conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, conf.name);
        sprintf(pool_str, "%s,%s,%s,%d,%s,%s", conf.subnet, conf.gateway, conf.range, lease_time, conf.dns, conf.name); 
    }else
    {
        sprintf(pool_str, ",,,%d,,", lease_time);
    }
    nvram_set(pool_name, pool_str);    
    
    free(config);
    fun_set_dhcpd_enable(pool);   

	return 0;
}

/*
 *  Function:  func_ip_lease_days_hours
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_lease_days_hours(struct users *u)
{    
    int pool, lease_time;
    dhcpd_conf conf;	
    int buffer1 = 0;
	int buffer2 = 0;
    char *config, pool_name[16], pool_str[256];
	
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer1, u);
	cli_param_get_int(STATIC_PARAM, 1, &buffer2, u);

    lease_time = buffer1*24*60*60+buffer2*60*60;

	pool = atoi(u->promptbuf+5);
	sprintf(pool_name,"dhcp_pool%d", pool);
	
	config = nvram_safe_get(pool_name);
    
    //subnet/mask,gateway,range,lease,dns,name
    memset(pool_str, '\0', sizeof(pool_str));
    if(strlen(config) > 4)
    {
        memset(&conf, '\0', sizeof(conf));
        get_parameter_dhcpd(config,  conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, conf.name);
        sprintf(pool_str, "%s,%s,%s,%d,%s,%s", conf.subnet, conf.gateway, conf.range, lease_time, conf.dns, conf.name); 
    }else
    {
        sprintf(pool_str, ",,,%d,,", lease_time);
    }
    nvram_set(pool_name, pool_str);    
    
    free(config);
    fun_set_dhcpd_enable(pool);   

	return 0;
}

/*
 *  Function:  func_ip_lease_days_hours_minutes
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_lease_days_hours_minutes(struct users *u)
{    
    int pool, lease_time;
    dhcpd_conf conf;	
    int buffer1 = 0;
	int buffer2 = 0;
	int buffer3 = 0;
    char *config, pool_name[16], pool_str[256];
	
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer1, u);
	cli_param_get_int(STATIC_PARAM, 1, &buffer2, u);
	cli_param_get_int(STATIC_PARAM, 2, &buffer3, u);

    lease_time = buffer1*24*60*60+buffer2*60*60+buffer3*60;

	pool = atoi(u->promptbuf+5);
	sprintf(pool_name,"dhcp_pool%d", pool);
	
	config = nvram_safe_get(pool_name);
    
    //subnet/mask,gateway,range,lease,dns,name
    memset(pool_str, '\0', sizeof(pool_str));
    if(strlen(config) > 4)
    {
        memset(&conf, '\0', sizeof(conf));
        get_parameter_dhcpd(config,  conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, conf.name);
        sprintf(pool_str, "%s,%s,%s,%d,%s,%s", conf.subnet, conf.gateway, conf.range, lease_time, conf.dns, conf.name); 
    }else
    {
        sprintf(pool_str, ",,,%d,,", lease_time);
    }
    nvram_set(pool_name, pool_str);    
    
    free(config);
    fun_set_dhcpd_enable(pool);   

	return 0;
}

/*
 *  Function:  func_ip_lease_infinite
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_lease_infinite(struct users *u)
{
    int pool, lease_time;
    dhcpd_conf conf;	
    int buffer1 = 0;
    char *config, pool_name[16], pool_str[256];
	
    lease_time = 366*24*60*60;
	pool = atoi(u->promptbuf+5);
	sprintf(pool_name,"dhcp_pool%d", pool);
	
	config = nvram_safe_get(pool_name);
    
    //subnet/mask,gateway,range,lease,dns,name
    memset(pool_str, '\0', sizeof(pool_str));
    if(strlen(config) > 4)
    {
        memset(&conf, '\0', sizeof(conf));
        get_parameter_dhcpd(config,  conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, conf.name);
        sprintf(pool_str, "%s,%s,%s,%d,%s,%s", conf.subnet, conf.gateway, conf.range, lease_time, conf.dns, conf.name); 
    }else
    {
        sprintf(pool_str, ",,,%d,,", lease_time);
    }
    nvram_set(pool_name, pool_str);    
    
    free(config);
    fun_set_dhcpd_enable(pool);   

	return 0;
}

/*
 *  Function:  nfunc_ip_network
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_network(struct users *u)
{
	printf("do nfunc_ip_network here\n");

	return 0;
}

/*
 *  Function:  func_ip_network_ip_mask
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_network_ip_mask(struct users *u)
{
    int pool;
    dhcpd_conf conf;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
	struct in_addr i;
	struct in_addr j;
    char *config, pool_name[16], pool_str[256];
	
	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &i, ip_mask, sizeof(ip_mask), u);

	pool = atoi(u->promptbuf+5);
	sprintf(pool_name,"dhcp_pool%d", pool);
	
	config = nvram_safe_get(pool_name);
    
    //subnet/mask,gateway,range,lease,dns,name
    memset(pool_str, '\0', sizeof(pool_str));
    if(strlen(config) > 4)
    {
        memset(&conf, '\0', sizeof(conf));
        get_parameter_dhcpd(config,  conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, conf.name);
        sprintf(pool_str, "%s/%d,%s,%s,%s,%s,%s", ip_str, get_mask_subnet(ip_mask), conf.gateway, conf.range, conf.lease, conf.dns, conf.name);
    }else
    {
        sprintf(pool_str, "%s/%d,,,,,", ip_str, get_mask_subnet(ip_mask));
    } 
    nvram_set(pool_name, pool_str);    
    
    free(config);
    fun_set_dhcpd_enable(pool);   
    
	return 0;
}

/*
 *  Function:  nfunc_ip_option_code
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_option_code(struct users *u)
{
	printf("do nfunc_ip_option_code here\n");

	return 0;
}

/*
 *  Function:  func_ip_option_code_ascii_str
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_option_code_ascii_str(struct users *u)
{
	printf("do func_ip_option_code_ascii_str here\n");

	return 0;
}

/*
 *  Function:  func_ip_option_code_hex_hex
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_option_code_hex_hex(struct users *u)
{
	printf("do func_ip_option_code_hex_hex here\n");

	return 0;
}

/*
 *  Function:  func_ip_option_code_ip_addr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_option_code_ip_addr(struct users *u)
{
	printf("do func_ip_option_code_ip_addr here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_dns
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_dns(struct users *u)
{
	printf("do nfunc_ipv6_dns here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_dns_addr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_dns_addr(struct users *u)
{
	printf("do func_ipv6_dns_addr here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_domain
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_domain(struct users *u)
{
	printf("do nfunc_ipv6_domain here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_domain_name
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_domain_name(struct users *u)
{
	printf("do func_ipv6_domain_name here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_lifetime
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_lifetime(struct users *u)
{
	printf("do nfunc_ipv6_lifetime here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_lifetime_pre_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_lifetime_pre_time(struct users *u)
{
	printf("do func_ipv6_lifetime_pre_time here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_lifetime_pre_infinite
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_lifetime_pre_infinite(struct users *u)
{
	printf("do func_ipv6_lifetime_pre_infinite here\n");

	return 0;
}

/*
 *  Function:  nfunc_ipv6_network
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ipv6_network(struct users *u)
{
	printf("do nfunc_ipv6_network here\n");

	return 0;
}

/*
 *  Function:  func_ipv6_network_addr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ipv6_network_addr(struct users *u)
{
	printf("do func_ipv6_network_addr here\n");

	return 0;
}

int func_ip_dhcp_range(struct users *u)
{    
    int pool;
    dhcpd_conf conf;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
	struct in_addr i;
	struct in_addr j;
    char *config, pool_name[16], pool_str[256];
	
	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &i, ip_mask, sizeof(ip_mask), u);

	pool = atoi(u->promptbuf+5);
	sprintf(pool_name,"dhcp_pool%d", pool);
	
	config = nvram_safe_get(pool_name);
    
    //subnet/mask,gateway,range,lease,dns,name
    memset(pool_str, '\0', sizeof(pool_str));
    if(strlen(config) > 4)
    {
        memset(&conf, '\0', sizeof(conf));
        get_parameter_dhcpd(config,  conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, conf.name);
        sprintf(pool_str, "%s,%s,%s-%s,%s,%s,%s", conf.subnet, conf.gateway, ip_str, ip_mask, conf.lease, conf.dns, conf.name);
    }else
    {
        sprintf(pool_str, ",,%s-%s,,,", ip_str, ip_mask);
    }
    
    nvram_set(pool_name, pool_str);    
    free(config);
    fun_set_dhcpd_enable(pool);   

	return 0;
}

int nfunc_ip_range(struct users *u)
{
	printf("do nfunc_ip_range here\n");

	return 0;
}

int fun_set_dhcpd_enable(int pool)
{
    int rval = 0;
    dhcpd_conf conf;
    char *config, pool_name[16], pool_str[256];
	
    memset(pool_name, '\0', sizeof(pool_name));
	sprintf(pool_name,"dhcp_pool%d", pool);
	
	config = nvram_safe_get(pool_name);
    
    //subnet/mask,gateway,range,lease,dns,name
    memset(pool_str, '\0', sizeof(pool_str));
    if(strlen(config) > 4)
    {
        memset(&conf, '\0', sizeof(conf));
        get_parameter_dhcpd(config,  conf.subnet, conf.gateway, conf.range, conf.lease, conf.dns, conf.name);
        if((strlen(conf.subnet) == 0) || (strlen(conf.gateway) == 0) ||(strlen(conf.range) == 0) 
             ||(strlen(conf.lease) == 0) ||(strlen(conf.dns) == 0))
        {
            vty_output("dhcp pool %d need more configure!\n", pool);
        }else
        {
            int flag = 0, vid = 0, iptype;
            char intf[256], ipv4[32], ipv6[64];
            char *ip, *p1, *l3_ip = nvram_safe_get("lan_ipaddr");
    
            ip = l3_ip;
            while((*ip != NULL) && (strlen(ip) > 0))
            {   
                memset(intf, '\0', sizeof(intf));
                p1 = strchr(ip, ';'); 
                memcpy(intf, ip, p1-ip);
                memset(ipv4, '\0', sizeof(ipv4));
                memset(ipv6, '\0', sizeof(ipv6));
                
                cli_interface_info_get(intf, &vid, &iptype, ipv4, ipv6);
                if(1 == isin_same_subnet(conf.subnet, ipv4))
                {    
                    flag = 1; 
                    break;   
                }
                ip = p1+1;  
            }
            free(l3_ip); 
            
            if(1 == flag)
            {
                int i, cnt = 0, flag1 = 0;
                char dhcp_conf[32][256], *dhcpd, *l3_dhcp, *pp1, *pp2, dhcp_str[8196];
                
                memset(dhcp_conf, '\0', sizeof(dhcp_conf));
                dhcpd = l3_dhcp = nvram_safe_get("l3_dhcp");  
                while((*dhcpd != NULL) && (strlen(dhcpd) > 0))
                {     
                    pp1 = dhcpd;  
                    pp2 = strchr(pp1, ';');
                    
                    memcpy(dhcp_conf[cnt], pp1, pp2-pp1);
                    if(vid == atoi(dhcp_conf[cnt]))
                        flag1 = 1;
                        
                    cnt++;
                    dhcpd = pp2+1;
                }
                
                memset(dhcp_str, '\0', sizeof(dhcp_str));
                if(1 == flag1)
                {
                    for(i = 0; i < cnt; i++) 
                	{
                	    if(vid != atoi(dhcp_conf[i]))
                            sprintf(dhcp_str, "%s%s;", dhcp_str, dhcp_conf[i]);  
                        else
                        {    
                            sprintf(dhcp_str, "%s%d,%s/%d,%s,%s,%s,;", dhcp_str,
                                vid, conf.gateway, get_mask_addr(conf.subnet), conf.range, conf.lease, conf.dns);
                        }        
                    }
                }else
                {
                    sprintf(dhcp_str, "%s%d,%s/%d,%s,%s,%s,;", l3_dhcp,
                        vid, conf.gateway, get_mask_addr(conf.subnet), conf.range, conf.lease, conf.dns);
                } 
                free(l3_dhcp); 
                nvram_set("l3_dhcp", dhcp_str);
                system("rc dhcpd restart  > /dev/null 2>&1 &");     
            }else
            {
                vty_output("dhcp pool %d hasn't interface, please set vlan interface first!\n",  pool);
            }   
        }     
	}
	free(config);
	
	return rval;
}  

int nfun_set_dhcpd_disable(int pool)
{

}    




