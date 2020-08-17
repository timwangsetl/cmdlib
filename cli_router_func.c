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

#include "cli_router_func.h"

/*
 *  Function:  func_router_bgp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_router_bgp(struct users *u)
{
    int num;
    char *as, asid[16];
    char *bgp_num = nvram_safe_get("bgp_as");

	as = strstr(u->linebuf, "bgp") + strlen("bgp");
	while(*as == ' ')
	    as++;

	num = atoi(as);    
    memset(asid, '\0', sizeof(asid));
	sprintf(asid, "%d", num);
	
	nvram_set("bgp_enable", "1");
	if(num != atoi(bgp_num))
	{
	    nvram_set("bgp_as", asid);    
        system("rc bgp restart  > /dev/null 2>&1");
    }
    free(bgp_num);    
	return 0;
}

/*
 *  Function:  nfunc_router_bgp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_router_bgp(struct users *u)
{
	nvram_set("bgp_enable", "0");
	nvram_set("bgp_as", "");
	nvram_set("bgp_remote", "");
	nvram_set("bgp_network", "");
	nvram_set("bgp6_remote", "");
	nvram_set("bgp6_config", "");

    system("rc bgp stop  > /dev/null 2>&1");

	return 0;
}

/*
 *  Function:  func_router_isis
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_router_isis(struct users *u)
{
    int num;
    char asid[16];

	cli_param_get_int(DYNAMIC_PARAM,0, &num, u);
//    printf("[%s:%d] num %d\n", __FUNCTION__, __LINE__, num);
    
    memset(asid, '\0', sizeof(asid));
	sprintf(asid, "%d", num);
	nvram_set("isis_enable", "1");
	nvram_set("isis_id", asid);

    system("rc isis restart  > /dev/null 2>&1");
	return 0;
}

/*
 *  Function:  nfunc_router_isis
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_router_isis(struct users *u)
{
	nvram_set("isis_enable", "0");
	nvram_set("isis_config", "");
	nvram_set("isis_intf_config", "");

    system("rc isis stop  > /dev/null 2>&1");
	return 0;
}

/*
 *  Function:  func_router_ospf
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_router_ospf(struct users *u)
{
    int ospf, ospfid;
    char enable[4], *p, * ospf_enable = nvram_safe_get("zebra");
	
	ospf = atoi(ospf_enable);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", ospf | 0x02);
	free(ospf_enable);
	nvram_set("zebra", enable);
 	
	p = strstr(u->linebuf, "ospf") + strlen("ospf");
	while(*p == ' ')
	    p++;
	ospfid = atoi(p);
	sprintf(enable, "%d", ospfid);
	nvram_set("ospfid", enable);  

    system("rc ospf restart  > /dev/null 2>&1");
	return 0;
}

/*
 *  Function:  nfunc_router_ospf
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_router_ospf(struct users *u)
{	
    int ospf;
    char enable[4], * ospf_enable = nvram_safe_get("zebra");
	
	ospf = atoi(ospf_enable);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", ospf & (~0x02));
	free(ospf_enable);
	nvram_set("zebra", enable);
	nvram_set("route_id", "");
    nvram_set("ospf_ip_config", "");
    nvram_set("ospf6_config", "");
    nvram_set("route_area", "");
    nvram_set("ospf_bfd", "0");

    system("/usr/bin/killall ospfd > /dev/null 2>&1");
    system("/usr/bin/killall ospf6d > /dev/null 2>&1");
	return 0;
}

/*
 *  Function:  func_ospf_id
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ospf_id(struct users *u)
{
	struct in_addr ip_addr;
	char *p, ip_buf[MAX_ARGV_LEN] = {'\0'};
	int id, retval = 0;

	p = strstr(u->linebuf, "no");
	if(p != NULL)
	{   
	    nvram_set("route_id", "");
	}    
    else
    { 
    	cli_param_get_ipv4(STATIC_PARAM, 0, &ip_addr, ip_buf, sizeof(ip_buf), u);
    	nvram_set("route_id", ip_buf);
    }
	
	system("rc ospf restart  > /dev/null 2>&1");
	return 0;
}

int func_bfd_ospf_enable(int enable)
{
	char en[4], *ospf_bfd = nvram_safe_get("ospf_bfd");
	int bfd_enable = atoi(ospf_bfd);

	if(bfd_enable != enable)
	{   
	    memset(en, '\0', sizeof(en));
	    en[0] = enable+'0';
	    nvram_set("ospf_bfd", en);
	    system("rc ospf restart  > /dev/null 2>&1");
	} 
	
	free(ospf_bfd);
	return 0;
}

/*
 *  Function:  nfunc_ospf_id
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ospf_id(struct users *u)
{
	printf("do nfunc_ospf_id here\n");

	return 0;
}

/*
 *  Function:  func_ospf_network
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ospf_network(struct users *u)
{	
    int area; 
	struct in_addr i;
	struct in_addr j;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
    char *p, *p1, *p2, *config, *ospf_config;
	char ospf_ip_str[4096], line[128], list[3][64], intf[64], area_id[32];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &j, ip_mask, sizeof(ip_mask), u);
	cli_param_get_int(STATIC_PARAM, 0, &area, u);
	
    memset(area_id, '\0', sizeof(area_id));
    sprintf(area_id, "%d", area);
    memset(intf, '\0', sizeof(intf));
    sprintf(intf, "%s/%d", ip_str, get_mask_subnet(ip_mask));
//    printf("[%s:%d] ip_str %s, ip_mask %s area %s intf %s\n", __FUNCTION__, __LINE__, ip_str, ip_mask, area_id, intf);  

    //2,0,0;3,0,0;24,222,1; vlan,area,type
    memset(ospf_ip_str, '\0', sizeof(ospf_ip_str));
    config = ospf_config = nvram_safe_get("ospf_ip_config");
    //192.168.1.2/24,0,0;192.168.10.2/24,0,0;24,222,1
    while((*config != NULL) && (strlen(config) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
       
        sscanf(line,"%[^,],%[^,],%[^,]", list[0],list[1],list[2]); 
        if(1 == isin_same_subnet(list[0], intf))  
        {    
            if((atoi(list[1]) == 0) && !strcmp(list[1], area_id))
            {    
                free(ospf_config);
                vty_output("Warning: the same network with old config, no action!\n");
            
                return 0;
            }   
        }  
        config = p1+1;   
    }
    
    sprintf(ospf_ip_str, "%s%s,%d,0;", ospf_config, intf, area); 
    free(ospf_config);
    nvram_set("ospf_ip_config", ospf_ip_str);
	system("rc ospf restart > /dev/null 2>&1");
	
	return 0;
}

/*
 *  Function:  func_ospf_network_mask
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   Kim Il Min
 *  Date:    2016/07/03
 */
int func_ospf_network_mask(struct users *u)
{
	struct in_addr i, j, k;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
	char area_id[MAX_ARGV_LEN] = {'\0'};
    char *p, *p1, *p2, *config, *ospf_config;//, *area_mask;
    int flag = 0, area, type = 0, vid; 
	char ospf_ip_str[4096], line[128], list[3][64], intf[64];//, area_mask[20];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &j, ip_mask, sizeof(ip_mask), u);
	cli_param_get_ipv4(STATIC_PARAM, 2, &k, area_id, sizeof(area_id), u);
	
    memset(intf, '\0', sizeof(intf));
    sprintf(intf, "%s/%d", ip_str, get_mask_subnet(ip_mask));
//    printf("[%s:%d] ip_str %s, ip_mask %s area %s intf %s\n", __FUNCTION__, __LINE__, ip_str, ip_mask, area_id, intf);  

    memset(ospf_ip_str, '\0', sizeof(ospf_ip_str));
    config = ospf_config = nvram_safe_get("ospf_ip_config");
    //192.168.1.2/24,0,0;192.168.10.2/24,0,0;24,222,1
    while((*config != NULL) && (strlen(config) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
        sscanf(line,"%[^,],%[^,],%[^,]", list[0],list[1],list[2]); 
        
        if(1 == isin_same_subnet(list[0], intf))  
        {    
            flag = 1;
            if((atoi(list[1]) == 0) && !strcmp(list[1], area_id))
            {    
                free(ospf_config);
                vty_output("Warning: the same network with old config, no action!\n");
                
                return 0;
            }   
        }  
        config = p1+1;   
    }
    
    sprintf(ospf_ip_str, "%s%s,%s,0;", ospf_config, intf, area_id); 
    free(ospf_config);
    nvram_set("ospf_ip_config", ospf_ip_str);
	system("rc ospf restart  > /dev/null 2>&1");
	
	return 0;
}

int func_ospf_network_ad(struct users *u)
{
    int area; 
	struct in_addr i;
	struct in_addr j;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
    char *p, *p1, *p2, *config, *ospf_config;
	char ospf_ip_str[4096], line[128], list[3][64], intf[64];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &j, ip_mask, sizeof(ip_mask), u);
	cli_param_get_int(STATIC_PARAM, 0, &area, u);

    memset(intf, '\0', sizeof(intf));
    sprintf(intf, "%s/%d", ip_str, get_mask_subnet(ip_mask));
//    printf("[%s:%d] ip_str %s, ip_mask %s area %d intf %s\n", __FUNCTION__, __LINE__, ip_str, ip_mask, area, intf);  

    memset(ospf_ip_str, '\0', sizeof(ospf_ip_str));
    config = ospf_config = nvram_safe_get("ospf_ip_config");
    //192.168.1.2/24,0,0;192.168.10.2/24,0,0;24,222,1
    while((*config != NULL) && (strlen(config) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
       
        sscanf(line,"%[^,],%[^,],%[^,]", list[0],list[1],list[2]); 
        if(1 == isin_same_subnet(list[0], intf))  
        {    
            if((atoi(list[1]) == 2) && (atoi(list[1]) == area))
            {    
                free(ospf_config);
                vty_output("Warning: the same network with old config, no action!\n");
                
                return 0;
            }   
        }
        config = p1+1;   
    }
    
    sprintf(ospf_ip_str, "%s%s,%d,1;", ospf_config, intf, area); 
    free(ospf_config);
    nvram_set("ospf_ip_config", ospf_ip_str);
	system("rc ospf restart  > /dev/null 2>&1");
	
	return 0;
}

int func_ospf_network_nad(struct users *u)
{
    int area; 
	struct in_addr i;
	struct in_addr j;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
    char *p, *p1, *p2, *config, *ospf_config;
	char ospf_ip_str[4096], line[128], list[3][64], intf[64];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &j, ip_mask, sizeof(ip_mask), u);
	cli_param_get_int(STATIC_PARAM, 0, &area, u);
	
    memset(intf, '\0', sizeof(intf));
    sprintf(intf, "%s/%d", ip_str, get_mask_subnet(ip_mask));
//    printf("[%s:%d] ip_str %s, ip_mask %s area %d intf %s\n", __FUNCTION__, __LINE__, ip_str, ip_mask, area, intf);  

    memset(ospf_ip_str, '\0', sizeof(ospf_ip_str));
    config = ospf_config = nvram_safe_get("ospf_ip_config");
    //192.168.1.2/24,0,0;192.168.10.2/24,0,0;24,222,1
    while((*config != NULL) && (strlen(config) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
       
        sscanf(line,"%[^,],%[^,],%[^,]", list[0],list[1],list[2]); 
        if(1 == isin_same_subnet(list[0], intf))  
        {    
            if((atoi(list[2]) == 2) && (atoi(list[1]) == area))
            {    
                free(ospf_config);
                vty_output("Warning: the same network with old config, no action!\n");
                
                return 0;
            }   
        }
        config = p1+1;   
    }
    
    sprintf(ospf_ip_str, "%s%s,%d,2;", ospf_config, intf, area); 
    free(ospf_config);
    nvram_set("ospf_ip_config", ospf_ip_str);
	system("rc ospf restart  > /dev/null 2>&1");
	
	return 0;
}

/*
 *  Function:  nfunc_ospf_network
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ospf_network(struct users *u)
{	
    nvram_set("ospf_ip_config", "");
    nvram_set("ospf6_config", "");
    nvram_set("route_area", "0");
    
    system("/usr/bin/killall ospfd > /dev/null 2>&1");
    system("/usr/bin/killall ospf6d > /dev/null 2>&1");
	
	return 0;
}

/*
 *  Function:  func_router_rip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_router_rip(struct users *u)
{
	int rip;
    char enable[4], * rip_enable = nvram_safe_get("zebra");

	rip = atoi(rip_enable);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", rip | 0x01);
	free(rip_enable);
	nvram_set("zebra", enable);

    system("rc rip restart  > /dev/null 2>&1 &");
	return 0;
}

/*
 *  Function:  nfunc_router_rip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_router_rip(struct users *u)
{
	int rip;
    char enable[4], * rip_enable = nvram_safe_get("zebra");

	rip = atoi(rip_enable);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", rip & (~0x01));
	free(rip_enable);
	nvram_set("zebra", enable);
	nvram_set("rip_ip_config", "");
    nvram_set("ripng_config", "");

    system("/usr/bin/killall ripd > /dev/null 2>&1");
    system("/usr/bin/killall ripngd > /dev/null 2>&1");
	return 0;
}

/*
 *  Function:  func_rip_auto_summary
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_rip_auto_summary(struct users *u)
{
	printf("do func_rip_auto_summary here\n");

	return 0;
}

/*
 *  Function:  nfunc_rip_auto_summary
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_rip_auto_summary(struct users *u)
{
	printf("do nfunc_rip_auto_summary here\n");

	return 0;
}

/*
 *  Function:  func_rip_default_originate
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_rip_default_originate(struct users *u)
{
	printf("do func_rip_default_originate here\n");

	return 0;
}

/*
 *  Function:  nfunc_rip_default_originate
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_rip_default_originate(struct users *u)
{
	printf("do nfunc_rip_default_originate here\n");

	return 0;
}

/*
 *  Function:  func_rip_network_ip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_rip_network_ip(struct users *u)
{
	struct in_addr i;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
    char *p, *p1, *p2, *config, *rip_config;
    int flag = 0, area, type = 0, vid; 
	char rip_ip_str[4096], line[128], list[2][32], intf[64];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	
    memset(intf, '\0', sizeof(intf));
    sprintf(intf, "%s/%d", ip_str, 24);
//    printf("[%s:%d] ip_str %s intf %s", __FUNCTION__, __LINE__, ip_str, intf);  

    config = rip_config = nvram_safe_get("rip_ip_config");
    memset(rip_ip_str, '\0', sizeof(rip_ip_str));
    
    //192.168.1.2/24,2;192.168.10.2/24,0,0;24,2;
    while((*config != NULL) && (strlen(config) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
       
        sscanf(line,"%[^,],%[^,]", list[0],list[1]); 
        if(1 == isin_same_subnet(list[0], intf))  
        {   
            flag = 1;
            vty_output("Warning: the same network with old config, no action!\n");
            free(rip_config);

            return 0; 
        }
          
        sprintf(rip_ip_str, "%s%s;", rip_ip_str, line);
        config = p1+1;   
    }
    
    sprintf(rip_ip_str, "%s%s,%d;", rip_config, intf, 2); 
    free(rip_config);
    nvram_set("rip_ip_config", rip_ip_str);
	system("rc rip restart  > /dev/null 2>&1");	
}

int func_rip_network_ip_mask(struct users *u)
{
	struct in_addr i;
	struct in_addr j;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
    char *p, *p1, *p2, *config, *rip_config;
    int flag = 0, area, type = 0, vid; 
	char rip_ip_str[4096], line[128], list[2][32], intf[64];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(STATIC_PARAM, 1, &j, ip_mask, sizeof(ip_mask), u);
	
    memset(intf, '\0', sizeof(intf));
    sprintf(intf, "%s/%d", ip_str, get_mask_subnet(ip_mask));
//	DEBUG("[%s:%d] ip_str %s, ip_mask %s intf %s", __FUNCTION__, __LINE__, ip_str, ip_mask, intf);  

    memset(rip_ip_str, '\0', sizeof(rip_ip_str));
    config = rip_config = nvram_safe_get("rip_ip_config");
    //192.168.1.2/24,2;192.168.10.2/24,0,0;24,2;
    while((*config != NULL) && (strlen(config) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
       
        sscanf(line,"%[^,],%[^,]", list[0],list[1]); 
        if(1 == isin_same_subnet(list[0], intf))  
        {   
            flag == 1;
            free(rip_config);
            vty_output("Warning: the same network with old config, no action!\n");
            
            return 0; 
        }
          
        sprintf(rip_ip_str, "%s%s;", rip_ip_str, line);
        config = p1+1;   
    }
    
    sprintf(rip_ip_str, "%s%s,%d;", rip_config, intf, 2); 
    free(rip_config);
    
    nvram_set("rip_ip_config", rip_ip_str);
	system("rc rip restart  > /dev/null 2>&1");
	
	return 0;
}

/*
 *  Function:  nfunc_rip_network
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_rip_network(struct users *u)
{
    nvram_set("rip_ip_config", "");
    nvram_set("ripng_config", "");
    
    system("/usr/bin/killall ripd > /dev/null 2>&1");
    system("/usr/bin/killall ripngd > /dev/null 2>&1");
    
	return 0;
}

/*
 *  Function:  func_rip_version_1
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_rip_version_1(struct users *u)
{
	printf("do func_rip_version_1 here\n");

	return 0;
}

int func_rip_version_2(struct users *u)
{
	printf("do func_rip_version_2 here\n");

	return 0;
}

/*
 *  Function:  nfunc_rip_version
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_rip_version(struct users *u)
{
	printf("do nfunc_rip_version here\n");

	return 0;
}

/*
 *  Function:  func_isis_net
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_isis_net(struct users *u)
{
    int count = 0, num;
    char *isis_id, *isis_config;
    char *p, *p1, netstr[64], config[256];

    memset(netstr, '\0', sizeof(netstr));
    cli_param_get_string(STATIC_PARAM, 0, netstr, u);
//    printf("[%s:%d] netstr %s\n", __FUNCTION__, __LINE__, netstr);
    
    for(p = netstr; *p != '\0'; p++)
    {
        if(*p == '.')
        {
            count++;
            p1 = p+1;
        }        
    }
//    printf("[%s:%d] count %d p1 %c %c \n", __FUNCTION__, __LINE__, count, *p1, *(p1+1));
    
    if((count < 5) || (*p1 != '0') || (*(p1+1) != '0'))
    {
        vty_output("Error: Wrong Type must such as 47.0001.aaaa.bbbb.cccc.00!!\n");    
    }else
    {
        isis_id = nvram_safe_get("isis_id");
        isis_config = nvram_safe_get("isis_config");
        
        memset(config, '\0', sizeof(config));
        p = strrchr(isis_config, ':');
        if(p != NULL)
        {
            num = atoi(p+1);
            sprintf(config, "%s:%s:%d;", isis_id, netstr, num);
        }  
        else  
            sprintf(config, "%s:%s:2;", isis_id, netstr);
    
	    nvram_set("isis_config", config);
        system("rc isis restart  > /dev/null 2>&1");
        
        free(isis_id);
        free(isis_config);
    }        

	return 0;
}

/*
 *  Function:  nfunc_isis_net
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_isis_net(struct users *u)
{
    int count = 0, num;
    char *isis_id, *isis_config;
    char *p, *p1, netstr[64], config[256];

    isis_id = nvram_safe_get("isis_id");
    isis_config = nvram_safe_get("isis_config");
    
    memset(config, '\0', sizeof(config));
    p = strrchr(isis_config, ':');
    if(p != NULL)
    {
	    nvram_set("isis_config", config);
        system("rc isis restart  > /dev/null 2>&1");
    }  
    
    free(isis_id);
    free(isis_config);

	return 0;
}

/*
 *  Function:  func_isis_type
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_isis_type_1(struct users *u)
{
    char *p, *p1, *isis_id, *isis_config, asid[16], config[256];

    memset(config, '\0', sizeof(config));
    isis_id = nvram_safe_get("isis_id");
    isis_config = nvram_safe_get("isis_config");
    
    p = strrchr(isis_config, ':');
    if(p == NULL)
    {
        sprintf(config, "%s::0;", isis_id);
        nvram_set("isis_config", config);
    }  
    else  
    {    
        memcpy(config, isis_config, p-isis_config);
        strcat(config, ":0;");
        nvram_set("isis_config", config);
        system("rc isis restart  > /dev/null 2>&1");
    }

    free(isis_id);
    free(isis_config);
    
	return 0;
}

int func_isis_type_2(struct users *u)
{
    char *p, *p1, *isis_id, *isis_config, asid[16], config[256];

    memset(config, '\0', sizeof(config));
    isis_id = nvram_safe_get("isis_id");
    isis_config = nvram_safe_get("isis_config");
    p = strrchr(isis_config, ':');
    if(p == NULL)
    {
        sprintf(config, "%s::1;", isis_id);
        nvram_set("isis_config", config);
    }  
    else  
    {    
        memcpy(config, isis_config, p-isis_config);
        strcat(config, ":1;");
        nvram_set("isis_config", config);
        system("rc isis restart  > /dev/null 2>&1");
    }

    free(isis_id);
    free(isis_config);
    
	return 0;
}

int func_isis_type_1_2(struct users *u)
{
    char *p, *p1, *isis_id, *isis_config, asid[16], config[256];

    memset(config, '\0', sizeof(config));
    isis_id = nvram_safe_get("isis_id");
    isis_config = nvram_safe_get("isis_config");
    p = strrchr(isis_config, ':');
    if(p == NULL)
    {
        sprintf(config, "%s::2;", isis_id);
        nvram_set("isis_config", config);
    }  
    else  
    {    
        memcpy(config, isis_config, p-isis_config);
        strcat(config, ":2;");
        nvram_set("isis_config", config);
        system("rc isis restart  > /dev/null 2>&1");
    }

    free(isis_id);
    free(isis_config);
    
	return 0;
}

/*
 *  Function:  nfunc_isis_type
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_isis_type(struct users *u)
{
    char *p, *p1, *isis_id, *isis_config, asid[16], config[256];

    memset(config, '\0', sizeof(config));
    isis_id = nvram_safe_get("isis_id");
    isis_config = nvram_safe_get("isis_config");
    p = strrchr(isis_config, ':');
    if(p == NULL)
    {
        sprintf(config, "%s::2;", isis_id);
        nvram_set("isis_config", config);
    }  
    else  
    {    
        memcpy(config, isis_config, p-isis_config);
        strcat(config, ":2;");
        nvram_set("isis_config", config);
        system("rc isis restart  > /dev/null 2>&1");
    }

    free(isis_id);
    free(isis_config);
    
	return 0;
}

/*
 *  Function:  func_bgp_neighbor
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_bgp_neighbor(struct users *u)
{
    int num, flag;
    char *ras, rasid[16], bgp_str[4096];
	struct in_addr i;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char *config, *bgp_config;

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);

	ras = strstr(u->linebuf, "remote-as") + strlen("remote-as");
	while(*ras == ' ')
	    ras++;

	num = atoi(ras);    
    memset(rasid, '\0', sizeof(rasid));
	sprintf(rasid, "%d", num);

    //2,0,0;3,0,0;24,222,1; vlan,area,type
    memset(bgp_str, '\0', sizeof(bgp_str));
    config = bgp_config = nvram_safe_get("bgp_remote");

    sprintf(bgp_str, "%s%s,%s;", bgp_config, ip_str, rasid); 
    free(bgp_config);
    nvram_set("bgp_remote", bgp_str);
	system("rc bgp restart  > /dev/null 2>&1 &");

	return 0;
}

/*
 *  Function:  nfunc_bgp_neighbor
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_bgp_neighbor(struct users *u)
{
	int num;
	char *p, *p1, *network, newsub[32], bgp_neighbor_str[4096];
	struct in_addr i;
	char ip_str[MAX_ARGV_LEN] = {'\0'}, line[128], list[2][32];
	char *config, *bgp_remote;
	
	int flag = 0;

	network = strstr(u->linebuf, "nei") + strlen("nei");// no neighbor 1.1.1.1
	while(*network != ' ')
	    network++;
	while(*network == ' ')
	    network++;
	
	p = network;
	while(*p != ' ') 
	    p++;
	*p = '\0'; 
	
    	memset(newsub, '\0', sizeof(newsub)); 

	sprintf(newsub, "%s", network); 
	
    	memset(bgp_neighbor_str, '\0', sizeof(bgp_neighbor_str));

   	config = bgp_remote = nvram_safe_get("bgp_remote"); 

	while((*config != NULL) && (strlen(config) > 0))
	{   
		memset(line, '\0', sizeof(line));
		memset(list, '\0', sizeof(list));

		p1 = strchr(config, ';'); 
		memcpy(line, config, p1-config);
		
		if(strncmp(line, newsub, 7) == 0)
			flag = 1;
		else{
			sprintf(bgp_neighbor_str, "%s%s;", bgp_neighbor_str, line);
		}
		config = p1+1;   
	}
	
	free(bgp_remote);
	
	if(flag == 1)
	{  
		nvram_set("bgp_remote", bgp_neighbor_str);
		system("rc bgp restart  > /dev/null 2>&1 &");
	}

	return 0;
}

/*
 *  Function:  func_bgp_neighbor_activate
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_bgp_neighbor_activate(struct users *u)
{
	printf("do func_bgp_neighbor_activate here\n");

	return 0;
}

/*
 *  Function:  func_bgp_network
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_bgp_network(struct users *u)
{
    int num;
    char *p, *network, rasid[16], bgp_str[4096];
	struct in_addr i;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char *config, *bgp_config;

	network = strstr(u->linebuf, "network") + strlen("network");
	while(*network == ' ')
	    network++;
	
	p = network;
	while(*p != ' ') 
	    p++;
	*p = '\0';   
  
    memset(bgp_str, '\0', sizeof(bgp_str));
    config = bgp_config = nvram_safe_get("bgp_network");  
    {
        if(strchr(network, '/') == NULL)
            sprintf(bgp_str, "%s%s/24;", bgp_config, network); 
        else    
            sprintf(bgp_str, "%s%s;", bgp_config, network); 
    }
    
    free(bgp_config);
    nvram_set("bgp_network", bgp_str);
    
	system("rc bgp restart  > /dev/null 2>&1 &");

	return 0;
}

/*
 *  Function:  nfunc_bgp_network
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_bgp_network(struct users *u)
{
    nvram_set("bgp_network", "");
	system("rc bgp restart  > /dev/null 2>&1 &");

	return 0;
}

int nfunc_bgp_network_sub(struct users *u)
{
	int num;
	char *p, *p1, *network, newsub[32], bgp_str[4096];
	struct in_addr i;
	char ip_str[MAX_ARGV_LEN] = {'\0'}, line[128], list[2][32];
	char *config, *bgp_config;
	
	int flag = 0;

	network = strstr(u->linebuf, "net") + strlen("net");// no net 1.1.1.1
	while(*network != ' ')
	    network++;
	while(*network == ' ')
	    network++;
	
	p = network;
	while(*p != ' ') 
	    p++;
	*p = '\0'; 
	
    	memset(newsub, '\0', sizeof(newsub));  
	if(strchr(network, '/') == NULL)
		sprintf(newsub, "%s/24", network); 
	else    
		sprintf(newsub, "%s", network); 

	//printf("newsub = %s\n", newsub);
	
    	memset(bgp_str, '\0', sizeof(bgp_str));

   	config = bgp_config = nvram_safe_get("bgp_network"); 
	
	while((*config != NULL) && (strlen(config) > 0))
	{   
		memset(line, '\0', sizeof(line));
		memset(list, '\0', sizeof(list));
		p1 = strchr(config, ';'); 
		memcpy(line, config, p1-config);
				
		//printf("555 : line = %s\n", line);
		//printf("555 : newsub = %s\n", newsub);
		if(strcmp(line, newsub) == 0)
			flag = 1;
		else{
			sprintf(bgp_str, "%s%s;", bgp_str, line);
		}
		config = p1+1;   
	}
	
	//printf("bgp_str = %s\n", bgp_str);
	free(bgp_config);
	
	if(flag == 1)
	{  
		nvram_set("bgp_network", bgp_str);

		system("rc bgp restart  > /dev/null 2>&1 &");
	}	
	
	return 0;
}

int nfunc_rip_network_sub(struct users *u)
{
	struct in_addr i;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
    char *p, *p1, *p2, *config, *rip_config;
    int flag = 0, area, type = 0, vid; 
	char rip_str[4096], rip_ip_str[4096], line[128], list[2][32], intf[64];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	
    memset(intf, '\0', sizeof(intf));
    sprintf(intf, "%s/%d", ip_str, 24);
//    printf("[%s:%d] ip_str %s intf %s", __FUNCTION__, __LINE__, ip_str, intf);  

    memset(rip_ip_str, '\0', sizeof(rip_ip_str));
    config = rip_config = nvram_safe_get("rip_ip_config");
    //192.168.1.2/24,2;192.168.10.2/24,0,0;24,2;
    while((*config != NULL) && (strlen(config) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
       
        sscanf(line,"%[^,],%[^,]", list[0],list[1]); 
        if(1 == is_in_same_subnet(ip_str, list[0]))  
        {   
            flag = 1;
        }else
        {    
            sprintf(rip_ip_str, "%s%s;", rip_ip_str, line);
        }        
        config = p1+1;   
    }
    free(rip_config);
    
    if(flag == 1)
    {  
        nvram_set("rip_ip_config", rip_ip_str);
        nvram_set("rip_config", rip_str);
        
    	system("rc rip restart  > /dev/null 2>&1 &");
    }else
    {
        vty_output("Warning: no this network config within old config, no action!\n");
    }  
    
    return 0;    	
}	

int nfunc_ospf_network_sub(struct users *u)
{
	struct in_addr i;
	struct in_addr j;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
    char *p, *p1, *p2, *config, *ospf_config;
    int flag = 0, area, type = 0, vid; 
	char ospf_ip_str[4096], line[128], list[3][64], intf[64];

	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
//    printf("[%s:%d] ip_str %s\n", __FUNCTION__, __LINE__, ip_str);  

    memset(ospf_ip_str, '\0', sizeof(ospf_ip_str));
    config = ospf_config = nvram_safe_get("ospf_ip_config");
    //192.168.1.2/24,0,0;192.168.10.2/24,0,0;24,222,1
    while((*config != NULL) && (strlen(config) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
       
        sscanf(line,"%[^,],%[^,],%[^,]", list[0],list[1],list[2]); 
        if(1 == is_in_same_subnet(ip_str, list[0]))  
        {    
            flag = 1;
        }
        else
        {
            sprintf(ospf_ip_str, "%s%s;", ospf_ip_str, line);
        }   
        config = p1+1;   
    }
    
    free(ospf_config);
    if(flag == 1)
    {  
        nvram_set("ospf_ip_config", ospf_ip_str);
    	system("rc ospf restart > /dev/null 2>&1");
    }
}

int func_rip_default_static(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_rip");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x01);
	free(rebute);
	
	nvram_set("rebute_rip", enable);

    system("rc rip restart  > /dev/null 2>&1 &");   
     
	return 0;
}

int nfunc_rip_default_static(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_rip");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x01));
	free(rebute);
	
	nvram_set("rebute_rip", enable);

    system("rc rip restart  > /dev/null 2>&1 &");   
	return 0;
}

int func_rip_default_ospf(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_rip");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x02);
	free(rebute);
	
	nvram_set("rebute_rip", enable);

    system("rc rip restart  > /dev/null 2>&1 &");     
	return 0;
}

int nfunc_rip_default_ospf(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_rip");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x02));
	free(rebute);
	
	nvram_set("rebute_rip", enable);

    system("rc rip restart  > /dev/null 2>&1 &");     
	return 0;
}

int func_rip_default_bgp(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_rip");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x04);
	free(rebute);
	
	nvram_set("rebute_rip", enable);

    system("rc rip restart  > /dev/null 2>&1 &");   
	return 0;
}

int nfunc_rip_default_bgp(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_rip");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x04));
	free(rebute);
	
	nvram_set("rebute_rip", enable);

    system("rc rip restart  > /dev/null 2>&1 &");   
	return 0;
}

int func_ospf_default_static(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_ospf");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x01);
	free(rebute);
	
	nvram_set("rebute_ospf", enable);

    system("rc ospf restart  > /dev/null 2>&1 &");   
	return 0;
}

int nfunc_ospf_default_static(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_ospf");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x01));
	free(rebute);
	
	nvram_set("rebute_ospf", enable);

    system("rc ospf restart  > /dev/null 2>&1 &");     
	return 0;
}

int func_ospf_default_rip(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_ospf");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x02);
	free(rebute);
	
	nvram_set("rebute_ospf", enable);

    system("rc ospf restart  > /dev/null 2>&1 &");    
	return 0;
}

int nfunc_ospf_default_rip(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_ospf");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x02));
	free(rebute);
	
	nvram_set("rebute_ospf", enable);

    system("rc ospf restart  > /dev/null 2>&1 &");    
	return 0;
}

int func_ospf_default_bgp(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_ospf");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x04);
	free(rebute);
	
	nvram_set("rebute_ospf", enable);

    system("rc ospf restart  > /dev/null 2>&1 &");    
	return 0;
}

int nfunc_ospf_default_bgp(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_ospf");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x04));
	free(rebute);
	
	nvram_set("rebute_ospf", enable);

    system("rc ospf restart  > /dev/null 2>&1 &");     
	return 0;
}

int func_bgp_default_static(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_bgp");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x01);
	free(rebute);
	
	nvram_set("rebute_bgp", enable);

    system("rc bgp restart  > /dev/null 2>&1 &");    
	return 0;
}

int nfunc_bgp_default_static(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_bgp");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x01));
	free(rebute);
	
	nvram_set("rebute_bgp", enable);

    system("rc bgp restart  > /dev/null 2>&1 &");     
	return 0;
}

int func_bgp_default_rip(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_bgp");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x02);
	free(rebute);
	
	nvram_set("rebute_bgp", enable);

    system("rc bgp restart  > /dev/null 2>&1 &");   
	return 0;
}

int nfunc_bgp_default_rip(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_bgp");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x02));
	free(rebute);
	
	nvram_set("rebute_bgp", enable);

    system("rc bgp restart  > /dev/null 2>&1 &");      
	return 0;
}

int func_bgp_default_ospf(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_bgp");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x04);
	free(rebute);
	
	nvram_set("rebute_bgp", enable);

    system("rc bgp restart  > /dev/null 2>&1 &");    
	return 0;
}

int nfunc_bgp_default_ospf(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_bgp");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x04));
	free(rebute);
	
	nvram_set("rebute_bgp", enable);

    system("rc bgp restart  > /dev/null 2>&1 &");     
	return 0;
}

int func_rip_connected(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_rip");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x08);
	free(rebute);
	
	nvram_set("rebute_rip", enable);

    system("rc rip restart  > /dev/null 2>&1 &");   
	return 0;
}

int nfunc_rip_connected(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_rip");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x08));
	free(rebute);
	
	nvram_set("rebute_rip", enable);

    system("rc rip restart  > /dev/null 2>&1 &");   
	return 0;
}

int func_ospf_connected(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_ospf");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x08);
	free(rebute);
	
	nvram_set("rebute_ospf", enable);

    system("rc ospf restart  > /dev/null 2>&1 &");    
	return 0;
}

int nfunc_ospf_connected(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_ospf");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x08));
	free(rebute);
	
	nvram_set("rebute_ospf", enable);

    system("rc ospf restart  > /dev/null 2>&1 &");     
	return 0;
}

int func_bgp_connected(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_bgp");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config | 0x08);
	free(rebute);
	
	nvram_set("rebute_bgp", enable);

    system("rc bgp restart  > /dev/null 2>&1 &");     
	return 0;
}

int nfunc_bgp_connected(struct users *u)
{
	int config;
    char enable[4], * rebute = nvram_safe_get("rebute_bgp");

	config = atoi(rebute);
	memset(enable, '\0', sizeof(enable));
	sprintf(enable, "%d", config &(~0x08));
	free(rebute);
	
	nvram_set("rebute_bgp", enable);

    system("rc bgp restart  > /dev/null 2>&1 &");     
	return 0;
}

int func_rip_network_ipv6(struct users *u)
{  
	struct in6_addr s;
	char ripng_str[4096];
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	char * ripng_config = nvram_safe_get("ripng_config");

	cli_param_get_ipv6(STATIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);
//    fprintf(stderr, "[%s:%d] ipv6_str %s\n", __FUNCTION__, __LINE__, ipv6_str);
    
    memset(ripng_str, '\0', sizeof(ripng_str));
    if(strchr(ipv6_str, '/') != NULL)
        sprintf(ripng_str, "%s%s;", ripng_config, ipv6_str); 
    else 
        sprintf(ripng_str, "%s%s/64;", ripng_config, ipv6_str);
    free(ripng_config);
    
    nvram_set("ripng_config", ripng_str);
	system("rc rip restart  > /dev/null 2>&1 &");
	
	return 0;
}

int nfunc_rip_network_ipv6(struct users *u)
{  
    int flag = 0;
	struct in6_addr s;
	char ripng_str[4096], line[128]; 
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	char *p1, *config, * ripng_config = nvram_safe_get("ripng_config");

	cli_param_get_ipv6(STATIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);
//    fprintf(stderr, "[%s:%d] ipv6_str %s\n", __FUNCTION__, __LINE__, ipv6_str);
    
    if(strchr(ipv6_str, '/') == NULL)
        strcat(ipv6_str, "/64");

    memset(ripng_str, '\0', sizeof(ripng_str));
    config = ripng_config;
    //192.168.1.2/24,2;192.168.10.2/24,0,0;24,2;
    while(strlen(config) > 0)
    {   
        memset(line, '\0', sizeof(line));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
        
        if(0 == check_ipv6_same_subnet(ipv6_str, line))  
        {   
            flag = 1;
        }else
        {    
            sprintf(ripng_str, "%s%s;", ripng_str, line);
        }        
        config = p1+1;   
    }
    free(ripng_config);

    if(flag == 1)
    {  
        nvram_set("ripng_config", ripng_str);
    	system("rc rip restart  > /dev/null 2>&1 &");
    }	

	return 0;
}

int func_ospf_network_ipv6(struct users *u)
{ 
    int num;
	struct in6_addr s;
	char ospf6_str[4096];
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	char * ospf6_config = nvram_safe_get("ospf6_config");

	cli_param_get_ipv6(STATIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);
	if(strchr(ipv6_str, '/') == NULL)
        strcat(ipv6_str, "/64");
        
//    fprintf(stderr, "[%s:%d] ipv6_str %s\n", __FUNCTION__, __LINE__, ipv6_str);

	cli_param_get_int(STATIC_PARAM, 0, &num, u);
//    fprintf(stderr, "[%s:%d] num %d\n", __FUNCTION__, __LINE__, num);
    
    memset(ospf6_str, '\0', sizeof(ospf6_str));
    sprintf(ospf6_str, "%s%s,%d;", ospf6_config, ipv6_str, num); 
    free(ospf6_config);
    
    nvram_set("ospf6_config", ospf6_str);
	system("rc ospf restart  > /dev/null 2>&1 &");
     
	return 0;
}

int nfunc_ospf_network_ipv6(struct users *u)
{  
    int flag = 0;
	struct in6_addr s;
	char ripng_str[4096], line[128]; 
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	char *p1, *p2, *config, * ripng_config = nvram_safe_get("ospf6_config");

	cli_param_get_ipv6(STATIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);
//    fprintf(stderr, "[%s:%d] ipv6_str %s\n", __FUNCTION__, __LINE__, ipv6_str);
    
    if(strchr(ipv6_str, '/') == NULL)
        strcat(ipv6_str, "/64");

    memset(ripng_str, '\0', sizeof(ripng_str));
    config = ripng_config;
    //192.168.1.2/24,2;192.168.10.2/24,0,0;24,2;
    while(strlen(config) > 0)
    {   
        memset(line, '\0', sizeof(line));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
        p2 = strchr(config, ','); 
        *p2 = '\0';
        
        if(0 == check_ipv6_same_subnet(ipv6_str, line))  
        {   
            flag = 1;
        }else
        {    
            sprintf(ripng_str, "%s%s;", ripng_str, line);
        }        
        config = p1+1;   
    }
    free(ripng_config);

    if(flag == 1)
    {  
        nvram_set("ospf6_config", ripng_str);
    	system("rc ospf restart  > /dev/null 2>&1 &");
    }	
    
	return 0;
}

int func_bgp_id(struct users *u)
{  
	struct in_addr ip_addr;
	char *p, ip_buf[MAX_ARGV_LEN] = {'\0'};
	int id, retval = 0;
	char *bgp_id = nvram_safe_get("bgp_route_id");

	cli_param_get_ipv4(STATIC_PARAM, 0, &ip_addr, ip_buf, sizeof(ip_buf), u);
//    fprintf(stderr, "[%s:%d] ip_buf %s\n", __FUNCTION__, __LINE__, ip_buf);
	nvram_set("bgp_route_id", ip_buf);
	
	if(strcmp(bgp_id, ip_buf))
	    system("rc bgp restart  > /dev/null 2>&1");
	free(bgp_id);
	return 0;
}

int nfunc_bpg_id(struct users *u)
{  
	struct in_addr ip_addr;
	char *p, ip_buf[MAX_ARGV_LEN] = {'\0'};
	int id, retval = 0;

	nvram_set("bgp_route_id", "");
	system("rc bgp restart  > /dev/null 2>&1");
	
	return 0;
}


int func_bgp_network_ipv6(struct users *u)
{  
	struct in6_addr s;
	char ripng_str[4096];
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	char * ripng_config = nvram_safe_get("bgp6_config");

	cli_param_get_ipv6(STATIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);
//    fprintf(stderr, "[%s:%d] ipv6_str %s\n", __FUNCTION__, __LINE__, ipv6_str);
    
    memset(ripng_str, '\0', sizeof(ripng_str));
    if(strchr(ipv6_str, '/') != NULL)
        sprintf(ripng_str, "%s%s;", ripng_config, ipv6_str); 
    else 
        sprintf(ripng_str, "%s%s/64;", ripng_config, ipv6_str);
    free(ripng_config);
    
    nvram_set("bgp6_config", ripng_str);
	system("rc bgp restart  > /dev/null 2>&1 &");
	
	return 0;
}

int nfunc_bgp_network_ipv6(struct users *u)
{  
    int flag = 0;
	struct in6_addr s;
	char ripng_str[4096], line[128]; 
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	char *p1, *config, * ripng_config = nvram_safe_get("bgp6_config");

	cli_param_get_ipv6(STATIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);
//    fprintf(stderr, "[%s:%d] ipv6_str %s\n", __FUNCTION__, __LINE__, ipv6_str);
    
    if(strchr(ipv6_str, '/') == NULL)
        strcat(ipv6_str, "/64");

    memset(ripng_str, '\0', sizeof(ripng_str));
    config = ripng_config;
    //192.168.1.2/24,2;192.168.10.2/24,0,0;24,2;
    while(strlen(config) > 0)
    {   
        memset(line, '\0', sizeof(line));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
        
        if(0 == check_ipv6_same_subnet(ipv6_str, line))  
        {   
            flag = 1;
        }else
        {    
            sprintf(ripng_str, "%s%s;", ripng_str, line);
        }        
        config = p1+1;   
    }
    free(ripng_config);

    if(flag == 1)
    {  
        nvram_set("bgp6_config", ripng_str);
    	system("rc bgp restart  > /dev/null 2>&1 &");
    }	

	return 0;
}

int func_bgp_ipv6_neighbor(struct users *u)
{  
    int num;
	struct in6_addr s;
	char ospf6_str[4096];
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	char *p, * ospf6_config = nvram_safe_get("bgp6_remote");

	cli_param_get_ipv6(STATIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);
	if((p = strchr(ipv6_str, '/')) != NULL)
        *p = '\0';
        
//    fprintf(stderr, "[%s:%d] ipv6_str %s\n", __FUNCTION__, __LINE__, ipv6_str);

	cli_param_get_int(STATIC_PARAM, 0, &num, u);
//    fprintf(stderr, "[%s:%d] num %d\n", __FUNCTION__, __LINE__, num);
    
    memset(ospf6_str, '\0', sizeof(ospf6_str));
    sprintf(ospf6_str, "%s%s,%d;", ospf6_config, ipv6_str, num); 
    free(ospf6_config);
    
    nvram_set("bgp6_remote", ospf6_str);
	system("rc bgp restart  > /dev/null 2>&1 &");
     
	return 0;
}

int nfunc_bgp_ipv6_neighbor(struct users *u)
{  
    int flag = 0;
	struct in6_addr s;
	char ripng_str[4096], line[128]; 
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	char *p, *p1, *p2, *config, * ripng_config = nvram_safe_get("bgp6_remote");

	cli_param_get_ipv6(STATIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);
//    fprintf(stderr, "[%s:%d] ipv6_str %s\n", __FUNCTION__, __LINE__, ipv6_str);
    
    if((p = strchr(ipv6_str, '/')) != NULL)
        *p = '\0';

    memset(ripng_str, '\0', sizeof(ripng_str));
    config = ripng_config;
    //192.168.1.2/24,2;192.168.10.2/24,0,0;24,2;
    while(strlen(config) > 0)
    {   
        memset(line, '\0', sizeof(line));
        p1 = strchr(config, ';'); 
        memcpy(line, config, p1-config);
        p2 = strchr(config, ','); 
        *p2 = '\0';
        
        if(!strcmp(ipv6_str, line))  
        {   
            flag = 1;
        }else
        {    
            sprintf(ripng_str, "%s%s;", ripng_str, line);
        }        
        config = p1+1;   
    }
    free(ripng_config);

    if(flag == 1)
    {  
        nvram_set("bgp6_remote", ripng_str);
    	system("rc bgp restart  > /dev/null 2>&1 &");
    }	
    
	return 0;
}

int func_router_pimsm(struct users *u)
{  
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");
	
	if(*ipmc_enable == '1')
	{
	    if((strlen(ipmc_type) > 0) && (*ipmc_type == '1'))
    	{    
            nvram_set("ipmc_type", "0");
    	    system("rc mroute restart  > /dev/null 2>&1");
    	}
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
	
    free(ipmc_enable);
    free(ipmc_type);
	return 0;
}

int func_router_pimdm(struct users *u)
{  
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");
	
	if(*ipmc_enable == '1')
	{
	    if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
    	{    
            nvram_set("ipmc_type", "1");
    	    system("rc mroute restart  > /dev/null 2>&1");
    	}
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
	
    free(ipmc_enable);
    free(ipmc_type);
	return 0;
}

