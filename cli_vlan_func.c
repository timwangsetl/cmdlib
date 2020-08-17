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

#include "cli_vlan_func.h"
#include "bcmutils.h"
#include "acl_utils.h"
#include "if_info.h"

int vlan_creat[VLAN_RANGE_MAX_LEN*2];

/*
 *  Function : cli_set_vlan          
 *  Purpose:
 *     set vlan id
 *  Parameters:
 *     vid  - VLAN ID
 *  Returns:
 *     CLI_SUCCESS - Success
 *     CLI_FAILED  - Failure
 *
 *  Author  : eagles.zhou
 *  Date    :2011/1/11
 */
static int cli_set_vlan(int vlan_num)
{
	return CLI_SUCCESS;
}

static int cli_set_vlan_name(char *name, struct users *u)
{
    char buff[MAX_ARGV_LEN] = {'\0'};
    int vlan, vid, type, flag = 0;
	char intf[256], *p1, *ip, *l3_ip = nvram_safe_get("lan_ipaddr");
	
	vlan = atoi(u->promptbuf+1);
	
    ip = l3_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        vid = atoi(intf);

        if(vlan == vid)
        {    
            int len1, vlanid, flag1 = 0;
            char *pp1, *ipp, *substr, *vlan_name = nvram_safe_get("vlan_name");

            flag = 1;
            len1 = strlen(vlan_name)+256;
        	substr = malloc(len1);
        	if(NULL == substr)
        	{
        		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
				free(l3_ip);
				free(vlan_name);
        		return -1;
        	}  
            memset(substr, '\0', len1);
        	
            ipp = vlan_name;
            while((*ipp != NULL) && (strlen(ipp) > 0))
            {   
                memset(intf, '\0', sizeof(intf));
                pp1 = strchr(ipp, ';'); 
                memcpy(intf, ipp, pp1-ipp);
                vlanid = atoi(intf);
                if(vlan == vlanid)
                {    
                    flag1 = 1;  
                    sprintf(substr, "%s%d:%s;", substr, vlan, name); 
                }
                else
                    sprintf(substr, "%s%s;", substr, intf); 
                
                ipp = pp1+1; 
            } 
            free(vlan_name);
            
            if(0 == flag1)
                sprintf(substr, "%s%d:%s;", substr, vlan, name); 
                
            scfgmgr_set("vlan_name", substr);
            free(substr);   
        } 
        ip = p1+1;  
    } 
    free(l3_ip);
    
    if(flag == 0)
	{
	    vty_output("Error: not found this interface vlan address, configure first!\n");
		return -1;
	}
	
	syslog(LOG_NOTICE, "[CONFIG-5-VLANNAME]: The name of VLAN was set to %s, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}


/*
 *  Function : cli_no_vlan_name
 *  Purpose:
 *     set vlan name default
 *  Parameters:
 *     type  - Config Type (CLI_CONF)
 *     addr  - Config Struct
 *  Returns:
 *     CLI_SUCCESS - Success
 *     CLI_FAILED  - Failure
 *
 *  Author  : eagles.zhou
 *  Date    :2011/2/14 (Valentine's Day ^_^)
 */
static int cli_no_vlan_name(struct users *u)
{
    int flag = 0, vlan, len, vlanid;
	char intf[256], *p1, *ip, *substr, *vlan_name = nvram_safe_get("vlan_name");
	
	vlan = atoi(u->promptbuf+1);
    len = strlen(vlan_name)+8;
	substr = malloc(len);
	if(NULL == substr)
	{
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		free(vlan_name);
		return -1;
	}  
    memset(substr, '\0', len);
	
    ip = vlan_name;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        vlanid = atoi(intf);
        if(vlan == vlanid)
        {    
            flag = 1;  
        }
        else
            sprintf(substr, "%s%s;", substr, intf); 
        
        ip = p1+1; 
    } 
    free(vlan_name);
    
    if(flag == 0)
    {
	    vty_output("Warning: not found this interface vlan %d with name!\n", vlan);
		free(substr);
		return 0;
    }

    scfgmgr_set("vlan_name", substr);
    free(substr);

	syslog(LOG_NOTICE, "[CONFIG-5-NOVLAN]: Delete VLAN %d, %s\n", vlan, getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}

#ifdef BCM_53344_L3
static int cli_set_ip_address(struct users *u, char *lan_ipaddr, char *lan_netmask)
{
    int vlan, len, vid, type, flag = 0;
	char intf[128], ipv4[32], ipv6[64];
	char *p1, *ip, *vlan_intf_str, *l3_ip = nvram_safe_get("lan_ipaddr");
	
	//l3_ip=1:0,192.168.1.1/24,2000::1:2345:6789:abcd/64;2:0,192.168.2.1/24,;4:0,,2001:db8:85a3:8a3:1319:8a2e:370:7344/64;
	vlan = atoi(u->promptbuf+1);
	len = strlen(l3_ip)+128;
	vlan_intf_str = malloc(len);
	
	if(NULL == vlan_intf_str)
	{
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		free(l3_ip);
		return -1;
	}    
    memset(vlan_intf_str, '\0', len);
    
    ip = l3_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        memset(ipv4, '\0', sizeof(ipv4));
        memset(ipv6, '\0', sizeof(ipv6));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        cli_interface_info_get(intf, &vid, &type, ipv4, ipv6); 
        if(vlan != vid)
            sprintf(vlan_intf_str, "%s%s;", vlan_intf_str, intf);  
        else
        {    
            flag = 1;
            sprintf(vlan_intf_str, "%s%d:%d,%s/%d,%s;", vlan_intf_str, 
                vlan, type, lan_ipaddr, get_mask_subnet(lan_netmask), ipv6); 
        }  
    
        ip = p1+1; 
    } 
     
    if(flag != 1)
        sprintf(vlan_intf_str, "%s%d:0,%s/%d,;", l3_ip, vlan, lan_ipaddr, get_mask_subnet(lan_netmask)); 

    free(l3_ip);
    scfgmgr_set("l3_ip", vlan_intf_str);    
    free(vlan_intf_str); 	
    system("killall -SIGUSR1 vlinkscan > /dev/null 2>&1");
        
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLAN]: Set the IP address of vlan %d to %s,and the netmask to %s, %s\n", vlan, lan_ipaddr, lan_netmask, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

#else
static int cli_set_ip_address(struct users *u, char *lan_ipaddr, char *lan_netmask)
{
	unsigned long int ipaddr, netmask = 0, bipaddr, gateaddr,nipaddr;
	int i,ret=0,mask_num = 24;
	struct in_addr addr;
	char *lan_bipaddr ;
	char *manage_IMP = nvram_safe_get("manage_IMP");
	char *manage_vlan = nvram_safe_get("manage_vlan");
	int vlan_id = atoi(manage_vlan);

	free(manage_vlan);
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

free_exit:

	if(manage_IMP != NULL)
		free(manage_IMP);

	return ret;
}
#endif

static void cli_set_dhcp(struct users *u)
{
    int vlan, len, vid, type, flag = 0, count = 0;
	char intf[128], ipv4[32], ipv6[64];
	char *p1, *ip, *vlan_intf_str, *l3_ip = nvram_safe_get("lan_ipaddr");
	
	//l3_ip=1:0,192.168.1.1/24,2000::1:2345:6789:abcd/64;2:0,192.168.2.1/24,;4:0,,2001:db8:85a3:8a3:1319:8a2e:370:7344/64;
	vlan = atoi(u->promptbuf+1);
	len = strlen(l3_ip)+128;
	vlan_intf_str = malloc(len);
	
	if(NULL == vlan_intf_str)
	{
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		free(l3_ip);
		return -1;
	}    
    memset(vlan_intf_str, '\0', len);
    
    ip = l3_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        memset(ipv4, '\0', sizeof(ipv4));
        memset(ipv6, '\0', sizeof(ipv6));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        cli_interface_info_get(intf, &vid, &type, ipv4, ipv6); 
        
        if(1 == type)
            count++;
            
        if(vlan != vid)
            sprintf(vlan_intf_str, "%s%s;", vlan_intf_str, intf);  
        else
        {    
            flag = 1;
            sprintf(vlan_intf_str, "%s%d:1,,;", vlan_intf_str, vlan); 
        }  
    
        ip = p1+1; 
    } 
    
    if(count > 1)
	{
		vty_output("Error: has configure interface as DHCP mode, allow only one DHCP interface!\n");
		free(l3_ip);
        free(vlan_intf_str); 	
		return -1;
	}    
     
    if(flag != 1)
        sprintf(vlan_intf_str, "%s%d:1,,;", l3_ip, vlan); 

    free(l3_ip);
    scfgmgr_set("lan_ipaddr", vlan_intf_str);  
    free(vlan_intf_str); 	
    system("killall -SIGUSR1 vlinkscan > /dev/null 2>&1");
        
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLAN]: Set the IP address of vlan %d to DHCP, %s\n", vlan, getenv("LOGIN_LOG_MESSAGE"));
	return;
}



/*
 *  Function : cli_set_no_ip_address
 *  Purpose:
 *     remove ip address
 *  Parameters:
 *     void
 *  Returns:
 *     void
 *
 *  Author  : eagles.zhou
 *  Date    :2011/5/19
 */
static void cli_set_no_ip_address(struct users *u)
{
    int vlan, len, vid, type, flag = 0;
	char intf[128], ipv4[32], ipv6[64];
	char *p1, *ip, *vlan_intf_str, *l3_ip = nvram_safe_get("lan_ipaddr");
	
	//l3_ip=1:0,192.168.1.1/24,2000::1:2345:6789:abcd/64;2:0,192.168.2.1/24,;4:0,,2001:db8:85a3:8a3:1319:8a2e:370:7344/64;
	vlan = atoi(u->promptbuf+1);
	len = strlen(l3_ip)+2;
	vlan_intf_str = malloc(len);
	
	if(NULL == vlan_intf_str)
	{
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		return -1;
	}    
    memset(vlan_intf_str, '\0', len);
    
    ip = l3_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        vid = atoi(intf);
        if(vlan != vid)
            sprintf(vlan_intf_str, "%s%s;", vlan_intf_str, intf);  
        else
        {    
            memset(ipv4, '\0', sizeof(ipv4));
            memset(ipv6, '\0', sizeof(ipv6));
            
            cli_interface_info_get(intf, &vid, &type, ipv4, ipv6);
            if(strlen(ipv6) > 0)
                sprintf(vlan_intf_str, "%s%d:%d,,%s;", vlan_intf_str, vlan, type, ipv6); 
             
            flag = 1;
        }  
    
        ip = p1+1; 
    } 
    free(l3_ip);
    
    if(1 == flag)
    {    
        scfgmgr_set("l3_ip", vlan_intf_str); 	  
        system("killall -SIGUSR1 vlinkscan > /dev/null 2>&1");
    }
    
    free(vlan_intf_str);    
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLAN]: delete the IP address of vlan %d, %s\n", vlan, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}


static int cli_set_cpu_ip_acl(char *acl_name, int direction)
{
	int drt,res, flag=0;  /* flag=0: ip standard acl,  flag=1: ip extended acl */
	char *cpu_ip_acl, name[ACL_NAME_LEN+1], *p, buff[64];	
	IP_STANDARD_ACL_ENTRY entry1;
	IP_EXTENDED_ACL_ENTRY entry2;
	
	drt = direction;
	
	memset(name, '\0', ACL_NAME_LEN+1);
	memset(buff, '\0', 64);
	memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
	
	res = ip_std_acl_set(acl_name, &entry1, ACL_NAME_CHECK, -1, 0x00ULL);
	/* ip standard acl name is not exist */
	if(res)
	{
		vty_output("standard access-group %s not exist\n", acl_name);  //test
		return -1;    //test
		
		/* following is for extended  */
		//res = ip_ext_acl_set(acl_name, &entry2, ACL_NAME_CHECK, -1, 0x00ULL);
		/* ip extended acl name is not exist */
		//if(res)
		//{
		//	vty_output("extended access-group %s not exist\n", acl_name);  //test
		//  vty_output("access-group %s not exist\n", acl_name);
		//	return -1;
		//}
		//else
		//	flag = 1;	/* extended */	
	}
	else
		flag = 0;  /* standard */
	
	cpu_ip_acl  = cli_nvram_safe_get(CLI_CPU_ACL, "cpu_ip_acl");
	p = strchr(cpu_ip_acl, ',');
	
	/*  engress  */
	if(ACL_OUT == drt)
	{
		strncpy(name, cpu_ip_acl, p-cpu_ip_acl);
		/* standard */
		if((strcmp(name, acl_name)) && (0 == flag))
		{
			if(strlen(name))
				ip_std_acl_set(name, &entry1, ACL_PORT_DEL, -1, (0x01ULL<<phy[0]));	
						
			ip_std_acl_set(acl_name, &entry1, ACL_PORT_ADD, -1, (0x01ULL<<phy[0]));
			
			ip_std_acl_set(acl_name, &entry1, ACL_WRITE_REGS, -1, 0x00ULL);
		}
		/* extendard */
/*		else if((strcmp(name, acl_name)) && (1 == flag))
		{
			if(strlen(name))
				ip_ext_acl_set(name, &entry2, ACL_PORT_DEL, -1, (0x01ULL<<phy[0]));
				
			ip_ext_acl_set(acl_name, &entry2, ACL_PORT_ADD, -1, (0x01ULL<<phy[0]));
			
			ip_ext_acl_set(acl_name, &entry2, ACL_WRITE_REGS, -1, 0x00ULL);
		} */
		
		strcat(buff, acl_name);
		strcat(buff, p);
	}
	/* ingress */
	else 
	{
		strcpy(name, p+1);
		/* standard */
		if((strcmp(name, acl_name)) && (0 == flag))
			ip_std_acl_set(acl_name, &entry1, ACL_CPU_OUT_SET, -1, (0x01ULL<<phy[0]));
		/* extendard */
/*		else if((strcmp(name, acl_name)) && (1 == flag))
			ip_ext_acl_set(acl_name, &entry2, ACL_CPU_OUT_SET, -1, (0x01ULL<<phy[0])); */
		
		strncpy(buff, cpu_ip_acl, p-cpu_ip_acl);
		strcat(buff, ",");
		strcat(buff, acl_name);
	}
	
	scfgmgr_set("cpu_ip_acl", buff);
		
	free(cpu_ip_acl);
	return 0;
}


static int cli_set_no_cpu_ip_acl(char *acl_name, int direction)
{
	int drt,res, flag=0;  /* flag=0: ip standard acl,  flag=1: ip extended acl */
	char *cpu_ip_acl, name[ACL_NAME_LEN+1], *p, buff[64];	
	IP_STANDARD_ACL_ENTRY entry1;
	IP_EXTENDED_ACL_ENTRY entry2;
	
	drt = direction;
	
	memset(name, '\0', ACL_NAME_LEN+1);
	memset(buff, '\0', 64);
	memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
	
	res = ip_std_acl_set(acl_name, &entry1, ACL_NAME_CHECK, -1, 0x00ULL);
	/* ip standard acl name is not exist */
	if(res)
	{
		vty_output("standard access-group %s not exist\n", acl_name);  //test
		return -1;    //test
		
		/* following is for extended  */
		//res = ip_ext_acl_set(acl_name, &entry2, ACL_NAME_CHECK, -1, 0x00ULL);
		/* ip extended acl name is not exist */
		//if(res)
		//{
		//	vty_output("extended access-group %s not exist\n", acl_name);  //test
		//  vty_output("access-group %s not exist\n", acl_name);
		//	return -1;
		//}
		//else
		//	flag = 1;	/* extended */	
	}
	else
		flag = 0;  /* standard */
		
	cpu_ip_acl  = cli_nvram_safe_get(CLI_CPU_ACL, "cpu_ip_acl");
	p = strchr(cpu_ip_acl, ',');
	
	if(ACL_OUT == drt)
	{
		strncpy(name, cpu_ip_acl, p-cpu_ip_acl);
		if(strcmp(name, acl_name))
		{
			vty_output("ip access-group %s out not be applied to Manage Vlan\n", acl_name);
			free(cpu_ip_acl);
			return -1;
		}
		/* standard */
		if(0 == flag)
		{
			ip_std_acl_set(name, &entry1, ACL_PORT_DEL, -1, (0x01ULL<<phy[0]));	
			ip_std_acl_set(acl_name, &entry1, ACL_WRITE_REGS, -1, 0x00ULL);
		}
		/* extended */
		else
		{
			ip_ext_acl_set(name, &entry2, ACL_PORT_DEL, -1, (0x01ULL<<phy[0]));
			ip_ext_acl_set(acl_name, &entry2, ACL_WRITE_REGS, -1, 0x00ULL);
		}
		
		strcat(buff, p);
	}
	else
	{
		strcat(name, p+1);
		if(strcmp(name, acl_name))
		{
			vty_output("ip access-group %s in not be applied to Manage Vlan\n", acl_name);
			free(cpu_ip_acl);
			return -1;
		}
		
		if(0 == flag)
			ip_std_acl_set(acl_name, &entry1, ACL_CPU_OUT_CLEAR, -1, 0x00ULL);
		else
			ip_ext_acl_set(acl_name, &entry2, ACL_CPU_OUT_CLEAR, -1, 0x00ULL);
		
		strncpy(buff, cpu_ip_acl, p-cpu_ip_acl);
		strcat(buff, ",");
	}
	
	scfgmgr_set("cpu_ip_acl", buff);
	
	free(cpu_ip_acl);
	return 0;
}


static int cli_check_ipv6_subnet(char *lan_ipv6addr, char *lan_ipv6gateway)
{
	struct in6_addr s6_ip;
	struct in6_addr s6_gw;
	int i, value;
	char tmp[64];
	char *str;

	if(strlen(lan_ipv6gateway) > 0) {
		if( (str = strstr(lan_ipv6addr, "/")) != NULL ) {
			memset(tmp, '\0', sizeof(tmp));
			memcpy(tmp, lan_ipv6addr, str-lan_ipv6addr);
			if(1 != inet_pton(AF_INET6, tmp, (void *)&s6_ip)) {
				syslog(LOG_ERR, "[CONFIG-3-FAILED]: Invalid IPv6 address, %s!\n", getenv("LOGIN_LOG_MESSAGE"));
				return CLI_FAILED;
			}
			memset(tmp, '\0', sizeof(tmp));
			str++;
			strcpy(tmp, str);
			for(i = 0; i < strlen(tmp); i++) {
				if( (*(tmp+i) < '0')||(*(tmp+i) > '9') ) {
					syslog(LOG_ERR, "[CONFIG-3-FAILED]: Invalid IPv6 mask, %s!\n", getenv("LOGIN_LOG_MESSAGE"));
					return CLI_FAILED;
				}
			}
			value = atoi(tmp);
			if( (value < 0) || (value > 128) ) {
				syslog(LOG_ERR, "[CONFIG-3-FAILED]: Invalid IPv6 mask, %s!\n", getenv("LOGIN_LOG_MESSAGE"));
				return CLI_FAILED;
			}

			if(1 != inet_pton(AF_INET6, lan_ipv6gateway, (void *)&s6_gw)) {
				syslog(LOG_ERR, "[CONFIG-3-FAILED]: Invalid IPv6 gateway, %s!\n", getenv("LOGIN_LOG_MESSAGE"));
				return CLI_FAILED;
			}
			if(value >= 96) {
				if( (s6_ip.s6_addr32[0] >> (value-96)) != (s6_gw.s6_addr32[0] >> (value-96)) ) {
					syslog(LOG_ERR, "[CONFIG-3-FAILED]: Invalid IPv6 gateway, not the same subnet with IPv6 address, %s!\n", getenv("LOGIN_LOG_MESSAGE"));
					vty_output("Default gateway should be in the same subnet with ip!\n");
					return CLI_FAILED;
				}
			} else if(value >= 64) {
				if( (s6_ip.s6_addr32[0] != s6_gw.s6_addr32[0]) || ((s6_ip.s6_addr32[1] >> (value-64)) != (s6_gw.s6_addr32[1] >> (value-64))) ) {
					syslog(LOG_ERR, "[CONFIG-3-FAILED]: Invalid IPv6 gateway, not the same subnet with IPv6 address, %s!\n", getenv("LOGIN_LOG_MESSAGE"));
					vty_output("Default gateway should be in the same subnet with ip!\n");
					return CLI_FAILED;
				}
			} else if(value >= 32) {
				if( (s6_ip.s6_addr32[0] != s6_gw.s6_addr32[0]) || (s6_ip.s6_addr32[1] != s6_gw.s6_addr32[1]) || ((s6_ip.s6_addr32[2] >> (value-32)) != (s6_gw.s6_addr32[2] >> (value-32))) ) {
					syslog(LOG_ERR, "[CONFIG-3-FAILED]: Invalid IPv6 gateway, not the same subnet with IPv6 address, %s!\n", getenv("LOGIN_LOG_MESSAGE"));
					vty_output("Default gateway should be in the same subnet with ip!\n");
					return CLI_FAILED;
				}
			} else {
				if( (s6_ip.s6_addr32[0] != s6_gw.s6_addr32[0]) || (s6_ip.s6_addr32[1] != s6_gw.s6_addr32[1]) || (s6_ip.s6_addr32[2] != s6_gw.s6_addr32[2]) || ((s6_ip.s6_addr32[3] >> (value)) != (s6_gw.s6_addr32[3] >> (value))) ) {
					syslog(LOG_ERR, "[CONFIG-3-FAILED]: Invalid IPv6 gateway, not the same subnet with IPv6 address, %s!\n", getenv("LOGIN_LOG_MESSAGE"));
					vty_output("Default gateway should be in the same subnet with ip!\n");
					return CLI_FAILED;
				}
			}
		} else {
			syslog(LOG_ERR, "[CONFIG-3-FAILED]: Invalid IPv6 address.Because it needed IPv6 mask, %s!\n", getenv("LOGIN_LOG_MESSAGE"));
			return CLI_FAILED;
		}
	}

	return CLI_SUCCESS;
}

static int cli_check_ipv6_local_link(char *lan_ipv6addr)
{
	char buff[8] = {'\0'};
	
	if(lan_ipv6addr == NULL)
		return -1;

	memset(buff, '\0', sizeof(buff));
	memcpy(buff, lan_ipv6addr, 4);
	if(strncasecmp(buff, "fe80", 4) == 0 
		|| strncasecmp(buff, "fe90", 4) == 0 
		|| strncasecmp(buff, "fea0", 4) == 0 
		|| strncasecmp(buff, "feb0", 4) == 0)
		return 1;

	return 0;
}


static void cli_set_ipv6_address(char *host)
{
	return;
}

static void cli_set_ipv6_local_address(char *host)
{
	return;
}
void nfunc_vlan_ipv6_address_local()
{
	return;
}

static void cli_set_no_ipv6_address(void)
{
	return;
}

/*
 *  Function : cli_set_iv_shutdown
 *  Purpose:
 *     shutdown interface vlan
 *  Parameters:
 *     void
 *  Returns:
 *     void
 *
 *  Author  : eagles.zhou
 *  Date    :2011/6/22
 */
static void cli_set_iv_shutdown(void)
{
	char *ip_staticip_enable = nvram_safe_get("ip_staticip_enable");
	char *lan_ipv6addr = nvram_safe_get("lan_ipv6addr");
	char *manage_IMP = nvram_safe_get("manage_IMP");

	if('1' == *manage_IMP) {
		scfgmgr_set("manage_IMP", "0");
		if('0' == *ip_staticip_enable) {
			SYSTEM("/usr/bin/killall udhcpc > /dev/null 2>&1");
			scfgmgr_set("lan_dhcp_ipaddr", "");
			scfgmgr_set("lan_dhcp_netmask", "");
			scfgmgr_set("lan_dhcp_gateway", "");
			scfgmgr_set("lan_dhcp_dns", "");
		}
	
		SYSTEM("ifconfig %s 0.0.0.0",IMP);
		SYSTEM("ifconfig %s del %s > /dev/null 2>&1&",IMP, lan_ipv6addr);
		SYSTEM("/sbin/route del default dev %s > /dev/null 2>&1", IMP);
		SYSTEM("/sbin/route -A inet6 del default dev %s > /dev/null 2>&1", IMP);
#if 0
		system("ifconfig eth0 down > /dev/null 2>&1");
#endif
	}
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLANSHUT]: Interface vlan is down, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	free(ip_staticip_enable);
	free(lan_ipv6addr);
	free(manage_IMP);

	return;	
}

/*
 *  Function : cli_set_no_shutdown
 *  Purpose:
 *     recover ip address mode
 *  Parameters:
 *     void
 *  Returns:
 *     void
 *
 *  Author  : eagles.zhou
 *  Date    :2011/5/19
 */
static void cli_set_no_shutdown(void)
{
    unsigned long int ipaddr, netmask, bipaddr;
    struct in_addr addr;
	char *lan_bipaddr;

	char *ip_staticip_enable = nvram_safe_get("ip_staticip_enable");
	char *manage_IMP = nvram_safe_get("manage_IMP");
	char *lan_ipaddr = nvram_safe_get("lan_ipaddr");
	char *lan_netmask = nvram_safe_get("lan_netmask");
    char *lan_gateway = nvram_safe_get("lan_gateway");
    char *lan_ipv6addr = nvram_safe_get("lan_ipv6addr");

	if('0' == *manage_IMP) {
		scfgmgr_set("manage_IMP", "1");
		
#if 0
		system("ifconfig eth0 up > /dev/null 2>&1");
#endif
		
		if('0' == *ip_staticip_enable) {
			SYSTEM("/usr/sbin/udhcpc -i %s -s /etc/udhcpc.script &", IMP);
		} else {
			if( (strlen(lan_ipaddr) > 0)&&(strlen(lan_netmask) > 0) ) {
				ipaddr = inet_addr(lan_ipaddr);
				netmask = inet_addr(lan_netmask);
	
				netmask = ~netmask;
				bipaddr = ipaddr | netmask;
				addr.s_addr = bipaddr;
				lan_bipaddr = inet_ntoa(addr);
	
				SYSTEM("ifconfig %s %s netmask %s broadcast %s",IMP,lan_ipaddr,lan_netmask,lan_bipaddr);
	
				if(strlen(lan_gateway) > 0)
					SYSTEM("/sbin/route add default gw %s dev %s > /dev/null 2>&1", lan_gateway, IMP);
			}
		}

		if(strlen(lan_ipv6addr) > 0)
			SYSTEM("ifconfig %s add %s > /dev/null 2>&1&",IMP, lan_ipv6addr);

		if(strlen(lan_ipv6addr) > 0)
			SYSTEM("/sbin/route -A inet6 add default gw %s dev %s > /dev/null 2>&1&", lan_ipv6addr, IMP);

		syslog(LOG_NOTICE, "[CONFIG-5-INTVLANNO]: Interface vlan is up, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	}

	free(lan_ipv6addr);
	free(ip_staticip_enable);
	free(lan_ipaddr);
	free(lan_netmask);
	free(lan_gateway);
	free(manage_IMP);

	return;
}

/*
 *  Function:  func_vlan
 *  Purpose:  set vlan
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_vlan(struct users *u)
{
    return 0;			   
}

/*
 *  Function:  nfunc_vlan
 *  Purpose:  undo set vlan
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int nfunc_vlan(struct users *u)
{
	return 0;
}

int func_private_vlan(struct users *u)
{
	vty_output("  The command doesn't support in this version!!\n");
	
	return 0;
}

/*
 *  Function:  func_vname
 *  Purpose:  set vlan name
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_vname(struct users *u)
{
	char name[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);

	/* set vlan name */
	cli_set_vlan_name(name, u);

	return 0;
}

/*
 *  Function:  nfunc_vname
 *  Purpose:  undo set vlan name
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */


int nfunc_vname(struct users *u)
{
	cli_no_vlan_name(u);
	
	return 0;
}

/*
 *  Function:  func_ip_adress_static
 *  Purpose:  set static ip
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_ip_adress_static(struct users *u)
{
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
	struct in_addr i;
	struct in_addr j;
	
	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
	cli_param_get_ipv4(DYNAMIC_PARAM, 0, &j, ip_mask, sizeof(ip_mask), u);
	
	cli_set_ip_address(u, ip_str, ip_mask);

	return 0;
}

/*
 *  Function:  func_ip_adress_dhcp
 *  Purpose:  set dhcp ip
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */


int func_ip_adress_dhcp(struct users *u)
{
	cli_set_dhcp(u);

	return 0;
}


/*
 *  Function:  nfunc_ip_adress
 *  Purpose:  undo set ip
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */


int nfunc_ip_adress(struct users *u)
{
	cli_set_no_ip_address(u);

	return 0;
}

/*
 *  Function:  func_ip_access_in
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_ip_access_in(struct users *u)
{
	char group[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, group, u);

	cli_set_cpu_ip_acl(group, ACL_IN);
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLAN]: Set the access list with name %s inbound packets, %s\n", group, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

/*
 *  Function:  func_ip_access_out
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_ip_access_out(struct users *u)
{
	char group[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, group, u);

	cli_set_cpu_ip_acl(group, ACL_OUT);
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLAN]: Set the access list with name %s outbound packets, %s\n", group, getenv("LOGIN_LOG_MESSAGE"));
	
	return 0;
}

/*
 *  Function:  nfunc_ip_access_in
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int nfunc_ip_access_in(struct users *u)
{
	char group[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, group, u);

	cli_set_no_cpu_ip_acl(group, ACL_IN);
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLANNO]: Set the inbound packets of access list name with %s to default, %s\n", group, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

/*
 *  Function:  nfunc_ip_access_out
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int nfunc_ip_access_out(struct users *u)
{
	char group[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, group, u);

	cli_set_no_cpu_ip_acl(group, ACL_OUT);
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLANNO]: Set the inbound packets of access list name with %s to default, %s\n", group, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

/*
 *  Function:  func_ipv6_global
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_ipv6_global(struct users *u)
{
	struct in6_addr s;
    int vlan, len, vid, type, flag = 0;
	char intf[128], ipv4[32], ipv6[64];
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	char *p1, *ip, *vlan_intf_str, *l3_ip = nvram_safe_get("lan_ipaddr");
	
	cli_param_get_ipv6(DYNAMIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);

	//l3_ip=1:0,192.168.1.1/24,2000::1:2345:6789:abcd/64;2:0,192.168.2.1/24,;4:0,,2001:db8:85a3:8a3:1319:8a2e:370:7344/64;
	vlan = atoi(u->promptbuf+1);
	len = strlen(l3_ip)+128;
	vlan_intf_str = malloc(len);
	
	if(NULL == vlan_intf_str)
	{
		free(l3_ip);
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		return -1;
	}    
    memset(vlan_intf_str, '\0', len);
    
    ip = l3_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        memset(ipv4, '\0', sizeof(ipv4));
        memset(ipv6, '\0', sizeof(ipv6));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        cli_interface_info_get(intf, &vid, &type, ipv4, ipv6); 
        
        if(vlan != vid)
            sprintf(vlan_intf_str, "%s%s;", vlan_intf_str, intf);  
        else
        {    
            flag = 1;
            sprintf(vlan_intf_str, "%s%d:%d,%s,%s;", vlan_intf_str, 
                vlan, type, ipv4, ipv6_str); 
        }  
    
        ip = p1+1; 
    } 
     
    if(flag != 1)
        sprintf(vlan_intf_str, "%s%d:0,,%s;", l3_ip, vlan, ipv6_str); 

    free(l3_ip);
    scfgmgr_set("l3_ip", vlan_intf_str);  
    free(vlan_intf_str); 	
    system("killall -SIGUSR1 vlinkscan > /dev/null 2>&1");
        
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLAN]: Set the IPv6 address of vlan %d to %s, %s\n", vlan, ipv6_str, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int cli_set_ipv6_realy(char *host)
{
	char *dhcp6_relay_enable = nvram_safe_get("dhcp6_relay_enable");	
	char *dhcp6_relay_server = nvram_safe_get("dhcp6_relay_server");	
	char *lan_ipv6addr = nvram_safe_get("lan_ipv6addr");

	if(strlen(lan_ipv6addr) == 0)	
		{		
			syslog(LOG_ERR, "[CONFIG-3-FAILED]: Failed to find a global address, Relay agent should have a global address first!, %s\n", getenv("LOGIN_LOG_MESSAGE"));		
			goto failed;
		}
	if('1' == *dhcp6_relay_enable)	
		{		
			if(strcmp(dhcp6_relay_server, host))		
				{			
					system("/usr/bin/killall dhcp6relay > /dev/null 2>&1");			
					scfgmgr_set("dhcp6_relay_server", host);			
					SYSTEM("/usr/sbin/dhcp6relay -s %s %s", host, IMP);		
				}
		}
	else	{
			scfgmgr_set("dhcp6_relay_enable", "1");
			scfgmgr_set("dhcp6_relay_server", host);
			SYSTEM("/usr/sbin/dhcp6relay -s %s %s", host, IMP);
		}
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLANIPV6]: The DHCPv6 relay is enable, relay server is %s, %s\n", host, getenv("LOGIN_LOG_MESSAGE"));
failed:		
	free(dhcp6_relay_enable);	
	free(dhcp6_relay_server);	
	free(lan_ipv6addr);
	return 0;
}
int nfunc_vlan_ipv6_dhcp_realy()
{
	char *dhcp6_relay_enable = nvram_safe_get("dhcp6_relay_enable");
	char *dhcp6_relay_server = nvram_safe_get("dhcp6_relay_server");	
	if('1' == *dhcp6_relay_enable) 
		{		
			system("/usr/bin/killall dhcp6relay > /dev/null 2>&1");	
		}	
	scfgmgr_set("dhcp6_relay_enable", "0");	
	scfgmgr_set("dhcp6_relay_server", "");	
	free(dhcp6_relay_enable);	
	free(dhcp6_relay_server);	
	return;


}

int func_vlan_ipv6_dhcp_realy_address(struct users *u)
{
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	struct in6_addr s;

	cli_param_get_ipv6(STATIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);
	cli_set_ipv6_realy(ipv6_str);

	return 0;


}
/*
 *  Function:  func_ipv6_local
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */


int func_ipv6_local(struct users *u)
{
	char ipv6_str[MAX_ARGV_LEN] = {'\0'};
	struct in6_addr s;

	cli_param_get_ipv6(DYNAMIC_PARAM, 0, &s, ipv6_str, sizeof(ipv6_str), u);
	cli_set_ipv6_local_address(ipv6_str);

	return 0;
}

/*
 *  Function:  nfunc_ipv6_adress
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int nfunc_ipv6_adress(struct users *u)
{
    int vlan, len, vid, type, flag = 0;
	char intf[128], ipv4[32], ipv6[64];
	char *p1, *ip, *vlan_intf_str, *l3_ip = nvram_safe_get("lan_ipaddr");
	
	//l3_ip=1:0,192.168.1.1/24,2000::1:2345:6789:abcd/64;2:0,192.168.2.1/24,;4:0,,2001:db8:85a3:8a3:1319:8a2e:370:7344/64;
	vlan = atoi(u->promptbuf+1);
	len = strlen(l3_ip)+2;
	vlan_intf_str = malloc(len);
	
	if(NULL == vlan_intf_str)
	{
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		free(l3_ip);
		return -1;
	}    
    memset(vlan_intf_str, '\0', len);
    
    ip = l3_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        vid = atoi(intf);
        if(vlan != vid)
            sprintf(vlan_intf_str, "%s%s;", vlan_intf_str, intf);  
        else
        {    
            memset(ipv4, '\0', sizeof(ipv4));
            memset(ipv6, '\0', sizeof(ipv6));
            
            cli_interface_info_get(intf, &vid, &type, ipv4, ipv6);
            if(strlen(ipv4) > 0)
                sprintf(vlan_intf_str, "%s%d:%d,%s,;", vlan_intf_str, vlan, type, ipv4); 
             
            flag = 1;
        }  
    
        ip = p1+1; 
    } 
    free(l3_ip);
    
    if(1 == flag)
    {    
        scfgmgr_set("l3_ip", vlan_intf_str); 	  
        system("killall -SIGUSR1 vlinkscan > /dev/null 2>&1");
    }
    
    free(vlan_intf_str);    
	syslog(LOG_NOTICE, "[CONFIG-5-INTVLAN]: delete the IPv6 address of vlan %d, %s\n", vlan, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

/*
 *  Function:  func_shutdown
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_shutdown(struct users *u)
{
	cli_set_iv_shutdown();

	return 0;
}

/*
 *  Function: nfunc_shutdown
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int nfunc_shutdown(struct users *u)
{
	cli_set_no_shutdown();

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_enable
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_enable(struct users *u)
{
	printf("do func_vlan_ipv6_enable here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_enable
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_enable(struct users *u)
{
	printf("do nfunc_vlan_ipv6_enable here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_ospf
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_ospf(struct users *u)
{
	printf("do func_vlan_ipv6_ospf here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_ospf
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_ospf(struct users *u)
{
	printf("do nfunc_vlan_ipv6_ospf here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_rip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_rip(struct users *u)
{
	printf("do func_vlan_ipv6_rip here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_rip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_rip(struct users *u)
{
	printf("do nfunc_vlan_ipv6_rip here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_router
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_router(struct users *u)
{
	printf("do func_vlan_ipv6_router here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_router
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_router(struct users *u)
{
	printf("do nfunc_vlan_ipv6_router here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_isis_circuit_level
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_isis_circuit_level_1(struct users *u)
{
	printf("do func_vlan_ipv6_isis_circuit_level_1 here\n");

	return 0;
}

int func_vlan_ipv6_isis_circuit_level_1_2(struct users *u)
{
	printf("do func_vlan_ipv6_isis_circuit_level_1_2 here\n");

	return 0;
}

int func_vlan_ipv6_isis_circuit_level_2_o(struct users *u)
{
	printf("do func_vlan_ipv6_isis_circuit_level_2_o here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_isis
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_isis(struct users *u)
{
	printf("do nfunc_vlan_ipv6_isis here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_traffic_name_in
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_traffic_name_in(struct users *u)
{
	printf("do func_vlan_ipv6_traffic_name_in here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_traffic_name_out
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_traffic_name_out(struct users *u)
{
	printf("do func_vlan_ipv6_traffic_name_out here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_traffic_name_in
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_traffic_name_in(struct users *u)
{
	printf("do nfunc_vlan_ipv6_traffic_name_in here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_traffic_name_out
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_traffic_name_out(struct users *u)
{
	printf("do nfunc_vlan_ipv6_traffic_name_out here\n");

	return 0;
}

/*
 *  Function:  func_vlan_vrrp_num_preempt
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_vrrp_num_preempt(struct users *u)
{
	int vlan, cnt = 0, flag = 0, vrid, nvrid;
    char line[128], list[8][64], intf[32], vrrp_str[2048];	
	char *p, *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");

	vlan = atoi(u->promptbuf+1);
    p = strstr(u->linebuf, "vrrp");
	p += strlen("vrrp");
	while(*p == ' ')
	    p++;
	vrid = atoi(p); 

//	DEBUG("[%s:%d] vlan %d vrid %d", __FUNCTION__, __LINE__, vlan, vrid);

    vrrp = vrrp_list;
    memset(vrrp_str, '\0', sizeof(vrrp_str));
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
       
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 
        
        if(atoi(list[0]) == vlan)  
        {    
            flag = 1; 
            
            if(atoi(list[1]) != vrid)
            {
                free(vrrp_list);
                vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
                return -1;
            }    
                 
            sprintf(vrrp_str, "%s%s,%s,%s,%s,%s,%s,%s,%s;", vrrp_str, 
                list[0], list[1], list[2],list[3],"1", list[5], list[6],list[7]);  
        }
        else
        {
            sprintf(vrrp_str, "%s%s;", vrrp_str, line);   
        }       
        vrrp = p1+1;   
        cnt++;    
    }
    free(vrrp_list);
    
    if(flag == 0)
    {
        vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
        return -1;
    }
    else
    {  
        scfgmgr_set("vrrp_list", vrrp_str);
        system("rc vrrp restart > /dev/null 2>&1");
    }
    
	return 0;
}

/*
 *  Function:  func_vlan_vrrp_num_desc_line
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_vrrp_num_desc_line(struct users *u)
{
	int vlan, cnt = 0, flag = 0, vrid, nvrid, auth[16];
    char line[128], list[8][64], intf[32], vrrp_str[2048];	
	char *p, *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");

	vlan = atoi(u->promptbuf+1);
    p = strstr(u->linebuf, "vrrp");
	p += strlen("vrrp");
	while(*p == ' ')
	    p++;
	vrid = atoi(p); 
	
    memset(auth, '\0', sizeof(auth));
    p = strstr(u->linebuf, "authentication");
	p += strlen("authentication");
	while(*p == ' ')
	    p++;
	memcpy(auth, p, 6);   
	
//	DEBUG("[%s:%d] vlan %d vrid %d auth %s", __FUNCTION__, __LINE__, vlan, vrid, auth);

    vrrp = vrrp_list;
    memset(vrrp_str, '\0', sizeof(vrrp_str));
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
       
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 
        
        if(atoi(list[0]) == vlan)  
        {    
            flag = 1; 
            
            if(atoi(list[1]) != vrid)
            {
                free(vrrp_list);
                vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
                return -1;
            }    
                 
            sprintf(vrrp_str, "%s%s,%s,%s,%s,%s,%s,%s,%s;", vrrp_str, 
                list[0], list[1], list[2], list[3], list[4], list[5], "1", auth);  
        }
        else
        {
            sprintf(vrrp_str, "%s%s;", vrrp_str, line);   
        }       
        vrrp = p1+1;   
        cnt++;    
    }
    free(vrrp_list);
    
    if(flag == 0)
    {
        vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
        return -1;
    }
    else
    {  
        scfgmgr_set("vrrp_list", vrrp_str);
        system("rc vrrp restart > /dev/null 2>&1");
    }

	return 0;
}

/*
 *  Function:  func_vlan_vrrp_num_ip_addr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_vrrp_num_ip_addr(struct users *u)
{
	struct in_addr i;
	int vlan, cnt = 0, flag = 0, vrid;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
    char line[128], list[8][64], intf[32], vrrp_str[2048];	
	char *p, *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");

	vlan = atoi(u->promptbuf+1);
    p = strstr(u->linebuf, "vrrp");
	p += strlen("vrrp");
	while(*p == ' ')
	    p++;
	vrid = atoi(p);  
	
	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
//	DEBUG("[%s:%d] vlan %d vrid %d ip_str %s", __FUNCTION__, __LINE__, vlan, vrid, ip_str);

    vrrp = vrrp_list;
    memset(vrrp_str, '\0', sizeof(vrrp_str));
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
       
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 
        
        if(atoi(list[0]) == vlan)  
        {    
            flag = 1; 
            sprintf(vrrp_str, "%s%s,%d,%s,%s,%s,%s,%s,%s;", vrrp_str, 
                list[0],vrid, ip_str,list[3],list[4],list[5],list[6],list[7]);  
        }
        else
        {
            sprintf(vrrp_str, "%s%s;", vrrp_str, line);   
        }       
        vrrp = p1+1;   
        cnt++;    
    }
    
    if((flag == 0)&&(cnt >= 8))
    {
        free(vrrp_list);
        vty_output("Error vrrp group number is larger than 8!\n"); 
        return -1;
    }     
    
    if(flag == 0)
        sprintf(vrrp_str, "%s%d,%d,%s,100,1,1,0,;", vrrp_str, vlan, vrid, ip_str);  

    free(vrrp_list);
    scfgmgr_set("vrrp_list", vrrp_str);
    system("rc vrrp restart > /dev/null 2>&1");
    
	return 0;
}

/*
 *  Function:  func_vlan_vrrp_num_priority_level
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_vrrp_num_priority_level(struct users *u)
{
	int vlan, cnt = 0, flag = 0, vrid, nvrid, prority;
    char line[128], list[8][64], intf[32], vrrp_str[2048];	
	char *p, *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");

	vlan = atoi(u->promptbuf+1);
    p = strstr(u->linebuf, "vrrp");
	p += strlen("vrrp");
	while(*p == ' ')
	    p++;
	vrid = atoi(p); 
	
    p = strstr(u->linebuf, "priority");
	p += strlen("priority");
	while(*p == ' ')
	    p++;
	prority = atoi(p);   
	
//	DEBUG("[%s:%d] vlan %d vrid %d prority %d", __FUNCTION__, __LINE__, vlan, vrid, prority);

    vrrp = vrrp_list;
    memset(vrrp_str, '\0', sizeof(vrrp_str));
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
       
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 
        
        if(atoi(list[0]) == vlan)  
        {    
            flag = 1; 
            
            if(atoi(list[1]) != vrid)
            {
                free(vrrp_list);
                vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
                return -1;
            }    
                 
            sprintf(vrrp_str, "%s%s,%s,%s,%d,%s,%s,%s,%s;", vrrp_str, 
                list[0], list[1], list[2], prority, list[4], list[5], list[6],list[7]);  
        }
        else
        {
            sprintf(vrrp_str, "%s%s;", vrrp_str, line);   
        }       
        vrrp = p1+1;   
        cnt++;    
    }
    free(vrrp_list);
    
    if(flag == 0)
    {
        vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
        return -1;
    }
    else
    {  
        scfgmgr_set("vrrp_list", vrrp_str);
        system("rc vrrp restart > /dev/null 2>&1");
    }

	return 0;
}

/*
 *  Function:  nfunc_vlan_vrrp_num_desc
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_vrrp_num_desc(struct users *u)
{
	printf("do nfunc_vlan_vrrp_num_desc here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_vrrp_num_ip_addr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_vrrp_num_ip_addr(struct users *u)
{
	struct in_addr i;
	int vlan, cnt = 0, flag = 0, vrid;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
    char line[128], list[8][64], intf[32], vrrp_str[2048];	
	char *p, *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");

	vlan = atoi(u->promptbuf+1);
    p = strstr(u->linebuf, "vrrp");
	p += strlen("vrrp");
	while(*p == ' ')
	    p++;
	vrid = atoi(p);  

//	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
//	DEBUG("[%s:%d] vlan %d vrid %d ip_str %s", __FUNCTION__, __LINE__, vlan, vrid, ip_str);

    vrrp = vrrp_list;
    memset(vrrp_str, '\0', sizeof(vrrp_str));
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
       
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 
        
        if((atoi(list[0]) == vlan)&&(atoi(list[1]) == vrid))  
        {    
            flag = 1; 
        }
        else
        {
            sprintf(vrrp_str, "%s%s;", vrrp_str, line);   
        }       
        vrrp = p1+1;   
        cnt++;    
    }
    free(vrrp_list);
    
    if(flag == 1)
    {    
        scfgmgr_set("vrrp_list", vrrp_str);
        system("rc vrrp restart > /dev/null 2>&1");
    }else
    {
        vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
        return -1;
    }    
    
	return 0;
}

/*
 *  Function:  nfunc_vlan_vrrp_num_preempt
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_vrrp_num_preempt(struct users *u)
{
	int vlan, cnt = 0, flag = 0, vrid, nvrid;
    char line[128], list[8][64], intf[32], vrrp_str[2048];	
	char *p, *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");

	vlan = atoi(u->promptbuf+1);
    p = strstr(u->linebuf, "vrrp");
	p += strlen("vrrp");
	while(*p == ' ')
	    p++;
	vrid = atoi(p); 

//	DEBUG("[%s:%d] vlan %d vrid %d", __FUNCTION__, __LINE__, vlan, vrid);

    vrrp = vrrp_list;
    memset(vrrp_str, '\0', sizeof(vrrp_str));
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
       
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 
        
        if(atoi(list[0]) == vlan)  
        {    
            flag = 1; 
            
            if(atoi(list[1]) != vrid)
            {
                free(vrrp_list);
                vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
                return -1;
            }    
                 
            sprintf(vrrp_str, "%s%s,%s,%s,%s,%s,%s,%s,%s;", vrrp_str, 
                list[0], list[1], list[2],list[3],"0", list[5], list[6],list[7]);  
        }
        else
        {
            sprintf(vrrp_str, "%s%s;", vrrp_str, line);   
        }       
        vrrp = p1+1;   
        cnt++;    
    }
    free(vrrp_list);
    
    if(flag == 0)
    {
        vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
        return -1;
    }
    else
    {  
        scfgmgr_set("vrrp_list", vrrp_str);
        system("rc vrrp restart > /dev/null 2>&1");
    }
    
	return 0;
}

/*
 *  Function:  nfunc_vlan_vrrp_num_priority
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_vrrp_num_priority(struct users *u)
{
	int vlan, cnt = 0, flag = 0, vrid, nvrid;
    char line[128], list[8][64], intf[32], vrrp_str[2048];	
	char *p, *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");

	vlan = atoi(u->promptbuf+1);
    p = strstr(u->linebuf, "vrrp");
	p += strlen("vrrp");
	while(*p == ' ')
	    p++;
	vrid = atoi(p); 
	
//	DEBUG("[%s:%d] vlan %d vrid %d", __FUNCTION__, __LINE__, vlan, vrid);

    vrrp = vrrp_list;
    memset(vrrp_str, '\0', sizeof(vrrp_str));
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
       
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 
        
        if(atoi(list[0]) == vlan)  
        {    
            flag = 1; 
            
            if(atoi(list[1]) != vrid)
            {
                free(vrrp_list);
                vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
                return -1;
            }    
                 
            sprintf(vrrp_str, "%s%s,%s,%s,%d,%s,%s,%s,%s;", vrrp_str, 
                list[0], list[1], list[2], 100, list[4], list[5], list[6],list[7]);  
        }
        else
        {
            sprintf(vrrp_str, "%s%s;", vrrp_str, line);   
        }       
        vrrp = p1+1;   
        cnt++;    
    }
    free(vrrp_list);
    
    if(flag == 0)
    {
        vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
        return -1;
    }
    else
    {  
        scfgmgr_set("vrrp_list", vrrp_str);
        system("rc vrrp restart > /dev/null 2>&1");
    }

	return 0;
}

/*
 *  Function:  func_gvrp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_gvrp(struct users *u)
{
    char *gvrp_enable = nvram_safe_get("gvrp_enable");

    if( '1' != *gvrp_enable )
    {    
        scfgmgr_set("gvrp_enable", "1");
        system("rc gvrp start >/dev/null 2>&1");
    }else
        system("killall -SIGUSR2 gvrpd >/dev/null 2>&1");

	free(gvrp_enable);
	
	return 0;
}

/*
 *  Function:  nfunc_gvrp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_gvrp(struct users *u)
{
    char *gvrp_enable = nvram_safe_get("gvrp_enable");

    if( '0' != *gvrp_enable )
    {    
        scfgmgr_set("gvrp_enable", "0");
        system("rc gvrp stop >/dev/null 2>&1");
    }

	free(gvrp_enable);
	return 0;
}

/*
 *  Function:  func_vlan_arp_timeout
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_arp_timeout(struct users *u)
{
    int time_out = 0, flag = 0, vlan, vlanid, timeout;
	char line[32], arp_str[8196];
	char *p1, *ip, *arp_timeout = nvram_safe_get("arp_timeout");
	
	vlan = atoi(u->promptbuf+1);
    cli_param_get_int(STATIC_PARAM, 0, &time_out, u);
	
	if(find_exist_interface(IMP, vlan) < 0)
	{
		free(arp_timeout);
	    vty_output("Error: not found this interface vlan static ipv4 address or no supervlan, configure first!\n");
		return -1;
	}  

    memset(arp_str, '\0', sizeof(arp_str));
    ip = arp_timeout;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(line, '\0', sizeof(line));
        p1 = strchr(ip, ';'); 
        memcpy(line, ip, p1-ip);
        sscanf(line, "%d:%d", &vlanid, &timeout);

        if(vlan == vlanid)
        {    
            flag = 1; 
            sprintf(arp_str, "%s%d:%d;", arp_str, vlan, time_out); 
        }    
        else    
        {    
            sprintf(arp_str, "%s%s;", arp_str, line); 
        } 
        ip = p1+1;  
    } 
    free(arp_timeout);
    
    if(flag == 0)
        sprintf(arp_str, "%s%d:%d;", arp_str, vlan, time_out); 

    scfgmgr_set("arp_timeout", arp_str);
    system("killall -SIGUSR1 arpd >/dev/null 2>&1");

	return 0;
}

/*
 *  Function:  nfunc_vlan_arp_timeout
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_arp_timeout(struct users *u)
{
    int time_out = 0, flag = 0, vlan, vlanid, timeout;
	char line[32], arp_str[8196];
	char *p1, *ip, *arp = nvram_safe_get("arp_timeout");
	
	vlan = atoi(u->promptbuf+1);

    memset(arp_str, '\0', sizeof(arp_str));
    ip = arp;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(line, '\0', sizeof(line));
        p1 = strchr(ip, ';'); 
        memcpy(line, ip, p1-ip);
        sscanf(line, "%d:%d", &vlanid, &timeout);

        if(vlan == vlanid)
        {    
            flag = 1; 
        }    
        else    
        {    
            sprintf(arp_str, "%s%s;", arp_str, line); 
        } 
        ip = p1+1;  
    } 
    free(arp);
    
    if(flag == 0)
	{
	    vty_output("Warning: not found this vlan interface with arp timeout setting!\n");
		return -1;
	}  
    else
    {    
        scfgmgr_set("arp_timeout", arp_str);
        system("killall -SIGUSR1 arpd >/dev/null 2>&1");
    }
    
	return 0;
}

/*
 *  Function:  func_vlan_arp_send_interval
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_arp_send_interval(struct users *u)
{
    int time_out = 0, flag = 0, vlan, vlanid, timeout;
	char line[32], arp_str[8196];
	char *p1, *ip, *arp = nvram_safe_get("free_arp");
	
	vlan = atoi(u->promptbuf+1);
    cli_param_get_int(STATIC_PARAM, 0, &time_out, u);
	
	if(find_exist_interface(IMP, vlan) < 0)
	{
		free(arp);
	    vty_output("Error: not found this vlan interface with ipv4/ipv6 address or dhcp, configure first!\n");
		return -1;
	}  

    memset(arp_str, '\0', sizeof(arp_str));
    ip = arp;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(line, '\0', sizeof(line));
        p1 = strchr(ip, ';'); 
        memcpy(line, ip, p1-ip);
        sscanf(line, "%d:%d", &vlanid, &timeout);

        if(vlan == vlanid)
        {    
            flag = 1; 
            sprintf(arp_str, "%s%d:%d;", arp_str, vlan, time_out); 
        }    
        else    
        {    
            sprintf(arp_str, "%s%s;", arp_str, line); 
        } 
        ip = p1+1;  
    } 
    free(arp);
    
    if(flag == 0)
        sprintf(arp_str, "%s%d:%d;", arp_str, vlan, time_out); 

    scfgmgr_set("free_arp", arp_str);
    system("killall -SIGUSR1 arpd >/dev/null 2>&1");

	return 0;
}

/*
 *  Function:  nfunc_vlan_arp_send_interval
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_arp_send_interval(struct users *u)
{
    int time_out = 0, flag = 0, vlan, vlanid, timeout;
	char line[32], arp_str[8196];
	char *p1, *ip, *arp = nvram_safe_get("free_arp");
	
	vlan = atoi(u->promptbuf+1);

    memset(arp_str, '\0', sizeof(arp_str));
    ip = arp;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(line, '\0', sizeof(line));
        p1 = strchr(ip, ';'); 
        memcpy(line, ip, p1-ip);
        sscanf(line, "%d:%d", &vlanid, &timeout);

        if(vlan == vlanid)
        {    
            flag = 1; 
        }    
        else    
        {    
            sprintf(arp_str, "%s%s;", arp_str, line); 
        } 
        ip = p1+1;  
    } 
    free(arp);
    
    if(flag == 0)
	{
	    vty_output("Warning: not found this vlan interface with free arp setting!\n");
		return -1;
	}  
    else
    {    
        scfgmgr_set("free_arp", arp_str);
        system("killall -SIGUSR1 arpd >/dev/null 2>&1");
    }
    
	return 0;
}

/*
 *  Function:  func_ip_proxy_arp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_proxy_arp(struct users *u)
{
    int vlan, len, vid, type, flag = 0;
	char intf[128], ipv4[32], ipv6[64];
	char *p1, *ip, *vlan_intf_str, *l3_ip = nvram_safe_get("lan_ipaddr");
	
	vlan = atoi(u->promptbuf+1);
    len = strlen(l3_ip)+8;
	vlan_intf_str = malloc(len);
	if(NULL == vlan_intf_str)
	{
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		free(l3_ip);
		return -1;
	}  
    memset(vlan_intf_str, '\0', len);
    
    ip = l3_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        vid = atoi(intf);
        if(vlan == vid)
        {    
            memset(ipv4, '\0', sizeof(ipv4));
            memset(ipv6, '\0', sizeof(ipv6));
            
            cli_interface_info_get(intf, &vid, &type, ipv4, ipv6);
            flag = 1; 
            sprintf(vlan_intf_str, "%s%d:%d,%s,%s;", vlan_intf_str, vlan, type | (1<<INTF_ARP_PROXY), ipv4, ipv6); 
        }    
        else    
        {    
            sprintf(vlan_intf_str, "%s%s;", vlan_intf_str, intf); 
        } 
        
        ip = p1+1;  
    } 
    free(l3_ip);
    
    if(flag == 0)
	{
	    vty_output("Error: not found this interface vlan address or no supervlan, configure first!\n");
        free(vlan_intf_str); 	
		return -1;
	}
	
    scfgmgr_set("l3_ip", vlan_intf_str);  
    free(vlan_intf_str);
    system("killall -SIGUSR1 vlinkscan >/dev/null 2>&1");
    system("killall -SIGUSR1 arpd >/dev/null 2>&1");

	return 0;
}

/*
 *  Function:  nfunc_ip_proxy_arp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_proxy_arp(struct users *u)
{
    int vlan, len, vid, type, flag = 0;
	char intf[128], ipv4[32], ipv6[64];
	char *p1, *ip, *vlan_intf_str, *l3_ip = nvram_safe_get("lan_ipaddr");
	
	vlan = atoi(u->promptbuf+1);
    len = strlen(l3_ip)+8;
	vlan_intf_str = malloc(len);
	if(NULL == vlan_intf_str)
	{
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		free(l3_ip);
		return -1;
	}  
    memset(vlan_intf_str, '\0', len);
    
    ip = l3_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        vid = atoi(intf);
        if(vlan == vid)
        {    
            memset(ipv4, '\0', sizeof(ipv4));
            memset(ipv6, '\0', sizeof(ipv6));
            
            cli_interface_info_get(intf, &vid, &type, ipv4, ipv6);
            
            flag = 1; 
            sprintf(vlan_intf_str, "%s%d:%d,%s,%s;", vlan_intf_str, vlan, type & ~(1<<INTF_ARP_PROXY), ipv4, ipv6); 
        }    
        else    
        {    
            sprintf(vlan_intf_str, "%s%s;", vlan_intf_str, intf); 
        } 
        
        ip = p1+1;  
    } 
    free(l3_ip);
    
    if(flag == 0)
	{
	    vty_output("Error: not found this interface vlan address or no supervlan, configure first!\n");
        free(vlan_intf_str); 	
		return -1;
	}
	
    scfgmgr_set("l3_ip", vlan_intf_str);  
    free(vlan_intf_str);
    system("killall -SIGUSR1 vlinkscan >/dev/null 2>&1");
    system("killall -SIGUSR1 arpd >/dev/null 2>&1");

	return 0;
}

/*
 *  Function:  func_vlan_ip_igmp_querier_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ip_igmp_querier_time(struct users *u)
{
    IPMC_ENTRY ipmc_entry;
    int i = 0, vlan, isin, ret, found = 0, num;
    char *p, *p1, *p2, *p3, *p4, *ipmc_config;
	char st_str[8196];
	
	vlan = atoi(u->promptbuf+1);
	cli_param_get_int(STATIC_PARAM,0,&num, u);
//	printf("[%s:%d] vlan %d num %d\n", __FUNCTION__, __LINE__, vlan, num);
    
    memset(st_str, '\0', sizeof(st_str));
    ipmc_config = nvram_safe_get("igmp_config");
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        if(ipmc_entry.vlanid == vlan)
        {    
            found = 1;
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, ipmc_entry.query, num);
        }else
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, ipmc_entry.query, ipmc_entry.timeout);
               
    }
    free(ipmc_config);  
    
    if(found == 1)
    {
        scfgmgr_set("igmp_config", st_str); 
	    system("rc mroute start > /dev/null 2>&1");     
    }
    else
    {
        vty_output("vlan%d igmp proxy is disabled, please run 'ip igmp' first!\n\n", vlan);    
    } 
     
	return 0;
}

/*
 *  Function:  nfunc_vlan_ip_igmp_querier_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ip_igmp_querier_time(struct users *u)
{
    IPMC_ENTRY ipmc_entry;
    int i = 0, vlan, isin, ret, found = 0;
    char *p, *p1, *p2, *p3, *p4, *ipmc_config;
	char st_str[8196];
	
	vlan = atoi(u->promptbuf+1);
//	printf("[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);
    
    memset(st_str, '\0', sizeof(st_str));
    ipmc_config = nvram_safe_get("igmp_config");
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        if(ipmc_entry.vlanid == vlan)
        {    
            found = 1;
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, ipmc_entry.query, 10);
        }else
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, ipmc_entry.query, ipmc_entry.timeout);
               
    }
    free(ipmc_config);  
    
    if(found == 1)
    {
        scfgmgr_set("igmp_config", st_str); 
	    system("rc mroute start > /dev/null 2>&1");     
    }
    else
    {
        vty_output("vlan%d igmp proxy is disabled, please run 'ip igmp' first!\n\n", vlan);    
    } 
     
	return 0;
}

/*
 *  Function:  func_ip_igmp_query_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_igmp_query_time(struct users *u)
{
    IPMC_ENTRY ipmc_entry;
    int i = 0, vlan, isin, ret, found = 0, num;
    char *p, *p1, *p2, *p3, *p4, *ipmc_config;
	char st_str[8196];
	
	vlan = atoi(u->promptbuf+1);
	cli_param_get_int(STATIC_PARAM,0,&num, u);
//	printf("[%s:%d] vlan %d num %d\n", __FUNCTION__, __LINE__, vlan, num);
    
    memset(st_str, '\0', sizeof(st_str));
    ipmc_config = nvram_safe_get("igmp_config");
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        if(ipmc_entry.vlanid == vlan)
        {    
            found = 1;
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, num, ipmc_entry.timeout);
        }else
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, ipmc_entry.query, ipmc_entry.timeout);
               
    }
    free(ipmc_config);  
    
    if(found == 1)
    {
        scfgmgr_set("igmp_config", st_str); 
	    system("rc mroute start > /dev/null 2>&1");     
    }
    else
    {
        vty_output("vlan%d igmp proxy is disabled, please run 'ip igmp' first!\n\n", vlan);    
    } 
     
	return 0;
}

/*
 *  Function:  nfunc_ip_igmp_query_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_igmp_query_time(struct users *u)
{
    IPMC_ENTRY ipmc_entry;
    int i = 0, vlan, isin, ret, found = 0;
    char *p, *p1, *p2, *p3, *p4, *ipmc_config;
	char st_str[8196];
	
	vlan = atoi(u->promptbuf+1);
//	printf("[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);
    
    memset(st_str, '\0', sizeof(st_str));
    ipmc_config = nvram_safe_get("igmp_config");
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        if(ipmc_entry.vlanid == vlan)
        {    
            found = 1;
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, 120, ipmc_entry.timeout);
        }else
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, ipmc_entry.query, ipmc_entry.timeout);
               
    }
    free(ipmc_config);  
    
    if(found == 1)
    {
        scfgmgr_set("igmp_config", st_str); 
	    system("rc mroute start > /dev/null 2>&1");     
    }
    else
    {
        vty_output("vlan%d igmp proxy is disabled, please run 'ip igmp' first!\n\n", vlan);    
    } 
     
	return 0;
}

/*
 *  Function:  func_ip_igmp_static_group
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_igmp_static_group(struct users *u)
{
	printf("do func_ip_igmp_static_group here\n");

	return 0;
}

/*
 *  Function:  nfunc_ip_igmp_static_group
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_igmp_static_group(struct users *u)
{
	printf("do nfunc_ip_igmp_static_group here\n");

	return 0;
}

/*
 *  Function:  func_ip_igmp_static_group_source
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_igmp_static_group_source(struct users *u)
{
	printf("do func_ip_igmp_static_group_source here\n");

	return 0;
}

/*
 *  Function:  func_ip_igmp_version_1
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
 
int func_ip_igmp(struct users *u)
{
    uint32 ipaddr;
    IPMC_ENTRY ipmc_entry;
    int i = 0, vlan, isin, ret, found = 0;
    char *p, *p1, *p2, *p3, *p4, *ipmc_config;
	char st_str[8196];
	
	vlan = atoi(u->promptbuf+1);
//	printf("[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);
    
    isin = find_vlan_intf_exit(vlan);
    if(0 == isin)
    {
        vty_output("vlan %d is unconfigure, please configure ip first\n\n", vlan); 
        return 0; 
    }else
    {
        ret = get_interface_ip(IMP, vlan, &ipaddr);
        if(ret < 0) 
        {
            vty_output("vlan %d is unconfigure, please configure ip first\n\n", vlan); 
            return 0; 
        }
    }    
        
    ipmc_config = nvram_safe_get("igmp_config");
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        if(ipmc_entry.vlanid == vlan)
        {    
            found = 1;
            break;
        }   
    }
    
    if(found == 1)
    {
        vty_output("vlan%d igmp proxy is enabled, no action!\n\n", vlan);  
    }
    else
    {
        memset(st_str, '\0', sizeof(st_str));
        sprintf(st_str, "%s%d,3,120,10;", ipmc_config, vlan);
        scfgmgr_set("igmp_config", st_str);  
        
	    system("rc mroute start > /dev/null 2>&1");     
    }
    free(ipmc_config);   
     
	return 0;
}

int func_ip_igmp_version_1(struct users *u)
{
    IPMC_ENTRY ipmc_entry;
    int i = 0, vlan, isin, ret, found = 0;
    char *p, *p1, *p2, *p3, *p4, *ipmc_config;
	char st_str[8196];
	
	vlan = atoi(u->promptbuf+1);
//	printf("[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);
    
    memset(st_str, '\0', sizeof(st_str));
    ipmc_config = nvram_safe_get("igmp_config");
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        if(ipmc_entry.vlanid == vlan)
        {    
            found = 1;
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, 1, ipmc_entry.query, ipmc_entry.timeout);
        }else
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, ipmc_entry.query, ipmc_entry.timeout);
               
    }
    free(ipmc_config);  
    
    if(found == 1)
    {
        scfgmgr_set("igmp_config", st_str); 
	    system("rc mroute start > /dev/null 2>&1");     
    }
    else
    {
        vty_output("vlan%d igmp proxy is disabled, please run 'ip igmp' first!\n\n", vlan);    
    } 
     
	return 0;
}

int func_ip_igmp_version_2(struct users *u)
{
    IPMC_ENTRY ipmc_entry;
    int i = 0, vlan, isin, ret, found = 0;
    char *p, *p1, *p2, *p3, *p4, *ipmc_config;
	char st_str[8196];
	
	vlan = atoi(u->promptbuf+1);
//	printf("[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);
    
    memset(st_str, '\0', sizeof(st_str));
    ipmc_config = nvram_safe_get("igmp_config");
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        if(ipmc_entry.vlanid == vlan)
        {    
            found = 1;
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, 2, ipmc_entry.query, ipmc_entry.timeout);
        }else
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, ipmc_entry.query, ipmc_entry.timeout);
               
    }
    free(ipmc_config);  
    
    if(found == 1)
    {
        scfgmgr_set("igmp_config", st_str); 
	    system("rc mroute start > /dev/null 2>&1");     
    }
    else
    {
        vty_output("vlan%d igmp proxy is disabled, please run 'ip igmp' first!\n\n", vlan);    
    } 
     
	return 0;
}

int func_ip_igmp_version_3(struct users *u)
{
    IPMC_ENTRY ipmc_entry;
    int i = 0, vlan, isin, ret, found = 0;
    char *p, *p1, *p2, *p3, *p4, *ipmc_config;
	char st_str[8196];
	
	vlan = atoi(u->promptbuf+1);
//	printf("[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);
    
    memset(st_str, '\0', sizeof(st_str));
    ipmc_config = nvram_safe_get("igmp_config");
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        if(ipmc_entry.vlanid == vlan)
        {    
            found = 1;
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, 3, ipmc_entry.query, ipmc_entry.timeout);
        }else
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, ipmc_entry.query, ipmc_entry.timeout);
               
    }
    free(ipmc_config);  
    
    if(found == 1)
    {
        scfgmgr_set("igmp_config", st_str); 
	    system("rc mroute start > /dev/null 2>&1");     
    }
    else
    {
        vty_output("vlan%d igmp proxy is disabled, please run 'ip igmp' first!\n\n", vlan);    
    } 
     
	return 0;
}

/*
 *  Function:  nfunc_ip_igmp_version
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
 
int nfunc_ip_igmp(struct users *u)
{
    IPMC_ENTRY ipmc_entry;
    int i = 0, vlan, isin, ret, found = 0;
    char *p, *p1, *p2, *p3, *p4, *ipmc_config;
	char st_str[8196];
	
	vlan = atoi(u->promptbuf+1);
//	printf("[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);
    
    memset(st_str, '\0', sizeof(st_str));
    ipmc_config = nvram_safe_get("igmp_config");
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        if(ipmc_entry.vlanid == vlan)
        {    
            found = 1;
            break;
        }else
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, ipmc_entry.query, ipmc_entry.timeout);
               
    }
    free(ipmc_config);  
    
    if(found == 1)
    {
        scfgmgr_set("igmp_config", st_str); 
	    system("rc mroute start > /dev/null 2>&1");     
    }
    else
    {
        vty_output("vlan%d igmp proxy is disabled, no action!\n\n", vlan);    
    } 
     
	return 0;
}
 
int nfunc_ip_igmp_version(struct users *u)
{

    IPMC_ENTRY ipmc_entry;
    int i = 0, vlan, isin, ret, found = 0;
    char *p, *p1, *p2, *p3, *p4, *ipmc_config;
	char st_str[8196];
	
	vlan = atoi(u->promptbuf+1);
//	printf("[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);
    
    memset(st_str, '\0', sizeof(st_str));
    ipmc_config = nvram_safe_get("igmp_config");
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        if(ipmc_entry.vlanid == vlan)
        {    
            found = 1;
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, 3, ipmc_entry.query, ipmc_entry.timeout);
        }else
            sprintf(st_str, "%s%d,%d,%d,%d;", st_str, ipmc_entry.vlanid, ipmc_entry.version, ipmc_entry.query, ipmc_entry.timeout);
               
    }
    free(ipmc_config);  
    
    if(found == 1)
    {
        scfgmgr_set("igmp_config", st_str); 
	    system("rc mroute start > /dev/null 2>&1");     
    }
    else
    {
        vty_output("vlan%d igmp proxy is disabled, please run 'ip igmp' first!\n\n", vlan);    
    } 
     
	return 0;
}

/*
 *  Function:  func_vlan_ip_pim
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ip_pim(struct users *u)
{
    int vlan;
	char key[8], vlan_str[8196];
	char *vlans = nvram_safe_get("pim_dm");
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");

	vlan = atoi(u->promptbuf+1);
	memset(key, '\0', sizeof(key));
	sprintf(key, ";%d:", vlan);
	memset(vlan_str, '\0', sizeof(vlan_str));
	sprintf(vlan_str, ";%s", vlans);
	
    if(*ipmc_enable == '1')
	{
	    if(*ipmc_type == '1')
    	{    
    	    if(strstr(vlan_str, key) == NULL)
        	{
	            memset(vlan_str, '\0', sizeof(vlan_str));
        	    sprintf(vlan_str, "%s%d:;", vlans, vlan);
                nvram_set("pim_dm", vlan_str);
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else
            {
                vty_output("Warning: PIM-DM has already enabled in vlan %d, no change!\n", vlan); 
            } 
    	}else
        {
            vty_output("Warning: PIM-DM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(ipmc_enable);
    free(ipmc_type);
    free(vlans);
	return 0;
}

/*
 *  Function:  nfunc_vlan_ip_pim
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ip_pim(struct users *u)
{
    int vlan;
	char key[8], vlan_str[8196], vlan_str1[8196];
	char *p1, *p2, *p3, *vlans = nvram_safe_get("pim_dm");
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");

	vlan = atoi(u->promptbuf+1);
	memset(key, '\0', sizeof(key));
	sprintf(key, ";%d:", vlan);
	memset(vlan_str, '\0', sizeof(vlan_str));
	sprintf(vlan_str, ";%s", vlans);
	
    if(*ipmc_enable == '1')
	{
	    if(*ipmc_type == '1')
    	{    
    	    if((p1 = strstr(vlan_str, key)) != NULL)
        	{
	            memset(vlan_str1, '\0', sizeof(vlan_str1));
	            memcpy(vlan_str1, vlan_str+1, p1-vlan_str);
	            p2 = strchr(p1+1, ';');
	            if(strlen(p2) > 1)
	            { 
	                strcat(vlan_str1, p2+1);
	            }
	            
                nvram_set("pim_dm", vlan_str1);
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else
            {
                vty_output("Warning: PIM-DM has already disabled in vlan %d, no change!\n", vlan); 
            } 
    	}else
        {
            vty_output("Warning: PIM-DM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(vlans);
    free(ipmc_enable);
    free(ipmc_type);
    
	return 0;
}


/*
 *  Function:  func_vlan_ip_pim_dr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ip_pim_dr(struct users *u)
{
    int vlan, pri;
	char *p1, *p2, key[8], vlan_str[8196], vlan_nstr[8196];
	char *vlans = nvram_safe_get("pim_dm");
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");

	vlan = atoi(u->promptbuf+1);
	memset(key, '\0', sizeof(key));
	sprintf(key, ";%d:", vlan);
	memset(vlan_str, '\0', sizeof(vlan_str));
	sprintf(vlan_str, ";%s", vlans);
	
	cli_param_get_int(STATIC_PARAM, 0, &pri, u);

    if(*ipmc_enable == '1')
	{
	    if(*ipmc_type == '1')
    	{    
    	    if((p1 = strstr(vlan_str, key)) != NULL)
        	{
	            memset(vlan_nstr, '\0', sizeof(vlan_nstr));
	            if((p1-(vlan_str+1)) > 0)
	            {    
	                memcpy(vlan_nstr, vlan_str+1, p1-(vlan_str+1));
	                strcat(vlan_nstr, ";");
	            }

	            p2 = strchr(p1+1, ';')+1;
	            if(strlen(p2) > 0)
	                strcat(vlan_nstr, p2); 

        	    sprintf(vlan_nstr, "%s%d:%d;", vlan_nstr, vlan, pri);
                nvram_set("pim_dm", vlan_nstr);
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else
            {
                vty_output("Warning: PIM-DM is disabled\n");  
            } 
    	}else
        {
            vty_output("Warning: PIM-DM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(ipmc_enable);
    free(ipmc_type);
    free(vlans);
    
	return 0;
}

/*
 *  Function:  nfunc_vlan_ip_pim_dr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ip_pim_dr(struct users *u)
{
    int vlan;
	char *p1, *p2, key[8], vlan_str[8196], vlan_nstr[8196];
	char *vlans = nvram_safe_get("pim_dm");
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");

	vlan = atoi(u->promptbuf+1);
	memset(key, '\0', sizeof(key));
	sprintf(key, ";%d:", vlan);
	memset(vlan_str, '\0', sizeof(vlan_str));
	sprintf(vlan_str, ";%s", vlans);
	
    if(*ipmc_enable == '1')
	{
	    if(*ipmc_type == '1')
    	{    
    	    if(strstr(vlan_str, key) != NULL)
        	{
	            memset(vlan_nstr, '\0', sizeof(vlan_nstr));
	            if((p1-(vlan_str+1)) > 0)
	            {    
	                memcpy(vlan_nstr, vlan_str+1, p1-(vlan_str+1));
	                strcat(vlan_nstr, ";");
	            }
	            
	            p2 = strchr(p1+1, ';')+1;
	            if(strlen(p2) > 0)
	                strcat(vlan_nstr, p2);    
	            
        	    sprintf(vlan_nstr, "%s%d:0;", vlan_nstr, vlan);
                nvram_set("pim_dm", vlan_nstr);
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else
            {
                vty_output("Warning: PIM-DM is disabled\n"); 
            } 
    	}else
        {
            vty_output("Warning: PIM-DM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(ipmc_enable);
    free(ipmc_type);
    free(vlans);
    
	return 0;
}


int func_vlan_ip_pim_sm(struct users *u)
{
    int vlan;
	char key[8], vlan_str[8196];
	char *vlans = nvram_safe_get("pim_sm");
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");

	vlan = atoi(u->promptbuf+1);
	memset(key, '\0', sizeof(key));
	sprintf(key, ";%d:", vlan);
	memset(vlan_str, '\0', sizeof(vlan_str));
	sprintf(vlan_str, ";%s", vlans);
	
    if(*ipmc_enable == '1')
	{
	    if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
    	{    
    	    if(strstr(vlan_str, key) == NULL)
        	{
	            memset(vlan_str, '\0', sizeof(vlan_str));
        	    sprintf(vlan_str, "%s%d:;", vlans, vlan);
                nvram_set("pim_sm", vlan_str);
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else
            {
                vty_output("Warning: PIM-SM has already enabled in vlan %d, no change!\n", vlan); 
            } 
    	}else
        {
            vty_output("Warning: PIM-SM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(vlans);
    free(ipmc_enable);
    free(ipmc_type);
	return 0;
}

int nfunc_vlan_ip_pim_sm(struct users *u)
{
    int vlan;
	char key[8], vlan_str[8196], vlan_str1[8196];
	char *p1, *p2, *p3, *vlans = nvram_safe_get("pim_sm");
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");

	vlan = atoi(u->promptbuf+1);
	memset(key, '\0', sizeof(key));
	sprintf(key, ";%d:", vlan);
	memset(vlan_str, '\0', sizeof(vlan_str));
	sprintf(vlan_str, ";%s", vlans);
	
    if(*ipmc_enable == '1')
	{
	    if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
    	{    
    	    if((p1 = strstr(vlan_str, key)) != NULL)
        	{
	            memset(vlan_str1, '\0', sizeof(vlan_str1));
	            memcpy(vlan_str1, vlan_str+1, p1-vlan_str);
	            p2 = strchr(p1+1, ';');
	            if(strlen(p2) > 1)
	            { 
	                strcat(vlan_str1, p2+1);
	            }
	            
                nvram_set("pim_sm", vlan_str1);
        	    system("rc mroute restart  > /dev/null 2>&1");
        	}
            else
            {
                vty_output("Warning: PIM-SM has already disabled in vlan %d, no change!\n", vlan); 
            } 
    	}else
        {
            vty_output("Warning: PIM-SM is disabled\n"); 
        } 
	}else
    {
        vty_output("Warning: ip multicast-routing is disabled\n"); 
    } 
    
    free(vlans);
    free(ipmc_enable);
    free(ipmc_type);
	return 0;
}

/*
 *  Function:  func_vlan_ipv6_mld_join_addr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_mld_join_addr(struct users *u)
{
	printf("do func_vlan_ipv6_mld_join_addr here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_mld_join_addr_in_src
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_mld_join_addr_in_src(struct users *u)
{
	printf("do func_vlan_ipv6_mld_join_addr_in_src here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_mld_join_addr_ex_src
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_mld_join_addr_ex_src(struct users *u)
{
	printf("do func_vlan_ipv6_mld_join_addr_ex_src here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_mld_join_addr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_mld_join_addr(struct users *u)
{
	printf("do nfunc_vlan_ipv6_mld_join_addr here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_mld_join_addr_in_src
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_mld_join_addr_in_src(struct users *u)
{
	printf("do nfunc_vlan_ipv6_mld_join_addr_in_src here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_mld_join_addr_ex_src
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_mld_join_addr_ex_src(struct users *u)
{
	printf("do nfunc_vlan_ipv6_mld_join_addr_ex_src here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_mld_querier
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_mld_querier(struct users *u)
{
	printf("do func_vlan_ipv6_mld_querier here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_mld_querier
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_mld_querier(struct users *u)
{
	printf("do nfunc_vlan_ipv6_mld_querier here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_mld_query
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_mld_query(struct users *u)
{
	printf("do func_vlan_ipv6_mld_query here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_mld_query
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_mld_query(struct users *u)
{
	printf("do nfunc_vlan_ipv6_mld_query here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_mld_static_all
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_mld_static_all(struct users *u)
{
	printf("do func_vlan_ipv6_mld_static_all here\n");

	return 0;
}

int func_vlan_ipv6_mld_static_all_in(struct users *u)
{
	printf("do func_vlan_ipv6_mld_static_all_in here\n");

	return 0;
}

int func_vlan_ipv6_mld_static_group(struct users *u)
{
	printf("do func_vlan_ipv6_mld_static_group here\n");

	return 0;
}

int func_vlan_ipv6_mld_static_group_in(struct users *u)
{
	printf("do func_vlan_ipv6_mld_static_group_in here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_ipv6_mld_static_all
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_ipv6_mld_static_all(struct users *u)
{
	printf("do nfunc_vlan_ipv6_mld_static_all here\n");

	return 0;
}

int nfunc_vlan_ipv6_mld_static_all_in(struct users *u)
{
	printf("do nfunc_vlan_ipv6_mld_static_all_in here\n");

	return 0;
}

int nfunc_vlan_ipv6_mld_static_group(struct users *u)
{
	printf("do nfunc_vlan_ipv6_mld_static_group here\n");

	return 0;
}

int nfunc_vlan_ipv6_mld_static_group_in(struct users *u)
{
	printf("do nfunc_vlan_ipv6_mld_static_group_in here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ipv6_pim
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ipv6_pim(struct users *u)
{
	printf("do func_vlan_ipv6_pim here\n");

	return 0;
}

int nfunc_vlan_ipv6_pim(struct users *u)
{
	printf("do nfunc_vlan_ipv6_pim here\n");

	return 0;
}

int func_vlan_ipv6_pim_bsr(struct users *u)
{
	printf("do func_vlan_ipv6_pim_bsr here\n");

	return 0;
}

int func_vlan_ipv6_pim_dr_priority(struct users *u)
{
	printf("do func_vlan_ipv6_pim_dr_priority here\n");

	return 0;
}

int nfunc_vlan_ipv6_pim_bsr(struct users *u)
{
	printf("do nfunc_vlan_ipv6_pim_bsr here\n");

	return 0;
}

int nfunc_vlan_ipv6_pim_dr_priority(struct users *u)
{
	printf("do nfunc_vlan_ipv6_pim_dr_priority here\n");

	return 0;
}

int func_vlan_vrrp_num_timer(struct users *u)
{
	int vlan, cnt = 0, flag = 0, vrid, nvrid, delay;
    char line[128], list[8][64], intf[32], vrrp_str[2048];	
	char *p, *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");

	vlan = atoi(u->promptbuf+1);
    p = strstr(u->linebuf, "vrrp");
	p += strlen("vrrp");
	while(*p == ' ')
	    p++;
	vrid = atoi(p); 
	
    p = strstr(u->linebuf, "timer");
	p += strlen("timer");
	while(*p == ' ')
	    p++;
	delay = atoi(p);   
	
//	DEBUG("[%s:%d] vlan %d vrid %d delay %d", __FUNCTION__, __LINE__, vlan, vrid, delay);

    vrrp = vrrp_list;
    memset(vrrp_str, '\0', sizeof(vrrp_str));
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
       
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 
        
        if(atoi(list[0]) == vlan)  
        {    
            flag = 1; 
            
            if(atoi(list[1]) != vrid)
            {
                free(vrrp_list);
                vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
                return -1;
            }    
                 
            sprintf(vrrp_str, "%s%s,%s,%s,%s,%s,%d,%s,%s;", vrrp_str, 
                list[0], list[1], list[2],list[3],list[4], delay, list[6],list[7]);  
        }
        else
        {
            sprintf(vrrp_str, "%s%s;", vrrp_str, line);   
        }       
        vrrp = p1+1;   
        cnt++;    
    }
    free(vrrp_list);
    
    if(flag == 0)
    {
        vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
        return -1;
    }
    else
    {  
        scfgmgr_set("vrrp_list", vrrp_str);
        system("rc vrrp restart > /dev/null 2>&1");
    }
	return 0;
}

int nfunc_vlan_vrrp_num_timer(struct users *u)
{
	int vlan, cnt = 0, flag = 0, vrid, nvrid, delay;
    char line[128], list[8][64], intf[32], vrrp_str[2048];	
	char *p, *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");

	vlan = atoi(u->promptbuf+1);
    p = strstr(u->linebuf, "vrrp");
	p += strlen("vrrp");
	while(*p == ' ')
	    p++;
	vrid = atoi(p); 
	
    p = strstr(u->linebuf, "timer");
	p += strlen("timer");
	while(*p == ' ')
	    p++;
	delay = atoi(p);   
	
//	DEBUG("[%s:%d] vlan %d vrid %d delay %d", __FUNCTION__, __LINE__, vlan, vrid, delay);

    vrrp = vrrp_list;
    memset(vrrp_str, '\0', sizeof(vrrp_str));
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
       
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 
        
        if(atoi(list[0]) == vlan)  
        {    
            flag = 1; 
            
            if(atoi(list[1]) != vrid)
            {
                free(vrrp_list);
                vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
                return -1;
            }    
                 
            sprintf(vrrp_str, "%s%s,%s,%s,%s,%s,%d,%s,%s;", vrrp_str, 
                list[0], list[1], list[2],list[3],list[4], 1, list[6],list[7]);  
        }
        else
        {
            sprintf(vrrp_str, "%s%s;", vrrp_str, line);   
        }       
        vrrp = p1+1;   
        cnt++;    
    }
    free(vrrp_list);
    
    if(flag == 0)
    {
        vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
        return -1;
    }
    else
    {      
        scfgmgr_set("vrrp_list", vrrp_str);
        system("rc vrrp restart > /dev/null 2>&1");
    }

	return 0;
}

int nfunc_vlan_vrrp_num_auth(struct users *u)
{
	int vlan, cnt = 0, flag = 0, vrid, nvrid;
    char line[128], list[8][64], intf[32], vrrp_str[2048];	
	char *p, *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");

	vlan = atoi(u->promptbuf+1);
    p = strstr(u->linebuf, "vrrp");
	p += strlen("vrrp");
	while(*p == ' ')
	    p++;
	vrid = atoi(p); 
	
//	DEBUG("[%s:%d] vlan %d vrid %d", __FUNCTION__, __LINE__, vlan, vrid);

    vrrp = vrrp_list;
    memset(vrrp_str, '\0', sizeof(vrrp_str));
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
       
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 
        
        if(atoi(list[0]) == vlan)  
        {    
            flag = 1; 
            
            if(atoi(list[1]) != vrid)
            {
                free(vrrp_list);
                vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
                return -1;
            }    
                 
            sprintf(vrrp_str, "%s%s,%s,%s,%s,%s,%s,%s,%s;", vrrp_str, 
                list[0], list[1], list[2], list[3], list[4], list[5], "0", "");  
        }
        else
        {
            sprintf(vrrp_str, "%s%s;", vrrp_str, line);   
        }       
        vrrp = p1+1;   
        cnt++;    
    }
    free(vrrp_list);
    
    if(flag == 0)
    {
        vty_output("Error: interface vlan %d hasn't vrid %d!\n", vlan, vrid); 
        return -1;
    }
    else
    {  
        scfgmgr_set("vrrp_list", vrrp_str);
        system("rc vrrp restart > /dev/null 2>&1");
    }
    
	return 0;
}

/*
 *  Function:  func_vlan_ip_rip_bfd
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ip_rip_bfd(struct users *u)
{
	printf("do func_vlan_ip_rip_bfd here\n");

	return 0;
}

int nfunc_vlan_ip_rip_bfd(struct users *u)
{
	printf("do func_vlan_ip_rip_bfd here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ip_ospf_bfd
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ip_ospf_bfd(struct users *u)
{
	printf("do func_vlan_ip_ospf_bfd here\n");

	return 0;
}

int nfunc_vlan_ip_ospf_bfd(struct users *u)
{
	printf("do func_vlan_ip_ospf_bfd here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ip_bgp_bfd
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ip_bgp_bfd(struct users *u)
{
	printf("do func_vlan_ip_bgp_bfd here\n");

	return 0;
}

int nfunc_vlan_ip_bgp_bfd(struct users *u)
{
	printf("do func_vlan_ip_bgp_bfd here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ip_isis_bfd
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ip_isis_bfd(struct users *u)
{
	printf("do func_vlan_ip_isis_bfd here\n");

	return 0;
}

int nfunc_vlan_ip_isis_bfd(struct users *u)
{
	printf("do func_vlan_ip_isis_bfd here\n");

	return 0;
}

/*
 *  Function:  func_vlan_ip_static_bfd
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_ip_static_bfd(struct users *u)
{
	printf("do func_vlan_ip_static_bfd here\n");

	return 0;
}

int nfunc_vlan_ip_static_bfd(struct users *u)
{
	printf("do func_vlan_ip_static_bfd here\n");

	return 0;
}

/*
 *  Function:  func_vlan_vrrp_num_bfd
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_vrrp_num_bfd(struct users *u)
{
	printf("do func_vlan_vrrp_num_bfd here\n");

	return 0;
}

int nfunc_vlan_vrrp_num_bfd(struct users *u)
{
	printf("do nfunc_vlan_vrrp_num_bfd here\n");

	return 0;
}

/*
 *  Function:  func_vlan_bfd
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_bfd(struct users *u)
{
    int len = 0, vlan, id, found = 0, i, j, k;
    char *p, *p1, config[128], *intf_config, *intf_str;

	vlan = atoi(u->promptbuf+1);
	cli_param_get_int(STATIC_PARAM, 0, &i, u);
	cli_param_get_int(STATIC_PARAM, 1, &j, u);
	cli_param_get_int(STATIC_PARAM, 2, &k, u);
//	printf("[%s:%d] vlan %d i %d j %d k %d\n", __FUNCTION__, __LINE__, vlan, i, j, k);

    intf_config = nvram_safe_get("bfd_intf");
    len = strlen(intf_config);
    intf_str = malloc(len+32);
    if(NULL == intf_str)
    {
        vty_output("Error: malloc failed, please check some error!\n", vlan);    
        free(intf_config);   
        return -1; 
    }    
    memset(intf_str, '\0', len+32);    
    
    p = intf_config;
    while((p1=strchr(p, ';')) != NULL)
    {    
        memset(config, '\0', sizeof(config));
        memcpy(config, p, p1-p); 
        id = atoi(config);   
        p = p1 + 1;
        
        if(id == vlan)
        {    
            found = 1;
            sprintf(intf_str, "%s%d:%d,%d,%d;", intf_str, vlan, i, j, k);
        }else
            sprintf(intf_str, "%s%s;", intf_str, config);
               
    }
    free(intf_config);  
    
    if(found == 0)
    {
        sprintf(intf_str, "%s%d:%d,%d,%d;", intf_str, vlan, i, j, k);
    }
    
    scfgmgr_set("bfd_intf", intf_str); 
    system("rc bfd restart > /dev/null 2>&1"); 
    system("rc ospf restart > /dev/null 2>&1");     
    
    free(intf_str); 
	return 0;
}

int nfunc_vlan_bfd(struct users *u)
{
    int len = 0, vlan, id, found = 0;
    char *p, *p1, config[128], *intf_config, *intf_str;

	vlan = atoi(u->promptbuf+1);
//	printf("[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);

    intf_config = nvram_safe_get("bfd_intf");
    len = strlen(intf_config);
    if(len < 4){
        free(intf_config);
        return 0;
	}
    intf_str = malloc(len+1);
    if(NULL == intf_str)
    {
        vty_output("Error: malloc failed, please check some error!\n", vlan);    
        free(intf_config);   
        return -1; 
    }    
    memset(intf_str, '\0', len+1);    
    
    p = intf_config;
    while((p1=strchr(p, ';')) != NULL)
    {    
        memset(config, '\0', sizeof(config));
        memcpy(config, p, p1-p); 
        id = atoi(config);   
        p = p1 + 1;
        
        if(id == vlan)
        {    
            found = 1;
        }else
            sprintf(intf_str, "%s%s;", intf_str, config);
               
    }
    free(intf_config);  
    
    if(found == 1)
    {
        scfgmgr_set("bfd_intf", intf_str); 
	    system("rc bfd restart > /dev/null 2>&1"); 
	    system("rc ospf restart > /dev/null 2>&1");     
    }
    
    free(intf_str); 
	return 0;
}

/*
 *  Function:  func_vlan_bfd_auth_md5
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_vlan_bfd_auth_md5(struct users *u)
{
	printf("do func_vlan_bfd_auth_md5 here\n");

	return 0;
}

int func_vlan_bfd_auth_simple(struct users *u)
{
	printf("do func_vlan_bfd_auth_simple here\n");

	return 0;
}

/*
 *  Function:  nfunc_vlan_bfd_auth_md5
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_vlan_bfd_auth_md5(struct users *u)
{
	printf("do nfunc_vlan_bfd_auth_md5 here\n");

	return 0;
}

int nfunc_vlan_bfd_auth_simple(struct users *u)
{
	printf("do nfunc_vlan_bfd_auth_simple here\n");

	return 0;
}

int func_vlan_router_isis(struct users *u)
{
    int i = 0, vlan, isin, id, isisd, found = 0, num;
    char *p, *p1, *p2, *p3, *p4, *isis_intf_config;
	char st_str[1024];
    char *isis_id = nvram_safe_get("isis_id");
	
	vlan = atoi(u->promptbuf+1);
//	printf("[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);
    
	cli_param_get_int(DYNAMIC_PARAM,0, &num, u);
//    printf("[%s:%d] isis_id %s num %d\n", __FUNCTION__, __LINE__, isis_id, num);
    
    isisd = atoi(isis_id);
    free(isis_id);
    
    if(isisd != num)
    {
        vty_output("isis%d  is disabled, no action!\n\n", num);    
        return 0;
    } 
    
    memset(st_str, '\0', sizeof(st_str));
    isis_intf_config = nvram_safe_get("isis_intf_config");

    p = isis_intf_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        id = atoi(p);      
        p = p4 + 1;
        
        if(id == vlan)
        {    
            found = 1;
            sprintf(st_str, "%s%d,%d;", st_str, id, isisd);
        }else
            sprintf(st_str, "%s%d,%d;", st_str, id, isisd);
               
    }
    free(isis_intf_config);  
    
    if(found == 0)
    {   
        sprintf(st_str, "%s%d,%d;", st_str, vlan, num);
    }
    scfgmgr_set("isis_intf_config", st_str);  
    system("rc isis restart > /dev/null 2>&1"); 
    
	return 0;
}

int nfunc_vlan_router_isis(struct users *u)
{
    int i = 0, vlan, isin, id, isisd, found = 0, num;
    char *p, *p1, *p2, *p3, *p4, *isis_intf_config;
	char st_str[1024];
    //char *isis_id = nvram_safe_get("isis_id");
	
	vlan = atoi(u->promptbuf+1);
//	printf("[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);

    memset(st_str, '\0', sizeof(st_str));
    isis_intf_config = nvram_safe_get("isis_intf_config");
    p = isis_intf_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        id = atoi(p);    
        p1 = strchr(p, ',')+1;
        isisd = atoi(p1);   
        p = p4 + 1;
        
        if(id == vlan)
        {    
            found = 1;
        }else
            sprintf(st_str, "%s%d,%d;", st_str, id, isisd);
               
    }
    free(isis_intf_config);  
    
    if(found == 1)
    {
        scfgmgr_set("isis_intf_config", st_str); 
	    system("rc isis restart > /dev/null 2>&1");     
    }
    else
    {
        vty_output("vlan%d isis is disabled, no action!\n\n", vlan);    
    } 
     
	return 0;
}

int func_supervlan(struct users *u)
{
    int vlan, len, vid, type, flag = 0;
	char intf[128], ipv4[32], ipv6[64];
	char *p1, *ip, *vlan_intf_str, *l3_ip = nvram_safe_get("lan_ipaddr");
	
	vlan = atoi(u->promptbuf+1);
    len = strlen(l3_ip)+8;
	vlan_intf_str = malloc(len);
	if(NULL == vlan_intf_str)
	{
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		free(l3_ip);
		return -1;
	}  
    memset(vlan_intf_str, '\0', len);
    
    ip = l3_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        vid = atoi(intf);

        if(vlan == vid)
        {    
            memset(ipv4, '\0', sizeof(ipv4));
            memset(ipv6, '\0', sizeof(ipv6));
            
            cli_interface_info_get(intf, &vid, &type, ipv4, ipv6);
            
            flag = 1; 
            sprintf(vlan_intf_str, "%s%d:%d,%s,%s;", vlan_intf_str, vlan, type | (1<<INTF_SUPERVLAN), ipv4, ipv6); 
        }    
        else    
        {    
            sprintf(vlan_intf_str, "%s%s;", vlan_intf_str, intf); 
        } 
        
        ip = p1+1;  
    } 
    free(l3_ip);
    
    if(flag == 0)
	{
	    vty_output("Error: not found this interface vlan address, configure first!\n");
        free(vlan_intf_str); 	
		return -1;
	}
	
    scfgmgr_set("l3_ip", vlan_intf_str);  
    free(vlan_intf_str);
    system("killall -SIGUSR1 vlinkscan >/dev/null 2>&1");

	return 0;
}

int nfunc_supervlan(struct users *u)
{
    int vlan, len, vid, type, flag = 0;
	char intf[128], ipv4[32], ipv6[64];
	char *p1, *ip, *vlan_intf_str, *l3_ip = nvram_safe_get("lan_ipaddr");
	//char *subvlan = nvram_safe_get("subvlan");
	
	vlan = atoi(u->promptbuf+1);
    len = strlen(l3_ip)+8;
	vlan_intf_str = malloc(len);
	if(NULL == vlan_intf_str)
	{
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		free(l3_ip);
		return -1;
	}  
    memset(vlan_intf_str, '\0', len);
    
    ip = l3_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        vid = atoi(intf);

        if(vlan == vid)
        {    
            memset(ipv4, '\0', sizeof(ipv4));
            memset(ipv6, '\0', sizeof(ipv6));
            
            cli_interface_info_get(intf, &vid, &type, ipv4, ipv6);
            
            if(type & (1<<INTF_SUPERVLAN))
            {
                int len1, vlanid, flag1 = 0;
                char line[256], *pp1, *ipp, *substr, *subvlan = nvram_safe_get("subvlan");
                
                flag = 1; 
                sprintf(vlan_intf_str, "%s%d:%d,%s,%s;", vlan_intf_str, vlan, type & ~(1<<INTF_SUPERVLAN), ipv4, ipv6); 
                
                len1 = strlen(subvlan)+8;
            	substr = malloc(len1);
            	if(NULL == substr)
            	{
            		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
                    free(vlan_intf_str);
					free(l3_ip);
					free(subvlan);
            		return -1;
            	}  
                memset(substr, '\0', len1);
            	
                ipp = subvlan;
                while((*ipp != NULL) && (strlen(ipp) > 0))
                {   
                    memset(intf, '\0', sizeof(intf));
                    pp1 = strchr(ipp, ';'); 
                    memcpy(intf, ipp, pp1-ipp);
                    vlanid = atoi(intf);
                    if(vlan == vlanid)
                    {    
                        flag1 = 1;  
                    }
                    else
                        sprintf(substr, "%s%s;", substr, intf); 
                    
                    ipp = pp1+1; 
                } 
                free(subvlan);
                
                if(1 == flag1)
                    scfgmgr_set("subvlan", substr);
                free(substr);   
            }else
            {
        	    vty_output("Warning: not found this interface supervlan configure!\n");
                free(vlan_intf_str);
				free(l3_ip);
        		return -1;
        	}
                   
        }    
        else    
        {    
            sprintf(vlan_intf_str, "%s%s;", vlan_intf_str, intf); 
        } 
        
        ip = p1+1;  
    } 
    free(l3_ip);
    
    if(flag == 0)
	{
	    vty_output("Warning: not found this interface supervlan configure!\n");
        free(vlan_intf_str);
		return -1;
	}
	
    scfgmgr_set("l3_ip", vlan_intf_str);
    free(vlan_intf_str);  
    system("killall -SIGUSR1 vlinkscan >/dev/null 2>&1");

	return 0;
}

int func_subvlan(struct users *u)
{    
    char buff[MAX_ARGV_LEN] = {'\0'};
    int vlan, len, vid, type, flag = 0;
	char intf[128], ipv4[32], ipv6[64], key[8];
	char *p1, *p2, *vlan_intf_str, *l3_ip = nvram_safe_get("lan_ipaddr");
	
	vlan = atoi(u->promptbuf+1);
    cli_param_get_string(STATIC_PARAM, 0, buff, u);
    
    len = strlen(l3_ip)+8;
	vlan_intf_str = malloc(len);
	if(NULL == vlan_intf_str)
	{
		free(l3_ip);
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		return -1;
	}  
    memset(vlan_intf_str, '\0', len);
    sprintf(vlan_intf_str, ";%s", l3_ip);
    free(l3_ip);
    
    memset(key, '\0', sizeof(key));
    sprintf(key, ";%d:", vlan);
    memset(intf, '\0', sizeof(intf));

    if((p1 =strstr(vlan_intf_str, key)) != NULL)
    {    
        p1 += 1;
        p2 = strchr(p1, ';');
        memset(ipv4, '\0', sizeof(ipv4));
        memset(ipv6, '\0', sizeof(ipv6));
        memcpy(intf, p1, p2-p1);
        
        cli_interface_info_get(intf, &vid, &type, ipv4, ipv6);
        
        if(type & (1<<INTF_SUPERVLAN))
        {
            int len1, vlanid, flag1 = 0;
            char line[256], *pp1, *ipp, *substr, *subvlan = nvram_safe_get("subvlan");

            len1 = strlen(subvlan)+256;
        	substr = malloc(len1);
        	if(NULL == substr)
        	{
        		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
                free(vlan_intf_str);
				free(subvlan);
        		return -1;
        	}  
            memset(substr, '\0', len1);
        	
            ipp = subvlan;
            while((*ipp != NULL) && (strlen(ipp) > 0))
            {   
                memset(intf, '\0', sizeof(intf));
                pp1 = strchr(ipp, ';'); 
                memcpy(intf, ipp, pp1-ipp);
                vlanid = atoi(intf);
                if(vlan == vlanid)
                {    
                    flag1 = 1;  
                    sprintf(substr, "%s%d:%s;", substr, vlan, buff); 
                }
                else
                    sprintf(substr, "%s%s;", substr, intf); 
                
                ipp = pp1+1; 
            } 
            free(subvlan);
            
            if(0 == flag1)
                sprintf(substr, "%s%d:%s;", substr, vlan, buff); 
                
            scfgmgr_set("subvlan", substr);
            free(substr);   
        }else
        {
    	    vty_output("Warning: not found this interface supervlan configure!\n");
            free(vlan_intf_str);
    		return -1;
    	}
    } 
    else
	{
	    vty_output("Error: not found this interface vlan address, configure first!\n");
        free(vlan_intf_str);
		return -1;
	}

	free(vlan_intf_str);	
    system("killall -SIGUSR1 vlinkscan >/dev/null 2>&1");
	return 0;
}

int nfunc_subvlan(struct users *u)
{     
    int flag = 0, vlan, len, vlanid;
	char intf[256], *p1, *ip, *substr, *subvlan = nvram_safe_get("subvlan");
	
	vlan = atoi(u->promptbuf+1);
    len = strlen(subvlan)+8;
	substr = malloc(len);
	if(NULL == substr)
	{
		free(subvlan);
		vty_output("Error: no enough memory for vlan %d setting!\n", vlan);
		return -1;
	}  
    memset(substr, '\0', len);
	
    ip = subvlan;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        vlanid = atoi(intf);
        if(vlan == vlanid)
        {    
            flag = 1;  
        }
        else
            sprintf(substr, "%s%s;", substr, intf); 
        
        ip = p1+1; 
    } 
    free(subvlan);
    
    if(flag == 0)
    {
	    vty_output("Warning: not found this interface vlan or not configure subvlan!\n");
		free(substr);
		return 0;
    }

    scfgmgr_set("subvlan", substr);
    free(substr);
    system("killall -SIGUSR1 vlinkscan >/dev/null 2>&1");
    
	return 0;
}

/*
 *  Function:  func_ip_helper_ip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_helper_ip(struct users *u)
{
	struct in_addr i;
	int vlan, flag = 0;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
    char line[256], list[3][64], relay_str[4096];	
	char *p, *p1, *ip, * ip_list = nvram_safe_get("dhcp_relay_ip");

	vlan = atoi(u->promptbuf+1);
	cli_param_get_ipv4(STATIC_PARAM, 0, &i, ip_str, sizeof(ip_str), u);
//    fprintf(stderr, "[%s:%d] vlan %d ip_str %s\n", __FUNCTION__, __LINE__, vlan, ip_str);

    ip = ip_list;
    memset(relay_str, '\0', sizeof(relay_str));
    //dhcp_relay_ip=1:192.168.1.1,2000::1:2345:6789:abcd;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        p1 = strchr(ip, ';'); 
        memcpy(line, ip, p1-ip);
       
        sscanf(line, "%[^:]:%[^,],%[^,],", list[0],list[1],list[2]); 
//        fprintf(stderr, "[%s:%d] vlan %s ipv4 %s ipv6 %s\n", __FUNCTION__, __LINE__,list[0],list[1],list[2]);
        
        if(atoi(list[0]) == vlan)  
        {    
            if(strcmp(list[1], ip_str))
            {    
                flag = 1; 
                sprintf(relay_str, "%s%d:%s,%s;", relay_str, vlan, ip_str, list[2]); 
            }else
            {
                free(ip_list);
                vty_output("Warning: the same configure, no change!\n"); 
                return 0;
            }     
        }
        else
        {
            sprintf(relay_str, "%s%s;", relay_str, line);   
        }   
        ip = p1+1;   
    }

    if(flag == 0)
        sprintf(relay_str, "%s%d:%s,;", relay_str, vlan, ip_str);  

    free(ip_list);
    scfgmgr_set("dhcp_relay_ip", relay_str);
    system("rc relay restart > /dev/null 2>&1");
    
	return 0;
}

/*
 *  Function:  nfunc_ip_helper_ip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_helper_ip(struct users *u)
{
	struct in_addr i;
	int vlan, flag = 0;
	char ip_str[MAX_ARGV_LEN] = {'\0'};
    char line[256], list[3][64], relay_str[4096];	
	char *p, *p1, *ip, * ip_list = nvram_safe_get("dhcp_relay_ip");

	vlan = atoi(u->promptbuf+1);
//    fprintf(stderr, "[%s:%d] vlan %d\n", __FUNCTION__, __LINE__, vlan);

    ip = ip_list;
    memset(relay_str, '\0', sizeof(relay_str));
    //dhcp_relay_ip=1:192.168.1.1,2000::1:2345:6789:abcd;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        p1 = strchr(ip, ';'); 
        memcpy(line, ip, p1-ip);
       
        sscanf(line, "%[^:]:%[^,],%[^,],", list[0],list[1],list[2]); 
//        fprintf(stderr, "[%s:%d] vlan %s ipv4 %s ipv6 %s\n", __FUNCTION__, __LINE__,list[0],list[1],list[2]);
        
        if(atoi(list[0]) == vlan)  
        {    
            flag = 1;    
        }
        else
        {
            sprintf(ip_str, "%s%s;", ip_str, line);   
        }   
        ip = p1+1;   
    }

    if(flag == 0)
    {
        free(ip_list);
        vty_output("Warning: no the this configure in vlan %d, no change!\n", vlan); 
        return 0;
    }     

    free(ip_list);
    scfgmgr_set("dhcp_relay_ip", ip_str);
    system("rc relay restart > /dev/null 2>&1");
    
	return 0;
}

