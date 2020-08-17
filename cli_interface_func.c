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

#include "cli_interface_func.h"
#include "bcmutils.h"
/*wuchunli 2012-4-12 13:51:12*/
#include "if_info.h"

static char *_strlwr(char *string)
{
	uint8 i, len = 0;
	char *c = string;

	if(c != NULL)
		len = strlen(c);
	else
		return NULL;

	for(i=0; i<len; i++)
	{
		if(*c >= 'A' && *c <= 'Z')
			*c += 0x20;
		c ++;
	}

	return string;
}

static void cli_create_trunk_group(int group)
{
	int flag = 0, index;

	memset(&cur_trunk_conf, 0, sizeof(cli_trunk_conf));
	cli_nvram_conf_get(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

	for(index = 0; index < cur_trunk_conf.group_count; index++) {
		if(cur_trunk_conf.cur_trunk_list[index].group_no == group) {
			flag = 1;
			break;	
		}
	}

	if(0 == flag){
		cur_trunk_conf.cur_trunk_list[cur_trunk_conf.group_count].group_no = group;
		sprintf(cur_trunk_conf.cur_trunk_list[cur_trunk_conf.group_count].name, "Trunk-%d", group);
		cur_trunk_conf.group_count++;
		cli_nvram_conf_set(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
		syslog(LOG_NOTICE, "[CONFIG-5-NO]: Create the trunk group %d, %s\n", group, getenv("LOGIN_LOG_MESSAGE"));
	}

	cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
	return;
}

/* cli remove trunk group */
static int cli_remove_trunk_group(int group)
{
	int flag = 0, index = 0, portid, skfd;
	char *port_enable;

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
        return -1;

	memset(&cur_trunk_conf, 0, sizeof(cli_trunk_conf));
	cli_nvram_conf_get(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

	for(index = 0; index < cur_trunk_conf.group_count; index++) {
		if(cur_trunk_conf.cur_trunk_list[index].group_no == group) {

			port_enable = cli_nvram_safe_get(CLI_ALL_ONE, "port_enable");
			for(portid = 1; portid <= PNUM; portid++) {
				if( cur_trunk_conf.cur_trunk_list[index].port_int & (0x01ULL << phy[portid]) ) {
					set_port_disable(skfd, portid);
					*(port_enable+portid-1) = '0';
				}
			}
			nvram_set("port_enable", port_enable);
			free(port_enable);

			for(; index < cur_trunk_conf.group_count; index++)
				memcpy(&cur_trunk_conf.cur_trunk_list[index], &cur_trunk_conf.cur_trunk_list[index+1], sizeof(cli_trunk_list));

			cur_trunk_conf.group_count--;
			cli_nvram_conf_set(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
			cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
			
			/*send signal when process lacp enable forever,
	  		  change by jiangyaohui 20120118*/
#if 0
			if(cur_trunk_conf.group_count > 0) {
				SYSTEM("/usr/bin/killall lacp > /dev/null 2>&1 &");
				SYSTEM("/usr/sbin/lacp &");
			} else
				SYSTEM("/usr/bin/killall lacp > /dev/null 2>&1 &");
#endif
#if 1
			system("killall -SIGUSR2 lacp");
#endif
			syslog(LOG_NOTICE, "[CONFIG-5-NO]: Remove the trunk group %d, %s\n", group, getenv("LOGIN_LOG_MESSAGE"));
			close(skfd);
			return CLI_SUCCESS;
		}
	}

	cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
	close(skfd);

	if(0 == flag)
		return CLI_FAILED;
	
	return CLI_SUCCESS;
}

/*
 *  Function : cli_remove_pvid_port
 *  Purpose:
 *     restore remove pvid port just for cli_set_link_type use
 *  Parameters:
 *     portid  - Port ID (1 - PNUM)
 *     pvid    - PVID
 *  Returns:
 *     CLI_SUCCESS - Success
 *     CLI_FAILED  - Failure
 *
 *  Author  : eagles.zhou
 *  Date    :2011/2/14 (Valentine's Day ^_^)
 */
static void cli_remove_interface_vlan(int vlan)
{
    int len, vid, type, flag = 0;
	char intf[128], ipv4[32], ipv6[64];
	char *p1, *ip, *vlan_intf_str, *l3_ip = nvram_safe_get("lan_ipaddr");
	
	//l3_ip=1:0,192.168.1.1/24,2000::1:2345:6789:abcd/64;2:0,192.168.2.1/24,;4:0,,2001:db8:85a3:8a3:1319:8a2e:370:7344/64;
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

int func_if_port(struct users *u)
{
	int retval = -1;
	
	if(ISSET_CMD_MSKBIT(u, IF_FAST_PORT))
	{
		if((retval = change_con_level(IF_PORT_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "%s%d", _strlwr(u->s_param.v_range), u->s_param.v_int[0]);
		}
	}
	else if(ISSET_CMD_MSKBIT(u, IF_GIGA_PORT))
	{
		if((retval = change_con_level(IF_GPORT_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "%s%d", _strlwr(u->s_param.v_range), u->s_param.v_int[0]);
		}
	}
	else if(ISSET_CMD_MSKBIT(u, IF_XE_PORT))
	{
		if((retval = change_con_level(IF_GPORT_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "%s%d", _strlwr(u->s_param.v_range), u->s_param.v_int[0]);
		}
	}
	else
		DEBUG_MSG(1, "Can't get the type of the interface!!\n", NULL);

	return retval;
}

int func_if_range_port(struct users *u)
{
	int retval = -1;
	uint32_t con_level = 0;

	if(ISSET_CMD_MSKBIT(u, IF_FAST_PORT))
		con_level = IF_PORT_TREE;
	else if(ISSET_CMD_MSKBIT(u, IF_GIGA_PORT))
		con_level = IF_GPORT_TREE;
	else if(ISSET_CMD_MSKBIT(u, IF_XE_PORT))
		con_level = IF_XPORT_TREE;
	else
		DEBUG_MSG(1, "Can't get the type of the interface!!\n", NULL);
	
	if((retval = change_con_level(con_level, u)) == 0)
	{
		memset(u->promptbuf, '\0', sizeof(u->promptbuf));
		if(strpbrk(u->s_param.v_range, ",-") != NULL)
			sprintf(u->promptbuf, "%s", _strlwr(u->s_param.v_range));
		else
			sprintf(u->promptbuf, "%s,0", _strlwr(u->s_param.v_range));
	}

	return retval;
}

int func_if_trunk_port(struct users *u)
{
	int retval = -1, groupid = 0;

	cli_param_get_int(STATIC_PARAM, 0, &groupid, u);
	cli_create_trunk_group(groupid);

	if((retval = change_con_level(IF_TRUNK_TREE, u)) == 0)
	{
		memset(u->promptbuf, '\0', sizeof(u->promptbuf));
		sprintf(u->promptbuf, "%s%d", _strlwr(u->s_param.v_range), u->s_param.v_int[0]);
	}

	return retval;
}

int func_if_vlan(struct users *u)
{
	int retval = -1, vlanid = 0;
	char vlan_id[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_int(STATIC_PARAM, 0, &vlanid, u);
	sprintf(vlan_id, "%d", vlanid);
	
	/* Enter Vlan mode */
	/* Change console level */
	if((retval = change_con_level(IF_VLAN_TREE, u)) == 0)
	{
		memset(u->promptbuf, '\0', sizeof(u->promptbuf));
		sprintf(u->promptbuf, "%s%d", _strlwr(u->s_param.v_range), u->s_param.v_int[0]);
	}

	return retval;
}

int nfunc_if_trunk_port(struct users *u)
{
	int groupid = 0;
	
	cli_param_get_int(STATIC_PARAM, 0, &groupid, u);
	
	if( CLI_FAILED == cli_remove_trunk_group(groupid) ) {
		vty_output("  Port aggregator group %d doesn't exist\n", groupid);
		return -1;
	}

	return 0;
}

int nfunc_if_vlan(struct users *u)
{
	int vlanid = 0;

	cli_param_get_int(STATIC_PARAM, 0, &vlanid, u);
	
	cli_remove_interface_vlan(vlanid);

	return 0;
}

int func_if_lo(struct users *u)
{
	int retval = -1;
	char *p1, *ip, *lo_ip = nvram_safe_get("lo_ip");

	struct in_addr stc_para;
	struct in_addr dyn_papa;
	
	char old_ip_str[MAX_ARGV_LEN] = {'\0'};
	char cmd1[MAX_ARGV_LEN] = {'\0'};
	char cmd2[MAX_ARGV_LEN] = {'\0'};
	char ip_str[MAX_ARGV_LEN] = {'\0'};
	char ip_mask[MAX_ARGV_LEN] = {'\0'};
	vlan_interface_conf loopback_intf[128];
	char *lan_bipaddr, intf[128], loopback_intf_str[8196], lanip[32], oldlanip[32];
    int cnt = 0, flag = 0, i, skfd,	loopback_id, netmask;
	
    sscanf(u->linebuf, "%s %s %d %s %s", cmd1, cmd2, &loopback_id, ip_str,ip_mask);  
    memset(loopback_intf, '\0', sizeof(loopback_intf));
    memset(loopback_intf_str, '\0', sizeof(loopback_intf_str));

	netmask = get_mask_subnet(ip_mask);
	cli_debug_p("ip_str %s ip_mask %s netmask %d\n", ip_str, ip_mask, netmask);
	
    ip = lo_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        sscanf(intf, "%d,%[^/]/%d", &loopback_intf[cnt].vlanid, loopback_intf[cnt].ipaddr, &loopback_intf[cnt].netmask);

		//	Delete loopback address exited aleady
        if(loopback_id == loopback_intf[cnt].vlanid)
            flag = 1;  
        
        ip = p1+1; 
        cnt++;      
    } 
    
    memset(lanip, '\0', sizeof(lanip));  
    if(flag == 1)
    {
        for(i = 0; i < cnt; i++) 
    	{
    	    if(loopback_id != loopback_intf[i].vlanid)
                sprintf(loopback_intf_str, "%s%d,%s/%d;", loopback_intf_str, loopback_intf[i].vlanid, loopback_intf[i].ipaddr, loopback_intf[i].netmask);  
            else
            {
            	sprintf(old_ip_str,"%s",loopback_intf[i].ipaddr);
                sprintf(loopback_intf_str, "%s%d,%s/%d;", loopback_intf_str, loopback_id, ip_str, netmask); 
            }
        }
    }
    else
    {
        sprintf(loopback_intf_str, "%s%d,%s/%d;", lo_ip, loopback_id, ip_str, netmask); 
    }

    free(lo_ip);
    scfgmgr_set("lo_ip", loopback_intf_str);
    system("rc lo restart > /dev/null 2>&1");
    system("rc service restart > /dev/null 2>&1 &");

	return retval;
}

int nfunc_if_lo(struct users *u)
{
	int vlanid, vid, flag = 0; 
	char lanip[64], intf[128], ipaddr[64], loopstr[1024];
	char *p, *p1, *ip, *lo_ip = nvram_safe_get("lo_ip");

	cli_param_get_int(STATIC_PARAM, 0, &vlanid, u);
	
    ip = lo_ip;
    memset(loopstr, '\0', sizeof(loopstr));
        
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        memset(lanip, '\0', sizeof(lanip));
        memset(ipaddr, '\0', sizeof(ipaddr));
      
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);

        sscanf(intf, "%d,%s", &vid, lanip);
        
        if(vid == vlanid)
        {  
    		flag = 1;
    	}else
    	    sprintf(loopstr, "%s%s;", loopstr, intf);
    	    
        ip = p1+1;  
    } 
    free(lo_ip);
    
    if(1 == flag)
    {    
        scfgmgr_set("lo_ip", loopstr);
        system("rc lo restart > /dev/null 2>&1");
        system("rc service restart > /dev/null 2>&1 &");
    }else
    {
        vty_output("Warning: interface loopback %d is disabled on the devices\n", vlanid); 
    }    
    
	return 0;
}

