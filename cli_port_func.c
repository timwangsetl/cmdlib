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
#include "memutils.h"
#include "bcmutils.h"
#include "sk_define.h"
#include "../err_disable/err_disable.h"

static uint64_t cur_port_int = 0x0ULL;
static cli_rstp_conf cur_rstp_port[PNUM];


#define ARP_CONFIG_FILE "/tmp/arp_config"

/*
 *    struct dofun_cli
 *
 *    1.id --- distinguish between different command tree
 *    2.name --- command name
 *    3.desciption --- command desciption
 *    4.level --- the current level of the command tree
 *    5.type --- command type contain of "word, ip, mac..."
 *    6.elf --- the command is the last one or not
 *    7.mul_flag --- multi command used
 *    8.mul_cnt --- multi command count
 */
typedef struct dofun_cli_t{
	int  id;
    char *name;
    char *desciption;
    int  level;
    int  type;
    int  elf;
    int  min;
    int  max;
    int  mul_flag;
    int  mul_cnt;
}dofun_cli;

/* restore the remove vlan info */
typedef struct cli_remove_pvid_t{
	int pvid;
	uint64_t access_port_int;
	uint64_t hybrid_port_int;
	uint64_t trunk_port_int;
}cli_remove_pvid;

typedef struct cli_remove_vlan_t{
	int count;
	cli_remove_pvid remove_pvid[PNUM];
}cli_remove_vlan;

static cli_remove_vlan remove_vlan;

static int prase_port_map(struct users *u)
{
	char *port_str, *port_type;
	int group_no, index;
	if((port_str = u->promptbuf) == NULL)
		return CLI_FAILED;

	if(0 == strlen(port_str))
		return CLI_FAILED;

	if( (port_str != NULL )) {
		if('p' == *port_str) {
			group_no = atoi(port_str+1);
			memset(&cur_trunk_conf, 0, sizeof(cli_trunk_conf));
			cli_nvram_conf_get(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

			for(index = 0; index < cur_trunk_conf.group_count; index++) {
				if(cur_trunk_conf.cur_trunk_list[index].group_no == group_no) {
					cur_port_int = cur_trunk_conf.cur_trunk_list[index].port_int;

					cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
/* 					if(0x0ULL == cur_port_int)
 * 						return CLI_FAILED;
 * 					else
 */
					return CLI_SUCCESS;

				}
			}

			cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

			return CLI_FAILED;
		}
	}

	cli_str2bitmap(port_str, &cur_port_int);
	
	if(0x0ULL == cur_port_int)
		return CLI_FAILED;

	return CLI_SUCCESS;
}

/*---------------------------------------------------trunk_group--------------------------------------*/

static int start_trunking(void)
{
	int i = 0, skfd;
	char *trunk_enable;

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;

	trunk_enable = nvram_safe_get("h_aggregation_enable");
	if(*trunk_enable == '1') {
		SYSTEM("/usr/bin/killall lacp > /dev/null 2>&1"); 
	}

	nvram_set("h_aggregation_enable", "1");

	/* Start lacp application */
	SYSTEM("/usr/sbin/lacp");

	free(trunk_enable); 
	close(skfd);
	   
	return 0;
}

static int cli_set_trunk_group(int group, int mode, struct users *u)
{
	char *port_str = NULL;
	int portid, index, flag = 0, cur_group, count = 0;
	uint64_t port_int, cur_int;
	char *trunk_list = NULL, *dot1x_enable;
	//port_str = getenv("CON_MULTIPORT");
	port_str = u ->promptbuf;
	if(0 == strlen(port_str)) {
		return CLI_SUCCESS;
	}

	cli_str2bitmap(port_str, &port_int);

	/* check dot1x port config */
	dot1x_enable = nvram_safe_get("dot1x_enable");
	if(*dot1x_enable == '1') {
		memset(cur_dot1x_conf, 0, sizeof(cli_dot1x_conf)*PNUM);
		cli_nvram_conf_get(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
		for(portid = 1; portid <= PNUM; portid++) {
			if( port_int & (0x01ULL << phy[portid]) ){
				if(cur_dot1x_conf[portid-1].auth_mode != CLI_DOT1X_FAUTH) {
#if (XPORT==0)	
					printf("  Command rejected: %s0/%d is Dot1x enabled port!\n", (portid<=FNUM)?"FastEthernet":"GigaEthernet",(portid<=FNUM)?portid:(portid-FNUM));
#endif		
#if (XPORT==1)	
					printf("  Command rejected: %s0/%d is Dot1x enabled port!\n", (portid<=GNUM)?"GigaEthernet":"TenGigaEthernet",(portid<=GNUM)?portid:(portid-GNUM));
#endif		
					cli_nvram_conf_free(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
					free(dot1x_enable);
					return CLI_SUCCESS;
				}
			}
		}
	}
	free(dot1x_enable);

	/* check aggregator group exist */
	memset(&cur_trunk_conf, 0, sizeof(cli_trunk_conf));
	cli_nvram_conf_get(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

	for(index = 0; index < cur_trunk_conf.group_count; index++) {
		if(cur_trunk_conf.cur_trunk_list[index].group_no == group) {
			cur_group = index;
			flag = 1;
			break;
		}
	}

	if(1 == flag){
		cur_int = cur_trunk_conf.cur_trunk_list[cur_group].port_int | port_int;
		for(portid = 1; portid <= PNUM; portid++) {
			if( cur_int & (0x01ULL << phy[portid]) )
				count++;
		}
		if(count > 8) {
			printf("  The max member number of aggregation group is 8!\n");
			cli_nvram_conf_free(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
			return CLI_SUCCESS;
		}

		for(index = 0; index < cur_trunk_conf.group_count; index++) {
			if(cur_trunk_conf.cur_trunk_list[index].group_no == group) {
				cur_trunk_conf.cur_trunk_list[index].mode = mode;
				cur_trunk_conf.cur_trunk_list[index].key = group;
				cur_trunk_conf.cur_trunk_list[index].port_int |= port_int;
			} else {
				cur_trunk_conf.cur_trunk_list[index].port_int &= (~port_int);
			}
		}
		cli_nvram_conf_set(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
		cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
	} else {
		cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
		return CLI_FAILED;
	}

	/*send signal when process lacp enable forever,
	  change by jiangyaohui 20120118*/
	//start_trunking();
	system("rc trunk restart  > /dev/null 2>&1 &"); 

	return CLI_SUCCESS;
}


/* check interface if it is dot1x auto mode or dot1x force-unauthorized mode*/
static int cli_check_interface_dot1x(uint64 bmap)
{
	int i,mode;
//	int portid;
//	uint64_t val64;
	char *auth_config = cli_nvram_safe_get(CLI_DOT1X_CONFIG, "dot1x_config");
	/*2012/2/8 hualimin */
	char *dot1x_enable = nvram_safe_get("dot1x_enable");
	uint64_t port_int;
	char *p,*q;
	q = dot1x_enable;
	if(atoi(q) == 0)
	{
		free(dot1x_enable);
		free(auth_config);
		return 0;
	}
    port_int = bmap;
    p = auth_config;
    
	for(i = 1; i <= PNUM; i++) 
	{
	    mode = atoi(p);
	    
	    p = strchr(p, ';')+1;
	    
	    if(1 == mode)
	        continue;
	        
		if(port_int & (0x01ULL << phy[i]))
		{		    
		    return 1;
		}
	}
	free(dot1x_enable);
    free(auth_config);
	return 0;
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
static int cli_remove_pvid_port(int portid, int pvid)
{
	int i, flag = 0;

	for(i=0; i < remove_vlan.count; i++) {
		if(pvid == remove_vlan.remove_pvid[i].pvid) {
			remove_vlan.remove_pvid[i].access_port_int |= (0x1ULL<<phy[portid]);
			flag = 1;
		}
	}
	if(0 == flag) {
		remove_vlan.remove_pvid[remove_vlan.count].pvid = pvid;
		remove_vlan.remove_pvid[remove_vlan.count].access_port_int = (0x1ULL<<phy[portid]);
		remove_vlan.count++;
	}

	return CLI_SUCCESS;
}

static int cli_set_no_port_duplex(struct users *u, int duplex_type)
{
	int i;
    FILE *fp;
	uint64_t port_int;
	char *port_str, *duplex_str;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	duplex_str  = cli_nvram_safe_get(CLI_DUPLEX_ALL_AUTO, "port_duplex");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
			*(duplex_str+i-1) = PORT_DUPLEX_AUTO+'0';
		}
	}
	
	nvram_set("port_duplex", duplex_str);
	if((fp=fopen("/tmp/web_port_config", "w")) != NULL)
	{ 
		fprintf(fp, "%s\n", bit2str(port_int));		
		fclose(fp);
	}	
	
	system("rc port start  > /dev/null 2>&1 &");
	free(duplex_str);
	
	return 0;
}

/* cli set port protected */
static int cli_set_port_protected(struct users *u, int type)
{
	if( prase_port_map(u) == CLI_FAILED )
		 return 0;
	char *port_protect_config,*port_config;
	uint64_t port_int;
	uint64_t bmaps = 0x00ULL;
//	int i;
	int skfd,port;
	char tmp[12],buff[256];
	char *p1,*p2,*p3,*ptr_1,*ptr_2;
	port_protect_config = cli_nvram_safe_get(CLI_PROTECT_CONFIG,"port_protect_config");	

	port_int = cur_port_int;

	p1=port_protect_config;
	memset(buff, '\0', sizeof(buff));
	while((p2=strchr(p1, ';'))!=NULL)
	{
		p3=strchr(p1,',');
		if( port_int & (0x01ULL << phy[atoi(p1)])){
			memset(tmp, '\0', sizeof(tmp));
			strncpy(tmp,p1,p3-p1+1);
			strcat(tmp,"0;");
		}
		else
		{
			memset(tmp, '\0', sizeof(tmp));
			memcpy(tmp,p1,p2-p1+1);
		}
		strcat(buff,tmp);
		
		p1=p2+1;
	}
	nvram_set("port_protect_config", buff);
	free(port_protect_config);

 	port_config = nvram_safe_get("port_protect_config");
    ptr_1 =port_config;
    while(strlen(ptr_1))
    {
        ptr_2 = strchr(ptr_1, ',');
        ptr_2++;
        port = atoi(ptr_1);
        if((*ptr_2)== '1')
        bmaps |= 0x01ULL << phy[port];
        ptr_1 = strchr(ptr_1, ';');
        ptr_1++;
    }
    free(port_config);
    
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
		
	bcm_port_protect_set(skfd, &bmaps);	
	close(skfd); 
	return 0;  
}

static int cli_set_port_duplex(struct users *u, int duplex_type)
{
	int i;
    FILE *fp;
	uint64_t port_int;
	char *port_str, *duplex_str;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	duplex_str  = cli_nvram_safe_get(CLI_DUPLEX_ALL_AUTO, "port_duplex");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
			*(duplex_str+i-1) = duplex_type + '0';
		}
	}
	
	nvram_set("port_duplex", duplex_str);
	if((fp=fopen("/tmp/web_port_config", "w")) != NULL)
	{ 
		fprintf(fp, "%s\n", bit2str(port_int));		
		fclose(fp);
	}	
	
	system("rc port start  > /dev/null 2>&1 &");
	free(duplex_str);
	
	return 0;
}

static int cli_set_port_flow(struct users *u, int type)
{
	int i;
    FILE *fp;
	uint64_t port_int;
	char *port_str, *flow_str;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	flow_str  = cli_nvram_safe_get(CLI_ALL_ZERO, "port_flow");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
			*(flow_str+i-1) = type + '0';
		}
	}
	
	nvram_set("port_flow", flow_str);
	if((fp=fopen("/tmp/web_port_config", "w")) != NULL)
	{ 
		fprintf(fp, "%s\n", bit2str(port_int));		
		fclose(fp);
	}	
	
	system("rc port start  > /dev/null 2>&1 &");
	free(flow_str);
	
	return 0;
}

/*
 *  Function : cli_set_storm
 *  Purpose:
 *     set storm control
 *  Parameters:
 *     type  -  broadcast or multicast or unicast
 *     rate  -  rate limit value (0 means no limit)
 *  Returns:
 *     CLI_SUCCESS - Success
 *     CLI_FAILED  - Failure
 *
 *  Author  : eagles.zhou
 *  Date    :2011/11/21
 */
static int cli_set_storm(struct users *u, int type, int rate)
{
//	cli_set_gport(u);  
	int skfd, portid, result;
	char *port_str;
	uint64_t port_int;

	
//	port_str = getenv("CON_MULTIPORT");	
	port_str = u->promptbuf;

	if(0 == strlen(port_str)){
	  	return CLI_FAILED;
	}
	cli_str2bitmap(port_str, &port_int);

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;

	memset(cur_rate_storm, 0, sizeof(cli_rate_storm)*PNUM);
	cli_nvram_conf_get(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);

	for(portid = 1; portid<=PNUM; portid++) {
		if(port_int & (0x01ULL << phy[portid])) {
			switch(type) {
				/* broadcast */ 
				case 0:
					cur_rate_storm[portid-1].storm_bro = rate;
					result = bcm_set_broadcast_data(skfd, portid, cur_rate_storm[portid-1].storm_bro);
					break;

				/* multicast */
				case 1:
					cur_rate_storm[portid-1].storm_mul = rate;
					result = bcm_set_multicast_data(skfd, portid, cur_rate_storm[portid-1].storm_mul);
					break;

				/* unicast */
				case 2:
					cur_rate_storm[portid-1].storm_uni = rate;
					result = bcm_set_dlfunicast_data(skfd, portid, cur_rate_storm[portid-1].storm_uni);
					break;

				default:
					break;	
			}
		}
	}
	cli_nvram_conf_set(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);
	cli_nvram_conf_free(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);

	close(skfd);

	return CLI_SUCCESS;
}


/*
 *  Function : cli_set_trunk_param
 *  Purpose:
 *     set trunk vlan param (vlan-allowed, vlan-untagged)
 *  Parameters:
 *     type  - TRUNK Type (CLI_TRUNK)
 *  Returns:
 *     CLI_SUCCESS - Success
 *     CLI_FAILED  - Failure
 *
 *  Author  : eagles.zhou
 *  Date    :2011/2/14 (Valentine's Day ^_^)
 */
static int cli_set_trunk_param(struct users *u, int type, char *buf)
{
	char *port_str;
	uint64_t port_int;
	int portid, flag = 0;

    /* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
		return 0;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	if(1 != cli_param_int32_multi_format(buf, 1, VLAN_MAX_NUM, u))
    {
    	vty_output("Invalid vlan format, the vlan range is 1-%d, please reset!!\n", VLAN_MAX_NUM);
    	return 0;
    }
    	
	cli_str2bitmap(port_str, &port_int);
//	DEBUG("[%s:%d] port_int: 0x%08x%08x", __FUNCTION__, __LINE__, (uint32)(port_int >> 32), (uint32)port_int);
	
	memset(cur_port_conf, 0, sizeof(cli_port_conf)*PNUM);
	cli_nvram_conf_get(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);
	
	for(portid = 1; portid <= PNUM; portid++) 
	{
		if(port_int & (0x01ULL << portid)) 
		{
		    if(cur_port_conf[portid-1].mode == '1')
		    {    
        	    vty_output("Invalid vlan config, access ports don't support this config!!\n");
    			flag = 0;
        	    break;
        	}    
        	else
        	{
        	    switch(type) {
    				case CLI_TRUNK_ALLOWED:
    					/* trunk vlan-allowed */
    					if(strcmp(cur_port_conf[portid-1].allow, buf))
    					{    
    					    flag = 1;
        					free(cur_port_conf[portid-1].allow);
        					cur_port_conf[portid-1].allow = strdup(buf);
        				}
    					break;
    				case CLI_TRUNK_UNTAGGED:
    					/* trunk vlan-untagged */
    					if(strcmp(cur_port_conf[portid-1].untag, buf))
    					{
    					    flag = 1;
        					free(cur_port_conf[portid-1].untag);
        					cur_port_conf[portid-1].untag = strdup(buf);
        				}
    					break;
    				default:
    					break;
    			}
        	}
		}
	}
	
	if(1 == flag)
	{
	    cli_nvram_conf_set(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);  	
        system("killall -SIGUSR1 vlinkscan > /dev/null 2>&1");
    }
	cli_nvram_conf_free(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);
	
	return CLI_SUCCESS;
}

/*
 *  Function : cli_set_storm_disable
 *  Purpose:
 *     disable storm control
 *  Parameters:
 *     type  -  broadcast or multicast or unicast
 *  Returns:
 *     CLI_SUCCESS - Success
 *     CLI_FAILED  - Failure
 *
 *  Author  : eagles.zhou
 *  Date    :2011/11/21
 */
static int cli_set_storm_disable(struct users *u, int type)
{
		/* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
		return 0;
	int skfd, portid, enable, result;
	uint64_t port_int;

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
	
	port_int = cur_port_int;

	memset(cur_rate_storm, 0, sizeof(cli_rate_storm)*PNUM);
	cli_nvram_conf_get(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);

	for(portid = 1; portid<=PNUM; portid++) {
		if(port_int & (0x01ULL << phy[portid])) {
			switch(type) {
				/* broadcast */ 
				case 0:
					cur_rate_storm[portid-1].storm_bro = 0;
					result = bcm_set_broadcast_data(skfd, portid, cur_rate_storm[portid-1].storm_bro);
					break;

				/* multicast */
				case 1:
					cur_rate_storm[portid-1].storm_mul = 0;
					result = bcm_set_multicast_data(skfd, portid, cur_rate_storm[portid-1].storm_mul);
					break;

				/* unicast */
				case 2:
					cur_rate_storm[portid-1].storm_uni = 0;
					result = bcm_set_dlfunicast_data(skfd, portid, cur_rate_storm[portid-1].storm_uni);
					break;

				default:
					break;	
			}
		}
	}
	cli_nvram_conf_set(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);
	cli_nvram_conf_free(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);

	close(skfd);

	return CLI_SUCCESS;
}


static int cli_set_link_type(struct users *u, char type)
{
	int i, portid, skfd;
	char *port_str, *dot1x_enable, *link_type_config;
	uint64_t port_int;
	
    /* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
		return 0;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
    /* check dot1x port */
	if( '3' == type) {
		dot1x_enable = nvram_safe_get("dot1x_enable");
	    DEBUG("[%s:%d] dot1x_enable: %s", __FUNCTION__, __LINE__, dot1x_enable);
		if(*dot1x_enable == '1') {
			memset(cur_dot1x_conf, 0, sizeof(cli_dot1x_conf)*PNUM);
			cli_nvram_conf_get(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
			for(portid = 1; portid<=PNUM; portid++) {
				if( port_int & (0x01ULL << phy[portid]) ){
					if(cur_dot1x_conf[portid-1].auth_mode != CLI_DOT1X_FAUTH) {
						vty_output("  Command rejected: A port which is enabled for 802.1X can not be configured to \"trunk\" mode!\n");
						cli_nvram_conf_free(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
						free(dot1x_enable);
						return CLI_SUCCESS;
					}
				}
			}
			cli_nvram_conf_free(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
		}
		free(dot1x_enable);
	}
	
	cli_str2bitmap(port_str, &port_int);
    link_type_config = cli_nvram_safe_get(CLI_ALL_ONE, "vlan_link_type");
    
	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
			*(link_type_config+i-1) = type;
		}
	}
	
	nvram_set("vlan_link_type", link_type_config);
    system("killall -SIGUSR1 vlinkscan > /dev/null 2>&1");
	free(link_type_config);
	return CLI_SUCCESS;
}


static int cli_set_port_max_addr(struct users *u, char *num_str)
{
	if( prase_port_map(u) == CLI_FAILED )
		return 0;
    int i, skfd, portid;
    uint64_t port_int;
	char *mac, *buff, *p, *ptr;	
	char *port_str = NULL;
	int mac_adv_cfg[PNUM];

	port_str = u->promptbuf;
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
	mac = cli_nvram_safe_get(CLI_MAC_ADVANCED, "mac_advanced_config");	
	port_int = cur_port_int;
	
	if(cli_check_interface_dot1x(port_int))
	{
	    vty_output("  Interface can not be dot1x auto mode or force-unauthorized mode!\n");
	    free(mac);
		close(skfd);
	    return CLI_FAILED;
	}
	
	buff = malloc(strlen(mac) + 512);
	if(NULL == buff)
	{
		free(mac);
		close(skfd);
	    return CLI_FAILED;
	}
	memset(buff, '\0', strlen(mac) + 512);
	if (str_to_arr_i(mac, mac_adv_cfg, PNUM) == -1) {
		free(buff);
		free(mac);
		close(skfd);
		return CLI_FAILED;
	}

	for(i = 1; i <= PNUM; i++) {
		if(port_int & (0x01ULL <<  phy[i])) {
			mac_adv_cfg[i-1] = atoi(num_str);
			bcm_set_max_mac_num(skfd, i, atoi(num_str));
			bcm_auth_mode_set(skfd, i, 2); 
		}
	}

	arr_to_str_i(mac_adv_cfg, buff, ',', PNUM);
	scfgmgr_set("mac_advanced_config", buff);
	
	free(mac);
	free(buff);
	close(skfd);
	return CLI_SUCCESS;
}

static int cli_set_port_pvid(struct users *u, int port_vid)
{
	uint64_t port_int;
	int portid, skfd, vid[PNUM], flag = 0;
	char *p, *port_str, vid_str[4096];
    char *pvid_config;
	
    if( prase_port_map(u) == CLI_FAILED )
		return 0;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);

    pvid_config = nvram_safe_get("pvid_config");

    memset(vid, '\0', sizeof(vid));
    p = pvid_config;
	for(portid = 1; portid<=PNUM; portid++) 
	{
    	if(port_int & (0x01ULL << portid))
		{
		    vid[portid-1] = atoi(p);
		    
		    if(vid[portid-1] != port_vid)
		    {
		        flag = 1;
    			vid[portid-1] = port_vid;
    		}
		}else
		    vid[portid-1] = atoi(p);
		
		p = strchr(p, ',');
		p++;    
	}
	
	if(1 == flag)
	{
	    memset(vid_str, '\0', sizeof(vid_str));
    	for(portid = 1; portid<=PNUM; portid++) 
    	{
            sprintf(vid_str, "%s%d,", vid_str, vid[portid-1]);  
        }
        
        scfgmgr_set("pvid_config", vid_str);   	
        system("rc pvid start > /dev/null 2>&1");
        system("killall -SIGUSR1 vlinkscan > /dev/null 2>&1");
    }
    free(pvid_config);

	return CLI_SUCCESS;
}


static int cli_set_no_trunk_param(struct users *u, int type)
{
	uint64_t port_int;
	int portid, flag = 0;
	char *port_str = NULL;
	
    if( prase_port_map(u) == CLI_FAILED )
		return 0;

	port_str = u ->promptbuf;
	cli_str2bitmap(port_str, &port_int);
	memset(cur_port_conf, 0, sizeof(cli_port_conf)*PNUM);
	cli_nvram_conf_get(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);
	
	for(portid = 1; portid <= PNUM; portid++) 
	{
		if(port_int & (0x01ULL << portid)) 
		{
    	    switch(type) {
				case CLI_TRUNK_ALLOWED:
					/* trunk vlan-allowed */
					if(strlen(cur_port_conf[portid-1].allow) > 0)
					{    
					    flag = 1;
    					free(cur_port_conf[portid-1].allow);
    					cur_port_conf[portid-1].allow = strdup("");
    					cur_port_conf[portid-1].untag = strdup("");
    				}
					break;
				case CLI_TRUNK_UNTAGGED:
					/* trunk vlan-untagged */
					if(strlen(cur_port_conf[portid-1].untag) > 0)
					{    
					    flag = 1;
    					free(cur_port_conf[portid-1].untag);
    					cur_port_conf[portid-1].untag = strdup("");
    				}
					break;
				default:
					break;
			}
		}
	}
	
	if(1 == flag)
	{
	    cli_nvram_conf_set(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);  	
        system("killall -SIGUSR1 vlinkscan > /dev/null 2>&1");
    }
	cli_nvram_conf_free(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);
	
	return CLI_SUCCESS;
}

/*
 *	Function:  interface_stp
 *	Returns:
 *	
 *	Author:   peng.liu
 *	Date:	 2011/12/1
 */

/* cli set rstp config */
static int cli_set_rstp_config(struct users *u, int type, int value)
{
	int portid;
	char *port_str, *rstp_enable;
	uint64_t port_int;
	
//	port_str = getenv("CON_MULTIPORT");
	port_str = u->promptbuf;
//	port_str = port_str + 3;
	if(0 == strlen(port_str)) {
		return 0;
	}
	cli_str2bitmap(port_str, &port_int);

	memset(cur_rstp_port, 0, sizeof(cli_rstp_conf)*PNUM);
	cli_nvram_conf_get(CLI_RSTP_PORT, (unsigned char *)&cur_rstp_port);
	/*shanming.ren 2012-4-9 18:17:00*/
	char *link_type = cli_nvram_safe_get(CLI_ALL_ONE, "vlan_link_type");
	for(portid = 1; portid<=PNUM; portid++) {
		if( port_int & (0x01ULL << phy[portid]) ){
			switch(type) {
				case CLI_PORT_ENABLE:
					cur_rstp_port[portid-1].status = value;
					break;
					
				case CLI_PORT_COST:
					cur_rstp_port[portid-1].pathcost = value;
					break;
					
				case CLI_PORT_PRIORITY:
					cur_rstp_port[portid-1].priority = value;
					break;
					
				case CLI_PORT_P2P:
					cur_rstp_port[portid-1].p2p = value;
					break;
					
				case CLI_PORT_EDGE:
					/*shanming.ren 2012-4-9 18:10:44 begin*/
					if(*(link_type+portid-1) == '3')/* port is trunk mode*/
					{
						/*wuchunli 2012-4-19 14:01:19 begin*/
						vty_output("trunk port can't set to portfast\n");
						cli_nvram_conf_free(CLI_RSTP_PORT, (unsigned char *)&cur_rstp_port);
						/*wuchunli 2012-4-19 14:01:41 end*/
						free(link_type);
						return 0;
					}
					/*shanming.ren 2012-4-9 18:19:10 end*/
					cur_rstp_port[portid-1].edge = value;
					break;

				case CLI_PORT_BPDU_GUARD:
					cur_rstp_port[portid-1].bpdu_guard = value;
					break;

				case CLI_PORT_BPDU_FILTER:
					cur_rstp_port[portid-1].bpdu_filter = value;
					break;

				case CLI_PORT_GUARD:
					cur_rstp_port[portid-1].guard = value;
					break;
				
				default:
					break;
			}
		}
	}
	free(link_type);
	cli_nvram_conf_set(CLI_RSTP_PORT, (unsigned char *)&cur_rstp_port);
	cli_nvram_conf_free(CLI_RSTP_PORT, (unsigned char *)&cur_rstp_port);

	rstp_enable = nvram_safe_get("rstp_enable");
	if('1' == *rstp_enable)
		SYSTEM("/usr/bin/killall -SIGUSR2 rstp>/dev/null 2>&1");

	free(rstp_enable);
	return 0;
}


/* cli set rstp config */
static int cli_set_no_rstp_config(struct users *u, int type, int value)
{
	if( prase_port_map(u) == CLI_FAILED )
		return 0;
	int portid;
	char *rstp_enable;
	uint64_t port_int;
	
	port_int = cur_port_int;

	memset(cur_rstp_port, 0, sizeof(cli_rstp_conf)*PNUM);
	cli_nvram_conf_get(CLI_RSTP_PORT, (unsigned char *)&cur_rstp_port);

	for(portid = 1; portid<=PNUM; portid++) {
		if( port_int & (0x01ULL << phy[portid]) ){
			switch(type) {
				case CLI_PORT_ENABLE:
					cur_rstp_port[portid-1].status = value;
					break;
					
				case CLI_PORT_COST:
					cur_rstp_port[portid-1].pathcost = value;
					break;
					
				case CLI_PORT_PRIORITY:
					cur_rstp_port[portid-1].priority = value;
					break;
					
				case CLI_PORT_P2P:
					cur_rstp_port[portid-1].p2p = value;
					break;
					
				case CLI_PORT_EDGE:
					cur_rstp_port[portid-1].edge = value;
					break;

				case CLI_PORT_BPDU_GUARD:
					cur_rstp_port[portid-1].bpdu_guard = value;
					break;

				case CLI_PORT_BPDU_FILTER:
					cur_rstp_port[portid-1].bpdu_filter = value;
					break;
								
				default:
					break;
			}
		}
	}

	cli_nvram_conf_set(CLI_RSTP_PORT, (unsigned char *)&cur_rstp_port);
	cli_nvram_conf_free(CLI_RSTP_PORT, (unsigned char *)&cur_rstp_port);

	rstp_enable = nvram_safe_get("rstp_enable");
	if('1' == *rstp_enable)
		SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");

	free(rstp_enable);
	return 0;
}

static int cli_stop_qos_port(void)  
{
	int skfd, i;

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
		
	for(i = 0; i <= PNUM; i++)	   //include IMP port
	{
		set_qos_port_priority(skfd, i, 0);
	}
	
	close(skfd);	
	return 0;
}
/*-------------------------------dhcp limin.hua 2012.3.1----------------------------------------------*/
int func_inter_port_dhcp_filter(struct users *u)
{
	char *port_str,*filter_dhcp_port;
	int portid;
	uint64_t port_int,port_map;
	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	port_int = cur_port_int;
	cli_str2bitmap(port_str, &port_int);
   // set_cfp_enable(skfd, port_int, 1);
	
	filter_dhcp_port = cli_nvram_safe_get(CLI_ALL_ZERO, "filter_dhcp_port");

	for(portid = 1; portid<=PNUM; portid++)
	{
		if( port_int & (0x01ULL << phy[portid]) )
		{
			*(filter_dhcp_port+portid-1) = '1';
		}
	}
	scfgmgr_set("filter_dhcp_port", filter_dhcp_port);
	//scfgmgr_set("filter_dhcp_port", filter_dhcp_port);
	str2phy_64(filter_dhcp_port, &port_map);
//	drop_dhcp_packet_with_port(skfd,CFP_DROP_DHCP,port_map);
	free(filter_dhcp_port);
	syslog(LOG_NOTICE, "[CONFIG-5-DHCP]: Set the filter dhcp packet enable, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int nfunc_inter_port_dhcp_filter(struct users *u)
{
	if( prase_port_map(u) == CLI_FAILED )
		return 0;
	char *port_str,*filter_dhcp_port;
	int portid;
	uint64_t port_int,port_map;

	port_int = cur_port_int;
	port_str = u->promptbuf;
	cli_str2bitmap(port_str, &port_int);

	filter_dhcp_port = cli_nvram_safe_get(CLI_ALL_ZERO, "filter_dhcp_port");

	for(portid = 1; portid<=PNUM; portid++)
	{
		if( port_int & (0x01ULL << phy[portid]) )
		{
			*(filter_dhcp_port+portid-1) = '0';
		}
	}
	scfgmgr_set("filter_dhcp_port", filter_dhcp_port);
	str2phy_64(filter_dhcp_port, &port_map);

//	drop_dhcp_packet_with_port(skfd,CFP_DROP_DHCP,port_map);
	free(filter_dhcp_port);
	syslog(LOG_NOTICE, "[CONFIG-5-DHCP]: disable the filter dhcp packet  %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return 0;

}

static int cli_start_qos_port(void)
{
	int skfd, i,prio;
	char *qos_enable = NULL;
	char *qos_port_enable = NULL;	  
	char *qos_port_cfg = NULL;
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;

    qos_enable = nvram_safe_get("qos_enable");
	qos_port_enable = nvram_safe_get("qos_port_enable");	  
	qos_port_cfg = nvram_safe_get("qos_port_config");  //range 0-7

	if((*qos_enable == '1')&&(strlen(qos_port_cfg)==PNUM))
	{
		for(i = 0; i < PNUM; i++)
		{
			/* priority range 0-7 */
		  prio = *(qos_port_cfg + i) - '0';
		  set_qos_port_priority(skfd, i+1, prio);
		}
	}
	else
	{		 
		for(i = 0; i <= PNUM; i++)	  //include IMP port
		{
			set_qos_port_priority(skfd, i, 0);
		}
	}
		
	free(qos_enable);
	free(qos_port_enable);
	free(qos_port_cfg); 
	close(skfd);	
	return 0;
}

static int cli_set_no_port_policy(char * policy_name,char * port_str)
{
	int i, res, flag=0;
	char name[ACL_NAME_LEN+1], buff[1024];
	POLICY_CLASSIFY classify;
	char *port_policy, *p, *ptr;
	uint64 bmaps;
	
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	/* -1: not exist,  0: exist*/
	res = policy_set(policy_name, &classify, POLICY_NAME_CHECK, -1, 0x00ULL);
		
	/* ip standard acl name is not exist */
	if(res)
	{
		vty_output("policy-map %s does not exist\n", policy_name);
		return -1;
	}
	
	port_policy = cli_nvram_safe_get(CLI_PORT_POLICY, "port_policy");	
	cli_str2bitmap(port_str, &bmaps);

	memset(buff, '\0', 1024);
	p = port_policy;
	
	for(i = 1; i <= PNUM; i++)
	{
		memset(name, '\0', ACL_NAME_LEN+1);
		ptr = strchr(p, ',');
		strncpy(name, p, ptr-p);
		if((bmaps>>phy[i]) & 0x01ULL)
		{
			if(0 == strcmp(name, policy_name))
			{
				/* standard, delete port from acl table struct */
				if(strlen(name))
				{
					policy_set(name, &classify, POLICY_PORT_DEL, -1, (0x01ULL<<phy[i]));
					flag = 1;
				}
								
				strcat(buff, ",");
			}
			else
			{
#if (XPORT==0)	
				if(i <= FNUM)
					vty_output("policy-map %s not be applied to interface FastEthernet 0/%d\n", policy_name, i);
				else
					vty_output("policy-map %s not be applied to interface GigaEthernet 0/%d\n", policy_name, (i-FNUM));
#endif		
#if (XPORT==1)	
				if(i <= GNUM)
					vty_output("policy-map %s not be applied to interface GigaEthernet 0/%d\n", policy_name, i);
				else
					vty_output("policy-map %s not be applied to interface TenGigaEthernet 0/%d\n", policy_name, (i-GNUM));
#endif		
				strcat(buff, name); 			
				strcat(buff, ",");
			}
		}
		else
		{
			strcat(buff, name); 			
			strcat(buff, ",");
		}
				
		p = ptr+1;
	}
	
	if(flag)
		policy_set(policy_name, &classify, POLICY_WRITE_REGS, -1, 0x00ULL);
	
	scfgmgr_set("port_policy", buff);	
	free(port_policy);
	syslog(LOG_NOTICE, "[CONFIG-5-POLICYMAP]: clear the port policy map %s, %s\n",policy_name, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}


int func_interface_trunk_mode_lacp(struct users *u)
{
	int port = 0;
	char agg_group[MAX_ARGV_LEN] = {"\0"};
	cli_param_get_int(STATIC_PARAM, 0, &port, u);
	sprintf(agg_group,"%d",port);
	if( CLI_FAILED == cli_set_trunk_group(port, 3, u) )
		vty_output("  Port aggregator group %s doesn't exist, please create it first\n", agg_group);
}

int func_interface_trunk_mode_static(struct users *u)
{
	int port = 0;
	char agg_group[MAX_ARGV_LEN] = {"\0"};
	cli_param_get_int(STATIC_PARAM, 0, &port, u);
	sprintf(agg_group,"%d",port);
	if( CLI_FAILED == cli_set_trunk_group(port, 1, u) )
		vty_output("  Port aggregator group %s doesn't exist, please create it first\n", agg_group);

}


int nfunc_remove_trunk_interface(struct users *u)
{
	if( prase_port_map(u) == CLI_FAILED )
		return 0;
		
	int index;
	int flag = 0, cur_group, cur_mode, cur_key;
	uint64_t port_int;

	port_int = cur_port_int;

	/* check aggregator group exist */
	memset(&cur_trunk_conf, 0, sizeof(cli_trunk_conf));
	cli_nvram_conf_get(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

	for(index = 0; index < cur_trunk_conf.group_count; index++) {
		cur_trunk_conf.cur_trunk_list[index].port_int &= (~port_int);
	}

	cli_nvram_conf_set(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
	cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

	/*send signal when process lacp enable forever,
	  change by jiangyaohui 20120118*/
	//start_trunking();
	system("killall -SIGUSR2 lacp");
	return CLI_SUCCESS;
}

//----------------------------interface arp ---------------------------
int func_if_arp_inspection(struct users *u)
{
	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}

int nfunc_if_arp_inspection(struct users *u)
{
	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}

//----------------------------interface cos---------------------------

int func_cos_default(struct users *u)
{
	int portid;
	uint64_t port_int;
	char *port_str;
	int buffer = 0;
	cli_param_get_int(DYNAMIC_PARAM, 0, &buffer, u);
	char buffer_str[MAX_ARGV_LEN];
	sprintf(buffer_str, "%d", buffer);
	//	int flag = buffer[0];
	char *port_cfg = NULL;
	//	port_str = getenv("CON_MULTIPORT");
	port_str = u ->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}

	cli_str2bitmap(port_str, &port_int);
	port_cfg = cli_nvram_safe_get(CLI_ALL_ZERO, "qos_port_config");

	for(portid = 1; portid<=PNUM; portid++)
	{
		if( port_int & (0x01ULL << phy[portid]) )
		{
			*(port_cfg+portid-1) = *buffer_str;
		}
	}

	//scfgmgr_set("qos_port_enable", "1");
	 scfgmgr_set("qos_port_config", port_cfg);

	cli_stop_qos_port();
	cli_start_qos_port();

	free(port_cfg);
	syslog(LOG_NOTICE, "[CONFIG-5-INTCOS]: Enabled QOS and set COS value to %d, %s\n", buffer, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int nfunc_inter_cos_default(struct users *u)
{	
	
	if( prase_port_map(u) == CLI_FAILED )
		return 0;

	int portid;
	uint64_t port_int;
	char *port_cfg = cli_nvram_safe_get(CLI_ALL_ZERO, "qos_port_config");

	port_int = cur_port_int;

	for(portid = 1; portid<=PNUM; portid++)
	{
		if( port_int & (0x01ULL << phy[portid]) )
		{
			*(port_cfg+portid-1) = '0';
		}
	}

	//scfgmgr_set("qos_port_enable", "1");
	scfgmgr_set("qos_port_config", port_cfg);

	cli_stop_qos_port();
	cli_start_qos_port();

	free(port_cfg);

	return CLI_SUCCESS;
}

//----------------------------interface description ---------------------------

int func_inter_port_description_line(struct users *u)
{
	/* Get the description of port */
	int buffer = 0;
	char *line = NULL, desc[CMDLINE_SIZE] = {'\0'};
	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);
	line = buffer;
	memcpy(desc, line, strlen(line));

	if(strlen(desc) > 128) {
		vty_output("Max length of the description is 128\n");
		return 0;
	}
	
 	/* Get port env */
	uint64_t port_int = 0x0ULL;
	char *port_str = NULL;
	port_str = u->promptbuf;
	if(0 == strlen(port_str)){
	  return -1;
	}
	cli_str2bitmap(port_str, &port_int);

	/* nvram get */
	char *port_description = NULL, *port_description_t = NULL;
	port_description = cli_nvram_safe_get(CLI_ALL_DES, "port_description");

	int portid = 1;
	char *p = NULL, *p1 = NULL, *p2 = NULL;
	p2 = p1 = p = port_description;
	while((p1=strchr(p,';')) != NULL)
  	{
  		if(port_int & (0x01ULL<<phy[portid])) {
			port_description_t = port_description;
			port_description_t = (char *)calloc((strlen(port_description_t)+CMDLINE_SIZE), sizeof(char));
			memcpy(port_description_t, port_description, (p-port_description));
			sprintf(port_description_t, "%s%s", port_description_t, desc);
			p2 = port_description_t + strlen(port_description_t);
			sprintf(port_description_t, "%s%s", port_description_t, p1);
			p1 = p2;
			free(port_description);
			port_description = port_description_t;
  		}
  		portid++;
  		p=p1+1;
  	}
  	syslog(LOG_NOTICE, "[CONFIG-5-INTDESCRIPTION]: The port %s's description is %s, %s\n", 
		port_str, desc, getenv("LOGIN_LOG_MESSAGE"));
  	scfgmgr_set("port_description", port_description);
	free(port_description);

  	return 0;
}

/* 
 * add by gujiajie for trunk description
 */
int func_inter_port_trunk_description_line(struct users *u)
{
	char tmp[2048] = {'\0'};
	char *port_str;
	char *port_description;
	uint64_t port_int;
	char *p ,*p1;
	int portid;
	int line;
	size_t i;
	char ch;

	memset(tmp,'\0',sizeof(tmp));
	cli_param_get_int(STATIC_PARAM, 0, &line, u);
	
 	port_description = cli_nvram_safe_get(CLI_ALL_DES, "agg_port_description");	
	port_str = u->promptbuf;
	if(0 == strlen(port_str)){
		return CLI_FAILED;
	}
	p = port_description;
	for (i = 0; i <(port_str[1] - '1'); p1 = strchr(p, ';'), p = p1 + 1, i++) 
		;
	
	ch = *p;
	*p = '\0';
	memcpy(tmp, port_description, strlen(port_description));
	strcat(tmp, (char *)line);
	if (ch == ';') {
		*p = ';';
	} else {
		p++;
		p = strchr(p, ';');
	}
	strcat(tmp, p);
  	scfgmgr_set("agg_port_description", tmp);
  	syslog(LOG_NOTICE, "[CONFIG-5-INTDESCRIPTION]: The port-aggregator %c's description is %s, %s\n", 
		port_str[1], (char *)line, getenv("LOGIN_LOG_MESSAGE"));
  	free(port_description);
  	return 0;
}


int nfunc_inter_port_description(struct users *u)
{
	uint64_t port_int;
	char *tmp = NULL, tmp1[256];
	char *port_description;
	char *p ,*p1;
	int portid;

	/* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
		return 0;

	port_description = cli_nvram_safe_get(CLI_ALL_DES, "port_description");
	tmp = (char *)malloc((strlen(port_description) + 1));
    memset(tmp, '\0', strlen(port_description) + 1);

	port_int = cur_port_int;
	p = port_description;
	for(portid = 1; portid <= PNUM; portid++)
  	{
  		memset(tmp1,'\0',sizeof(tmp1));
  	    p1 = strchr(p, ';');
  		if(port_int&(0x01ULL <<portid)){
  			sprintf(tmp1,";");
  		} else {
		    strncpy(tmp1,p,p1-p+1);
  		}	    
  		strcat(tmp, tmp1);
  		p=p1+1; 	
  	}	
  	
  	scfgmgr_set("port_description", tmp);
  	syslog(LOG_NOTICE, "[CONFIG-5-INTDESCRIPTION]: NO description, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	free(port_description);	
	free(tmp);
	
  	return 0;
}

/* 
 * add by gujiajie for no trunk description
 */
int nfunc_inter_port_trunk_description(struct users *u)
{
	char tmp[2048] = {'\0'}, tmp1[CMDLINE_SIZE] = {'\0'};
	char *port_str;
	char *port_description;
	uint64_t port_int;
	char *p ,*p1;
	int portid;
	int buffer = 0;
	char *line;
	size_t i;
	char ch;
	memset(tmp,'\0',sizeof(tmp));
	
	port_str = u->promptbuf;
	if(0 == strlen(port_str)){
	  return CLI_FAILED;
	}

 	port_description = cli_nvram_safe_get(CLI_ALL_DES, "agg_port_description");	
	p = port_description;
	for (i = 0; i < (port_str[1] - '1'); p1 = strchr(p, ';'), p = p1 + 1, i++) 
		;
	
	ch = *p;
	*p = '\0';
	memcpy(tmp, port_description, strlen(port_description));
	strcat(tmp, "");
	if (ch == ';') {
		*p = ';';
	} else {
		p++;
		p = strchr(p, ';');
	}
	strcat(tmp, p);
  	scfgmgr_set("agg_port_description", tmp);
  	syslog(LOG_NOTICE, "[CONFIG-5-INTDESCRIPTION]: NO port-aggregator %c's description, %s\n", 
		port_str[1], getenv("LOGIN_LOG_MESSAGE"));
  	free(port_description);
  	return 0;
}


//set mac learning enable/disable
static int cli_set_learning_ability(struct users *u, char *learn)
{
	if( prase_port_map(u) == CLI_FAILED )
		return 0;

    int skfd, portid;
    uint64_t port_int, learn_maps = 0x00ULL;
    char *port_learn;
    
    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
      return -1;

	port_int = cur_port_int;
    port_learn = cli_nvram_safe_get(CLI_ALL_ONE, "port_learn");

	for(portid = 1; portid<=PNUM; portid++)
	{
	    if( port_int & (0x01ULL << phy[portid]) )
	        *(port_learn+portid-1) = *learn;
	        
	    if(*(port_learn+portid-1) != '1')
	        learn_maps |= (0x01ULL << phy[portid]);
	}

    scfgmgr_set("port_learn", port_learn);

    //set port learning disable
    set_port_learn_disable(skfd, learn_maps);

    //clear mac for ports that are static ports
    for(portid = 0; portid < PNUM; portid++)
	{
        if(*(port_learn+portid) == '0')
            bcm_l2_addr_delete_by_port(skfd, 0, portid+1);
    }

    free(port_learn);
    close(skfd);   
    return CLI_SUCCESS;  
}

int nfunc_duplex(struct users *u)
{
    cli_set_no_port_duplex(u, PORT_DUPLEX_AUTO);
  	return 0;
}

int func_duplex_auto(struct users *u)
{
  	cli_set_port_duplex(u, PORT_DUPLEX_AUTO);
 	return 0;
}

int func_duplex_full(struct users *u)
{
  	cli_set_port_duplex(u, PORT_DUPLEX_FULL);
  	return 0;
}

int func_duplex_half(struct users *u)
{
  	cli_set_port_duplex(u, PORT_DUPLEX_HALF);
  	return 0;
}

int func_flo_con_on(struct users *u)
{
  	cli_set_port_flow(u, 1);
	syslog(LOG_NOTICE, "[CONFIG-5-INTFLOWCONTROL]: Set interface flow-control on, %s\n", getenv("LOGIN_LOG_MESSAGE"));
 	return 0;
}

int func_flo_con_off(struct users *u)
{
  	cli_set_port_flow(u, 0);
	syslog(LOG_NOTICE, "[CONFIG-5-INTFLOWCONTROL]: Set interface flow-control off, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return 0;
}

int nfunc_ip_acc_grp(struct users *u)
{
	/* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
		return 0;

	int i, res, flag=0;
	char name[ACL_NAME_LEN+1], buff[1024];
	IP_STANDARD_ACL_ENTRY entry1;
	IP_EXTENDED_ACL_ENTRY entry2;
	POLICY_CLASSIFY classify;
	char buffer[MAX_ARGV_LEN] = {'\0'};
    cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);
	char *port_acl, *p, *ptr;
	uint64 bmaps;
	
	memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	
	/* check if acl name is exist */
	res = ip_std_acl_set(buffer, &entry1, ACL_NAME_CHECK, -1, 0x00ULL);
	/* ip standard acl name is not exist */ 
	if(res)
	{
		
		/* following is for extended  */
		res = ip_ext_acl_set(buffer, &entry2, ACL_NAME_CHECK, -1, 0x00ULL);
		/* ip extended acl name is not exist */
		if(res)
		{
		//	vty_output("extended access-group %s not exist\n", acl_name);  //test
			vty_output("access-group %s not exist\n", buffer);
			return -1;
		}
		else
			flag = 1;	/* extended */
	}
		
	port_acl  = cli_nvram_safe_get(CLI_PORT_ACL, "port_ip_acl");	

	bmaps = cur_port_int;
	
	//memset(buff, '\0', strlen(port_acl));
	memset(buff, '\0', 1024);
	p = port_acl;
	for(i = 1; i <= PNUM; i++)
	{
		memset(name, '\0', ACL_NAME_LEN+1);
		ptr = strchr(p, ',');
		strncpy(name, p, ptr-p);
					
		if((bmaps >> phy[i]) & 0x01ULL)
		{
			if(0 == strcmp(name, buffer))
			{
				/* standard, delete port from acl table struct */
				if((strlen(name)) && (flag==0))
					ip_std_acl_set(name, &entry1, ACL_PORT_DEL, -1, (0x01ULL<<phy[i]));
				
				/* extended, delete port from acl table struct */
				if((strlen(name)) && (flag==1))
					ip_ext_acl_set(name, &entry2, ACL_PORT_DEL, -1, (0x01ULL<<phy[i]));
				
				strcat(buff, ",");
			}
			else
			{
#if (XPORT==0)	
				if(i <= FNUM)
					vty_output("ip access-group %s not be applied to interface FastEthernet 0/%d\n", buffer, i);
				else
					vty_output("ip access-group %s not be applied to interface GigaEthernet 0/%d\n", buffer, (i-FNUM));
#endif		
#if (XPORT==1)
				if(i <= GNUM)
					vty_output("ip access-group %s not be applied to interface GigaEthernet 0/%d\n", buffer, i);
				else
					vty_output("ip access-group %s not be applied to interface TenGigaEthernet 0/%d\n", buffer, (i-GNUM));
#endif		
				strcat(buff, name);				
				strcat(buff, ",");
			}
		}
		else
		{
			strcat(buff, name);				
			strcat(buff, ",");
		}
		
		p = ptr+1;		
	}
		
	/* standard, write regs */
	if(flag == 0)
		ip_std_acl_set(buffer, &entry1, ACL_WRITE_REGS, -1, 0x00ULL);
	/* extended, write regs */
	else
		ip_ext_acl_set(buffer, &entry2, ACL_WRITE_REGS, -1, 0x00ULL);

	/* write policy */
	policy_set("", &classify, POLICY_WRITE_REGS, -1, 0x00ULL);
	
	scfgmgr_set("port_ip_acl", buff);
	
	free(port_acl);
	return 0;
}


int func_inter_qos_policy_ingress(struct users *u)
{
	int i, res, flag=0;
	uint64_t bmaps;
	char buffer[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);
	char name[ACL_NAME_LEN+1], buff[1024];
	char *port_str, *port_policy, *p, *ptr;
	POLICY_CLASSIFY classify;
	
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	
	/* -1: not exist,  0: exist*/
	res = policy_set(buffer, &classify, POLICY_NAME_CHECK, -1, 0x00ULL);
		
	/* ip standard acl name is not exist */
	if(res)
	{
		vty_output("policy-map %s does not exist\n", buffer);
		return -1;
	}
	port_policy  = cli_nvram_safe_get(CLI_PORT_POLICY, "port_policy");	
//	port_str = getenv("CON_MULTIPORT"); 
	port_str = u ->promptbuf;
	cli_str2bitmap(port_str, &bmaps);
	
	memset(buff, '\0', 1024);
	p = port_policy;
	
	for(i = 1; i <= PNUM; i++)
	{
		memset(name, '\0', ACL_NAME_LEN+1);
		ptr = strchr(p, ',');
		strncpy(name, p, ptr-p);
		
		if((bmaps>>phy[i]) & 0x01ULL)
		{
			if(strcmp(name, buffer))
			{
				if(strlen(name))
					policy_set(name, &classify, POLICY_PORT_DEL, -1, (0x01ULL<<phy[i]));	
				policy_set(buffer, &classify, POLICY_PORT_ADD, -1, (0x01ULL<<phy[i]));	
				flag = 1;								
			}		
			strcat(buff, buffer);
			strcat(buff, ",");	
		}
		else
		{
			strcat(buff, name); 			
			strcat(buff, ",");
		}	
		p = ptr+1;
	}
	if(flag)
	{
		policy_set(buffer, &classify, POLICY_WRITE_REGS, -1, 0x00ULL);
	}
	
	scfgmgr_set("port_policy", buff);
	
	free(port_policy);
	syslog(LOG_NOTICE, "[CONFIG-5-INTQOS]: Config the port policy map %s ingress, %s\n",buffer, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}


int nfunc_inter_qos_policy(struct users *u)
{
	char buffer[MAX_ARGV_LEN] = {'\0'};
	char *port_str;
	cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);
	port_str = u ->promptbuf;
	cli_set_no_port_policy(buffer,port_str);
	return 0;
}


/*
 *  Function : cli_set_no_rate_limit
 *  Purpose:
 *     disable rate limit
 *  Parameters:
 *     type  -  ingress or egress
 *  Returns:
 *     CLI_SUCCESS - Success
 *     CLI_FAILED  - Failure
 *
 *  Author  : eagles.zhou
 *  Date    :2011/11/21
 */
static int cli_set_no_rate_limit(struct users *u, int type)
{
	if( prase_port_map(u) == CLI_FAILED )
		return 0;

	int skfd, portid, enable, result;
	uint64_t port_int;
	char buff[512], *in, *out;

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
	
	memset(buff, '\0', sizeof(buff));
    for(portid = 1; portid <= PNUM; portid++)
    	strcat(buff, ",");
    	
	port_int = cur_port_int;

	memset(cur_rate_storm, 0, sizeof(cli_rate_storm)*PNUM);
	cli_nvram_conf_get(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);

	for(portid = 1; portid<=PNUM; portid++) {
		if(port_int & (0x01ULL << phy[portid])) {
			switch(type) {
				/* ingress */ 
				case 0:
					cur_rate_storm[portid-1].rate_igr = 0;
					result = bcm_rate_bandwidth_ingress_set(skfd, portid, cur_rate_storm[portid-1].rate_igr, 64);
					break;

				/* egress */
				case 1:
					cur_rate_storm[portid-1].rate_egr = 0;
					result = bcm_rate_bandwidth_egress_set(skfd, portid, cur_rate_storm[portid-1].rate_egr, 64);
					break;

				default:
					break;	
			}
		}
	}
	cli_nvram_conf_set(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);
	cli_nvram_conf_free(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);

	in = cli_nvram_safe_get(CLI_COMMA, "rate_ingress");
	out = cli_nvram_safe_get(CLI_COMMA, "rate_egress"); 
	
	if(!strcmp(in, buff) && !strcmp(out, buff))
	    scfgmgr_set("rate_enable", "0");
	else    
	    scfgmgr_set("rate_enable", "1");
	    
	free(in);
	free(out);
	close(skfd);

	return CLI_SUCCESS;
}

/*
 *  Function : cli_set_rate_limit
 *  Purpose:
 *     set rate limit
 *  Parameters:
 *     type  -  ingress or egress
 *     rate  -  rate limit value
 *  Returns:
 *     CLI_SUCCESS - Success
 *     CLI_FAILED  - Failure
 *
 *  Author  : eagles.zhou
 *  Date    :2011/11/21
 */
static int cli_set_rate_limit(struct users *u, int type, int rate)
{
	if( prase_port_map(u) == CLI_FAILED )
		return 0;

	int skfd, portid, result;
	uint64_t port_int;
	char buff[512], *in, *out;

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
	
	memset(buff, '\0', sizeof(buff));
    for(portid = 1; portid <= PNUM; portid++)
    	strcat(buff, ",");
		
	port_int = cur_port_int;

	memset(cur_rate_storm, 0, sizeof(cli_rate_storm)*PNUM);
	cli_nvram_conf_get(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);

	for(portid = 1; portid<=PNUM; portid++) {
		if(port_int & (0x01ULL << phy[portid])) {
			switch(type) {
				/* ingress */ 
				case 0:
					cur_rate_storm[portid-1].rate_igr = rate;
					result = bcm_rate_bandwidth_ingress_set(skfd, portid, cur_rate_storm[portid-1].rate_igr, 64);
					break;

				/* egress */
				case 1:
					cur_rate_storm[portid-1].rate_egr = rate;
					result = bcm_rate_bandwidth_egress_set(skfd, portid, cur_rate_storm[portid-1].rate_egr, 64);
					break;

				default:
					break;	
			}
		}
	}
	cli_nvram_conf_set(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);
	cli_nvram_conf_free(CLI_RATE_STORM, (unsigned char *)&cur_rate_storm);
	
	in = cli_nvram_safe_get(CLI_COMMA, "rate_ingress");
	out = cli_nvram_safe_get(CLI_COMMA, "rate_egress"); 
	
	if(!strcmp(in, buff) && !strcmp(out, buff))
	    scfgmgr_set("rate_enable", "0");
	else    
	    scfgmgr_set("rate_enable", "1");
	    
	free(in);
	free(out);
	close(skfd);

	return CLI_SUCCESS;
}

int func_ip_acc_grp(struct users *u)
{
	int i, res, flag=0;  /* flag=0: ip standard acl,  flag=1: ip extended acl */
	uint64_t bmaps;
	
	char buffer[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);
	
	char name[ACL_NAME_LEN+1], buff[1024], temp[PNUM + 1];
	char *port_str, *port_ip_acl, *port_mac_acl, *p, *ptr;
	IP_STANDARD_ACL_ENTRY entry1;
	IP_EXTENDED_ACL_ENTRY entry2;
	
	memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
	
	res = ip_std_acl_set(buffer, &entry1, ACL_NAME_CHECK, -1, 0x00ULL);
	/* ip standard acl name is not exist */
	if(res)
	{
		/* following is for extended  */
		res = ip_ext_acl_set(buffer, &entry2, ACL_NAME_CHECK, -1, 0x00ULL);
		/* ip extended acl name is not exist */
		if(res)
		{
			vty_output("access-group %s not exist\n", buffer);
			return -1;
		}
		else
			flag = 1;	/* extended */	
	}
	else
		flag = 0;  /* standard */

	
	port_ip_acl  = cli_nvram_safe_get(CLI_PORT_ACL, "port_ip_acl");	
	port_mac_acl = cli_nvram_safe_get(CLI_PORT_ACL, "port_mac_acl");	
//	port_str = getenv("CON_MULTIPORT");
	port_str = u->promptbuf;
  	cli_str2bitmap(port_str, &bmaps);
    
    /* check if port use mac acl */
    p = port_mac_acl;
    for(i = 1; i <= PNUM; i++)
    {
    	ptr = strchr(p, ',');
    	if(p != ptr)
    		temp[i] = '1';
    	else
    		temp[i] = '0';
    	p = ptr + 1;
    }
    	
	memset(buff, '\0', 1024);
	p = port_ip_acl;
	for(i = 1; i <= PNUM; i++)
	{
		memset(name, '\0', ACL_NAME_LEN+1);
		ptr = strchr(p, ',');
		strncpy(name, p, ptr-p);
		
		if((bmaps>>phy[i]) & 0x01ULL)
		{
			if((strcmp(name, buffer)) && (temp[i] == '0'))
			{
				/* standard, delete port from acl table struct */
				if((strlen(name)) && (flag==0))
					ip_std_acl_set(name, &entry1, ACL_PORT_DEL, -1, (0x01ULL<<phy[i]));
				
				/* extended, delete port from acl table struct */
				if((strlen(name)) && (flag==1))
					ip_ext_acl_set(name, &entry2, ACL_PORT_DEL, -1, (0x01ULL<<phy[i]));
				
				/* standard, add port yo acl table struct */	
				if(flag == 0)
					ip_std_acl_set(buffer, &entry1, ACL_PORT_ADD, -1, (0x01ULL<<phy[i]));
				/* extended, add port yo acl table struct */
				else
					ip_ext_acl_set(buffer, &entry2, ACL_PORT_ADD, -1, (0x01ULL<<phy[i]));
					
				strcat(buff, buffer);
				strcat(buff, ",");													
			}
			else if((strcmp(name, buffer)) && (temp[i] == '1'))
			{
#if (XPORT==0)	
				if(i <= FNUM)
					vty_output("ip access-group failed on interface FastEthernet 0/%d\n", i);	
				else
					vty_output("ip access-group failed on interface GigaEthernet 0/%d\n", (i-FNUM));
#endif		
#if (XPORT==1)		
				if(i <= GNUM)
					vty_output("ip access-group failed on interface GigaEthernet 0/%d\n", i);	
				else
					vty_output("ip access-group failed on interface TenGigaEthernet 0/%d\n", (i-GNUM));
#endif		
				strcat(buff, name);				
				strcat(buff, ",");
			}
			else
			{
				strcat(buff, buffer);
				strcat(buff, ",");	
			}
			
		}
		else
		{							
			strcat(buff, name);				
			strcat(buff, ",");
		}
		
		p = ptr+1;
	}
	
	/* standard, write regs */
	if(flag == 0)
		ip_std_acl_set(buffer, &entry1, ACL_WRITE_REGS, -1, 0x00ULL);
	/* extended, write regs */
	else
		ip_ext_acl_set(buffer, &entry2, ACL_WRITE_REGS, -1, 0x00ULL);
	
	scfgmgr_set("port_ip_acl", buff);
			
	free(port_ip_acl);
	free(port_mac_acl);
	syslog(LOG_NOTICE, "[CONFIG-5-INTIP]: Set the port ACL name to %s, %s\n",buffer, getenv("LOGIN_LOG_MESSAGE"));
	return 0;  
}

int func_ipv6_acc_grp(struct users *u)
{
	int i, res;
	uint64_t bmaps;
	char buffer[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);

	char name[ACL_NAME_LEN+1], buff[1024], mac_flag[PNUM];
	char *port_str, *port_ipv6_acl, *port_mac_acl, *p, *ptr;
	IPV6_STANDARD_ACL_ENTRY entry;
	POLICY_CLASSIFY classify;
	
	memset(&entry, '\0', sizeof(IPV6_STANDARD_ACL_ENTRY));
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	
	res = ipv6_std_acl_set(buffer, &entry, ACL_NAME_CHECK, -1, 0x00ULL);
	/* ip standard acl name is not exist */
	if(res)
	{
		vty_output("access-group %s not exist\n", buffer);
		return -1;
	}
	
	port_ipv6_acl  = cli_nvram_safe_get(CLI_PORT_ACL, "port_ipv6_acl");	
	port_mac_acl = cli_nvram_safe_get(CLI_PORT_ACL, "port_mac_acl");	
	port_str = u->promptbuf;
	
  	cli_str2bitmap(port_str, &bmaps);
//    str2bit(port_str, &bmaps);
    
    /* check if port use mac acl */
    p = port_mac_acl;
    for(i = 1; i <= PNUM; i++)
    {
    	ptr = strchr(p, ',');
    	if(p != ptr)
    		mac_flag[i] = '1';
    	else
    		mac_flag[i] = '0';
    	p = ptr + 1;
    }
       	
	memset(buff, '\0', 1024);
	p = port_ipv6_acl;
	for(i = 1; i <= PNUM; i++)
	{
		memset(name, '\0', ACL_NAME_LEN+1);
		ptr = strchr(p, ',');
		strncpy(name, p, ptr-p);
		
		if((bmaps>>phy[i]) & 0x01ULL)
		{
			/* use diff acl and does not apply mac acl */
			if((strcmp(name, buffer)) && (mac_flag[i] == '0'))
			{
				if(strlen(name))
				{
					/* ipv6 standard, delete port from acl table struct */
					ipv6_std_acl_set(name, &entry, ACL_PORT_DEL, -1, (0x01ULL<<phy[i]));
				}				
				
				/* ipv6 standard, add port to acl table struct */	
				ipv6_std_acl_set(buffer, &entry, ACL_PORT_ADD, -1, (0x01ULL<<phy[i]));
					
				strcat(buff, buffer);
				strcat(buff, ",");													
			}
			else if((strcmp(name, buffer)) && (mac_flag[i] == '1'))
			{
#if (XPORT==0)	
				if(i <= FNUM)
					vty_output("ip access-group failed on interface FastEthernet 0/%d\n", i);	
				else
					vty_output("ip access-group failed on interface GigaEthernet 0/%d\n", (i-FNUM));	
#endif		
#if (XPORT==1)	
				if(i <= GNUM)
					vty_output("ip access-group failed on interface GigaEthernet 0/%d\n", i);	
				else
					vty_output("ip access-group failed on interface TenGigaEthernet 0/%d\n", (i-GNUM));	
#endif		
				strcat(buff, name);				
				strcat(buff, ",");
			}
			else
			{
				strcat(buff, buffer);
				strcat(buff, ",");	
			}
			
		}
		else
		{							
			strcat(buff, name);				
			strcat(buff, ",");
		}
		
		p = ptr+1;
	}
	
	/* ipv6 standard, write regs */
	ipv6_std_acl_set(buffer, &entry, ACL_WRITE_REGS, -1, 0x00ULL);
		
	/* write policy */
	policy_set("", &classify, POLICY_WRITE_REGS, -1, 0x00ULL);

	scfgmgr_set("port_ipv6_acl", buff);
			
	free(port_ipv6_acl);
	free(port_mac_acl);
	syslog(LOG_NOTICE, "[CONFIG-5-INTIP]: Set the port ACL name to %s , %s",buffer, getenv("LOGIN_LOG_MESSAGE"));
	return 0;  
}

int nfunc_ipv6_acc_grp(struct users *u)
{
	/* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
		return 0;
	int i, res, flag=0;
	char name[ACL_NAME_LEN+1], buff[1024];
	IPV6_STANDARD_ACL_ENTRY entry;
	POLICY_CLASSIFY classify;
	char *port_acl, *p, *ptr;
	uint64 bmaps;
	char buffer[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);

	memset(&entry, '\0', sizeof(IPV6_STANDARD_ACL_ENTRY));
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	
	/* check if acl name is exist */
	res = ipv6_std_acl_set(buffer, &entry, ACL_NAME_CHECK, -1, 0x00ULL);
	/* ipv6 standard acl name is not exist */ 
	if(res)
	{
		printf("access-group %s not exist\n", buffer);
		return -1;
	}
		
	port_acl  = cli_nvram_safe_get(CLI_PORT_ACL, "port_ipv6_acl");	

	bmaps = cur_port_int;
	
	//memset(buff, '\0', strlen(port_acl));
	memset(buff, '\0', 1024);
	p = port_acl;
	for(i = 1; i <= PNUM; i++)
	{
		memset(name, '\0', ACL_NAME_LEN+1);
		ptr = strchr(p, ',');
		strncpy(name, p, ptr-p);
					
		if((bmaps >> phy[i]) & 0x01ULL)
		{
			if(0 == strcmp(name, buffer))
			{
				/* standard, delete port from acl table struct */
				if(strlen(name))
					ipv6_std_acl_set(name, &entry, ACL_PORT_DEL, -1, (0x01ULL<<phy[i]));
				
				strcat(buff, ",");
			}
			else
			{
#if (XPORT==0)	
				if(i <= FNUM)
					printf("ip access-group %s not be applied to interface FastEthernet 0/%d\n", buffer, i);
				else
					printf("ip access-group %s not be applied to interface GigaEthernet 0/%d\n", buffer, (i-FNUM));
#endif		
#if (XPORT==1)
				if(i <= GNUM)
					printf("ip access-group %s not be applied to interface GigaEthernet 0/%d\n", buffer, i);
				else
					printf("ip access-group %s not be applied to interface TenGigaEthernet 0/%d\n", buffer, (i-GNUM));
#endif		
				strcat(buff, name);				
				strcat(buff, ",");
			}
		}
		else
		{
			strcat(buff, name);				
			strcat(buff, ",");
		}
		
		p = ptr+1;		
	}
		
	/* ipv6 standard, write regs */
	if(flag == 0)
		ipv6_std_acl_set(buffer, &entry, ACL_WRITE_REGS, -1, 0x00ULL);

	/* write policy */
	policy_set("", &classify, POLICY_WRITE_REGS, -1, 0x00ULL);
	
	scfgmgr_set("port_ipv6_acl", buff);
	
	free(port_acl);
	return 0;

}
int func_ip_arp_inspect_trust(struct users *u)
{
	int portid, skfd;
	uint64_t port_int;
	char *port_str, *arp_trust_port;

	FILE *fp;
	char *arp_enable;
	char *snoop_enable;
	char *relay_enable;
	
//	port_str = getenv("CON_MULTIPORT");
	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return CLI_FAILED;
	}

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return CLI_FAILED;

	//scfgmgr_set("port_range_modify", port_str);
	
	cli_str2bitmap(port_str, &port_int);

	arp_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "arp_trust_port");
	arp_enable = nvram_safe_get("arp_enable");
	snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	relay_enable = nvram_safe_get("relay_enable");

	for(portid = 1; portid<=PNUM; portid++) {
		if( port_int & (0x01ULL << phy[portid]) ){
			*(arp_trust_port+portid-1) = '1';
		}
	}
	scfgmgr_set("arp_trust_port", arp_trust_port);
	
	if( ('1' == *arp_enable)||('1' == *snoop_enable)||('1' == *relay_enable) ) {
		if((fp=fopen(ARP_CONFIG_FILE,"w+")) != NULL) {
			fprintf(fp, "arp_trust_port=%s\n", arp_trust_port);
			fclose(fp);
		}
		SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
	}

	free(arp_trust_port);
	free(arp_enable);
	free(snoop_enable);
	free(relay_enable);
	syslog(LOG_NOTICE, "[CONFIG-5-INTIP]: Set the trust state to ARP inspection, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	close(skfd);
	
	return CLI_SUCCESS;
}


int func_ip_arp_inspect_limit_rate(struct users *u)
{
    int i;
    uint64_t port_int;
    
    char buf[MAX_ARGV_LEN] = {'\0'};
    int buffer = 0;
    cli_param_get_int(DYNAMIC_PARAM, 0, &buffer, u);
    sprintf(buf,"%d",buffer);
    char *port_str, *filter, buff[1024], *p, *p1;
    
	
//	port_str = getenv("CON_MULTIPORT");
	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}

	cli_str2bitmap(port_str, &port_int);
					
//    set_cfp_enable(skfd, port_int, 1);
//    set_arp_rate_by_phymaps(skfd, port_int, buffer);    
    
    filter = cli_nvram_safe_get(CLI_COMMA_ZERO, "filter_arp");
    
    memset(buff, '\0', 1024);
    p = filter;
    
    for(i = 1; i <= PNUM; i++)
    {
        p1 = strchr(p, ',');
        
        if( port_int & (0x01ULL << phy[i]) )
        {
            strcat(buff, buf);
        }
        else
        {
            if(i < PNUM)
                strncat(buff, p, p1-p);
            else
                strcat(buff, p);
        }
        
        if(i < PNUM)
            strcat(buff, ",");
        
        p = p1+1;
    }
        
    scfgmgr_set("filter_arp", buff);
    
    free(filter);
    syslog(LOG_NOTICE, "[CONFIG-5-INTIP]: Set ARP inspection limit rate to %sKPS, %s\n",buf, getenv("LOGIN_LOG_MESSAGE"));
    return 0;
}

int nfunc_ip_arp_inspect_trust(struct users *u)
{
	/* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
		return 0;
	int portid;
	uint64_t port_int;
	char *arp_trust_port;

	FILE *fp;
	char *arp_enable = nvram_safe_get("arp_enable");
	char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	char *relay_enable = nvram_safe_get("relay_enable");


	port_int = cur_port_int;

	arp_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "arp_trust_port");

	for(portid = 1; portid<=PNUM; portid++) {
		if( port_int & (0x01ULL << phy[portid]) ){
			*(arp_trust_port+portid-1) = '0';
		}
	}
	scfgmgr_set("arp_trust_port", arp_trust_port);
	
	if( ('1' == *arp_enable)||('1' == *snoop_enable)||('1' == *relay_enable) ) {
		if((fp=fopen(ARP_CONFIG_FILE,"w+")) != NULL) {
			fprintf(fp, "arp_trust_port=%s\n", arp_trust_port);
			fclose(fp);
		}
		SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
	}

	free(arp_trust_port);
	free(arp_enable);
	free(snoop_enable);
	free(relay_enable);
	
	return CLI_SUCCESS;
}

int nfunc_ip_arp_inspect_limit(struct users *u)
{
	/* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
	  return 0;

    int i;
    uint64_t port_int;
    char *p, *p1, buff[1024], *filter;
    			
	port_int = cur_port_int;
    		
//    disable_arp_rate_by_phymaps(skfd, port_int);
    
    filter = cli_nvram_safe_get(CLI_COMMA_ZERO, "filter_arp");
    
    memset(buff, '\0', 1024);
    p = filter;
    for(i = 1; i <= PNUM; i++)
    {
        p1 = strchr(p, ',');
        
        if( port_int & (0x01ULL << phy[i]) )
        {
            strcat(buff, "0");
        }
        else
        {
            if(i < PNUM)
                strncat(buff, p, p1-p);
            else
                strcat(buff, p);
        }
        
        if(i < PNUM)
            strcat(buff, ",");
        
        p = p1+1;
    }
        
    scfgmgr_set("filter_arp", buff);
    
    free(filter);
    return CLI_SUCCESS;
}

int func_ip_dhcp_sno_trust_set(char *port_str, int enable)
{
    int portid=0, skfd=0;
    uint64_t port_int;
    char *snoop_trust_port=NULL;
    char *snoop_enable=NULL;

    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) {
        return CLI_FAILED;
    }
    snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
    if('1' != *snoop_enable) {
        vty_output(" dhcp snooping is disable, please enable!\n");
        if(snoop_enable){
            free(snoop_enable);
            snoop_enable=NULL;
        }
        close(skfd);
        return CLI_FAILED;
    }
    scfgmgr_set("port_range_modify", port_str);
    cli_str2bitmap(port_str, &port_int);
    snoop_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "snoop_trust_port");
    for(portid = 1; portid<=PNUM; portid++) {
        if( port_int & (0x01ULL << phy[portid]) ){
            if(enable)
                *(snoop_trust_port+portid-1) = '1';
            else
                *(snoop_trust_port+portid-1) = '0';
        }
    }
    scfgmgr_set("snoop_trust_port", snoop_trust_port);
    SYSTEM("/usr/sbin/rc dhcpsnoop restart > /dev/null 2>&1");

    if(snoop_enable){
        free(snoop_enable);
        snoop_enable=NULL;
    }
    if(snoop_trust_port){
        free(snoop_trust_port);
        snoop_trust_port=NULL;
    }
    close(skfd);
    return CLI_SUCCESS;
}

int nfunc_ip_dhcp_sno_trus(struct users *u)
{
#if 1
    char *port_str=NULL;

    port_str = u->promptbuf;
    if(0 == strlen(port_str)) {
        return CLI_FAILED;
    }

    func_ip_dhcp_sno_trust_set(port_str, DISABLE);
#else
	/* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
		return 0;
	int portid, skfd;
	uint64_t port_int;
	char *snoop_trust_port;

	FILE *fp;
	char *arp_enable = nvram_safe_get("arp_enable");
	char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	char *relay_enable = nvram_safe_get("relay_enable");

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return CLI_FAILED;

	port_int = cur_port_int;

	snoop_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "snoop_trust_port");

	for(portid = 1; portid<=PNUM; portid++) {
		if( port_int & (0x01ULL << phy[portid]) ){
			*(snoop_trust_port+portid-1) = '0';
		}
	}
	scfgmgr_set("snoop_trust_port", snoop_trust_port);

	if( ('1' == *arp_enable)||('1' == *snoop_enable)||('1' == *relay_enable) ) {
		if((fp=fopen(ARP_CONFIG_FILE,"w+")) != NULL) {
			fprintf(fp, "snoop_trust_port=%s\n", snoop_trust_port);
			fclose(fp);
		}
		SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
	}

	free(snoop_trust_port);
	free(arp_enable);
	free(snoop_enable);
	free(relay_enable);

	close(skfd);
	#endif
	return CLI_SUCCESS;
}

int func_ip_dhcp_sno_trus(struct users *u)
{
#if 1
    char *port_str=NULL;

    port_str = u->promptbuf;
    if(0 == strlen(port_str)) {
        return CLI_FAILED;
    }
    func_ip_dhcp_sno_trust_set(port_str, ENABLE);
#else
    int portid, skfd;
    uint64_t port_int;
    char *port_str, *snoop_trust_port;

	FILE *fp;
	char *arp_enable = nvram_safe_get("arp_enable");
	char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	char *relay_enable = nvram_safe_get("relay_enable");

    //	port_str = getenv("CON_MULTIPORT");
    port_str = u->promptbuf;
    if(0 == strlen(port_str)) {
        return CLI_FAILED;
    }


    scfgmgr_set("port_range_modify", port_str);

    cli_str2bitmap(port_str, &port_int);

    snoop_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "snoop_trust_port");

    for(portid = 1; portid<=PNUM; portid++) {
        if( port_int & (0x01ULL << phy[portid]) ){
            *(snoop_trust_port+portid-1) = '1';
        }
    }
    scfgmgr_set("snoop_trust_port", snoop_trust_port);

    if( ('1' == *arp_enable)||('1' == *snoop_enable)||('1' == *relay_enable) ) {
        if((fp=fopen(ARP_CONFIG_FILE,"w+")) != NULL) {
            fprintf(fp, "snoop_trust_port=%s\n", snoop_trust_port);
            fclose(fp);
        }
        SYSTEM("/usr/bin/killall -SIGUSR1 arp_inspection > /dev/null 2>&1");
    }

    free(snoop_trust_port);
    free(arp_enable);
    free(snoop_enable);
    free(relay_enable);

    close(skfd);
#endif
    syslog(LOG_NOTICE, "[CONFIG-5-INTIP]: Set the trust state to DHCP snooping, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return CLI_SUCCESS;
}
int func_ipv6_dhcp_sno_trus(struct users *u)
{
	int portid, skfd, portlist,enable;
	uint64_t port_int;
	char *port_str;
	char *dhcp6_snoop_enable, *dhcp6_snoop_trust_port;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return CLI_FAILED;
	}

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return CLI_FAILED;

	cli_str2bitmap(port_str, &port_int);

	dhcp6_snoop_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "dhcp6_snoop_trust_port");
	dhcp6_snoop_enable = nvram_safe_get("dhcp6_snoop_enable");

	for(portid = 1; portid<=PNUM; portid++) {
		if( port_int & (0x01ULL << phy[portid]) ){
			*(dhcp6_snoop_trust_port+portid-1) = '1';
		}
	}
	scfgmgr_set("dhcp6_snoop_trust_port", dhcp6_snoop_trust_port);

	portlist = 0;
	if('1' == *dhcp6_snoop_enable) {
		for(portid = 0; portid < PNUM; portid++){
			enable = *(dhcp6_snoop_trust_port+portid)-'0';
			portlist |= (enable<<portid);
		}
	}else{
		portlist = 0x80000000;//need cancel DHCPv6 response packet drop
	}
	bcm_dhcpv6_trustport_set(skfd, portlist);

	free(dhcp6_snoop_enable);
	free(dhcp6_snoop_trust_port);
	
	close(skfd);
	syslog(LOG_NOTICE, "[CONFIG-5-INTIP]: Set the trust state to DHCP6 snooping, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;

}

int nfunc_ipv6_dhcp_sno_trus(struct users *u)
{
	int portid, skfd, portlist, enable;
	uint64_t port_int, untrust_port;
	char *port_str;
	char *dhcp6_snoop_enable, *dhcp6_snoop_trust_port;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return CLI_FAILED;
	}

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return CLI_FAILED;

	cli_str2bitmap(port_str, &port_int);

	dhcp6_snoop_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "dhcp6_snoop_trust_port");

	for(portid = 1; portid<=PNUM; portid++) {
		if( port_int & (0x01ULL << phy[portid]) ){
			*(dhcp6_snoop_trust_port+portid-1) = '0';
		}
	}
	scfgmgr_set("dhcp6_snoop_trust_port", dhcp6_snoop_trust_port);

	dhcp6_snoop_enable = nvram_safe_get("dhcp6_snoop_enable");

	portlist = 0;
	if('1' == *dhcp6_snoop_enable) {
		for(portid = 0; portid < PNUM; portid++){
			enable = *(dhcp6_snoop_trust_port+portid)-'0';
			portlist |= (enable<<portid);
		}
		if(portlist == 0)
			portlist = 0x80000000;
	}else{
		portlist = 0x80000000;//need cancel DHCPv6 response packet drop
	}
	bcm_dhcpv6_trustport_set(skfd, portlist);

	free(dhcp6_snoop_enable);
	free(dhcp6_snoop_trust_port);

	close(skfd);
	syslog(LOG_NOTICE, "[CONFIG-5-INTIP]: Set the trust state to DHCP6 snooping, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;

}

int nfunc_mac_acc_grp(struct users *u)
{
		/* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
		return 0;
	int i, res;
	char name[ACL_NAME_LEN+1], buff[1024];
	
	char buffer[MAX_ARGV_LEN] = {'0'};
 	cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);
	
	MAC_ACL_ENTRY entry;
	POLICY_CLASSIFY classify;
	char *port_acl, *p, *ptr;
	uint64 bmaps;
	
	memset(&entry, '\0', sizeof(MAC_ACL_ENTRY));
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	/* check if acl name is exist */
	res = mac_acl_set(buffer, &entry, ACL_NAME_CHECK, -1, 0x00ULL);
	/* acl name is not exist */
	if(res)
	{
		vty_output("access-group %s not exist\n", buffer);
		return -1;
	}
		
	port_acl = cli_nvram_safe_get(CLI_PORT_ACL, "port_mac_acl");	

	bmaps = cur_port_int;
	
	//memset(buff, '\0', strlen(port_acl));
	memset(buff, '\0', 1024);
	p = port_acl;
	for(i = 1; i <= PNUM; i++)
	{
		memset(name, '\0', ACL_NAME_LEN+1);
		ptr = strchr(p, ',');
		strncpy(name, p, ptr-p);
					
		if((bmaps >> phy[i]) & 0x01ULL)
		{
			if(0 == strcmp(name, buffer))
			{
				if(strlen(name))
					mac_acl_set(name, &entry, ACL_PORT_DEL, -1, (0x01ULL<<phy[i]));
				strcat(buff, ",");
			}
			else
			{
#if (XPORT==0)	
				if(i <= FNUM)
					vty_output("mac access-group %s not be applied to interface FastEthernet 0/%d\n", buffer, i);
				else
					vty_output("mac access-group %s not be applied to interface GigaEthernet 0/%d\n", buffer, (i-FNUM));
#endif		
#if (XPORT==1)
				if(i <= GNUM)
					vty_output("mac access-group %s not be applied to interface GigaEthernet 0/%d\n", buffer, i);
				else
					vty_output("mac access-group %s not be applied to interface TenGigaEthernet 0/%d\n", buffer, (i-GNUM));
#endif		
				strcat(buff, name);				
				strcat(buff, ",");
			}
		}
		else
		{
			strcat(buff, name);				
			strcat(buff, ",");
		}
		
		p = ptr+1;		
	}
	
	mac_acl_set(buffer, &entry, ACL_WRITE_REGS, -1, 0x00ULL);
	
	/* write policy */
	policy_set("", &classify, POLICY_WRITE_REGS, -1, 0x00ULL);
	
	scfgmgr_set("port_mac_acl", buff);
	
	free(port_acl);
	return 0;
}

int func_mac_learn_limit_set(struct users *u)
{
	uint64_t bmaps;
	int i, port = -1;	
	char buffer[MAX_ARGV_LEN] = {0};
	char *port_str, *ptr;
	char *port_mac_limit = NULL;
	
  	cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);
	port_str = u->promptbuf;
	cli_str2bitmap(port_str, &bmaps);
	if(pmap2port(bmaps,&port) < 0){
		return ;
	}
	
	port_mac_limit = nvram_safe_get("port_mac_limit");
	ptr = calloc(strlen(port_mac_limit)+strlen("port,maclimit;"),sizeof(char));	
	sprintf(&ptr[strlen(port_mac_limit)],"P%d,%s;",port,buffer);
	bcm_l2_learn_limit_by_port(port,atoi(buffer),1);
	scfgmgr_set("port_mac_limit", ptr);

	free(ptr);
	free(port_mac_limit);
	syslog(LOG_NOTICE, "[CONFIG-5-INTMAC]: Set the port mac limit to %s, %s\n",buffer, getenv("LOGIN_LOG_MESSAGE"));
	
	return 0;  
}

int func_mac_learn_limit_del(struct users *u)
{
	uint64_t bmaps;
	int i, port = -1;
	char tem[MAX_ARGV_LEN] = {0};
	char *port_str,*ptr,*pk,*ph;
	char *port_mac_limit = NULL;
	
	port_str = u->promptbuf;
	cli_str2bitmap(port_str, &bmaps);
	if(pmap2port(bmaps,&port) < 0){
		return ;
	}
	
	bcm_l2_learn_limit_by_port(port,0,0);
	
	port_mac_limit = nvram_safe_get("port_mac_limit");
	if(strlen(port_mac_limit) == 0)
		return 0;
		
	sprintf(tem,"P%d,",port);
	if((pk = strcasestr(port_mac_limit,tem,strlen(tem))) == NULL){
		free(port_mac_limit);
    	return CLI_SUCCESS;
    }
    
    if((ph = strchr(pk,';')) == NULL){
    	printf("not exist\n");
		free(port_mac_limit);
    	return CLI_SUCCESS;
    }
    
	ph++;
	memcpy(port_mac_limit,ph,strlen(ph));
	
	scfgmgr_set("port_mac_limit", port_mac_limit);
	free(port_mac_limit);
	syslog(LOG_NOTICE, "[CONFIG-5-INTMAC]: Set the port mac limit to %s\n", getenv("LOGIN_LOG_MESSAGE"));
	
	return 0;  
}

int func_mac_acc_grp(struct users *u)
{
	int i, res;
	uint64_t bmaps;
	
	char buffer[MAX_ARGV_LEN] = {'0'};
  cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);
	
	char name[ACL_NAME_LEN+1], buff[1024];
	char *port_str, *port_acl, *p, *ptr;
	MAC_ACL_ENTRY entry;
	
	memset(&entry, '\0', sizeof(MAC_ACL_ENTRY));
	res = mac_acl_set(buffer, &entry, ACL_NAME_CHECK, -1, 0x00ULL);
	/* acl name is not exist */
	if(res)
	{
		vty_output("access-group %s not exist\n", buffer);
		return -1;
	}
	
	port_acl  = cli_nvram_safe_get(CLI_PORT_ACL, "port_mac_acl");	
//	port_str = getenv("CON_MULTIPORT");
	port_str = u->promptbuf;
	
	cli_str2bitmap(port_str, &bmaps);
    	
	memset(buff, '\0', 1024);
	p = port_acl;
	for(i = 1; i <= PNUM; i++)
	{
		memset(name, '\0', ACL_NAME_LEN+1);
		ptr = strchr(p, ',');
		strncpy(name, p, ptr-p);
		
		if((bmaps>>phy[i]) & 0x01ULL)
		{
			if(strcmp(name, buffer))
			{
				if(strlen(name))
					mac_acl_set(name, &entry, ACL_PORT_DEL, -1, (0x01ULL<<phy[i]));
		
				 mac_acl_set(buffer, &entry, ACL_PORT_ADD, -1, (0x01ULL<<phy[i]));								
			}
			
			strcat(buff, buffer);
			strcat(buff, ",");
		}
		else
		{							
			strcat(buff, name);				
			strcat(buff, ",");
		}
		
		p = ptr+1;
	}
	
	mac_acl_set(buffer, &entry, ACL_WRITE_REGS, -1, 0x00ULL);
	
	scfgmgr_set("port_mac_acl", buff);
			
	free(port_acl);
	syslog(LOG_NOTICE, "[CONFIG-5-INTMAC]: Set the port ACL name to %s, %s\n",buffer, getenv("LOGIN_LOG_MESSAGE"));
	return 0;  
}

int func_rmon_collet_histy(struct users *u)
{
  	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}

int func_rmon_collet_stats(struct users *u)
{
  	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}

static int cli_set_no_port_speed(struct users *u, int speed_type)
{
	int i;
    FILE *fp;
	uint64_t port_int;
	char *port_str, *speed_str;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	speed_str  = cli_nvram_safe_get(CLI_SPEED_ALL_AUTO,  "port_speed");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
			*(speed_str+i-1) = '0';
		}
	}
	
	scfgmgr_set("port_speed", speed_str);
	if((fp=fopen("/tmp/web_port_config", "w")) != NULL)
	{ 
		fprintf(fp, "%s\n", bit2str(port_int));		
		fclose(fp);
	}	
	
	system("rc port start  > /dev/null 2>&1 &");
	free(speed_str);
	
	return 0;
}

static int cli_set_port_speed(struct users *u, int speed_type)
{
	int i;
    FILE *fp;
	uint64_t port_int;
	char *port_str, *speed_str;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	speed_str  = cli_nvram_safe_get(CLI_SPEED_ALL_AUTO,  "port_speed");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
			*(speed_str+i-1) = speed_type + '0';
		}
	}
	
	scfgmgr_set("port_speed", speed_str);
	if((fp=fopen("/tmp/web_port_config", "w")) != NULL)
	{ 
		fprintf(fp, "%s\n", bit2str(port_int));		
		fclose(fp);
	}	
	
	system("rc port start  > /dev/null 2>&1 &");
	free(speed_str);
	return 0;
}

int nfunc_speed(struct users *u)
{
    cli_set_no_port_speed(u, PORT_SPEED_AUTO);
    return 0;
}

int func_speed_ten(struct users *u)
{
  	cli_set_port_speed(u, PORT_SPEED_10);
  	return 0;
}

int func_speed_hundred(struct users *u)
{
  	cli_set_port_speed(u, PORT_SPEED_100);
  	return 0;
}

int func_speed_giga(struct users *u)
{	
    int i;
    uint64_t port_int;
	char *port_str;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
#if (XPORT==0)	
	cli_str2bitmap(port_str, &port_int);
	for(i = 1; i <= FNUM; i++)
    {
        if((0x01ULL<<i) & port_int)
        {    
            vty_output("FastEthernet port don't support 1000M speed!\n");
            return -1;
        }
    }
#endif	
     
  	cli_set_port_speed(u, PORT_SPEED_1000);
  	return 0;
}

int func_speed_auto(struct users *u)
{
	
  	cli_set_port_speed(u, PORT_SPEED_AUTO);
  	return 0;
}

int func_inter_shutdown_edr(int iPort)
{
    int skfd;
    struct sockaddr_un edr_sock_addr, cli_sock_addr;
	IPC_SK tx;
	SK_EDR *pstTx = (EDR_PORT *)tx.acData;
	if(-1 == creat_sk_client(&skfd, &edr_sock_addr, SOCK_PATH_EDR, &cli_sock_addr, SOCK_PATH_CONSOLE, 0))
	{
		return -1;
	}

	/*operate data for sending*/
	
	tx.stHead.enCmd = IPC_CMD_EDR_RECOVER;
	tx.stHead.cOpt = 0;
	tx.stHead.cBack = IPC_SK_NOBACK;
	pstTx->iPort = iPort;
	/*send data to server*/
	if(ipc_send(skfd, &tx, &edr_sock_addr) == -1)
	{
		unlink(cli_sock_addr.sun_path);
		return -1;
	}

	unlink(cli_sock_addr.sun_path);
	return 0;
}

int nfunc_inter_shutdown(struct users *u)
{
	int i;
    FILE *fp;
	uint64_t port_int;
	char *port_str, *enable_str;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	enable_str  = cli_nvram_safe_get(CLI_ALL_ONE, "port_enable");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
			/* recover port state for loopback(no errdisable detect loopback)
			shanming.ren 2012-4-12 15:50:10*/
//			func_inter_shutdown_edr(i);

			*(enable_str+i-1) = '1';
			syslog(LOG_NOTICE, "[LINK-5-CHANGED]: Port %s0/%d changed state to administratively up, %s\n", (i<=GNUM)?"G":"T", (i<=GNUM)?i:(i-GNUM), getenv("LOGIN_LOG_MESSAGE"));				
		}
	}
	scfgmgr_set("port_enable", enable_str);
	
	if((fp=fopen("/tmp/web_port_config", "w")) != NULL)
	{ 
		fprintf(fp, "%s\n", bit2str(port_int));		
		fclose(fp);
	}	
	
	system("rc port start  > /dev/null 2>&1 &");
	free(enable_str);
	
	return 0;
}

//int func_shutdown(struct users *u, int argc, char *argv[])
int func_inter_shutdown(struct users *u)
{
	int i;
    FILE *fp;
	uint64_t port_int;
	char *port_str, *enable_str;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
DEBUG("[%s:%d] port_str %s port_int:0x%08x%08x\n", __FUNCTION__, __LINE__, port_str, (uint32)(port_int >> 32), (uint32)port_int);	
	enable_str  = cli_nvram_safe_get(CLI_ALL_ONE, "port_enable");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
			/* recover port state for loopback(no errdisable detect loopback)
			shanming.ren 2012-4-12 15:50:10*/
//			func_inter_shutdown_edr(i);
			*(enable_str+i-1) = '0';
			syslog(LOG_NOTICE, "[LINK-5-CHANGED]: Port %s0/%d changed state to administratively down, %s\n", (i<=GNUM)?"G":"T", (i<=GNUM)?i:(i-GNUM), getenv("LOGIN_LOG_MESSAGE"));				
		}
	}
	
	scfgmgr_set("port_enable", enable_str);
	if((fp=fopen("/tmp/web_port_config", "w")) != NULL)
	{ 
		fprintf(fp, "%s\n", bit2str(port_int));		
		fclose(fp);
	}	
	
	system("rc port start  > /dev/null 2>&1 &");
	free(enable_str);
	
	system("usr/sbin/snmptrap -v 1 -c public '1.3.6.1.2.1' 6 2 '' > /dev/null 2>&1");
	//SYSTEM("/usr/bin/killall -SIGUSR1 err_disable >/dev/null 2>&1");
	return 0;	
}


int func_storm_contr_broad(struct users *u)
{
	int buffer = 0;
  	cli_param_get_int(DYNAMIC_PARAM, 0, &buffer, u);
  	cli_set_storm(u, 0, buffer);
  	return 0;
}

int func_storm_contr_mul(struct users *u)
{
	int buffer = 0;
  	cli_param_get_int(DYNAMIC_PARAM, 0, &buffer, u);
  	cli_set_storm(u, 1, buffer);
  	return 0;
}

int func_storm_contr_uni(struct users *u)
{
	int buffer = 0;
  	cli_param_get_int(DYNAMIC_PARAM, 0, &buffer, u);
  	cli_set_storm(u, 2, buffer);
  	return 0;
}

int nfunc_storm_contr_broad(struct users *u)
{
  	cli_set_storm_disable(u, 0);
  	return 0;
}

int nfunc_storm_contr_mul(struct users *u)
{
  	cli_set_storm_disable(u, 1);
  	return 0;
}

int nfunc_storm_contr_uni(struct users *u)
{
  	cli_set_storm_disable(u, 2);
  	return 0;
}


int nfunc_sw_block(struct users *u)
{
	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}

int func_sw_block(struct users *u)
{
	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}

int nfunc_sw_loop(struct users *u)
{
	if( prase_port_map(u) == CLI_FAILED )
    	return 0;
	  
    int portid;
    int dtc_stc=0;
    uint64_t port_int;
    char *lo_config = cli_nvram_safe_get(CLI_ALL_ZERO, "lo_config");
	char *lo_enable = nvram_safe_get("lo_enable");

	if('0' == *lo_enable) {
		vty_output("  You should start loopdetect first!\n");
		free(lo_enable);
		free(lo_config);
		return CLI_SUCCESS;
	}
	
	port_int = cur_port_int;
	for(portid = 1; portid<=PNUM; portid++)
	{
		if( port_int & (0x01ULL << phy[portid]) )
		{
			*(lo_config+portid-1) = '0';
		}
		if(*(lo_config+portid-1) == '1')
			dtc_stc++;
	}
	scfgmgr_set("lo_config", lo_config);
	usleep(5000);
	if(dtc_stc == 0)
	{
		SYSTEM("/usr/bin/killall loopback > /dev/null 2>&1");
		scfgmgr_set("lo_enable", "0");
	}
	else
		SYSTEM("/usr/bin/killall -SIGUSR1 loopback > /dev/null 2>&1");

	usleep(50000);

    free(lo_config);
    free(lo_enable);

    return 0;	
}

int  func_sw_loop(struct users *u, char *port_str)
{
	if (prase_port_map(u) == CLI_FAILED)
		return 0;
	int portid;
	uint64_t port_int; 	
	char *lo_enable, *lo_config;
	char *link_type;

	port_int = cur_port_int;

	lo_config= cli_nvram_safe_get(CLI_ALL_ZERO, "lo_config");	
	link_type = cli_nvram_safe_get(CLI_ALL_ONE, "vlan_link_type");
	
	for(portid = 1; portid <= PNUM; portid++) {
		if( port_int & (0x01ULL <<  phy[portid]) )
		{
			if(*(link_type+portid-1) == '3')/* port is trunk mode*/
			{
				printf("trunk port can't start loopback detecting\n");
				free(lo_config);
				free(link_type);
				return 0;
			}
			*(lo_config+portid-1) = '1';
		}
	}
	
	scfgmgr_set("lo_config", lo_config);

	lo_enable = nvram_safe_get("lo_enable");
	if('0' == *lo_enable) {
		scfgmgr_set("lo_enable", "1");
		SYSTEM("/usr/sbin/loopback > /dev/null 2>&1 &");
	} else {
		scfgmgr_set("lo_enable", "1");
		SYSTEM("/usr/bin/killall -SIGUSR1 loopback > /dev/null 2>&1");
	}


	free(lo_config);
	free(lo_enable);
	free(link_type);
	return 0;
}


int nfunc_sw_mode(struct users *u)
{
	cli_set_link_type(u, '1');
	return 0;
}

int nfunc_sw_pro(struct users *u)
{
	cli_set_port_protected(u, 0);
	return 0;
}

int func_sw_mode_acc(struct users *u)
{
	cli_set_link_type(u, '1');
	return 0;
}

int func_sw_mode_pri_vlan(struct users *u)
{
	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}

int func_sw_mode_tru(struct users *u)
{
	/* Set Interface trunk mode */
	cli_set_link_type(u, '3');

	return 0;
}	

int func_sw_mode_qinq_uplink(struct users *u, int mode)
{
	int i, portid, flag = 0;
	char *port_str, *qinq_config;
	uint64_t port_int;
	
    /* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
		return 0;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
//	DEBUG("[%s:%d] port_int: 0x%08x%08x", __FUNCTION__, __LINE__, (uint32)(port_int >> 32), (uint32)port_int);

	qinq_config = cli_nvram_safe_get(CLI_ALL_ONE,  "qinq_config");
	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
		    if(1 == mode)
		    {   
		        if(*(qinq_config+i-1) == '1')
			    {
    			    *(qinq_config+i-1) = '2';
    			    flag = 1;
			    }else if(*(qinq_config+i-1) == '0')
			    {
			        vty_output("Warning: this port(s) isn't in QinQ mode!!\n");
			    }
			        
			}
			else
			{
			    if(*(qinq_config+i-1) != '2')
			    {
			        vty_output("Warning: this port(s) isn't in QinQ Uplink Type mode!!\n");
			    }else
    		    {    
    			    *(qinq_config+i-1) = '1';
    			    flag = 1;
    			}     
			}          
		}
	}
	
	if(1 == flag)
	{    
    	scfgmgr_set("qinq_config", qinq_config);
    	system("rc qinq restart > /dev/null 2>&1");
    }
    free(qinq_config);

	return 0;
}

int nfunc_sw_portsec_dy(struct users *u)
{
	if( prase_port_map(u) == CLI_FAILED )
	  return 0;
    int i, skfd, portid;
    uint64 port_int;
    char *mac, *buff, *p, *ptr;
    int def_num = 8191;
	char *port_str = NULL;
	int mac_adv_cfg[PNUM];

	port_str = u->promptbuf;

    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
		
	mac = cli_nvram_safe_get(CLI_MAC_ADVANCED, "mac_advanced_config");

	port_int = cur_port_int;

    if(cli_check_interface_dot1x(port_int))
	{
	    vty_output("  Interface can not be dot1x auto mode or force-unauthorized mode!\n");
	    free(mac);
		close(skfd);
	    return CLI_FAILED;
	}

    buff = malloc(strlen(mac)+512);
    if(NULL ==buff)
    {
        free(mac);
		close(skfd);
        return CLI_FAILED; 
    }
    memset(buff,'\0',sizeof(buff));
	if (str_to_arr_i(mac, mac_adv_cfg, PNUM) == -1) {
		free(buff);
		free(mac);
		close(skfd);
		return CLI_FAILED;
	}

	for(i = 1; i <= PNUM; i++) {
		if(port_int & (0x01ULL <<  phy[i])) {
			mac_adv_cfg[i-1] = def_num;
			bcm_set_max_mac_num(skfd, i, def_num);
			bcm_auth_mode_set(skfd, i, 2); 
		}
	}

	arr_to_str_i(mac_adv_cfg, buff, ',', PNUM);

	scfgmgr_set("mac_advanced_config", buff);
	
	free(mac);	
	free(buff);
	close(skfd);
	return CLI_SUCCESS;

}		

int nfunc_sw_portsec_mo(struct users *u)
{
	if( prase_port_map(u) == CLI_FAILED )
		return 0;
    int skfd, portid;
    uint64_t port_int, learn_maps = 0x00ULL;
     
    char *port_learn = cli_nvram_safe_get(CLI_ALL_ONE, "port_learn");
    
    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
	  return -1;

	port_int = cur_port_int;
	
	for(portid = 1; portid<=PNUM; portid++)
	{
	    if( port_int & (0x01ULL << phy[portid]) )
	        *(port_learn+portid-1) = '1';
	        
	    if(*(port_learn+portid-1) != '1')
	        learn_maps |= (0x01ULL << phy[portid]);
	}
       
    scfgmgr_set("port_learn", port_learn);
    
    //set port learning disable
    set_port_learn_disable(skfd, learn_maps);
    
    //clear mac for ports that are static ports
    for(portid = 1; portid <= PNUM; portid++)
	{
        if(*(port_learn+portid-1) == '0')
            bcm_l2_addr_delete_by_port(skfd, 0, portid);
    }
            
    free(port_learn);
    close(skfd);   
    return CLI_SUCCESS; 
}

int func_sw_portsec_dy_max(struct users *u)
{
	int buffer = 0;
  	char buff[MAX_ARGV_LEN] = {'\0'};
  	cli_param_get_int(DYNAMIC_PARAM, 0, &buffer, u);
  	sprintf(buff,"%d",buffer);
 	/*Set interface maximum address*/
  	cli_set_port_max_addr(u, buff);

	return 0;
}	

int func_sw_portsec_mo_dy(struct users *u)
{
	cli_set_learning_ability(u, "1");

	return 0;
}

int func_sw_portsec_mo_sta_acc(struct users *u)
{
	 /*set learning enable*/
  	cli_set_learning_ability(u, "0");

	return 0;
}

int func_sw_pro(struct users *u)
{
	if( prase_port_map(u) == CLI_FAILED )
		return 0;
	char *port_protect_config, *port_protect;
	uint64_t port_int;
	uint64_t bmaps = 0x00ULL;
	int skfd,port;
	char tmp[32],buff[256];
	char *p1,*p2,*p3,*ptr_1,*ptr_2;
	scfgmgr_set("port_protect_enable", "1");
	port_protect_config = cli_nvram_safe_get(CLI_PROTECT_CONFIG,"port_protect_config");	

	port_int = cur_port_int;
	
	p1=port_protect_config;
	memset(buff, '\0', sizeof(buff));
	while((p2=strchr(p1, ';'))!=NULL)
	{
		p3=strchr(p1,',');
		if( port_int & (0x01ULL << phy[atoi(p1)])){
			memset(tmp, '\0', sizeof(tmp));
			strncpy(tmp,p1,p3-p1+1);
			strcat(tmp,"1;");
		}
		else
		{
			memset(tmp, '\0', sizeof(tmp));
			memcpy(tmp,p1,p2-p1+1);
		}
		strcat(buff,tmp);
		p1=p2+1;
	}
	scfgmgr_set("port_protect_config", buff);	
	
	port_protect = cli_nvram_safe_get(CLI_PROTECT_CONFIG,"port_protect_config");		
	ptr_1 = port_protect;
	while(strlen(ptr_1)){
	ptr_2 = strchr(ptr_1, ',');
	ptr_2++;
	port = atoi(ptr_1);
	if((*ptr_2)== '1')
	bmaps |= 0x01ULL << phy[port];
  
	ptr_1 = strchr(ptr_1, ';');
 	ptr_1++;
	}
	
	free(port_protect_config);
	free(port_protect);
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
	bcm_port_protect_set(skfd, &bmaps);	
	close(skfd);  
	  
	return 0;  
}

int func_inter_vlan(struct users *u)
{
	int buffer = 0;
  	cli_param_get_int(DYNAMIC_PARAM, 0, &buffer, u);
	cli_set_port_pvid(u, buffer);
	
	return 0;
}

int nfunc_inter_vlan(struct users *u)
{
  /* set Interface pvid 1 */
  	cli_set_port_pvid(u, 1);
    
	return 0;
}	

int func_rate_limit(struct users *u)
{
  	vty_output("  The command doesn't support in this version!!\n");
	return 0;
}	

int nfunc_rate_limit_egr(struct users *u)
{
  	cli_set_no_rate_limit(u, 1);
	return 0;
}	

int nfunc_rate_limit_ing(struct users *u)
{
  	cli_set_no_rate_limit(u, 0);
    return 0;
}	

int func_rate_limit_egr(struct users *u)
{
	int buffer = 0;
    cli_param_get_int(DYNAMIC_PARAM, 0, &buffer, u);
    cli_set_rate_limit(u, 1, buffer);
	return 0;
}	

int func_rate_limit_ing(struct users *u)
{
	int buffer = 0;
    cli_param_get_int(DYNAMIC_PARAM, 0, &buffer, u);
    cli_set_rate_limit(u, 0, buffer);
	return 0;
}	

int func_tru_vlan_allo(struct users *u)
{
    char buff[MAX_ARGV_LEN] = {'\0'};
    cli_param_get_string(STATIC_PARAM, 0, buff, u);

    cli_set_trunk_param(u, CLI_TRUNK_ALLOWED, buff);
    
	return 0;
}	

int func_tru_vlan_untag(struct users *u)
{
	char buff[MAX_ARGV_LEN] = {'\0'};
  	cli_param_get_string(STATIC_PARAM, 0, buff, u);
  /* Set switch trunk vlan allow */
//	  setenv("CON_VLAN", buff, 1);
	cli_set_trunk_param(u, CLI_TRUNK_UNTAGGED, buff);
	
	return 0;
}	

int nfunc_tru_vlan_allo(struct users *u)
{
  /* set trunk vlan-allowed default */
  	cli_set_no_trunk_param(u, CLI_TRUNK_ALLOWED);
  	
	return 0;
}	


int nfunc_tru_vlan_untag(struct users *u)
{
	/* set trunk vlan-untagged default */
  	cli_set_no_trunk_param(u, CLI_TRUNK_UNTAGGED);
  	
	return 0;
}	


int func_stp_int_bpduf_dis(struct users *u)
{
   /* set rstp budp filter of port disable*/
  	cli_set_rstp_config(u, CLI_PORT_BPDU_FILTER, 2);
  	return 0;
}

int func_stp_int_bpduf_en(struct users *u)
{
  	/* set rstp budp filter of port enable*/
  	cli_set_rstp_config(u, CLI_PORT_BPDU_FILTER, 1);
  	return 0;
}

int func_stp_int_bpdug_en(struct users *u)
{
 	/* set rstp budp guard of port disable*/
  	cli_set_rstp_config(u, CLI_PORT_BPDU_GUARD, 1);
  	return 0;
}

int func_stp_int_bpdug_dis(struct users *u)
{
 	/* set rstp budp guard of port enable*/
  	cli_set_rstp_config(u, CLI_PORT_BPDU_GUARD, 2);
  	return 0;
}

int func_stp_int_cost(struct users *u)
{
  	int buffer = 0;
  	cli_param_get_int(DYNAMIC_PARAM, 0, &buffer, u);
  	/* set rstp port cost */
  	cli_set_rstp_config(u, CLI_PORT_COST, buffer);
  	return 0;
}

int func_stp_int_guard_none(struct users *u)
{
  /*Set guard mode to none*/
  	cli_set_rstp_config(u, CLI_PORT_GUARD, 0);
 	return 0;
}

int func_stp_int_guard_root(struct users *u)
{
   /*Set guard mode to root guard on interface*/
  	cli_set_rstp_config(u, CLI_PORT_GUARD, 1);
  	return 0;
}

int func_stp_int_link_point(struct users *u)
{
   /* set rstp p2p port */
  	cli_set_rstp_config(u, CLI_PORT_P2P, 0);
  	return 0;
}

int func_stp_int_link_shared(struct users *u)
{
   /* set rstp p2p port */
  	cli_set_rstp_config(u, CLI_PORT_P2P, 1);
  	return 0;
}

int func_stp_int_portp(struct users *u)
{
  	/* set rstp port priority */
    int i;
  	int buffer = 0;
  	cli_param_get_int(DYNAMIC_PARAM, 0, &buffer, u);
  	i = buffer;
  	if(i % 16 == 0)
  	{
		cli_set_rstp_config(u, CLI_PORT_PRIORITY, buffer);
  	}
  	else
 	{
		vty_output("Port Priority in increments of 16 is required\n");
  	}
  	return 0;
}

int func_stp_int_portf(struct users *u)
{
 /* set rstp edge port */
  	cli_set_rstp_config(u, CLI_PORT_EDGE, 1);
  	return 0;
}

int nfunc_stp_int_bpduf(struct users *u)
{
  /* set rstp port bpdu filter default*/
 	cli_set_no_rstp_config(u, CLI_PORT_BPDU_FILTER, 0);
  	return 0;
}

int nfunc_stp_int_bpdug(struct users *u)
{
  /* set rstp port bpdu guard default*/
    cli_set_no_rstp_config(u, CLI_PORT_BPDU_GUARD, 0);
  	return 0;
}

int nfunc_stp_int_cost(struct users *u)
{
	/* set rstp port cost default auto */
	cli_set_no_rstp_config(u, CLI_PORT_COST, 0);
  	return 0;
}

int nfunc_stp_int_guard(struct users *u)
{
	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}

int nfunc_stp_int_link(struct users *u)
{
	/* set rstp port p2p auto */
	cli_set_no_rstp_config(u, CLI_PORT_P2P, 2);

	return 0;
}

int nfunc_stp_int_portp(struct users *u)
{
	/* set rstp port priority defualt 0 */
	cli_set_no_rstp_config(u, CLI_PORT_PRIORITY, 128);

	return 0;
}

int nfunc_stp_int_portf(struct users *u)
{
	/* set rstp port edge disable */
	cli_set_no_rstp_config(u, CLI_PORT_EDGE, 0);

	return 0;
}


int cli_start_dot1x()
{
	int skfd, auth, i;
	char *enable = nvram_safe_get("dot1x_enable");
	char *auth_config = cli_nvram_safe_get(CLI_DOT1X_CONFIG, "dot1x_config");
	uint64_t auth_map = 0x00ULL;
	char *p, *ptr;
	p = auth_config;
	
	if(*enable =='1')
	{
		system("rc auth restart > /dev/null 2>&1");
	}
	
	free(auth_config);
	free(enable);
	return 0;
}

int cli_stop_dot1x() 
{
	int skfd, i;
	//char *dot1x_enable = nvram_safe_get("dot1x_enable");
	//char *lock_enable = nvram_safe_get("lock_enable");
	
//	  if((*dot1x_enable == '1') || ((*dot1x_enable == '0') && (*lock_enable == '0')))		  
	system("/usr/bin/killall hostapd > /dev/null 2>&1");
		   
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;

	for(i = 1; i <= PNUM; i++) 
	{
		bcm_auth_mode_set(skfd, i, 0);
	}
	
	//(lock_enable);
	//free(dot1x_enable);
	close(skfd);	
	return 0;
}


/*set dot1x port control mode*/
int func_set_dot1x_port_control(char *mode,struct users *u)
{
	int portid, index;
	char *port_str, *p, *ptr,buff[1024];
	uint64_t port_int;
	char *auth_config = NULL, *dot1x_enable;
	char port_buf[20],*p1;
       port_str = u->promptbuf;
//	p1 = u->promptbuf;
//	p1 = strchr(p1,'/');
//	p1++;
//	strcpy(port_buf,p1);
//	  port_str = getenv("CON_MULTIPORT");
//	port_str = port_buf;

	if(0 == strlen(port_str)) {
		return -1;
	}
	cli_str2bitmap(port_str, &port_int);

	if( '1' != *mode) {
		dot1x_enable = nvram_safe_get("dot1x_enable");
		if(*dot1x_enable == '1') {
			/* check port is trunk mode */
			memset(cur_port_conf, 0, sizeof(cli_port_conf)*PNUM);
			memset(&cur_trunk_conf, 0, sizeof(cli_trunk_conf));
			cli_nvram_conf_get(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);
			cli_nvram_conf_get(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

			for(portid = 1; portid<=PNUM; portid++) {
				if( port_int & (0x01ULL << phy[portid]) )
			    {
					if( cur_port_conf[portid-1].mode == '3' ) {
						vty_output("  Command rejected: Dot1x is supported only on Ethernet interfaces configured in Access!\n");
						cli_nvram_conf_free(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);
						cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
						free(dot1x_enable);
						return CLI_SUCCESS;
					}
					for(index = 0; index < cur_trunk_conf.group_count; index++) {
						if( cur_trunk_conf.cur_trunk_list[index].port_int & (0x1ULL << phy[portid]) ) {
							vty_output("  Command rejected: Trunking enabled on one or more ports.\n");
							vty_output("  Please disable Trunking before enabling dot1x!\n");
							cli_nvram_conf_free(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);
							cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
							free(dot1x_enable);
							return CLI_SUCCESS;
						}
					}
				}
			}
			cli_nvram_conf_free(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);
			cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
		}
		free(dot1x_enable);
	}
	auth_config = cli_nvram_safe_get(CLI_DOT1X_CONFIG, "dot1x_config");
	p = auth_config;
	memset(buff, '\0', sizeof(buff));
	for(portid = 1; portid<=PNUM; portid++)
	{
		if( port_int & (0x01ULL << phy[portid]) )
		{
			strcat(buff, mode);
			p = strchr(p, ',');
			ptr = strchr(p, ';');
			strncat(buff, p, (ptr-p+1));
		}
		else
		{
			ptr = strchr(p, ';');
			strncat(buff, p, (ptr-p+1));
		}
		
		p = ptr + 1;
	}
	scfgmgr_set("dot1x_config", buff);
	cli_stop_dot1x();
	cli_start_dot1x();
	
	free(auth_config);

	if( '2' == *mode)
		syslog(LOG_NOTICE, "[CONFIG-5-INTDOT1X]: Set the dot1x port_control to auto, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	else if( '1' == *mode)
		syslog(LOG_NOTICE, "[CONFIG-5-INTDOT1X]: Set the dot1x port_control to force-authorized, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	else
		syslog(LOG_NOTICE, "[CONFIG-5-INTDOT1X]: Set the dot1x port_control to force-unauthorized, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	return CLI_SUCCESS;

}

int func_set_guest_vlan_id(char *vlan_id, struct users *u)
{
    char *port_str;
	uint64_t port_int;
	int portid, vlan = atoi(vlan_id);
	char *gust_enable;
	
	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return -1;
	}
	
	cli_str2bitmap(port_str, &port_int);
	gust_enable = nvram_safe_get("guest_vlan_enable");
	if(*gust_enable != '1')
	{
		vty_output("Failed!You have not enabled guest_vlan \n");
		free(gust_enable);
		return 0;	
	}
	
	if(vlan > 4096)
	{
		free(gust_enable);
        vty_output("Failed! because the number of vlan_id  shouldn't be largger than 4096\n");
        return 0;
	}
	
    memset(cur_dot1x_conf, 0, sizeof(cli_dot1x_conf)*PNUM);
    cli_nvram_conf_get(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
	for(portid = 1; portid<=PNUM; portid++)
	{
		if( port_int & (0x01ULL << portid))
		{
		    cur_dot1x_conf[portid-1].guest_id = vlan;
		}
    }
    cli_nvram_conf_set(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
    cli_nvram_conf_free(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);   
    
    system("/usr/bin/killall -SIGUSR1 vlinkscan >/dev/null 2>&1");
    system("/usr/bin/killall -SIGHUP hostapd > /dev/null 2>&1"); 		

	free(gust_enable);
	return CLI_SUCCESS; 
}


int nfunc_set_guest_vlan(struct users *u)
{
    int portid;
    char *port_str;
	uint64_t port_int;
	char *gust_enable;
	
	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return -1;
	}
	
	cli_str2bitmap(port_str, &port_int);
	gust_enable = nvram_safe_get("guest_vlan_enable");
	if(*gust_enable != '1')
	{
		free(gust_enable);
		vty_output("Failed!You have not enabled guest_vlan \n");
		return 0;	
	}

    memset(cur_dot1x_conf, 0, sizeof(cli_dot1x_conf)*PNUM);
    cli_nvram_conf_get(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
	for(portid = 1; portid<=PNUM; portid++)
	{
		if( port_int & (0x01ULL << portid) )
		{
		    cur_dot1x_conf[portid-1].guest_id = 0;
		}
    }
    cli_nvram_conf_set(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
    cli_nvram_conf_free(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);  
    system("/usr/bin/killall -SIGUSR1 vlinkscan >/dev/null 2>&1"); 
    system("/usr/bin/killall -SIGHUP hostapd > /dev/null 2>&1"); 		

	free(gust_enable);
	return CLI_SUCCESS; 
}

/*set the max number accessed in port*/
int func_set_dot1x_max_user(char *max,struct users *u)
{
	int portid;
	static int sum_user = 0;
	char *port_str, *p,*p1,*ptr, buff[1024];
	uint64_t port_int;
	char *auth_config;
	char port_buf[20];
	port_str = u->promptbuf;
//	p1 = u->promptbuf;
//	p1 = strchr(p1,'/');
//	p1++;
//	strcpy(port_buf,p1);
//	port_str = port_buf;
	if(0 == strlen(port_str)){
			return 0;
	}
	cli_str2bitmap(port_str, &port_int);

	auth_config = cli_nvram_safe_get(CLI_DOT1X_CONFIG, "dot1x_config");
	p = auth_config;
	for(portid = 1; portid<=PNUM; portid++){ 
		ptr = strchr(p, ';');
		p1 = p;
		if(*p=='2'||*p=='3'){
				if( port_int & (0x01ULL << phy[portid]) )
					{
						sum_user=sum_user+atoi(max);	
					}else{
						p1 = strchr(p1, ',');
						p1++;
						p1 = strchr(p1, ',');
						p1++;
						sum_user=sum_user+atoi(p1); 
					}
				if(sum_user>4096){
						vty_output("Failed! because the number of user in auto and force-authorated mode shouldn't be largger than 4096\n");
						return 0;
				}			
		}
		p = ptr + 1;
	}
	
	
	p = auth_config;
	memset(buff, '\0', sizeof(buff));
	for(portid = 1; portid<=PNUM; portid++)
	{
		if( port_int & (0x01ULL << phy[portid]) ){
			ptr = strchr(p, ';');
			p1 = p;
			p1 = strchr(p1, ',');
			p1++;
			p1 = strchr(p1, ',');
			strncat(buff, p, (p1-p+1));
			strcat(buff, max);
			strcat(buff, ";");
		}else{
			ptr = strchr(p, ';');
			strncat(buff, p, (ptr-p+1));
		}
		p = ptr + 1;
	}
	scfgmgr_set("dot1x_config", buff);
	cli_stop_dot1x();
	cli_start_dot1x();
	free(auth_config);
	return CLI_SUCCESS;
}

/* check all interface include trunk or not */
int cli_check_interface_trunk_group(struct users *u)
{
	int skfd, i, portid;
	uint64_t val64;
	
	uint64_t port_int;
	char *port_str;
	char port_buf[20],*p;
       port_str = u->promptbuf;
//	p = u->promptbuf;
//	p = strchr(p,'/');
//	p++;
//	strcpy(port_buf,p);

//	port_str = port_buf;
	if(0 == strlen(port_str)) {
		return CLI_SUCCESS;
	}

//	if( (port_type = getenv("CON_PORT")) != NULL ) {
//		if('p' == *port_type) {
//			return CLI_SUCCESS;
//		}
//	}

	cli_str2bitmap(port_str, &port_int);
	
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;

	for(i = 1; i <= CLI_TRUNK_GROUP; i++) {
		if(-1 == cli_get_port_trunk_status(skfd, i, &val64)) {
			close(skfd);
			return CLI_SUCCESS;
		}else
		{
			if( val64&port_int ) {
				for(portid = 1; portid <= PNUM; portid++) {
					if( val64&(0x1ULL<<phy[portid]) ){
						if(0 == ( port_int&(0x1ULL<<phy[portid])) ) {
							close(skfd);
							return CLI_FAILED;
						}
					}
				}
			}
		}
	}

	close(skfd);
	return CLI_SUCCESS;
}

/*remove set max user*/
void nfunc_set_max_user(struct users *u)
{
	int portid;
	char *port_str, *p,*p1,*ptr,buff[1024];
	uint64_t port_int;
	char port_buf[20];
	port_str = u->promptbuf;
//	p1 = u->promptbuf;
//	p1 = strchr(p1,'/');
//	p1++;
//	strcpy(port_buf,p1);
	char *auth_config = cli_nvram_safe_get(CLI_DOT1X_CONFIG, "dot1x_config");
//	port_str = port_buf;
	 if(0 == strlen(port_str))
	{
			return 0;
	 }
	cli_str2bitmap(port_str, &port_int);
	p = auth_config;
	memset(buff, '\0', sizeof(buff));
	for(portid = 1; portid<=PNUM; portid++)
	{
	ptr = strchr(p, ';');
	if( port_int & (0x01ULL << phy[portid]) )
	{
		p1 = p;
		p1 = strchr(p1, ',');
		p1++;
		p1 = strchr(p1, ',');
		strncat(buff, p, (p1-p+1));
		p1++;
		strcat(buff, "4096;");
	}
	else
		strncat(buff, p, (ptr-p+1));
	p = ptr + 1;
	}
	scfgmgr_set("dot1x_config",buff);
  free(auth_config);
  return CLI_SUCCESS;
}

/*
 *  Function:  func_port_gvrp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_gvrp(struct users *u)
{
	uint64_t port_int;
    int i, buffer = 0, mtu[PNUM];
	char *port_str, *gvrp_config;

  	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	gvrp_config = cli_nvram_safe_get(CLI_ALL_ZERO, "gvrp_config");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
			*(gvrp_config + (i-1)) = '1';
	}
	
	scfgmgr_set("gvrp_config", gvrp_config);
	system("killall -SIGUSR2 gvrpd  > /dev/null 2>&1 &");
	
	free(gvrp_config);
	return 0;
}

/*
 *  Function:  nfunc_port_gvrp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_gvrp(struct users *u)
{
	uint64_t port_int;
    int i, buffer = 0, mtu[PNUM];
	char *port_str, *gvrp_config;

  	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	gvrp_config = cli_nvram_safe_get(CLI_ALL_ZERO, "gvrp_config");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
			*(gvrp_config + (i-1)) = '0';
	}
	
	scfgmgr_set("gvrp_config", gvrp_config);
	system("killall -SIGUSR2 gvrpd  > /dev/null 2>&1 &");
	
	free(gvrp_config);
	return 0;
}

/*
 *  Function:  func_port_gmrp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_gmrp(struct users *u)
{
	uint64_t port_int;
    int i, buffer = 0, mtu[PNUM];
	char *port_str, *gmrp_config;

  	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	gmrp_config = cli_nvram_safe_get(CLI_ALL_ZERO, "gmrp_config");

	//printf("gmrp_config :%s\n",gmrp_config );
	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i)){
			if(*(gmrp_config + (i-1)) != '1'){
				*(gmrp_config + (i-1)) = '1';				
				COMMAND("rc gmrp restart > /dev/null 2>&1");
			}
		}
	}
	
	//printf("gmrp_config :%s\n",gmrp_config );
	scfgmgr_set("gmrp_config", gmrp_config);
	
	//COMMAND("killall -SIGUSR2 gmrpd  > /dev/null 2>&1 &");
	free(gmrp_config);
	
	return 0;
}

/*
 *  Function:  nfunc_port_gmrp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_gmrp(struct users *u)
{
	uint64_t port_int;
    int i, buffer = 0, mtu[PNUM];
	char *port_str, *gmrp_config;

  	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	gmrp_config = cli_nvram_safe_get(CLI_ALL_ZERO, "gmrp_config");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
			*(gmrp_config + (i-1)) = '0';
	}
	
	scfgmgr_set("gmrp_config", gmrp_config);
	system("killall -SIGUSR2 gvrpd  > /dev/null 2>&1 &");
	
	free(gmrp_config);
	return 0;
}

/*
 *  Function:  func_ip_router_isis
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ip_router_isis(struct users *u)
{
	printf("do func_ip_router_isis here\n");

	return 0;
}

/*
 *  Function:  nfunc_ip_router_isis
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_ip_router_isis(struct users *u)
{
	printf("do nfunc_ip_router_isis here\n");

	return 0;
}

/*
 *  Function:  func_port_ipv6_nd_cache_expire
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ipv6_nd_cache_expire(struct users *u)
{
	printf("do func_port_ipv6_nd_cache_expire here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ipv6_nd_cache_expire
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ipv6_nd_cache_expire(struct users *u)
{
	printf("do nfunc_port_ipv6_nd_cache_expire here\n");

	return 0;
}

/*
 *  Function:  func_port_ipv6_router_ospf_area
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ipv6_router_ospf_area(struct users *u)
{
	printf("do func_port_ipv6_router_ospf_area here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ipv6_router_ospf_area
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ipv6_router_ospf_area(struct users *u)
{
	printf("do nfunc_port_ipv6_router_ospf_area here\n");

	return 0;
}

/*
 *  Function:  func_port_ipv6_router_rip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ipv6_router_rip(struct users *u)
{
	printf("do func_port_ipv6_router_rip here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ipv6_router_rip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ipv6_router_rip(struct users *u)
{
	printf("do nfunc_port_ipv6_router_rip here\n");

	return 0;
}

/*
 *  Function:  func_port_ipv6_router_isis
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ipv6_router_isis(struct users *u)
{
	printf("do func_port_ipv6_router_isis here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ipv6_router_isis
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ipv6_router_isis(struct users *u)
{
	printf("do nfunc_port_ipv6_router_isis here\n");

	return 0;
}


/*
 *  Function:  func_port_ip_igmp_join_group
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_igmp_join_group(struct users *u)
{
	printf("do func_port_ip_igmp_join_group here\n");

	return 0;
}

int func_port_ip_igmp_join_group_in(struct users *u)
{
	printf("do func_port_ip_igmp_join_group_in here\n");

	return 0;
}

int func_port_ip_igmp_join_group_ex(struct users *u)
{
	printf("do func_port_ip_igmp_join_group_ex here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_igmp_join_group
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_igmp_join_group(struct users *u)
{
	printf("do nfunc_port_ip_igmp_join_group here\n");

	return 0;
}

int nfunc_port_ip_igmp_join_group_in(struct users *u)
{
	printf("do nfunc_port_ip_igmp_join_group_in here\n");

	return 0;
}

int nfunc_port_ip_igmp_join_group_ex(struct users *u)
{
	printf("do nfunc_port_ip_igmp_join_group_ex here\n");

	return 0;
}

/*
 *  Function:  func_port_ip_igmp_querier_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_igmp_querier_time(struct users *u)
{
	printf("do func_port_ip_igmp_querier_time here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_igmp_querier_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_igmp_querier_time(struct users *u)
{
	printf("do nfunc_port_ip_igmp_querier_time here\n");

	return 0;
}

/*
 *  Function:  func_port_ip_igmp_last_query_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_igmp_last_query_time(struct users *u)
{
	printf("do func_port_ip_igmp_last_query_time here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_igmp_last_query_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_igmp_last_query_time(struct users *u)
{
	printf("do nfunc_port_ip_igmp_last_query_time here\n");

	return 0;
}

/*
 *  Function:  func_port_ip_igmp_query_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_igmp_query_time(struct users *u)
{
	printf("do func_port_ip_igmp_query_time here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_igmp_query_time
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_igmp_query_time(struct users *u)
{
	printf("do nfunc_port_ip_igmp_query_time here\n");

	return 0;
}

/*
 *  Function:  func_port_ip_igmp_static_all
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_igmp_static_all(struct users *u)
{
	printf("do func_port_ip_igmp_static_all here\n");

	return 0;
}

/*
 *  Function:  func_port_ip_igmp_static_all_in
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_igmp_static_all_in(struct users *u)
{
	printf("do func_port_ip_igmp_static_all_in here\n");

	return 0;
}

/*
 *  Function:  func_port_ip_igmp_static_group
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_igmp_static_group(struct users *u)
{
	printf("do func_port_ip_igmp_static_group here\n");

	return 0;
}

/*
 *  Function:  func_port_ip_igmp_static_group_in
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_igmp_static_group_in(struct users *u)
{
	printf("do func_port_ip_igmp_static_group_in here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_igmp_static_all
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_igmp_static_all(struct users *u)
{
	printf("do nfunc_port_ip_igmp_static_all here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_igmp_static_all_in
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_igmp_static_all_in(struct users *u)
{
	printf("do nfunc_port_ip_igmp_static_all_in here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_igmp_static_group
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_igmp_static_group(struct users *u)
{
	printf("do nfunc_port_ip_igmp_static_group here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_igmp_static_group_in
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_igmp_static_group_in(struct users *u)
{
	printf("do nfunc_port_ip_igmp_static_group_in here\n");

	return 0;
}

/*
 *  Function:  func_port_ip_igmp_version
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_igmp_version_1(struct users *u)
{
	printf("do func_port_ip_igmp_version_1 here\n");

	return 0;
}

int func_port_ip_igmp_version_2(struct users *u)
{
	printf("do func_port_ip_igmp_version_2 here\n");

	return 0;
}

int func_port_ip_igmp_version_3(struct users *u)
{
	printf("do func_port_ip_igmp_version_3 here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_igmp_version
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_igmp_version(struct users *u)
{
	printf("do nfunc_port_ip_igmp_version here\n");

	return 0;
}

/*
 *  Function:  func_port_ip_pim
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_pim(struct users *u)
{
	printf("do func_port_ip_pim here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_pim
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_pim(struct users *u)
{
	printf("do nfunc_port_ip_pim here\n");

	return 0;
}

/*
 *  Function:  func_port_ip_pim_bsr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_pim_bsr(struct users *u)
{
	printf("do func_port_ip_pim_bsr here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_pim_bsr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_pim_bsr(struct users *u)
{
	printf("do nfunc_port_ip_pim_bsr here\n");

	return 0;
}

/*
 *  Function:  func_port_ip_pim_dr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_ip_pim_dr(struct users *u)
{
	printf("do func_port_ip_pim_dr here\n");

	return 0;
}

/*
 *  Function:  nfunc_port_ip_pim_dr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_ip_pim_dr(struct users *u)
{
	printf("do nfunc_port_ip_pim_dr here\n");

	return 0;
}

/*
 *  Function:  func_port_lldp_transmit
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_lldp_transmit(struct users *u)
{
	uint64_t port_int;
    int i, buffer = 0, mtu[PNUM];
	char *port_str, *lldp_tx;

  	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	lldp_tx = cli_nvram_safe_get(CLI_ALL_ONE, "lldp_tx");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
			*(lldp_tx + (i-1)) = '1';
	}
	
	scfgmgr_set("lldp_tx", lldp_tx);
	system("rc lldp restart > /dev/null 2>&1");
	
	free(lldp_tx);
}

/*
 *  Function:  nfunc_port_lldp_transmit
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_lldp_transmit(struct users *u)
{
	uint64_t port_int;
    int i, buffer = 0, mtu[PNUM];
	char *port_str, *lldp_tx;

  	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	lldp_tx = cli_nvram_safe_get(CLI_ALL_ONE, "lldp_tx");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
			*(lldp_tx + (i-1)) = '0';
	}
	
	scfgmgr_set("lldp_tx", lldp_tx);
	system("rc lldp restart > /dev/null 2>&1 ");
	
	free(lldp_tx);
}

/*
 *  Function:  func_port_lldp_receive
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_lldp_receive(struct users *u)
{
	uint64_t port_int;
    int i, buffer = 0, mtu[PNUM];
	char *port_str, *lldp_rx;

  	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	lldp_rx = cli_nvram_safe_get(CLI_ALL_ONE, "lldp_rx");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
			*(lldp_rx + (i-1)) = '1';
	}
	
	scfgmgr_set("lldp_rx", lldp_rx);
	system("rc lldp restart > /dev/null 2>&1 ");
	
	free(lldp_rx);
	return 0;
}

/*
 *  Function:  nfunc_port_lldp_receive
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int nfunc_port_lldp_receive(struct users *u)
{
	uint64_t port_int;
    int i, buffer = 0, mtu[PNUM];
	char *port_str, *lldp_rx;

  	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	lldp_rx = cli_nvram_safe_get(CLI_ALL_ONE, "lldp_rx");

	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
			*(lldp_rx + (i-1)) = '0';
	}
	
	scfgmgr_set("lldp_rx", lldp_rx);
	system("rc lldp restart > /dev/null 2>&1 ");
	
	free(lldp_rx);
	return 0;
}

/*
 *  Function:  func_port_tunnel_stp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_port_tunnel_stp(struct users *u)
{
    int i;
	uint64_t port_int;
	char *port_str, *port_l2tp;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
//	fprintf(stderr, "port_str  %s\n", port_str);
	cli_str2bitmap(port_str, &port_int);
//	fprintf(stderr, "[%s:%d] get port link: 0x%08x%08x\n", __FUNCTION__, __LINE__, (uint32)(port_int >> 32), (uint32)port_int);
		
	port_l2tp  = cli_nvram_safe_get(CLI_ALL_ZERO,  "port_l2tp");
	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
			*(port_l2tp+i-1) = '0';
		}
	}
	scfgmgr_set("port_l2tp", port_l2tp);
	system("rc l2tp start > /dev/null 2>&1");
	free(port_l2tp);
	return 0;
}

int nfunc_port_tunnel_stp(struct users *u)
{
    int i;
	uint64_t port_int;
	char *port_str, *port_l2tp;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
//	fprintf(stderr, "port_str  %s\n", port_str);
	cli_str2bitmap(port_str, &port_int);
//	fprintf(stderr, "[%s:%d] get port link: 0x%08x%08x\n", __FUNCTION__, __LINE__, (uint32)(port_int >> 32), (uint32)port_int);
		
	port_l2tp  = cli_nvram_safe_get(CLI_ALL_ZERO,  "port_l2tp");
	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
			*(port_l2tp+i-1) = '1';
		}
	}
	scfgmgr_set("port_l2tp", port_l2tp);
	system("rc l2tp start > /dev/null 2>&1");
	free(port_l2tp);
	return 0;
}

/*
 *  Function:  func_sw_ring
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_sw_ring(struct users *u)
{
    char *port_str;
	uint64_t port_int; 
    cli_ring_conf conf;
	int portid, ringid, count = 0, type;
    
    cli_param_get_int(STATIC_PARAM, 0, &ringid, u);
//	fprintf(stderr, "[%s:%d] ringid %d\n", __FUNCTION__, __LINE__, ringid);
	
	if (prase_port_map(u) == CLI_FAILED)
		return 0;
		
	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	cli_str2bitmap(port_str, &port_int);
//	fprintf(stderr, "[%s:%d] port_int: 0x%08x%08x\n", __FUNCTION__, __LINE__, (uint32)(port_int >> 32), (uint32)port_int);

    memset(&conf, '\0', sizeof(cli_ring_conf));
    cli_nvram_conf_get(CLI_RING_INFO, (unsigned char *)&conf);
    
	if((conf.ident[0] != ringid)&&(conf.ident[1] != ringid))
	{
	    vty_output("no this exit ring entry with id %d!\n", ringid);
		return -1;
	}

	for(portid = 1; portid <= PNUM; portid++) 
	{
		if( port_int & (0x01ULL << portid))
		{
			count++;
		}
	}
	
	if(conf.ident[0] == ringid)
	{
	    if((conf.type == 1)&&(count > 2))
    	{
    	    vty_output("single ring only two ports!\n");
    		return -1;
    	}
    	
    	if(2 == count)
    	{
            count = 0;
            for(portid = 1; portid <= PNUM; portid++) 
        	{
        		if( port_int & (0x01ULL << portid))
        		{
        			conf.ports[count++] = portid;
        		}
        	}
    	}else 
    	{
    	    if(conf.ports[0] == 0)
                count = 0;
            else
                count = 1;
                
            for(portid = 1; portid <= PNUM; portid++) 
        	{
        		if( port_int & (0x01ULL << portid))
        		{
        			conf.ports[count] = portid;
        		}
        	}
    	}  
    	
    	if((conf.ports[0] != 0) && (conf.ports[1] != 0)) 
    	    conf.enable = 1;
    	else    
    	    conf.enable = 0;
	    
	}else if(conf.ident[1] == ringid)
	{
	    if((conf.type == 2)&&(count > 1))
    	{
    	    vty_output("coupling ring only one port!\n");
    		return -1;
    	}else if((conf.type == 1)&&(count > 2))
    	{
    	    vty_output("double ring only two ports!\n");
    		return -1;
    	}
    	
    	if(2 == count)
    	{
            count = 2;
            for(portid = 1; portid <= PNUM; portid++) 
        	{
        		if( port_int & (0x01ULL << portid))
        		{
        			conf.ports[count++] = portid;
        		}
        	}
    	}else 
    	{
    	    if((conf.ports[2] == 0)||(conf.type == 2))
                count = 2;
            else
                count = 3;
                
            for(portid = 1; portid <= PNUM; portid++) 
        	{
        		if( port_int & (0x01ULL << portid))
        		{
        			conf.ports[count] = portid;
        		}
        	}
    	}  
	}
	     
    cli_nvram_conf_set(CLI_RING_INFO, (unsigned char *)&conf);
    system("rc rstp restart");
    
	return 0;
}

int nfunc_sw_ring(struct users *u)
{
    scfgmgr_set("ring", "0"); 
    scfgmgr_set("ring_type", "0");   
    scfgmgr_set("ring_ident", "0:0");  
    scfgmgr_set("ring_config", "0:0:0:0:");     

    system("rc rstp restart > /dev/null 2>&1");
	return 0;
}

int func_port_mtu(struct users *u)
{
	uint64_t port_int;
    int i, buffer = 0, mtu[PNUM];
	char *port_str, *mtu_str, *config, mtuconig[512];

  	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	mtu_str  = cli_nvram_safe_get(CLI_COMMA,  "port_mtu");

    config = mtu_str;
    memset(mtuconig, '\0', sizeof(mtuconig));
	for(i = 1; i <= PNUM; i++) 
	{
        mtu[i-1] = atoi(config);
        config = strchr(config, ',')+1;
		if(port_int & (0x01ULL << i))
			mtu[i-1] = buffer;
		sprintf(mtuconig, "%s%d,", mtuconig, mtu[i-1]);
	}
	
	scfgmgr_set("port_mtu", mtuconig);
	system("rc mtu start  > /dev/null 2>&1 &");
	free(mtu_str);
	
  	return 0;
}

int nfunc_port_mtu(struct users *u)
{
    FILE *fp;
	uint64_t port_int;
    int i, buffer = 0, mtu[PNUM];
	char *port_str, *mtu_str, *config, mtuconig[512];

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	mtu_str  = cli_nvram_safe_get(CLI_COMMA,  "port_mtu");

    config = mtu_str;
    memset(mtuconig, '\0', sizeof(mtuconig));
	for(i = 1; i <= PNUM; i++) 
	{
        mtu[i-1] = atoi(config);
        config = strchr(config, ',')+1;
		if(port_int & (0x01ULL << i))
			mtu[i-1] = 1500;
		sprintf(mtuconig, "%s%d,", mtuconig, mtu[i-1]);
	}
	
	scfgmgr_set("port_mtu", mtuconig);
	system("rc mtu start  > /dev/null 2>&1 &");
	free(mtu_str);
	
  	return 0;
}


int func_sw_qinq_mode(struct users *u, int mode)
{
	int i, portid, flag = 0;
	uint64_t port_int;
	char *port_str, *qinq_config;
	char *p1, *p2, *vlantrans;
	char pconf[PNUM][256], qinq_trans[8192];
	
    /* prase multi port map */
	if( prase_port_map(u) == CLI_FAILED )
		return 0;

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	cli_str2bitmap(port_str, &port_int);
	qinq_config = cli_nvram_safe_get(CLI_ALL_ONE,  "qinq_config");
	
	memset(pconf, '\0', sizeof(pconf));
	memset(qinq_trans, '\0', sizeof(qinq_trans));
	vlantrans = nvram_safe_get("qinq_trans");
	if(strchr(vlantrans, ';') != NULL)
    {
        i = 0;
        p1 = vlantrans;
        while((p2 = strchr(p1, ';')) != NULL)
    	{
    	    memcpy(pconf[i], p1, p2-p1);
    	    p1 = p2+1;
    	    i++;
    	}
    }
    free(vlantrans);
	
	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
		    if(3 == mode)
		    {    
			    if(*(qinq_config+i-1) != '3')
			    {
    			    *(qinq_config+i-1) = '3';
    			    flag = 1;
    			}
			}
			else if(2 == mode)
		    {    
			    if(*(qinq_config+i-1) != '2')
			    {
    			    *(qinq_config+i-1) = '2';
    			    flag = 1;
    			}
			}  
			else
			{
			    if(*(qinq_config+i-1) != '1')
    		    {    
    			    *(qinq_config+i-1) = '1';
    			    flag = 1;
    			}     
			}  
			
			if(0 == flag)
        	{    
            	strcat(qinq_trans, pconf[i-1]);
            	strcat(qinq_trans, ";");
            }
			else
        	    strcat(qinq_trans, ";");   
		}
		else
    	{    
        	strcat(qinq_trans, pconf[i-1]);
        	strcat(qinq_trans, ";");
        }
	}
	
	if(1 == flag)
	{    
    	scfgmgr_set("qinq_config", qinq_config);  
	    scfgmgr_set("qinq_trans", qinq_trans);
    	system("rc qinq restart > /dev/null 2>&1");
    }
    free(qinq_config);

	return 0;
}	

int func_sw_qinq_trans(struct users *u)
{
	uint64_t port_int;
    int i, vid = 0, mode[PNUM+1];
	char *p1, *p2, *port_str, *vlantrans, *qinq_config;
	char pconf[PNUM][256], line[256], qinq_trans[8192], buffer[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(STATIC_PARAM, 0, buffer, u);
  	cli_param_get_int(STATIC_PARAM, 0, &vid, u);

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}
	
	if(1 != cli_param_int32_multi_format(buffer, 1, VLAN_MAX_NUM, u))
    {
    	vty_output("Invalid vlan format, the vlan range is 1-%d, please reset!!\n", VLAN_MAX_NUM);
    	return 0;
    }
	
	cli_str2bitmap(port_str, &port_int);
	qinq_config = cli_nvram_safe_get(CLI_ALL_ONE,  "qinq_config");
	for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
    	    if(mode[i] == '3')
    	    {
    	        p1 = strchr(buffer, ',');
    	        p2 = strchr(buffer, '-');
    	        
    	        if((p1 != NULL) || (p2 != NULL))
    	        {
#if (XPORT==0)	
        			if(i <= FNUM)
        				vty_output("Error: interface F0/%d ", i); 
        			else
        				vty_output("Error: interface G0/%d ", (i-FNUM)); 
#endif		
#if (XPORT==1)
        			if(i <= GNUM)
        				vty_output("Error: interface G0/%d ", i); 
        			else
        				vty_output("Error: interface T0/%d ", (i-GNUM)); 
#endif		
				
                	vty_output("flat mode only supporte one-vlan tranlate to another-vlan!!\n\n");
                    free(qinq_config);
                	return 0;
                }
    	    }
    	}
	}
	free(qinq_config);
	
	memset(pconf, '\0', sizeof(pconf));
	memset(qinq_trans, '\0', sizeof(qinq_trans));
	vlantrans = nvram_safe_get("qinq_trans");
	if(strchr(vlantrans, ';') != NULL)
    {
        i = 0;
        p1 = vlantrans;
        while((p2 = strchr(p1, ';')) != NULL)
    	{
    	    memcpy(pconf[i], p1, p2-p1);
    	    p1 = p2+1;
    	    i++;
    	}
    }
    free(vlantrans);
    
    for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
	        memset(line, '\0', sizeof(line));
            if(strlen(pconf[i-1]) == 0)
                sprintf(line, "%s:%d", buffer, vid);
            else
                sprintf(line, "/%s:%d", buffer, vid);
            strcat(pconf[i-1], line);     
    	}
    	strcat(qinq_trans, pconf[i-1]);
    	strcat(qinq_trans, ";");
	}
//    fprintf(stderr, "[%s:%d] qinq_trans %s\n", __FUNCTION__, __LINE__, qinq_trans);   
    
	scfgmgr_set("qinq_trans", qinq_trans);
	system("rc qinq restart > /dev/null 2>&1");
    
  	return 0;
}	


int func_mapping_trans(struct users *u)
{
	int skfd;
    int vid_first = 0, vid_second = 0, vid_des = 0;
    char buffer[MAX_ARGV_LEN] = {'\0'};
	int i = 0, ret = 0;
	char *port_str = NULL;
	uint64_t port_int;

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0)
		return CLI_FAILED;

	cli_param_get_int(STATIC_PARAM, 0, &vid_first, u);	
	cli_param_get_int(STATIC_PARAM, 1, &vid_second, u);
	cli_param_get_int(STATIC_PARAM, 2, &vid_des, u);

	if(!vid_des)
	{
		vid_des = vid_second;
		vid_second = 0;
	}
	
//	cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);
	port_str = u->promptbuf;

	if(0 == strlen(port_str)){
		close(skfd);
	  	return CLI_FAILED;
	}
	
	cli_str2bitmap(port_str, &port_int);

	for(i=0; i<28; i++)
		if(port_int & (0x01ULL << i))	
		{
			if(!vid_second)
				bcm_port_doubletag_set(skfd, i, vid_first, vid_second, vid_des, 2);			
			else
				bcm_port_doubletag_set(skfd, i, vid_first, vid_second, vid_des, 3);
		}
    
	close(skfd);
	
    return 0;

}

int nfunc_mapping_trans(struct users *u)
{	
	int skfd;
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0)
		return CLI_FAILED;
	
	bcm_port_doubletag_delete_all(skfd, 1);
	
	close(skfd);
	return 0;
}


int nfunc_sw_qinq_trans(struct users *u)
{
	uint64_t port_int;
    int i, vid = 0, mode[PNUM+1];
	char *p1, *p2, *port_str, *vlantrans;
	char pconf[PNUM][256], qinq_trans[8192];

	port_str = u->promptbuf;
	if(0 == strlen(port_str)) {
		return 0;
	}

	cli_str2bitmap(port_str, &port_int);

	memset(pconf, '\0', sizeof(pconf));
	memset(qinq_trans, '\0', sizeof(qinq_trans));
	vlantrans = nvram_safe_get("qinq_trans");
	if(strchr(vlantrans, ';') != NULL)
    {
        i = 0;
        p1 = vlantrans;
        while((p2 = strchr(p1, ';')) != NULL)
    	{
    	    memcpy(pconf[i], p1, p2-p1);
    	    p1 = p2+1;
    	    i++;
    	}
    }
    free(vlantrans);
    
    for(i = 1; i <= PNUM; i++) 
	{
		if(port_int & (0x01ULL << i))
		{
        	strcat(qinq_trans, ";");
    	}else
    	{    
        	strcat(qinq_trans, pconf[i-1]);
        	strcat(qinq_trans, ";");
        }
	}
	
//    fprintf(stderr, "[%s:%d] qinq_trans %s\n", __FUNCTION__, __LINE__, qinq_trans);   
	scfgmgr_set("qinq_trans", qinq_trans);
	system("rc qinq restart > /dev/null 2>&1");
    
  	return 0;
}	
