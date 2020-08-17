/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_clock_func.c
 * Function   : show command function
 * Auther     : dawei.hu
 * Version    : 1.0
 * Date       : 2011/11/21
 *                                         
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

#include "cli_clock_func.h"
#include "bcmutils.h"

static int start_ntp()
{
    int interval;
    char *pt=nvram_safe_get("time_ntp");
    char *time_server=nvram_safe_get("time_server");
    char *ntp_sleeptime = nvram_safe_get("ntp_sleeptime");
	
    if(strlen(ntp_sleeptime)>0)
    {
    	interval = atoi(ntp_sleeptime);
    }
    else
    {
    	interval = 1;
    	nvram_set("ntp_sleeptime", "1");
    }
	
    if( *pt == '1' && strlen(time_server)>0)
    {
    	system("/usr/bin/killall ntp  > /dev/null 2>&1");
    	SYSTEM("/usr/sbin/ntp %d -h %s& ",  interval, time_server);
    }
	
    free(pt);
    free(time_server);
    free(ntp_sleeptime);
	
	return 0;
}

int stop_ntp(void)
{
	nvram_set("time_ntp", "0");
	nvram_set("time_server", "");
	nvram_set("ntp_sleeptime", "");
	SYSTEM("/usr/bin/killall ntp  > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Stop the NTP, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

#if 0                  
static int cli_start_qinq()
{
    int i, skfd;
    uint16 tpid;
    uint64_t qinq_maps = 0x00ULL;
    char qinq_config[PNUM+1];
    char *qinq_tpid, *link_type;
    
    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
            return -1;
            
    memset(qinq_config, '\0', PNUM+1);
    
	qinq_tpid = nvram_safe_get("qinq_tpid");
	link_type = cli_nvram_safe_get(CLI_ALL_ONE, "vlan_link_type");	
	
	for(i = 0; i < PNUM; i++)
	{
	    if(*(link_type+i) == '3')
	        qinq_config[i] = '1';
	    else
	        qinq_config[i] = '2';
    }
    
    nvram_set("qinq_enable", "1");    
    nvram_set("qinq_config", qinq_config);
    if(!strlen(qinq_tpid))
        nvram_set("qinq_tpid", "33024");
	
	for(i = 1; i <= PNUM; i++)
	{
        if(qinq_config[i-1] == '1')
            qinq_maps |= (0x01ULL << phy[i]);							
    }
    
    tpid = (strlen(qinq_tpid) == 0) ? 0x8100 : atoi(qinq_tpid);
        
    set_vlan_qinq_tpid(skfd, tpid);
    set_vlan_qinq_portmap(skfd, qinq_maps);
    set_trusted_cvlan_portmap_enable(skfd, 0);
    set_vlan_qinq_enable(skfd,  1);
		
    SYSTEM("echo 0x%04x > /proc/qinq", tpid);
				
    free(qinq_tpid);
    free(link_type);

    /* remove CFP entry for access port drop tag packet */
    drop_packet_with_tag(skfd, CFP_DROP_TAG, 0x0ULL);

    close(skfd); 
    return 0;
} 


/*
 *  Function : cli_drop_access_tag
 *  Purpose:
 *     set cfp for access port drop tag packet
 *  Parameters:
 *     skfd  -  socket id
 *  Returns:
 *
 *  Author  : eagles.zhou
 *  Date    :2011/2/14 (Valentine's Day ^_^)
 */
static void cli_drop_access_tag(int skfd)
{
	int portid;
	uint64_t access_port_int = 0x0ULL;

	memset(cur_port_conf, 0, sizeof(cli_port_conf)*PNUM);
	cli_nvram_conf_get(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);

	for(portid = 1; portid <= PNUM; portid++) {
		if('1' == cur_port_conf[portid-1].mode)
			access_port_int |= (0x01ULL << phy[portid]);
	}
	cli_nvram_conf_free(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);

	drop_packet_with_tag(skfd, CFP_DROP_TAG, access_port_int);

	return;
}

static int cli_stop_qinq()
{
    int skfd;
    
    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
            return -1;
    
    set_MII_Frm_FwdMap_Chk(skfd, 1);
	
	set_vlan_qinq_portmap(skfd, 0x00ULL);
	set_trusted_cvlan_portmap_enable(skfd, 1);
    set_vlan_qinq_enable(skfd, 0);
	SYSTEM("echo 0x0000 > /proc/qinq");
	
	close(skfd);
    return 0;
}

static int cli_set_qinq_disable()
{
    int skfd;

    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0)
            return -1;

    set_MII_Frm_FwdMap_Chk(skfd, 1);

	set_vlan_qinq_portmap(skfd, 0x00ULL);
	set_trusted_cvlan_portmap_enable(skfd, 1);
    set_vlan_qinq_enable(skfd, 0);
	SYSTEM("echo 0x0000 > /proc/qinq");

	nvram_set("qinq_enable", "0");

	/* when qinq is disable, access port drop tag packet by CFP */
	cli_drop_access_tag(skfd);

	close(skfd);
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Disable the QINQ function, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return 0;
}
#endif

/*
 *  Function: func_clock
 *  Purpose:   Setup time
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/24
 */

int func_clock(struct users *u)
{
	char command[35]; 
	char *timezone;
	int offset;	
	struct timeval tv;
	struct timezone tz;	
	char buff[MAX_ARGV_LEN] = {'\0'};
	int day = 0, month = 0, year = 0;
	
	cli_param_get_string(STATIC_PARAM, 0, buff, u); 
	cli_param_get_int(STATIC_PARAM, 0, &day, u);
	cli_param_get_int(STATIC_PARAM, 1, &month, u);
	cli_param_get_int(STATIC_PARAM, 2, &year, u);
	
	/*wuchunli 2012-4-16 9:31:16 begin 
	  modify format*/
	switch (month) {
		case 2:
			if (0 == year % 4) {
				if (day > 29) {
					vty_output("Invalid day format!\n");
					return 0;	
				}
			} else {
				if (day > 28) {
					vty_output("Invalid day format!\n");
					return 0;	
				}
			}
			break;
		case 4:
		case 6:
		case 9:
		case 11:
			if (day > 30) {
				vty_output("Invalid day format!\n");
				return 0;	
			}
			break;
		default:
			break;
	}	
	
	sprintf(command, "/bin/date -s \"%d-%02d-%02d %s\"", year, month, day, buff);
	system(command);

	timezone = nvram_safe_get("time_zone");
	gettimeofday (&tv , &tz);
	tv.tv_sec -= time_adjust(timezone)*60;
	settimeofday(&tv, &tz);
	free(timezone);
    system("rtc write  > /dev/null 2>&1");   
    
	return 0;
}  

/*
 *  Function: func_clock
 *  Purpose:   Setup timezone
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/24
 */

int func_timezone(struct users *u)
{
	struct timeval tv;
	struct timezone tz;
	char buff[MAX_ARGV_LEN] = {'\0'};
	char offset[4];
	int timeoffset = 0;

	cli_param_get_string(STATIC_PARAM, 0, buff, u);
//	cli_param_get_string(STATIC_PARAM, 1, offset, u);
	cli_param_get_int(STATIC_PARAM, 0, &timeoffset, u);
	
	if (timeoffset > 12 || timeoffset < -12) {
		vty_output("  Invalid Input, Offset out of range\n");
		return -1;
	}	
	
	if(timeoffset >= 0)
        sprintf(buff, "GTM+%d", timeoffset);
    else
        sprintf(buff, "GTM%d", timeoffset);
            
	nvram_set("time_zone", buff);

//	/* modified by gujiajie on 05/14/2012 */
//	gettimeofday(&tv, &tz);
//	tz.tz_minuteswest = -timeoffset* 60;
//	settimeofday(&tv, &tz);
	/* modified by gujiajie end */

//	sprintf(offset, "%d", timeoffset);
//	nvram_set("time_offset", offset);

	syslog(LOG_NOTICE, "[CONFIG-5-TIMEZONE]: Time_zone %s 's Hours offset from UTC was set to %s, %s\n", buff, offset, getenv("LOGIN_LOG_MESSAGE"));

	return 0;			   
}

/*
 *  Function: nfunc_clock
 *  Purpose:  Undo setup time zone
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/24
 */

int nfunc_timezone(struct users *u)
{
	nvram_set("time_zone","gmt");
	nvram_set("time_offset","+0");
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set the time_zone to GMT and time_offset to 0, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

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
	ip_two = strsep(&ip_add,".");
	ip_thr = strsep(&ip_add,".");
	if (atoi(ip_add) == 255 || atoi(ip_add) == 0) {
		return 1;
	}	
	return 0;
}

/*
 *  Function: func_ntp_server
 *  Purpose:  set ntp server IP
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/9
 */
int func_ntp_server(struct users *u)
{
	struct in_addr s;
	int valid;
	char ip_addr[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_ipv4(STATIC_PARAM, 0, &s, ip_addr, sizeof(ip_addr), u);
	valid = check_ipaddr(ip_addr);
	if (valid == 1) {
		vty_output("Invalid ip address\n");
		return 0;
	}
	cli_param_get_ipv4(STATIC_PARAM, 0, &s, ip_addr, sizeof(ip_addr), u);

	nvram_set("time_server", ip_addr);
	nvram_set("time_ntp", "1");
	start_ntp();
	syslog(LOG_NOTICE, "[CONFIG-5-NTP]: The NTP server IP was set to %s, %s\n", ip_addr, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

/*
 *  Function: func_ntp_time
 *  Purpose:  set ntp server query time
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/9
 */
int func_ntp_time(struct users *u)
{
	int time = 0;
	cli_param_get_int(STATIC_PARAM, 0, &time, u);
	char timestr[MAX_ARGV_LEN] = {"\0"};
	sprintf(timestr, "%d", time);
	
	nvram_set("ntp_sleeptime", timestr);
	start_ntp();
	syslog(LOG_NOTICE, "[CONFIG-5-NTP]: The interval to query NTP server was set to %s, %s\n",timestr, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}
/*
 *  Function: nfunc_ntp
 *  Purpose:  Undo ntp set
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/9
 */
int nfunc_ntp(struct users *u)
{
	stop_ntp();
	
	return 0;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  nfunc_ntp_query
 *  Description:  no function of query_interval
 * 		 Author:  gujiajie
 *		   Date:  05/04/2012
 * =====================================================================================
 */
int nfunc_ntp_query(struct users *u)
{
	nvram_set("ntp_sleeptime", "1");
	start_ntp();
	syslog(LOG_NOTICE, "[CONFIG-5-NTP]: The interval to query NTP server was set to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

#if 0
int func_config_dot1q(struct users *u)
{
	cli_stop_qinq();
	cli_start_qinq();

	return 0;
}

int nfunc_config_dot1q(struct users *u)
{
	cli_set_qinq_disable();

	return 0;
}
#endif
