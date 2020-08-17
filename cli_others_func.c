#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/stat.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/file.h>
#include <syslog.h>
#include <termios.h>
#include <netdb.h>
#include <math.h>
#include <arpa/inet.h>

#include "console.h"
#include "cmdparse.h"
#include "parameter.h"
#include "bcmutils.h"
#include "acl_utils.h"
#include "cli_others_func.h"

/* eagles 2016 */
static int cli_set_dos_access_address(int skfd,uint32 addr)
{
	return 0;
}

int func_traceroute(struct users *u)
{
	printf("Flags:  ! -  ICMP_UNREACH_PORT       	 	!N - ICMP_UNREACH_NET\n");
	printf("	!H - ICMP_UNREACH_HOST 			!P - ICMP_UNREACH_PROTOCOL\n");
	printf("	!F - ICMP_UNREACH_NEEDFRAG 		!S - ICMP_UNREACH_SRCFAIL\n");
	printf("-----+-----------+-------------------------------------------------------------\n");
	
	char buf[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(STATIC_PARAM, 0, buf, u);
	SYSTEM("/usr/bin/traceroute %s", buf);	
	return 0;
}

static int cli_set_dos_protect(int enable)
{
	TCAMDATA tcam;
	
	int skfd;
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return 0;
	
	/* eagles 2016 */

	close(skfd);
	syslog(LOG_NOTICE, "[CONFIG-5-DOS]: Open the protect from DOS attact, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int func_anti_dos_ena(struct users *u)
{
    cli_set_dos_protect(1);
    return 0;
}

int func_exec_timeout(struct users *u)
{
	int buffer = 0, i;
	char buf[128] = {'\0'}, *login_timeout = NULL;	/*add by wei.zhang*/
	char *p = buf, temp_buf[8];
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);
	
	u->exec_timeout = buffer;
	
	login_timeout = nvram_safe_get("login_timeout");
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "%s", login_timeout);
	for(i = 0; i < 17; i++)
		p = strchr( p, ':' ) + 1;
	bzero(p, sizeof(p));
	bzero(temp_buf, sizeof(temp_buf));
	snprintf(temp_buf, sizeof(temp_buf), "%d;", buffer);
	strcat(buf, temp_buf);
	nvram_set("login_timeout",buf);
	syslog(LOG_NOTICE, "[CONFIG-5-EXEC]: login_exec_timeout is set %d\n", u->exec_timeout);
	free(login_timeout);
	
	return 0;
}

int func_flow_interval(struct users *u)
{
	int buffer = 0, i;
	char buf[128] = {'\0'}, *login_timeout = NULL;	/*add by wei.zhang*/
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);
	
	login_timeout = nvram_safe_get(NVRAM_STR_FLOW_INTERVAL);
	if(login_timeout == NULL)
	    return 0;
	//vty_output("The func_flow_interval is %d(s)\n", login_timeout);
	if(buffer == atoi(login_timeout))
	    return 0;
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "%d", buffer);

	nvram_set(NVRAM_STR_FLOW_INTERVAL,buf);
	syslog(LOG_NOTICE, "[CONFIG-5-EXEC]: flow_interval is set %s\n", buf);
	free(login_timeout);
	return 0;
}

int nfunc_exec_timeout(struct users *u)
{
	int buffer = 0, i;
	char buf[128] = {'\0'}, *login_timeout = NULL;	/*add by wei.zhang*/
	char *p = buf, temp_buf[8];
	
	/*modify by wei.zhang 2012-05-03*/
	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);
	u->exec_timeout = buffer;
	login_timeout = nvram_safe_get("login_timeout");
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "%s", login_timeout);
	for(i = 0; i < 17; i++)
		p = strchr( p, ':' ) + 1;
	bzero(p, sizeof(p));
	bzero(temp_buf, sizeof(temp_buf));
	snprintf(temp_buf, sizeof(temp_buf), "%d;", 0);
	strcat(buf, temp_buf);
	nvram_set("login_timeout",buf);
	u->exec_timeout = 0;
	syslog(LOG_NOTICE, "[CONFIG-5-EXEC]: login_exec_timeout is unlimited!\n");
	free(login_timeout);
    
    return 0;
}

int nfunc_flow_interval(struct users *u)
{
	int buffer = 0, i;
	char buf[128] = {'\0'}, *login_timeout = NULL;	/*add by wei.zhang*/
	
	/*modify by wei.zhang 2012-05-03*/
	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);
	login_timeout = nvram_safe_get(NVRAM_STR_FLOW_INTERVAL);
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "%d", 300);

	nvram_set(NVRAM_STR_FLOW_INTERVAL,buf);
	
	syslog(LOG_NOTICE, "[CONFIG-5-EXEC]: flow_interval is set default(%s)!\n",buf);
	free(login_timeout);
    
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
    
    /* eagles 2016 */
//	drop_packet_with_tag(skfd, CFP_DROP_TAG, access_port_int);

	/* rewrite policy to fix policy bug */
    POLICY_CLASSIFY classify;	
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));	
	policy_set("", &classify, POLICY_WRITE_REGS, -1, 0x00ULL);

	return;
}

int func_config_dot1q(struct users *u)
{
    char *qinq_enable = nvram_safe_get("qinq_enable");
    
    if(*qinq_enable != '1')
    {    
        nvram_set("qinq_enable", "1");
    	system("rc qinq restart > /dev/null 2>&1");
    }
    free(qinq_enable);
	return 0;
}

int nfunc_config_dot1q(struct users *u)
{
    nvram_set("qinq_enable", "0");
	nvram_set("qinq_tpid", "33024");
	nvram_set("qinq_config", "");
	nvram_set("qinq_port_config", "");
	
	system("rc qinq stop > /dev/null 2>&1");
	
	return 0;
} 
 
int func_config_portal(struct users *u)
{
    char *portal_enable = nvram_safe_get("portal_enable");
    
    if(*portal_enable != '1')
    {    
        nvram_set("portal_enable", "1");
    	system("rc portal restart > /dev/null 2>&1");
    }
    
    free(portal_enable);
	return 0;
}

int nfunc_config_portal(struct users *u)
{
    nvram_set("portal_enable", "0");
	system("rc portal stop > /dev/null 2>&1");
	
	return 0;
}

int nfunc_config_dot1q_tpid(struct users *u)
{
	nvram_set("qinq_tpid", "33024");
	char *qinq_enable = nvram_safe_get("qinq_enable");
	
	if(*qinq_enable == '1')
		system("rc qinq restart > /dev/null 2>&1");
	
	free(qinq_enable);
	return 0;
}

int func_error_disable_recover_enable(u)
{
    nvram_set("lo_protect_enable", "1");
	system("rc loopback restart > /dev/null 2>&1");
	
	return 0;
}

int func_error_disable_recover_timeout(u)
{
	int buffer = 0, i;
	char buf[128] = {'\0'}, *timeout = NULL;	/*add by wei.zhang*/
	char *p = buf, temp_buf[8];
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer, u);
	timeout = nvram_safe_get("lo_protect_time");
	
	if(atoi(timeout) != buffer)
	{    
    	bzero(buf, sizeof(buf));
    	sprintf(buf,"%d", buffer);
    	nvram_set("lo_protect_time", buf);
    	
    	syslog(LOG_NOTICE, "[CONFIG-5-EXEC]: lo_protect_time is set %d\n", buffer);
    	system("rc loopback restart > /dev/null 2>&1");
    }
    free(timeout);
    	
	return 0;
}

int nfunc_error_disable_recover(u)
{
    nvram_set("lo_protect_enable", "0");
    nvram_set("lo_protect_time", "300");
	system("rc loopback restart > /dev/null 2>&1");
	
	return 0;
}

int func_config_dot1q_tpid(struct users *u)
{
	char *qinq_enable;
	char buf[MAX_ARGV_LEN] = {'\0'};
	int  data[4];
	int i;
	uint32_t tpid = 0;

	cli_param_get_string(STATIC_PARAM, 0, buf, u);

	for(i = 0;buf[i] != '\0';i++)
	{
		if((buf[i] >= '0') && (buf[i] <= '9'))
		{
			data[i] = buf[i] - '0';
		}else if((buf[i] >= 'a') && (buf[i] <= 'a'))
		{
			data[i] = buf[i] - 'a' + 10;
		}else if((buf[i] >= 'A') && (buf[i] <= 'F'))
		{
			data[i] = buf[i] - 'A' + 10;
		}
		else{
			vty_output("Command error! only Hex number can be set!\n");
			return;
		}
		
		if(i > 3){
			vty_output("Command error! over 4 characters!\n");
			return;
		}
	}

	for(i = 0; i<=3; i++)
	{
		tpid += (data[i] * pow(16, (3-i)));
	}
	
	memset(buf,'\0',sizeof(buf));
	sprintf(buf,"%d",tpid);
	nvram_set("qinq_tpid", buf);
	
	qinq_enable = nvram_safe_get("qinq_enable");
	if(*qinq_enable == '1')
		system("rc qinq restart > /dev/null 2>&1");
	
	free(qinq_enable);
	return 0;
}
