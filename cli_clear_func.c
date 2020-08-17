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
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/sockios.h>

#include <sys/un.h>

#include "console.h"
#include "cmdparse.h"
#include "parameter.h"
#include "bcmutils.h"
#include "acl_utils.h"

#include "cli_clear_func.h"
#include "sk_define.h"
#include "cli_line_func.h"

/*
 *  Function : cli_clear_arp
 *  Purpose:
 *     clear CPU arp cache
 *  Parameters:
 *     void
 *  Returns:
 *     void
 *  Author  : eagles.zhou
 *  Date    :2011/3/11
 */
static void cli_clear_arp(void)
{
	int errno, s;
	struct arpreq ar;
	struct sockaddr_in *sin;

	bzero((caddr_t)&ar, sizeof (ar));
	ar.arp_pa.sa_family = AF_INET;
	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
		
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		return;
	}
	SYSTEM("killall arpd > /dev/null 2>&1");
	syslog(LOG_NOTICE, "[CONFIG-5-CLEAR] Clear dynamic arp, %s\n", getenv("LOGIN_LOG_MESSAGE"));   

	close(s);
	return;
}

/*
 *  Function : cli_clear_arl_by_port
 *  Purpose:
 *     clear arl table by port
 *  Parameters:
 *     void
 *  Returns:
 *     void
 *  Author  : eagles.zhou
 *  Date    :2011/3/30
 */
static void cli_clear_arl_by_port(void)
{
	int portid, skfd;

    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;

	for(portid = 1; portid <= PNUM; portid++)
		bcm_l2_addr_delete_by_port(skfd, 0, portid);

	close(skfd);
	return;
}

/*add by wuchunli begin*/
static int cli_clear_acl_counters()
{   
    IP_STANDARD_ACL_ENTRY entry1;
    IP_EXTENDED_ACL_ENTRY entry2;
    
    memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
    memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
    
    ip_std_acl_set("", &entry1, ACL_COUNTERS_CLEAR_ALL, -1, 0x00ULL);
    ip_ext_acl_set("", &entry2, ACL_COUNTERS_CLEAR_ALL, -1, 0x00ULL);
            
    return 0;
}

static int cli_clear_acl_counters_by_name(char* acl_name)
{
    int res = 0;
    int flag = 0;   
    IP_STANDARD_ACL_ENTRY entry1;
    IP_EXTENDED_ACL_ENTRY entry2;
    
    memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
    memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
    
    res = ip_std_acl_set(acl_name, &entry1, ACL_NAME_CHECK, -1, 0x00ULL);
    /* ip standard acl name is not exist */
    if(res)
    {
        /* following is for extended  */
        res = ip_ext_acl_set(acl_name, &entry2, ACL_NAME_CHECK, -1, 0x00ULL);
        /* ip extended acl name is not exist */
        if(res)
        {
            vty_output("access-list %s is not exist\n", acl_name);
            return -1;
        }
        else
        {
            flag = 1;   /* extended */
        }       
    }
    else
    {
        flag = 0;  /* standard */
    }  
    
    if(0 == flag)   
    {
        ip_std_acl_set(acl_name, &entry1, ACL_COUNTERS_CLEAR_ONE, -1, 0x00ULL);
    }
    else
    {
        ip_ext_acl_set(acl_name, &entry2, ACL_COUNTERS_CLEAR_ONE, -1, 0x00ULL);
    }
        
    return 0;
}

/*
 *  Function: func_clear_arp
 *  Purpose:   clear CPU arp cache
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/8
 */


int func_clear_arp(struct users *u)
{
	cli_clear_arp();

	return 0;
}

/*
 *  Function: func_clear_logging
 *  Purpose:   clear log
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/8
 */
/*modified by wuchunli 2012-3-30 14:00:09*/
int func_clear_logging(struct users *u)
{
    nvram_set("log_clear_flag","1");//just clear logging messages
	SYSTEM("/bin/rm /var/log/messages > /dev/null 2>&1");
	system("/usr/bin/killall -SIGUSR2 syslogd  > /dev/null 2>&1");
	sleep(1);
	syslog(LOG_NOTICE, "[CONFIG-5-CLEAR] Clear all syslog messages, %s\n", getenv("LOGIN_LOG_MESSAGE"));   

	return 0;
}

/*
 *  Function: func_clear_counters
 *  Purpose:   Clear counters
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/8
 */

int func_clear_counters(struct users *u)
{
	/* Clear ports flow statistics */
	bcm_clear_all_counters();

	return 0;
}

/*
 *  Function: func_clear_mac
 *  Purpose:   clear arl table by port
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/8
 */

int func_clear_mac(struct users *u)
{
	/* clear mac for ports that are static ports */ 	
	cli_clear_arl_by_port();

	return 0;
}

/*
 *  Function: func_clear_telnet
 *  Purpose:   Clear telnet
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/8
 */

int func_clear_telnet(struct users *u, int line_id)
{
#ifdef CLI_AAA_MODULE
	//by zhangwei
    int skfd,retval;
    struct sockaddr_un server_sock_addr, client_sock_addr;
	IPC_SK tx, rx;
	int i, j;
	char client_path[30] = "";
	
	int telnet_id = 0;
	if( line_id == 0 )
		cli_param_get_int(STATIC_PARAM, 0, &telnet_id, u);
	else
		telnet_id = line_id;
	
	fd_set rfds;
	
	memset( client_path, 0, sizeof(client_path) );
	sprintf( client_path, "%s%d", SOCK_PATH_CLIENT, sta_info.nas_port );
	if (creat_sk_client(&skfd, &server_sock_addr, SOCK_PATH_SERVER, &client_sock_addr, client_path, 0)){
		return -1;
	}
	/*operate data for sending*/

	tx.stHead.enCmd = IPC_CMD_SET;
	tx.stHead.cOpt = 1;
	tx.stHead.cBack = IPC_SK_BACK;
	
	if( telnet_id > 0 && telnet_id <= MAX_VTY )		/*clear specfied telnet session*/
		tx.acData[0] = telnet_id;
	else
		tx.acData[0] = CLEAR_ALL_TELNET;		/*clear all telnet*/


	/*send data to server*/	
	if (ipc_send(skfd, &tx, &server_sock_addr) == -1){
		return -1;
	}

	unlink(client_sock_addr.sun_path);
#endif
	return 0;
}

/*
 *  Function: func_clear_ssh
 *  Purpose:   Clear access-list
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   wei.zhang
 *  Date:    2012/4/24
 */
int func_clear_ssh(struct users *u, int lineid)
{
	int fd;
	char ssh_ip[30] = "", buf[128] = "";
	int ssh_port;
	int line_id;
	int ssh_pid;
	char *p = buf;
	char sys_cmd[30] = "";
	char del_ip[MAX_VTY_NUM][50];
	int  del_port[MAX_VTY_NUM];
	int	 del_count = 0, i;
	int  clear_id[MAX_VTY_NUM];
	int ssh_id = 0;
	
	if(lineid == 0)
		cli_param_get_int(STATIC_PARAM, 0, &ssh_id, u);
	else
		ssh_id = lineid;
	
	for( i = 0; i < MAX_VTY_NUM; i++ )
		clear_id[i] = 0;
		
	if ( (fd = fopen("/tmp/ssh_sessions","r")) == NULL ) {
		return;
	}
	
	for( ; fgets(buf, 128, fd) != NULL; ){
		p = buf;
		strcpy( ssh_ip, strsep( &p, "," ) );
		ssh_port = atoi( strsep( &p, ",") );
		ssh_pid = atoi( strsep( &p, ",") );
		line_id = atoi( strsep( &p, ";") );
		if( ssh_id == line_id ){
			memset( sys_cmd, 0, sizeof(sys_cmd) );
			sprintf( sys_cmd, "kill -SIGTERM %d", ssh_pid );
			system( sys_cmd );
		}
		else if( ssh_id == 0 ){
			memset( sys_cmd, 0, sizeof(sys_cmd) );
			sprintf( sys_cmd, "kill -SIGTERM %d", ssh_pid );
			system( sys_cmd );
		}
		memset(buf, 0, sizeof(buf) );
	}
	fclose(fd);
	return 0;
}


/*
 *  Function: func_clear_access
 *  Purpose:   Clear access-list
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/8
 */

int func_clear_access(struct users *u)
{	
	/* cli clear acl counters */
	cli_clear_acl_counters();

	return 0;
}

/*
 *  Function: func_clear_name
 *  Purpose:   Clear access-list name
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/12/8
 */

int func_clear_name(struct users *u)
{
	char name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(STATIC_PARAM, 0, &name, u);
	cli_clear_acl_counters_by_name(name);

	return 0;
}

/*
 *  Function: func_clear_ip_dhcp_binding_addr
 *  Purpose:   Clear ip dhcp binding
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/12/8
 */
int func_clear_ip_dhcp_binding_addr(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ip_dhcp_binding_addr here\n");

	return retval;
}

/*
 *  Function: func_clear_ip_dhcp_binding_all
 *  Purpose:   Clear ip dhcp binding
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/12/8
 */
int func_clear_ip_dhcp_binding_all(struct users *u)
{
	int retval = -1;

	retval = 0;
	
    unlink("/var/udhcpd.leases");
    system("rc dhcpd restart  > /dev/null 2>&1 &");   
    
	return retval;
}

/*
 *  Function: func_clear_ipv6_dhcp_binding_all
 *  Purpose:   Clear ipv6 dhcp binding
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/12/8
 */
int func_clear_ipv6_dhcp_binding_all(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ipv6_dhcp_binding_all here\n");

	return retval;
}

/*
 *  Function: func_clear_ipv6_dhcp_binding_addr
 *  Purpose:   Clear ipv6 dhcp binding
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/12/8
 */
int func_clear_ipv6_dhcp_binding_addr(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ipv6_dhcp_binding_addr here\n");

	return retval;
}

/*
 *  Function: func_clear_ip_igmp_group
 *  Purpose:   Clear ipv6 igmp
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/12/8
 */
int func_clear_ip_igmp_group(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ip_igmp_group here\n");

	return retval;
}

/*
 *  Function: func_clear_ip_mroute_pim_all
 *  Purpose:   Clear ip mroute
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/12/8
 */
int func_clear_ip_mroute_pim_all(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ip_mroute_pim_all here\n");

	return retval;
}

int func_clear_ip_mroute_pim_group(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ip_mroute_pim_group here\n");

	return retval;
}

int func_clear_ip_mroute_pim_group_src(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ip_mroute_pim_group_src here\n");

	return retval;
}

/*
 *  Function: func_clear_ip_pim_rp
 *  Purpose:   Clear ip pim
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/12/8
 */
int func_clear_ip_pim_rp(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ip_pim_rp here\n");

	return retval;
}

int func_clear_ip_pim_rp_ip(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ip_pim_rp_ip here\n");

	return retval;
}

/*
 *  Function: func_clear_ipv6_mld_group_int
 *  Purpose:   Clear ip mroute
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/12/8
 */
int func_clear_ipv6_mld_group_int(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ipv6_mld_group_int here\n");

	return retval;
}

int func_clear_ipv6_mld_group_int_ip(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ipv6_mld_group_int_ip here\n");

	return retval;
}

/*
 *  Function: func_clear_ipv6_mroute_pim_all
 *  Purpose:   Clear ipv6 mroute
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/12/8
 */
int func_clear_ipv6_mroute_pim_all(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ipv6_mroute_pim_all here\n");

	return retval;
}

int func_clear_ipv6_mroute_pim_group(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ipv6_mroute_pim_group here\n");

	return retval;
}

int func_clear_ipv6_mroute_pim_group_src(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ipv6_mroute_pim_group_src here\n");

	return retval;
}

/*
 *  Function: func_clear_ipv6_pim_rp
 *  Purpose:   Clear ipv6 pim
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/12/8
 */
int func_clear_ipv6_pim_rp(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ipv6_pim_rp here\n");

	return retval;
}

int func_clear_ipv6_pim_rp_ip(struct users *u)
{
	int retval = -1;

	retval = 0;

	printf("do func_clear_ipv6_pim_rp_ip here\n");

	return retval;
}

