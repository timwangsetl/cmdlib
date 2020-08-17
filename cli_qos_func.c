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

#include "cli_qos_func.h"
#include "acl_utils.h"
#include "bcmutils.h"
static uint64_t cur_port_int = 0x0ULL;

static int cli_check_range_id(int rate)
{
	char *por = nvram_safe_get("ring_ident");
	char *ptr =	strchr(por, ':') + 1;
	if((rate==por)||(rate==ptr))
	{
		vty_output(" Ring %d already exist,Please reset!\n", rate);
		free(por);
		return -1;
	}
	free(por);

	return CLI_SUCCESS;	
}
	
static int 	cli_set_ring(struct users *u, int type, int id)
{	
    cli_ring_conf conf;

    memset(&conf, '\0', sizeof(cli_ring_conf));
    cli_nvram_conf_get(CLI_RING_INFO, (unsigned char *)&conf);

    if(0 == type)
    {
        if(conf.ident[1] == id) 
        {
	        vty_output("Error: exit ring entry 2 id %s exist, must change entry 2 first!\n", id);
	        return -1;
		}
		conf.ident[0] = id;
    }    
    else
    {    
        if(conf.ident[0] != 0)
        {    
            if(conf.ident[0] == id)
        	{
                vty_output("Error: exit ring entry 1 id %s exist, must change entry 1 first!\n", id);
        		return -1;
        	}
        	
		    conf.type = type;
		    conf.ident[1] = id;
        }else
        {
	        vty_output("Error: double or coupling ring is working based on single ring, config it first!\n");
	        return -1;
		}  
    }  

    cli_nvram_conf_set(CLI_RING_INFO, (unsigned char *)&conf);
    COMMAND("rc rstp restart");
    
    return CLI_SUCCESS;
}

/* -1: not exist, 0: std, 1: ext*/
static int check_ip_acl_name_exist(char *acl_name)
{
	int res, flag;
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
			flag = -1;
		else 
			flag = 1;
	}
	else
		flag = 0;	
	
	return flag;
}

static int check_mac_acl_name_exist(char *acl_name)
{
	int res;
	MAC_ACL_ENTRY entry;
	
	memset(&entry, '\0', sizeof(MAC_ACL_ENTRY));
	res = mac_acl_set(acl_name, &entry, ACL_NAME_CHECK, -1, 0x00ULL);
	/* acl name is not exist */
	if(res)
	{
		vty_output("access-group %s not exist\n", acl_name);
		return -1;
	}
	
	return 0;
}

static int cli_add_classify(int type_flag, char *str, int ip_flag)
{
	int res, num = 0, num1 = 0;
	POLICY_CLASSIFY classify;
	MAC_ACL_ENTRY entry1;
	IP_STANDARD_ACL_ENTRY entry2;
	IP_EXTENDED_ACL_ENTRY entry3;
	char *policy_name = nvram_safe_get("policy_name");
	
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	memset(&entry1, '\0', sizeof(MAC_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry3, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
	
	switch(type_flag)
	{
		case CLASSIFY_TYPE_IP:
			strcpy(classify.name, str);
			classify.type_flag = CLASSIFY_TYPE_IP;
			//standard ip acl
			if(0 == ip_flag)
				num1 = ip_std_acl_set(classify.name, &entry2, ACL_ENTRY_NUM, -1, 0x00ULL);
			//extended ip acl
			else
				num1 = ip_ext_acl_set(classify.name, &entry3, ACL_ENTRY_NUM, -1, 0x00ULL);
			break;
			
		case CLASSIFY_TYPE_MAC:
			strcpy(classify.name, str);
			classify.type_flag = CLASSIFY_TYPE_MAC;
			num1 = mac_acl_set(classify.name, &entry1, ACL_ENTRY_NUM, -1, 0x00ULL);
			break;
			
		case CLASSIFY_TYPE_DSCP:
			classify.val = atoi(str);
			classify.type_flag = CLASSIFY_TYPE_DSCP;
			break;					
			
		case CLASSIFY_TYPE_VLAN:
			classify.val = atoi(str);
			classify.type_flag = CLASSIFY_TYPE_VLAN;									
			break;
			
		case CLASSIFY_TYPE_COS:
			classify.val = atoi(str);
			classify.type_flag = CLASSIFY_TYPE_COS;	
			break;
			
		case CLASSIFY_TYPE_ANY:
			classify.type_flag = CLASSIFY_TYPE_ANY;
			break;
			
		default:
			break;
	}
	
	if(0 == num1)
		num1 = 1;
	
	res = policy_set(policy_name, &classify, POLICY_CLASSIFY_CHECK, 0, 0x00ULL);	
	/* this classify not exist */		
	if(res == 0)
	{
		num = policy_set("", &classify, POLICY_ACL_ENTRY_NUM, 0, 0x00ULL);  //current policy acl num
		if((num+num1) > POLICY_NUM)
			vty_output("Adding this rule, all policy entris number will exceed %d !\n", POLICY_NUM);
		else
			policy_set(policy_name, &classify, POLICY_CLASSIFY_ADD, 0, 0x00ULL);
	}
			
	free(policy_name);
	return 0;
}

static int cli_start_qos(void)
{
	COMMAND("rc qos start");
    return 0;	
}

static int cli_set_no_classify(int type_flag, char *str)
{
	int res;
//	int val;
	char *pol_name;
	POLICY_CLASSIFY classify;
	
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	
	/* get value from nvram */
	pol_name = nvram_safe_get("policy_name");
	
	if(0 == strlen(pol_name)) 
	{
		free(pol_name);
		return -1;
	}
	
	if((CLASSIFY_TYPE_MAC == type_flag) || (CLASSIFY_TYPE_IP == type_flag))
		strcpy(classify.name, str);
	else if(NULL != str)
		classify.val = atoi(str);
		
	classify. type_flag = type_flag;
	
	/* delete the entry */
	res = 	policy_set(pol_name, &classify, POLICY_CLASSIFY_DEL, -1, 0x00ULL);
	/* entry is not exist or the acl name is not exist */
	if(res == 0)
		vty_output("The classify has not existed in the policy-map.\n");		
	
	free(pol_name);
	return 0;
}

static int cli_set_scheduler_enable()
{
    scfgmgr_set("qos_enable", "1");
    cli_start_qos();
    
    return 0;
}

/* changed by jiangyaohui 20120309 */
static int cli_stop_qos(void)  
{
	COMMAND("rc qos stop");
    return 0;	
}

static int cli_set_scheduler_disable()
{
    //scfgmgr_set("qos_enable", "0");
    
    cli_stop_qos();
    
    syslog(LOG_NOTICE, "[CONFIG-5-SCHEDULER]: Disabled scheduler function, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return CLI_SUCCESS;
}

static int cli_set_policy(char *policy)
{
    scfgmgr_set("qos_schedule", policy);
	COMMAND("rc qos restart");
	
    return 0;
}

static int cli_set_bandwidth(int rc)
{
	int rate, res;
	POLICY_CLASSIFY classify;
	char *role = nvram_safe_get("pol_role");
	char *policy_name = nvram_safe_get("policy_name");
	char *pol_val = nvram_safe_get("pol_val");
	rate = rc * 64;	
	
	if((0 == strlen(role)) || (0 == strlen(policy_name)))
	{
		free(role);
		free(policy_name);
		free(pol_val);
		return 0;
	}
	
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	
	switch(atoi(role))
	{
		case CLASSIFY_TYPE_IP:
			strcpy(classify.name, pol_val);
			classify.type_flag = CLASSIFY_TYPE_IP;
			break;
			
		case CLASSIFY_TYPE_MAC:
			strcpy(classify.name, pol_val);
			classify.type_flag = CLASSIFY_TYPE_MAC;
			break;
			
		case CLASSIFY_TYPE_DSCP:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_DSCP;
			break;					
			
		case CLASSIFY_TYPE_VLAN:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_VLAN;									
			break;
			
		case CLASSIFY_TYPE_COS:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_COS;	
			break;
			
		case CLASSIFY_TYPE_ANY:
			classify.type_flag = CLASSIFY_TYPE_ANY;
			break;
			
		default:
			break;
	}

	classify.action_flag = 0x01 << CLASSIFY_ACTION_BANDWIDTH;
	classify.bandwidth = rc;

	res = policy_set(policy_name, &classify, POLICY_CLASSIFY_CHECK, 0, 0x00ULL);
	/* policy name not exist */
	if(res == -1){
		free(role);
		free(policy_name);
		free(pol_val);
		return 0;
	}
	/* this classify not exist */	
	else if(res == 0)
		policy_set(policy_name, &classify, POLICY_CLASSIFY_ADD, 0, 0x00ULL);
	/* this classify exist */
	else
		policy_set(policy_name, &classify, POLICY_CLASSIFY_MODIFY, 0, 0x00ULL);
	
	
	free(role);
	free(policy_name);
	free(pol_val);
	
	return 0;
}


static int cli_set_drop()
{
	int res;
	POLICY_CLASSIFY classify;
	char *role = nvram_safe_get("pol_role");
	char *policy_name = nvram_safe_get("policy_name");
	char *pol_val = nvram_safe_get("pol_val");

	if((0 == strlen(role)) || (0 == strlen(policy_name)))
	{
		free(role);
		free(policy_name);
		free(pol_val);
		return 0;
	}
	
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	
	switch(atoi(role))
	{
		case CLASSIFY_TYPE_IP:
			strcpy(classify.name, pol_val);
			classify.type_flag = CLASSIFY_TYPE_IP;
			break;
			
		case CLASSIFY_TYPE_MAC:
			strcpy(classify.name, pol_val);
			classify.type_flag = CLASSIFY_TYPE_MAC;
			break;
			
		case CLASSIFY_TYPE_DSCP:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_DSCP;
			break;					
			
		case CLASSIFY_TYPE_VLAN:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_VLAN;									
			break;
			
		case CLASSIFY_TYPE_COS:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_COS;	
			break;
			
		case CLASSIFY_TYPE_ANY:
			classify.type_flag = CLASSIFY_TYPE_ANY;
			break;
			
		default:
			break;
	}

	classify.action_flag = 0x01 << CLASSIFY_ACTION_DROP;
	
	res = policy_set(policy_name, &classify, POLICY_CLASSIFY_CHECK, 0, 0x00ULL);
	/* policy name not exist */
	if(res == -1){
		free(role);
		free(policy_name);
		free(pol_val);
		return 0;
	}
	/* this classify not exist */	
	else if(res == 0)
		policy_set(policy_name, &classify, POLICY_CLASSIFY_ADD, 0, 0x00ULL);
	/* this classify exist */
	else
		policy_set(policy_name, &classify, POLICY_CLASSIFY_MODIFY, 0, 0x00ULL);
	
	
	free(role);
	free(policy_name);
	free(pol_val);
		
	return 0;
}

static int cli_set_action(int action, int val)
{
	int res;
	//uint32 access=0;
	char *role = nvram_safe_get("pol_role");
	char *policy_name = nvram_safe_get("policy_name");
	char *pol_val = nvram_safe_get("pol_val");
	POLICY_CLASSIFY classify;
	
	if((0 == strlen(role)) || (0 == strlen(policy_name)))
	{
		free(role);
		free(policy_name);
		free(pol_val);
		return 0;
	}

	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	
	/* if set vlanId, then check all "set vlanId" can not exceed 16 */
	if(CLASSIFY_ACTION_VLANID == action)
	{
		res = policy_set("", &classify, POLICY_CHECK_VLANID, 0, 0x00ULL);
		if(-1 == res)
		{
			vty_output("Flow to vlan number can not exceed %d!\n", FLOW_TO_VLAN_NUM);
			free(role); 
			free(policy_name);
			free(pol_val);
			return -1;
		}
	}
		
	switch(atoi(role))
	{
		case CLASSIFY_TYPE_IP:
			strcpy(classify.name, pol_val);
			classify.type_flag = CLASSIFY_TYPE_IP;
			break;
			
		case CLASSIFY_TYPE_MAC:
			strcpy(classify.name, pol_val);
			classify.type_flag = CLASSIFY_TYPE_MAC;
			break;
			
		case CLASSIFY_TYPE_DSCP:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_DSCP;
			break;					
			
		case CLASSIFY_TYPE_VLAN:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_VLAN;									
			break;
			
		case CLASSIFY_TYPE_COS:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_COS;	
			break;
			
		case CLASSIFY_TYPE_ANY:
			classify.type_flag = CLASSIFY_TYPE_ANY;
			break;
			
		default:
			break;
	}
	
	switch(action)
	{
		case CLASSIFY_ACTION_COS:
			classify.action_flag = 0x01 << action;
			classify.cos = val;
			break;
			
		case CLASSIFY_ACTION_DSCP:
			classify.action_flag = 0x01 << action;
			classify.dscp = val;
			break;
			
		case CLASSIFY_ACTION_VLANID:
			classify.action_flag = 0x01 << action;
			classify.vlanId = val;
			break;
		
		default:
			break;
	}
				
	res = policy_set(policy_name, &classify, POLICY_CLASSIFY_CHECK, 0, 0x00ULL);
	/* policy name not exist */
	if(res == -1){
		free(role);
		free(policy_name);
		free(pol_val);
		return 0;
	}
	/* this classify not exist */	
	else if(res == 0)
		policy_set(policy_name, &classify, POLICY_CLASSIFY_ADD, 0, 0x00ULL);
	/* this classify exist */
	else
		policy_set(policy_name, &classify, POLICY_CLASSIFY_MODIFY, 0, 0x00ULL);
	
	free(role);
	free(policy_name);
	free(pol_val);
	return 0;
}


/*
* function: no classify element
*/
static int cli_set_classify_no(int action_flag)
{
	int res;
	POLICY_CLASSIFY classify;
	char *role = nvram_safe_get("pol_role");
	char *policy_name = nvram_safe_get("policy_name");
	char *pol_val = nvram_safe_get("pol_val");	

	if((0 == strlen(role)) || (0 == strlen(policy_name)))
	{
		free(role);
		free(policy_name);
		free(pol_val);
		return 0;
	}
	
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	
	switch(atoi(role))
	{
		case CLASSIFY_TYPE_IP:
			strcpy(classify.name, pol_val);
			classify.type_flag = CLASSIFY_TYPE_IP;
			break;
			
		case CLASSIFY_TYPE_MAC:
			strcpy(classify.name, pol_val);
			classify.type_flag = CLASSIFY_TYPE_MAC;
			break;
			
		case CLASSIFY_TYPE_DSCP:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_DSCP;
			break;					
			
		case CLASSIFY_TYPE_VLAN:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_VLAN;									
			break;
			
		case CLASSIFY_TYPE_COS:
			classify.val = atoi(pol_val);
			classify.type_flag = CLASSIFY_TYPE_COS;	
			break;
			
		case CLASSIFY_TYPE_ANY:
			classify.type_flag = CLASSIFY_TYPE_ANY;
			break;
			
		default:
			break;
	}

	classify.action_flag = 0x01 << action_flag;
	
	res = policy_set(policy_name, &classify, POLICY_CLASSIFY_CHECK, 0, 0x00ULL);
	/* this classify exist */
	if((res != -1) && (res != 0))
		policy_set(policy_name, &classify, POLICY_CLASSIFY_ELEMENT_DEL, 0, 0x00ULL);
		
	free(role);
	free(policy_name);
	free(pol_val);
		
	return 0;
}


/*
 *  Function : prase_port_map
 *  Purpose:
 *     prase port map
 *  Parameters:
 *  Returns:
 *
 *  Author  : eagles.zhou
 *  Date    :2011/8/18
 */
static int prase_port_map(struct users *u)
{
	char *port_str;
	int group_no, index;

	if( (port_str = u->promptbuf) == NULL )
		return CLI_FAILED;

	if(0 == strlen(port_str))
		return CLI_FAILED;

	if( port_str != NULL ) {
		if('p' == *port_str) {
			group_no = atoi(port_str + 3);
			
			memset(&cur_trunk_conf, 0, sizeof(cli_trunk_conf));
			cli_nvram_conf_get(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

			for(index = 0; index < cur_trunk_conf.group_count; index++) {
				if(cur_trunk_conf.cur_trunk_list[index].group_no == group_no) {
					cur_port_int = cur_trunk_conf.cur_trunk_list[index].port_int;

					cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

					if(0x0ULL == cur_port_int)
						return CLI_FAILED;
					else
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


/*-------------------------------------------------------------------------------------*/

int func_qos_policy_map(struct users *u)
{
	char buffer[MAX_ARGV_LEN] = {'\0'};
	POLICY_CLASSIFY classify;
	
	cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);
	
	scfgmgr_set("policy_name", buffer);
	
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));

	policy_set(buffer, &classify, POLICY_ADD, 0, 0x00ULL);
	syslog(LOG_NOTICE, "[CONFIG-5-POLICYMAP]: The policy-map name was set to %s, %s\n", buffer, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int func_qos_classify(struct users *u)
{
	int flag = -1, v_int = -1;
	char v_string[MAX_ARGV_LEN] = {'\0'};
	char pol_role[MAX_ARGV_LEN] = {'\0'};
	char pol_val[MAX_ARGV_LEN] = {'\0'};

	if(ISSET_CMD_MSKBIT(u, QOS_CLASSITY_IP))
	{
		cli_param_get_string(DYNAMIC_PARAM, 0, v_string, u);
		
		flag = check_ip_acl_name_exist(v_string);
		if(-1 == flag)
		{
			vty_output("access-group %s not exist\n", v_string);
			return -1;
		}
		else
		{
			sprintf(pol_role, "%d", CLASSIFY_TYPE_IP);
			scfgmgr_set("pol_role", pol_role);
			scfgmgr_set("pol_val", v_string);
			cli_add_classify(CLASSIFY_TYPE_IP, v_string, flag);
		}
	}
	else if(ISSET_CMD_MSKBIT(u, QOS_CLASSITY_DSCP))
	{
		cli_param_get_int(DYNAMIC_PARAM, 0, &v_int, u);
		
		sprintf(pol_role, "%d", CLASSIFY_TYPE_DSCP);
		sprintf(pol_val, "%d", v_int);
		scfgmgr_set("pol_role", pol_role);
		scfgmgr_set("pol_val", pol_val);
		cli_add_classify(CLASSIFY_TYPE_DSCP, pol_val, -1);
	}
	else if(ISSET_CMD_MSKBIT(u, QOS_CLASSITY_MAC))
	{
		cli_param_get_string(DYNAMIC_PARAM, 0, v_string, u);

		if(0 == (check_mac_acl_name_exist(v_string)))
		{
			sprintf(pol_role, "%d", CLASSIFY_TYPE_MAC);
			scfgmgr_set("pol_role", pol_role);
			scfgmgr_set("pol_val", v_string);
			cli_add_classify(CLASSIFY_TYPE_MAC, v_string, -1);
		}
	}
	else if(ISSET_CMD_MSKBIT(u, QOS_CLASSITY_VLAN))
	{
		cli_param_get_int(DYNAMIC_PARAM, 0, &v_int, u);
		
		sprintf(pol_role, "%d", CLASSIFY_TYPE_VLAN);
		sprintf(pol_val, "%d", v_int);
		scfgmgr_set("pol_role", pol_role);
		scfgmgr_set("pol_val", pol_val);
		cli_add_classify(CLASSIFY_TYPE_VLAN, pol_val, -1);
	}
	else if(ISSET_CMD_MSKBIT(u, QOS_CLASSITY_COS))
	{
		cli_param_get_int(DYNAMIC_PARAM, 0, &v_int, u);
		
		sprintf(pol_role, "%d", CLASSIFY_TYPE_COS);
		sprintf(pol_val, "%d", v_int);
		scfgmgr_set("pol_role", pol_role);
		scfgmgr_set("pol_val", pol_val);
		cli_add_classify(CLASSIFY_TYPE_COS, pol_val, -1);
	}
	else if(ISSET_CMD_MSKBIT(u, QOS_CLASSITY_ANY))
	{
		sprintf(pol_role, "%d", CLASSIFY_TYPE_ANY);
		scfgmgr_set("pol_role", pol_role);
		cli_add_classify(CLASSIFY_TYPE_ANY, NULL, -1);
	}
	else
		DEBUG_MSG(1, "Unknow classify!!\n", NULL);
	
	return 0;
}
/*--------------------------------------------------------------------------------------*/

int func_qos_sch_po_sp(struct users *u)
{
	/* changed by jiangyaohui 20120309 */
	char *qos_schedule = nvram_safe_get("qos_schedule");
	if(strcmp(qos_schedule,"sp") != 0){
		scfgmgr_set("qos_schedule","sp");
		cli_start_qos();
	}
	free(qos_schedule);
	/*cli_set_scheduler_enable();
	cli_set_policy("1");*/
	syslog(LOG_NOTICE, "[CONFIG-5-SCHEDULER]: Enabled the cos priority queue schedule policy and the schedule policy is sp, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int func_qos_sch_po_wrr(struct users *u)
{  
	/* changed by jiangyaohui 20120309 */
	char *qos_schedule = nvram_safe_get("qos_schedule");
	if(strcmp(qos_schedule,"wrr") != 0){
		scfgmgr_set("qos_schedule","wrr");
		cli_start_qos();
	}
	free(qos_schedule);
	/*cli_set_scheduler_enable();
	cli_set_policy("0");*/
	syslog(LOG_NOTICE, "[CONFIG-5-SCHEDULER]: Enabled the cos priority queue schedule policy and the schedule policy is wrr, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int func_qos_sch_po_drr(struct users *u)
{  
	char *qos_schedule = nvram_safe_get("qos_schedule");
	if(strcmp(qos_schedule,"drr") != 0){
		scfgmgr_set("qos_schedule","drr");
		cli_start_qos();
	}
	
	free(qos_schedule);
	/*cli_set_scheduler_disable();*/
	return 0;
}

int func_qos_sch_po_wfq(struct users *u)
{  
	/* changed by jiangyaohui 20120309 */
	char *qos_schedule = nvram_safe_get("qos_schedule");
	if(strcmp(qos_schedule,"wfq") != 0){
		scfgmgr_set("qos_schedule","wfq");
		cli_start_qos();
	}
	
	free(qos_schedule);
	/*cli_set_scheduler_disable();*/
	return 0;
}

int func_qos_sch_po_wred(struct users *u)
{  
	/* changed by jiangyaohui 20120309 */
	char *qos_schedule = nvram_safe_get("qos_schedule");
	if(strcmp(qos_schedule,"wred") != 0){
		scfgmgr_set("qos_drop_profile","wred");
		cli_start_qos();
	}
	
	free(qos_schedule);
	/*cli_set_scheduler_disable();*/
	return 0;
}

int func_qos_sch_wrr_ban_1(struct users *u)
{
    char *qos_mode = nvram_safe_get("qos_schedule"); 
	int buffer1 = 0;
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer1, u);
	
	bcm_config_set_wrr_weight(1, buffer1);
	
	if(*qos_mode == '0')
	    COMMAND("rc qos start > /dev/null 2>&1");
	    
	free(qos_mode);    
	return 0;
}

int func_qos_sch_wrr_ban_2(struct users *u)
{
    char *qos_mode = nvram_safe_get("qos_schedule"); 
	int buffer1 = 0;
	int buffer2 = 0;
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer1, u);
	cli_param_get_int(STATIC_PARAM, 1, &buffer2, u);
	
	bcm_config_set_wrr_weight(1, buffer1);
	bcm_config_set_wrr_weight(2, buffer2);
	
	if(*qos_mode == '0')
	    COMMAND("rc qos start > /dev/null 2>&1");
	    
	free(qos_mode);    
	return 0;
}

int func_qos_sch_wrr_ban_3(struct users *u)
{
    char *qos_mode = nvram_safe_get("qos_schedule"); 
	int buffer1 = 0;
	int buffer2 = 0;
	int buffer3 = 0; 
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer1, u);
	cli_param_get_int(STATIC_PARAM, 1, &buffer2, u);
	cli_param_get_int(STATIC_PARAM, 2, &buffer3, u);
	
	bcm_config_set_wrr_weight(1, buffer1);
	bcm_config_set_wrr_weight(2, buffer2);
	bcm_config_set_wrr_weight(3, buffer3);
	
	if(*qos_mode == '0')
	    COMMAND("rc qos start > /dev/null 2>&1");
	    
	free(qos_mode);    
	return 0;
}

int func_qos_sch_wrr_ban_4(struct users *u)
{
    char *qos_mode = nvram_safe_get("qos_schedule"); 
	int buffer1 = 0;
	int buffer2 = 0;
	int buffer3 = 0;
	int buffer4 = 0;
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer1, u);
	cli_param_get_int(STATIC_PARAM, 1, &buffer2, u);
	cli_param_get_int(STATIC_PARAM, 2, &buffer3, u);
	cli_param_get_int(STATIC_PARAM, 3, &buffer4, u);
	
	bcm_config_set_wrr_weight(1, buffer1);
	bcm_config_set_wrr_weight(2, buffer2);
	bcm_config_set_wrr_weight(3, buffer3);
	bcm_config_set_wrr_weight(4, buffer4);
	
	if(*qos_mode == '0')
	    COMMAND("rc qos start > /dev/null 2>&1");
	    
	free(qos_mode);    
	return 0;
}

int func_qos_sch_wrr_ban_5(struct users *u)
{
    char *qos_mode = nvram_safe_get("qos_schedule"); 
	int buffer1 = 0;
	int buffer2 = 0;
	int buffer3 = 0;
	int buffer4 = 0;
	int buffer5 = 0;
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer1, u);
	cli_param_get_int(STATIC_PARAM, 1, &buffer2, u);
	cli_param_get_int(STATIC_PARAM, 2, &buffer3, u);
	cli_param_get_int(STATIC_PARAM, 3, &buffer4, u);
	cli_param_get_int(STATIC_PARAM, 4, &buffer5, u);
	
	bcm_config_set_wrr_weight(1, buffer1);
	bcm_config_set_wrr_weight(2, buffer2);
	bcm_config_set_wrr_weight(3, buffer3);
	bcm_config_set_wrr_weight(4, buffer4);
	bcm_config_set_wrr_weight(5, buffer5);
	
	if(*qos_mode == '0')
	    COMMAND("rc qos start > /dev/null 2>&1");
	    
	free(qos_mode);    
	return 0;
}

int func_qos_sch_wrr_ban_6(struct users *u)
{
    char *qos_mode = nvram_safe_get("qos_schedule"); 
	int buffer1 = 0;
	int buffer2 = 0;
	int buffer3 = 0;
	int buffer4 = 0;
	int buffer5 = 0;
	int buffer6 = 0;
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer1, u);
	cli_param_get_int(STATIC_PARAM, 1, &buffer2, u);
	cli_param_get_int(STATIC_PARAM, 2, &buffer3, u);
	cli_param_get_int(STATIC_PARAM, 3, &buffer4, u);
	cli_param_get_int(STATIC_PARAM, 4, &buffer5, u);
	cli_param_get_int(STATIC_PARAM, 5, &buffer6, u);
	
	bcm_config_set_wrr_weight(1, buffer1);
	bcm_config_set_wrr_weight(2, buffer2);
	bcm_config_set_wrr_weight(3, buffer3);
	bcm_config_set_wrr_weight(4, buffer4);
	bcm_config_set_wrr_weight(5, buffer5);
	bcm_config_set_wrr_weight(6, buffer6);
	
	if(*qos_mode == '0')
	    COMMAND("rc qos start > /dev/null 2>&1");
	    
	free(qos_mode);    
	return 0;
}

int func_qos_sch_wrr_ban_7(struct users *u)
{
    char *qos_mode = nvram_safe_get("qos_schedule"); 
	int buffer1 = 0;
	int buffer2 = 0;
	int buffer3 = 0;
	int buffer4 = 0;
	int buffer5 = 0;
	int buffer6 = 0;
	int buffer7 = 0;
	
	cli_param_get_int(STATIC_PARAM, 0, &buffer1, u);
	cli_param_get_int(STATIC_PARAM, 1, &buffer2, u);
	cli_param_get_int(STATIC_PARAM, 2, &buffer3, u);
	cli_param_get_int(STATIC_PARAM, 3, &buffer4, u);
	cli_param_get_int(STATIC_PARAM, 4, &buffer5, u);
	cli_param_get_int(STATIC_PARAM, 5, &buffer6, u);
	cli_param_get_int(STATIC_PARAM, 6, &buffer7, u);
	
	bcm_config_set_wrr_weight(1, buffer1);
	bcm_config_set_wrr_weight(2, buffer2);
	bcm_config_set_wrr_weight(3, buffer3);
	bcm_config_set_wrr_weight(4, buffer4);
	bcm_config_set_wrr_weight(5, buffer5);
	bcm_config_set_wrr_weight(6, buffer6);
	bcm_config_set_wrr_weight(7, buffer7);
	
	if(*qos_mode == '0')
	    COMMAND("rc qos start > /dev/null 2>&1");
	    
	free(qos_mode);    
	return 0;
}

int func_qos_sch_wrr_ban_8(struct users *u)
{
    char *qos_mode = nvram_safe_get("qos_schedule"); 
	int buffer1 = 0;
	int buffer2 = 0;
	int buffer3 = 0;
	int buffer4 = 0;
	int buffer5 = 0;
	int buffer6 = 0;
	int buffer7 = 0;
	int buffer8 = 0;
	cli_param_get_int(STATIC_PARAM, 0, &buffer1, u);
	cli_param_get_int(STATIC_PARAM, 1, &buffer2, u);
	cli_param_get_int(STATIC_PARAM, 2, &buffer3, u);
	cli_param_get_int(STATIC_PARAM, 3, &buffer4, u);
	cli_param_get_int(STATIC_PARAM, 4, &buffer5, u);
	cli_param_get_int(STATIC_PARAM, 5, &buffer6, u);
	cli_param_get_int(STATIC_PARAM, 6, &buffer7, u);
	cli_param_get_int(STATIC_PARAM, 7, &buffer8, u);
	
	bcm_config_set_wrr_weight(1, buffer1);
	bcm_config_set_wrr_weight(2, buffer2);
	bcm_config_set_wrr_weight(3, buffer3);
	bcm_config_set_wrr_weight(4, buffer4);
	bcm_config_set_wrr_weight(5, buffer5);
	bcm_config_set_wrr_weight(6, buffer6);
	bcm_config_set_wrr_weight(7, buffer7);
	bcm_config_set_wrr_weight(8, buffer8);
	
	if(*qos_mode == '0')
	    COMMAND("rc qos start > /dev/null 2>&1");
	    
	free(qos_mode);    
	return 0;
}

int nfunc_classify_ip_access(struct users *u)
{
	char buffer[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);
	cli_set_no_classify(CLASSIFY_TYPE_IP, buffer);

	return 0;
}

int nfunc_classify_dscp(struct users *u)
{
	int dscp = 0;
	char buffer[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_int(DYNAMIC_PARAM, 0, &dscp, u);
	sprintf(buffer, "%d", dscp);
	cli_set_no_classify(CLASSIFY_TYPE_DSCP, buffer);

	return 0;
}

int nfunc_classify_mac_acc(struct users *u)
{
	char buffer[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, buffer, u);
	cli_set_no_classify(CLASSIFY_TYPE_MAC, buffer);
	return 0;
}

int nfunc_classify_vlan(struct users *u)
{	
	int vlan = 0;
	char buffer[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_int(DYNAMIC_PARAM, 0, &vlan, u);
	sprintf(buffer, "%d", vlan);
	cli_set_no_classify(CLASSIFY_TYPE_VLAN, buffer);
	
	return 0;
}

int nfunc_classify_cos(struct users *u)
{	
	int cos = 0;
	char buffer[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_int(DYNAMIC_PARAM, 0, &cos, u);
	sprintf(buffer, "%d", cos);
	cli_set_no_classify(CLASSIFY_TYPE_COS, buffer);
	
	return 0;
}

int nfunc_classify_any(struct users *u)
{
	cli_set_no_classify(CLASSIFY_TYPE_ANY, NULL);
	return 0;
}

int func_class_band(struct users *u)
{
	int band = 0;
	cli_param_get_int(DYNAMIC_PARAM, 0, &band, u);
	cli_set_bandwidth(band);

	return 0;
}

int func_class_drop(struct users *u)
{
	cli_set_drop();

	return 0;
}

int func_class_set_cos(struct users *u)
{
	int action = 0;
	cli_param_get_int(DYNAMIC_PARAM, 0, &action, u);
	cli_set_action(CLASSIFY_ACTION_COS, action);

	return 0;
}

int func_class_set_dscp(struct users *u)
{
	int action = 0;
	cli_param_get_int(DYNAMIC_PARAM, 0, &action, u);
	cli_set_action(CLASSIFY_ACTION_DSCP, action);

	return 0;
}

int func_class_set_vlanid(struct users *u)
{
	int action = 0;
	cli_param_get_int(DYNAMIC_PARAM, 0, &action, u);
	cli_set_action(CLASSIFY_ACTION_VLANID, action);

	return 0;
}

int nfunc_class_band(struct users *u)
{
	cli_set_classify_no(CLASSIFY_ACTION_BANDWIDTH);

	return 0;
}

int nfunc_class_drop(struct users *u)
{
	cli_set_classify_no(CLASSIFY_ACTION_DROP);

	return 0;
}

int nfunc_class_set_cos(struct users *u)
{
	cli_set_classify_no(CLASSIFY_ACTION_COS);

	return 0;
}

int nfunc_class_set_dscp(struct users *u)
{
	cli_set_classify_no(CLASSIFY_ACTION_DSCP);

	return 0;
}

int nfunc_class_set_vlanid(struct users *u)
{
	cli_set_classify_no(CLASSIFY_ACTION_VLANID);

	return 0;
}

/* delete policy-map list with specific name */
static int cli_delete_policy_list(char *name, struct users *u)
{
	int res, i, flag;
	//uint64_t bmaps;
	char temp[ACL_NAME_LEN+3], buff[1024];
	char *port_str, *port_policy, *p, *ptr;

	POLICY_CLASSIFY classify;

	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	res = policy_set(name, &classify, POLICY_DEL, -1, 0x00ULL);
	/* 0: delete successfully, -1: policy name is not exist */
	if(-1 == res)
	{
		printf("Can not find policy-map %s\n", name);
		return -1;
	}

	//port_policy  = nvram_safe_get("port_policy");
	port_policy  = cli_nvram_safe_get(CLI_PORT_POLICY, "port_policy");
	//port_str = u->promptbuf;
    //cli_str2bitmap(port_str, &bmaps);

	p = port_policy;
	memset(buff, '\0', 1024);
	for(i = 0; i < PNUM; i++)
	{
		memset(temp, '\0', ACL_NAME_LEN+3);
		ptr = strchr(p, ',');
		strncpy(temp, p, ptr-p);

		if(0 == strcmp(temp, name))
		{
			flag = 1;
			strcat(buff, ",");
		}
		else
		{
			strcat(buff, temp);
			strcat(buff, ",");
		}
		p = ptr+1;
	}

	if(flag)
		scfgmgr_set("port_policy", buff);

	free(port_policy);
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Deleted policy list with name %s, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int nfunc_qos_policy_map(struct users *u)
{
	char name[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);
	cli_delete_policy_list(name, u);
	
	return 0;
}

int nfunc_sched_pol(struct users *u)
{
	cli_set_scheduler_disable();
	return 0;
}


//set default scheduler wrr weight
static int cli_set_wrr_default()
{
    char *wrr = nvram_safe_get_def("qos_wrr");
    char *qos_wrr = nvram_safe_get("qos_wrr");
	
	if(strcmp(qos_wrr, wrr) != 0){
	    scfgmgr_set("qos_wrr", wrr);
	    cli_start_qos();
	}
	free(qos_wrr);
    free(wrr);
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: The value of qos wrr bandwidth be set to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return CLI_SUCCESS;
}

int nfunc_sched_wrr_band(struct users *u)
{
	/*set default scheduler wrr weight*/
	cli_set_wrr_default();

	return 0;
}

/*
 *  Function:  func_filter_period
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_filter_period(struct users *u)
{
    int timer_p;
	char timer_period[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_int(STATIC_PARAM, 0, &timer_p, u);
	sprintf(timer_period,"%d",timer_p);
	   
	nvram_set("filter_period_time", timer_period);	
	    
}

int nfunc_filter_period(struct users *u)
{
	printf("do nfunc_filter_period here\n");

	return 0;
}

/*
 *  Function:  func_filter_threshold
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_filter_threshold(struct users *u)
{
    int timer_t;
	char timer_threshold[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_int(STATIC_PARAM, 0, &timer_t, u);
	sprintf(timer_threshold,"%d",timer_t);
	   
	nvram_set("filter_threshold_value", timer_threshold);	
	    
}

int nfunc_filter_threshold(struct users *u)
{
	printf("do nfunc_filter_threshold here\n");

	return 0;
}

/*
 *  Function:  func_filter_block
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_filter_block(struct users *u)
{
    int timer_b;
	char timer_block[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_int(STATIC_PARAM, 0, &timer_b, u);

	sprintf(timer_block,"%d",timer_b);
	   
	nvram_set("filter_block_value", timer_block);	
	    
}

int nfunc_filter_block(struct users *u)
{
	printf("do nfunc_filter_block here\n");

	return 0;
}

/*
 *  Function:  func_filter_igmp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_filter_igmp(struct users *u)
{
 
    char *filter_igmp = nvram_safe_get("filter_igmp_enable");

  
        nvram_set("filter_igmp_enable","1");

    
    free(filter_igmp);
    
    return 0;
}

int nfunc_filter_igmp(struct users *u)
{
	printf("do nfunc_filter_igmp here\n");

	return 0;
}

/*
 *  Function:  func_filter_ip_source
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_filter_ip_source(struct users *u)
{

    char *filter_ip_source = nvram_safe_get("filter_ip_source_enable");
   
    

            nvram_set("filter_ip_source_enable","1");
            
   
          
    
    free(filter_ip_source);
   
	return 0;
}

int nfunc_filter_ip_source(struct users *u)
{
	printf("do nfunc_filter_ip_source here\n");

	return 0;
}

/*
 *  Function:  func_filter_arp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_filter_arp(struct users *u)
{
	char *filter_arp = nvram_safe_get("filter_arp_enable");


 
        nvram_set("filter_arp_enable","1");

    free(filter_arp);

	return 0;
}

int nfunc_filter_arp(struct users *u)
{
	printf("do nfunc_filter_arp here\n");

	return 0;
}

/*
 *  Function:  func_filter_enable
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_filter_enable(struct users *u)
{
    char *filter_enable = nvram_safe_get("filter_enable");

    
        nvram_set("filter_enable","1");
        
        func_filter_arp(u);
        func_filter_ip_source(u);
        func_filter_igmp(u);

     
    free(filter_enable);
    
	return 0;
	

}

int nfunc_filter_enable(struct users *u)
{
	printf("do nfunc_filter_enable here\n");

	return 0;
}

/*
 *  Function:  func_cluster_member_id
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_cluster_member_id(struct users *u)
{
    int num;
	char cluster_id[8], group[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(STATIC_PARAM, 0, group, u);
//    printf("[%s:%d] group %s\n", __FUNCTION__, __LINE__, group, num);
    
    memset(cluster_id, '\0', sizeof(cluster_id));
	cli_param_get_int(STATIC_PARAM, 0, &num, u);
	sprintf(cluster_id, "%d", num);
//    printf("[%s:%d] member num %d\n", __FUNCTION__, __LINE__, num);

    scfgmgr_set("cluster_enable", "1");
    scfgmgr_set("cluster_id", cluster_id);
    scfgmgr_set("cluster_mac", group);
    
	return 0;
}

int nfunc_cluster_member_id(struct users *u)
{
    scfgmgr_set("cluster_enable", "");
    scfgmgr_set("cluster_id", "");
    scfgmgr_set("cluster_mac", "");

	return 0;
}

/*
 *  Function:  func_ring_id
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_ring_id_mode_single(struct users *u)
{
    int number = 0;
    
    cli_param_get_int(STATIC_PARAM, 0, &number, u);
    cli_check_range_id(number);
    cli_set_ring(u, 0, number);
	
	return 0;
}

int func_ring_id_mode_double(struct users *u)
{
    int number = 0;
    cli_param_get_int(STATIC_PARAM, 0, &number, u);
    cli_check_range_id(number);
    cli_set_ring(u, 1, number);
	
	return 0;
}

int func_ring_id_mode_coupling(struct users *u)
{
    int number = 0;
    cli_param_get_int(STATIC_PARAM, 0, &number, u);
    cli_check_range_id(number);
    cli_set_ring(u, 2, number);
	
	return 0;
}

int nfunc_ring_id(struct users *u)
{
    int number = 0, changed = 0;
    cli_ring_conf conf;
	
    cli_param_get_int(STATIC_PARAM, 0, &number, u);
    memset(&conf, '\0', sizeof(cli_ring_conf));
    cli_nvram_conf_get(CLI_RING_INFO, (unsigned char *)&conf);
    
    if(conf.ident[1] == number)
    {
        changed = 1;
        vty_output("disable ring entry 2 id %d success!\n", number);
        
        conf.ident[1] = 0;
        conf.type = 0;
        conf.ports[2] = 0;
        conf.ports[3] = 0;
    }
    else if(conf.ident[0] == number)
	{
        changed = 1;
        
        if(conf.ident[1] != 0)
	        vty_output("2nd ring is working based on 1nd ring, so remove toger!\n", conf.ident[1]);
	    else    
            vty_output("disable ring entry 1 id %d success!\n", number);
	        
		memset(&conf, '\0', sizeof(cli_ring_conf));
	}
    else 
	{
	    vty_output("no this exit ring entry with id %d!\n", number);
		return -1;
	}
	
	if(changed == 1)
    {
        cli_nvram_conf_set(CLI_RING_INFO, (unsigned char *)&conf);
        COMMAND("rc rstp restart");
    }
    
	return 0;
}


int do_trust_dot1p_set(struct users *u){
	
	scfgmgr_set("qos_enable","1");
	scfgmgr_set("qos_8021p_enable","1");

	COMMAND("/usr/sbin/rc qos restart");	
    syslog(LOG_INFO, "[CONFIG-5-QOS] QoS config dot1p enable!\n"); 
	
	return 0;
}

int no_trust_dot1p_set(struct users *u){
	
	scfgmgr_set("qos_8021p_enable","0");

	COMMAND("/usr/sbin/rc qos restart");	
    syslog(LOG_INFO, "[CONFIG-5-QOS] QoS config dot1p disable!\n"); 
	
	return 0;
}

int do_trust_dscp_set(struct users *u){
	
	printf("%s %d \n",__FUNCTION__,__LINE__);
	scfgmgr_set("qos_enable","1");	
	scfgmgr_set("qos_8021p_enable","1");
	scfgmgr_set("tos_dscp_enable","1");

	COMMAND("/usr/sbin/rc qos_tos_dscp restart");	
    syslog(LOG_INFO, "[CONFIG-5-QOS] QoS config dscp enable!\n"); 
	
	return 0;
}

int no_trust_dscp_set(struct users *u){
	
	scfgmgr_set("tos_dscp_enable","0");

	COMMAND("/usr/sbin/rc qos_tos_dscp restart");	
    syslog(LOG_INFO, "[CONFIG-5-QOS] QoS config dscp disable!\n"); 
	
	return 0;
}

int no_qos_set(struct users *u){
	
	scfgmgr_set("qos_enable","0");
	scfgmgr_set("qos_8021p_enable","0");
	scfgmgr_set("tos_dscp_enable","0");

	COMMAND("/usr/sbin/rc qos restart");
	COMMAND("/usr/sbin/rc qos_tos_dscp restart");	
    syslog(LOG_INFO, "[CONFIG-5-QOS] QoS config dscp disable!\n"); 
	
	return 0;
}



