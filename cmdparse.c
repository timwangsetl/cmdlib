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

/* Golbal variables */
struct cmd_node *view_tree_node = NULL;
struct cmd_node *ena_tree_node = NULL;
struct cmd_node *config_tree_node = NULL;
struct cmd_node *vlan_tree_node = NULL;
struct cmd_node *if_vlan_tree_node = NULL;
struct cmd_node *if_port_tree_node = NULL;
struct cmd_node *if_gport_tree_node = NULL;
struct cmd_node *if_xport_tree_node = NULL;
struct cmd_node *if_trunk_tree_node = NULL;
struct cmd_node *if_loopback_tree_node = NULL;
struct cmd_node *policy_map_tree_node = NULL;
struct cmd_node *classify_tree_node = NULL;
struct cmd_node *ip_acl_tree_node = NULL;
struct cmd_node *ipv6_acl_tree_node = NULL;
struct cmd_node *mac_acl_tree_node = NULL;
struct cmd_node *line_tree_node = NULL;
struct cmd_node *ip_dhcp_tree_node = NULL;
struct cmd_node *ipv6_dhcp_tree_node = NULL;
struct cmd_node *router_ospf_tree_node = NULL;
struct cmd_node *router_rip_tree_node = NULL;
struct cmd_node *router_isis_tree_node = NULL;
struct cmd_node *router_bgp_tree_node = NULL;
struct cmd_node *config_mst_tree_node = NULL;
struct cmd_node *time_range_tree_node = NULL;
struct cmd_node *config_erps_tree_node = NULL;

/* name, cmd_st, cmd_tree */
struct cmd_mask topcmds_mask[] = {
	{ "reboot", CMD_ST_CONF, ALL_TREE},
	{ "write", CMD_ST_CONF, ALL_TREE},
	{ "delete", CMD_ST_CONF, ALL_TREE},
	{ "format", CMD_ST_CONF, ALL_TREE},

	{ "no", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "default", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "exit", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "help", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "ping", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "default", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "telnet", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "quit", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "chinese", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "english", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "show", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "end", CMD_ST_NO|CMD_ST_DEF, ALL_TREE},
	{ "private-vlan", CMD_ST_NO|CMD_ST_DEF, VLAN_TREE},
	{ "vlan", CMD_ST_NO|CMD_ST_DEF, VLAN_TREE},
	{ "interface", CMD_ST_NO|CMD_ST_DEF, IF_VLAN_TREE|IF_PORT_TREE|IF_GPORT_TREE|IF_LOOPBACK_TREE|IF_XPORT_TREE},
	{ "flow-control", CMD_ST_NO|CMD_ST_DEF, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE},
	{ "arp", CMD_ST_NO|CMD_ST_DEF, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE},
	{ "rmon", CMD_ST_NO|CMD_ST_DEF, IF_PORT_TREE|IF_GPORT_TREE|IF_XPORT_TREE},
	{ CMD_MSK_END }
};

/* function */
/* General func */

/* 0:unmask 1:mask */
static int cli_check_topmask(char *name, struct users *u)
{
	struct cmd_mask *cmd_msk_ptr = topcmds_mask;

	while(cmd_msk_ptr != NULL && cmd_msk_ptr->cmd_name != NULL)
	{
		if(strcasecmp(name, cmd_msk_ptr->cmd_name) != 0)
		{
			cmd_msk_ptr += 1;
			continue;
		}

		/* user is on the cmd_mask tree or not */
		if(cmd_msk_ptr->con_level & u->con_level)
		{
			/* check cmd state */
			if(ISSET_CMD_ST(u, CMD_ST_NO))
			{
				if(cmd_msk_ptr->cmd_st & CMD_ST_NO)
					return 1;
			}
			if(ISSET_CMD_ST(u, CMD_ST_DEF))
			{
				if(cmd_msk_ptr->cmd_st & CMD_ST_DEF)
					return 1;
			}
		}

		/* check next */
		cmd_msk_ptr += 1;
	}

	return 0;
}

/* check u->cmdmask */
/* 0:unmask 1:mask */
static int cli_check_submask(uint32_t mask, uint32_t mask_cmd)
{
	if(mask_cmd == 0)
		return 0;
	else
	{
		if((mask & mask_cmd))
			return 1;
		else
			return 0;
	}
}

/* 0:unmask 1:mask */
static int cli_check_matchmode_mask(uint32_t *mask, int match_mode)
{
	uint32_t match_msk = 0x00000000;

	switch(match_mode)
	{
		case CLI_CMD:
		case CLI_CMD_UNUSAL:
		case CLI_CHAR_NO_BLANK:
		case CLI_CHAR_UNUSAL:
			DEBUG_MSG(1, "This match_mode: %d should not be here!!", match_mode);
			break;
		case CLI_INT_UNUSAL:
		case CLI_INT:
		case CLI_INT_RANGE:
		case CLI_INT_MULTI:
			match_msk = MATCH_INT_MSK;
			break;
		case CLI_MAC:
			match_msk = MATCH_MAC_MSK;
			break;
		case CLI_TIME:
			match_msk = MATCH_TIME_MSK;
			break;
		case CLI_IPV4:
		case CLI_IPV4_MASK:
			match_msk = MATCH_IPV4_MSK;
			break;
		case CLI_IPV6:
		case CLI_IPV6_MASK:
		case CLI_IPV6_NOMASK:
			match_msk = MATCH_IPV6_MSK;
			break;
		case CLI_LINE:
			match_msk = MATCH_LINE_MSK;
			break;
		case CLI_WORD:
			match_msk = MATCH_WORD_MSK;
			break;
		default :
			DEBUG_MSG(1, "Unknow match_mode: %d!!\n", match_mode);
			break;
	}
	
	if((~(*mask) & match_msk) == 0)
		return 1;
	else
	{
		*mask |= match_msk;
		return 0;
	}
}

/* check users's privilege, (1:succeed) */
static int cli_check_cmd_privilege(uint32_t cmd_pv_level, struct users *u)
{
#if 0
	uint32_t users_pv_level = u->cmd_pv;

	/* smaller pv_level, higher privilege */
	if(cmd_pv_level < users_pv_level)
		return 0;
	else
		return 1;
	
	return 0;
#else
	return 1;
#endif
}

/* check matchmode priority, search_cmds return the matchmode priority is higher */
/* 0:low 1:high pri */
static int cli_check_matchmode_priority(int last_match, int cur_match)
{
	if(last_match > cur_match)
		return 1;
	else if(last_match == cur_match)
	{
		DEBUG_MSG(1, "Check the same matchmode on the same level of subcmds!!\n", NULL);
		return 1;
	}
	else
		return 0;
}

static void cli_tab_buffer_parse(char *buffer, int match_cnt, int match_len, struct users *u)
{
	int len = 0;
	char buff[MAX_ARGV_LEN], buff1[MAX_ARGV_LEN], buff2[MAX_ARGV_LEN];
	char *p1 = NULL, *p2 = NULL;

	memset(buff, '\0', sizeof(buff));
	if(match_cnt > 1)
	{
		p1 = p2 = buffer;
		
		p2 = strchr(p2, ' ');
		memset(buff1, '\0', sizeof(buff1));
		memcpy(buff1, p1, p2-p1);
		
		len = strlen(buff1);
		p2 = p2+1;
		p1 = p2;

#if 0
		p2 = strchr(p2, ' ');		
		memset(buff2, '\0', sizeof(buff2));
		memcpy(buff2, p1, p2-p1);

		while((len > 0) && (strncasecmp(buff1, buff2, len) != 0))
			len -= 1;

		if(len > 0)
			memcpy(buff, buff1, len);
		else
			printf("topcmds_tab_buffer_parse() error!1\n");
#else
		while((p2 = strchr(p2, ' ')) != NULL)
		{
			memset(buff2, '\0', sizeof(buff2));
			memcpy(buff2, p1, p2-p1);
			
			p2 = p2+1;
			p1 = p2;

			while((len > 0) && (strncasecmp(buff1, buff2, len) != 0))
				len -= 1;

			if(len > 0)
			{
				memset(buff1, '\0', sizeof(buff1));
				memcpy(buff1, buff2, len);
			}
			else
				DEBUG_MSG(1, "Error: TAB buffer parse failed!!\n", NULL);
		}

		if(len > 0)
			memcpy(buff, buff1, len);
		else
			DEBUG_MSG(1, "Error: TAB buffer parse failed!!\n", NULL);
#endif

		DEBUG_MSG(1, "buff1=%s, buff2=%s, buff=%s, len=%d\n", buff1, buff2, buff, len);
		DEBUG_MSG(1, "buffer=%s\n", buffer);

		vty_output("%s\n", buffer);
	}
	else if(match_cnt == 1)
		memcpy(buff, buffer, strlen(buffer));

	memcpy(&(u->linebuf[u->linelen]), (buff + match_len), (strlen(buff) - match_len));		//fill cmds
	u->linelen = u->linelen - match_len + strlen(buff);
}

static void cli_help_buffer_parse(char *name, char *comment)
{
	char *name_ptr = NULL, *comment_ptr = NULL;
	int name_len = 0, comment_len = 0;

	if(name == NULL && comment == NULL)
		return ;

	if(name == NULL)
		name_ptr = "";
	else
		name_ptr = name;
	
	if(comment == NULL)
		comment_ptr = "";
	else
		comment_ptr = comment;

	name_len = strlen(name_ptr);
	comment_len = strlen(comment_ptr);

	if(comment_len == 0)
		vty_output("  %-24.24s    %-50.50s\n", name_ptr, "");
	else
	{
		vty_output("  %-24.24s -- %-50.50s\n", name_ptr, comment_ptr);

		while(1)
		{
			if(comment_len > 50)
			{
				comment_ptr += 50;
				comment_len -= 50;
			}
			else
				break;
			
			vty_output("%-30.30s%-50.50s\n", "", comment_ptr);
		}
	}

	return;
}

/* failed:-1 succeed:0 */
static int reset_users_err_ptr(int argc, char *argv[], struct users *u)
{
	int len = 0;
	char *ptr = NULL, buff[MAX_ARGV_LEN] = {'\0'};
	
	if(argc < 1 || argv == NULL || u == NULL)
		return -1;
	
	/* Check '?'  and 'TAB' flag */
	if((ptr = strstr(argv[0], HELP_SUFFIX)) != NULL || (ptr = strstr(argv[0], TAB_SUFFIX)) != NULL){
		len = ptr - argv[0];

		if(len != 0)
		{
			memcpy(buff, argv[0], len);
			if((ptr = strstr(u->err_ptr, buff)) == NULL)
				return -1;

			/* Refresh err_ptr */
			u->err_ptr = ptr;
		}

		DEBUG_MSG(1, "\n argc=%d, argv[0]=%s u:err_ptr=%s\n", argc, argv[0], u->err_ptr);
		return 0;
	}
	else
	{
		if((ptr = strstr(u->err_ptr, argv[0])) == NULL)
			return -1;
		
		/* Refresh err_ptr */
		u->err_ptr = ptr;
		
		DEBUG_MSG(1, "\n argc=%d, argv[0]=%s u:err_ptr=%s\n", argc, argv[0], u->err_ptr);
		return 0;
	}
	
	return 0;
}

/* Commands Register Function */
struct cmd_node *init_cmd_node(struct topcmds *cmd_entry)
{
	struct cmd_node *node = NULL;
	
	if((node = (struct cmd_node *)malloc(sizeof (struct cmd_node))) == NULL)
		DEBUG_MSG(1, "Error: cmd_node malloc failed!!\n", NULL);
	
	if(node != NULL)
	{
		memset (node, '\0', sizeof (struct cmd_node));
		node->topcmds_name = cmd_entry->name;
		node->topcmds_pv_level = cmd_entry->pv_level;
		node->topcmds_entry = cmd_entry;
		node->next = NULL;
		
		return node;
	}

	return NULL;
}

/* Register topcmds to cmd_tree */
struct cmd_node *register_cmd_tree(struct cmd_node *cmd_tree, struct topcmds *cmd_entry)
{
	int retval = -1;
	struct cmd_node *pre_cmd_ptr = NULL, *cmd_ptr = NULL;
	struct cmd_node *new_cmd_node = NULL, *ret_cmd_node = NULL;

	/* Convert topcmds to cmd_node */
	if((new_cmd_node = init_cmd_node(cmd_entry)) == NULL)
		return NULL;

	if(cmd_tree == NULL)
		return new_cmd_node;
	else
	{
		/* Add the cmd_node to the cmd_tree */
		ret_cmd_node = new_cmd_node;
		cmd_ptr = cmd_tree;

		retval = strcasecmp(ret_cmd_node->topcmds_name, cmd_ptr->topcmds_name);
		if(retval < 0)
		{
			new_cmd_node->next = cmd_ptr;
			return ret_cmd_node;
		}
		else if(retval == 0)
		{
			/* if name is the same ,reload it */
			ret_cmd_node = cmd_ptr;
			cmd_ptr->topcmds_entry = new_cmd_node->topcmds_entry;
			return ret_cmd_node;
		}
		else
		{
			ret_cmd_node = cmd_ptr;
			pre_cmd_ptr = cmd_ptr; 
			cmd_ptr = cmd_ptr->next;
			while(cmd_ptr != NULL)
			{
				retval = strcasecmp(new_cmd_node->topcmds_name, cmd_ptr->topcmds_name);
				if(retval < 0)
				{
					pre_cmd_ptr->next = new_cmd_node;
					new_cmd_node ->next = cmd_ptr;
					break;
				}
				else if(retval == 0)
				{
					/* if name is the same ,reload it */
					cmd_ptr->topcmds_entry = new_cmd_node->topcmds_entry;
					break;
				}

				pre_cmd_ptr = cmd_ptr;
				cmd_ptr = cmd_ptr->next;
			}

			if(cmd_ptr == NULL)
				pre_cmd_ptr->next = new_cmd_node;
		}
	}

	return ret_cmd_node;
}

/* 0:done -1:error */
int registercmd(struct topcmds *cmd_entry)
{
	if(cmd_entry == NULL || cmd_entry->name == NULL)
		return -1;

	if(cmd_entry->con_level & VIEW_TREE)
	{
		if((view_tree_node = register_cmd_tree(view_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " VIEW_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " VIEW_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & ENA_TREE)
	{
		if((ena_tree_node = register_cmd_tree(ena_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " ENA_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " ENA_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & CONFIG_TREE)
	{
		if((config_tree_node = register_cmd_tree(config_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " CONFIG_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " CONFIG_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & VLAN_TREE)
	{
		if((vlan_tree_node = register_cmd_tree(vlan_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " VLAN_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " VLAN_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & IF_VLAN_TREE)
	{
		if((if_vlan_tree_node = register_cmd_tree(if_vlan_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " IF_VLAN_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " IF_VLAN_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & IF_LOOPBACK_TREE)
	{
		if((if_loopback_tree_node = register_cmd_tree(if_loopback_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " IF_LOOPBACK_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " IF_LOOPBACK_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & IF_PORT_TREE)
	{
		if((if_port_tree_node = register_cmd_tree(if_port_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " IF_PORT_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " IF_PORT_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & IF_GPORT_TREE)
	{
		if((if_gport_tree_node = register_cmd_tree(if_gport_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " IF_GPORT_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " IF_GPORT_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & IF_XPORT_TREE)
	{
		if((if_xport_tree_node = register_cmd_tree(if_xport_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " IF_XPORT_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " IF_XPORT_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & IF_TRUNK_TREE)
	{
		if((if_trunk_tree_node = register_cmd_tree(if_trunk_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " IF_TRUNK_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " IF_TRUNK_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & POLICY_MAP_TREE)
	{
		if((policy_map_tree_node = register_cmd_tree(policy_map_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " POLICY_MAP_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " POLICY_MAP_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & CLASSIFY_TREE)
	{
		if((classify_tree_node = register_cmd_tree(classify_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " POLICY_MAP_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " POLICY_MAP_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & IP_ACL_TREE)
	{
		if((ip_acl_tree_node = register_cmd_tree(ip_acl_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " IP_ACL_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " IP_ACL_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & IPV6_ACL_TREE)
	{
		if((ipv6_acl_tree_node = register_cmd_tree(ipv6_acl_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " IPV6_ACL_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " IPV6_ACL_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & MAC_ACL_TREE)
	{
		if((mac_acl_tree_node = register_cmd_tree(mac_acl_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " MAC_ACL_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " MAC_ACL_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & LINE_TREE)
	{
		if((line_tree_node = register_cmd_tree(line_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " LINE_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " LINE_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & IP_DHCP_TREE)
	{
		if((ip_dhcp_tree_node = register_cmd_tree(ip_dhcp_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " IP_DHCP_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " IP_DHCP_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & IP_DHCPv6_TREE)
	{
		if((ipv6_dhcp_tree_node = register_cmd_tree(ipv6_dhcp_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " IP_DHCPv6_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " IP_DHCPv6_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & ROUTER_OSPF_TREE)
	{
		if((router_ospf_tree_node = register_cmd_tree(router_ospf_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " ROUTER_OSPF_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " ROUTER_OSPF_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & ROUTER_RIP_TREE)
	{
		if((router_rip_tree_node = register_cmd_tree(router_rip_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " ROUTER_RIP_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " ROUTER_RIP_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & ROUTER_ISIS_TREE)
	{
		if((router_isis_tree_node = register_cmd_tree(router_isis_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " ROUTER_ISIS_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " ROUTER_ISIS_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & ROUTER_BGP_TREE)
	{
		if((router_bgp_tree_node = register_cmd_tree(router_bgp_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " ROUTER_BGP_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " ROUTER_BGP_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & CONFIG_MST_TREE)
	{
		if((config_mst_tree_node = register_cmd_tree(config_mst_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " CONFIG_MST_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " CONFIG_MST_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & CONFIG_ERPS_TREE)
	{
		if((config_erps_tree_node = register_cmd_tree(config_erps_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " CONFIG_MST_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " CONFIG_MST_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}
	if(cmd_entry->con_level & TIME_RANGE_TREE)
	{
		if((time_range_tree_node = register_cmd_tree(time_range_tree_node, cmd_entry)) != NULL)	
			DEBUG_MSG(1, " TIME_RANGE_TREE, %s - done!\n", cmd_entry->name);
		else
		{
			DEBUG_MSG(1, " TIME_RANGE_TREE, %s - failed!\n", cmd_entry->name);
			return -1;
		}
	}

	return 0;
	
}

/* return the num of registerd succeed */
int registerncmd(struct topcmds *cmd_entry, int num)
{
	int i;

	if(cmd_entry == NULL || num <= 0)
		return -1;

	for(i=0; i< num; i++)
		if(registercmd((cmd_entry+i)) < 0)	break;
	
	return i;
}

struct cmd_node *cli_get_cmd_tree(struct users *u)
{
	struct cmd_node *cmd_tree = NULL;

	if(u == NULL)	return NULL;
	
	/* search the topcmds at the cmd_tree */
	switch(u->con_level)
	{
		case VIEW_TREE:
			cmd_tree = view_tree_node;
			break;
		case ENA_TREE:
			cmd_tree =  ena_tree_node;
			break;
		case CONFIG_TREE:
			cmd_tree =  config_tree_node;
			break;
		case VLAN_TREE:
			cmd_tree =  vlan_tree_node;
			break;
		case IF_VLAN_TREE:
			cmd_tree =  if_vlan_tree_node;
			break;
		case IF_PORT_TREE:
			cmd_tree =  if_port_tree_node;
			break;
		case IF_LOOPBACK_TREE:
			cmd_tree =  if_loopback_tree_node;
			break;
		case IF_GPORT_TREE:
			cmd_tree =  if_gport_tree_node;
			break;
		case IF_XPORT_TREE:
			cmd_tree =  if_xport_tree_node;
			break;
		case IF_TRUNK_TREE:
			cmd_tree =  if_trunk_tree_node;
			break;
		case POLICY_MAP_TREE:
			cmd_tree =  policy_map_tree_node;
			break;
		case CLASSIFY_TREE:
			cmd_tree =	classify_tree_node;
			break;
		case IP_ACL_TREE:
			cmd_tree =  ip_acl_tree_node;
			break;
		case IPV6_ACL_TREE:
			cmd_tree =	ipv6_acl_tree_node;
			break;
		case MAC_ACL_TREE:
			cmd_tree =  mac_acl_tree_node;
			break;
		case LINE_TREE:
			cmd_tree =  line_tree_node;
			break;
		case IP_DHCP_TREE:
			cmd_tree =  ip_dhcp_tree_node;
			break;
		case IP_DHCPv6_TREE:
			cmd_tree =  ipv6_dhcp_tree_node;
			break;
		case ROUTER_OSPF_TREE:
			cmd_tree =  router_ospf_tree_node;
			break;
		case ROUTER_RIP_TREE:
			cmd_tree =  router_rip_tree_node;
			break;
		case ROUTER_ISIS_TREE:
			cmd_tree =  router_isis_tree_node;
			break;
		case ROUTER_BGP_TREE:
			cmd_tree =  router_bgp_tree_node;
			break;
		case CONFIG_MST_TREE:
			cmd_tree =  config_mst_tree_node;
			break;
		case CONFIG_ERPS_TREE:
			cmd_tree =  config_erps_tree_node;
			break;	
		case TIME_RANGE_TREE:
			cmd_tree =  time_range_tree_node;
			break;
		default :
			DEBUG_MSG(1, "Unknow con_level: %08x!!\n", u->con_level);
			cmd_tree =  NULL;
			break;
	}

	return cmd_tree;
}

/* topcmd parse function */
/* 0:succeed; 1:help or tab; -1:error */
int top_cmdparse (int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct cmd_node *cmd_tree = NULL;
	struct topcmds *topcmds_ptr = NULL;

	if(u == NULL)		return -1;

	/* Do argc and argv offset */
	argc -= u->args_offset;
	argv += u->args_offset;
	u->args_offset = 0;

	/* Check argc and argv */
	if(argc < 1 || argv == NULL)
	{
		if(ISSET_CMD_ST(u, CMD_ST_END))
			return 0;
		else
		{
			SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
			return -1;
		}
	}
	
	#if 0
	if(strlen(argv[0]) > MAX_ARGV_LEN)
	{
		sprintf(u->err_ptr, "%s: Too long!!\n", argv[0]);
		return -1;
	}
	#endif
	
	DEBUG_MSG(1, "argc=%d, argv[0]=%s\n", argc, argv[0]);

	/* Get cmd tree, base on console level */
	if((cmd_tree = cli_get_cmd_tree(u)) == NULL)
		return -1;

	/* Reset err_no */
	SET_ERR_NO(u, CLI_ERR_NONE);

	/* Check for '?' and 'TAB' flag */
	if(strcmp(argv[0], HELP_SUFFIX) == 0)
	{
		/* argv[0] == HELP_SUFFIX , show cmd_tree */
		top_cmdparse_help(cmd_tree, argc, argv, u);
		return 1;
	}
	else if(strcmp(argv[0], TAB_SUFFIX) == 0)
	{
		/* argv[0] == TAB_SUFFIX , show cmd_tree */
		top_cmdparse_tab(cmd_tree, argc, argv, u);
		return 1;
	}
	else
	{
		/* Check for NO_BLANK matchmode */
		if(*argv[0] == '\0')
		{
			/* NO_BLANK matchmode end */
			if(ISSET_CMD_ST(u, CMD_ST_END))
				return 0;
			else
			{
				SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
				return -1;
			}
		}
		
		/* Reset the error buffer and err_no */
		if(reset_users_err_ptr(argc, argv, u) < 0)
			DEBUG_MSG(1, "Can't find the pointer of argv[0]!!\n", NULL);
		
		/* Search topcmds entry */
		topcmds_ptr = search_topcmds(cmd_tree, argc, argv, u);
	}

	if(topcmds_ptr == NULL)
	{
		/* Check for '?' and 'TAB' flag (No blank) */
		if(strstr(argv[0], HELP_SUFFIX) != NULL)
			retval = top_cmdparse_help_show(cmd_tree, argc, argv, u);
		else if(strstr(argv[0], TAB_SUFFIX) != NULL)
			retval = top_cmdparse_tab_show(cmd_tree, argc, argv, u);
		else
			return -1;
	}
	else
	{
		/* Record the topcmd */
		memset(u->his_topcmd, '\0', sizeof(u->his_topcmd));
		memcpy(u->his_topcmd, argv[0], strlen(argv[0]));
		
		/* Change u->cmd_st base on end_flag */
		if((ISSET_CMD_ST(u, CMD_ST_NO) && (topcmds_ptr->end_flag & CLI_END_NO))
			|| (ISSET_CMD_ST(u, CMD_ST_DEF) && (topcmds_ptr->end_flag & CLI_END_DEF))
			|| (!ISSET_CMD_ST(u, CMD_ST_NO) && !ISSET_CMD_ST(u, CMD_ST_DEF) && (topcmds_ptr->end_flag & CLI_END_FLAG)))
			SET_CMD_ST(u, CMD_ST_END);
		else
			CLEAR_CMD_ST(u, CMD_ST_END);
	
		/* Process the func */
		if(ISSET_CMD_ST(u, CMD_ST_NO) && topcmds_ptr->nopref != NULL)
			retval = topcmds_ptr->nopref(argc, argv, u);
		else if(ISSET_CMD_ST(u, CMD_ST_DEF)&& topcmds_ptr->defpref != NULL)
			retval = topcmds_ptr->defpref(argc, argv, u);
		else if(topcmds_ptr->func != NULL)
			retval = topcmds_ptr->func(argc, argv, u);
		else
			DEBUG_MSG(1, "Error: func, nopref or defpref  is NULL!!\n", NULL);
	}
	
	return retval;
}

/* 1:done -1:error */
/*static*/ int top_cmdparse_help(struct cmd_node *cmd_tree, int argc, char *argv[], struct users *u)
{
	char *name = NULL, *comment = NULL;
	struct cmd_node *cmd_node_ptr = cmd_tree;
	struct topcmds *topcmds_ptr = NULL;

	if(argc < 1 || argv == NULL || u == NULL)
		return -1;

	/* show cmd_tree */
	while(cmd_node_ptr != NULL)
	{
		topcmds_ptr = cmd_node_ptr->topcmds_entry;
		
		if(cli_check_cmd_privilege(topcmds_ptr->pv_level, u)
			&& !cli_check_topmask(topcmds_ptr->name, u))
		{
			name = topcmds_ptr->name;
			comment = ISSET_CMD_ST(u, CMD_ST_CN)? topcmds_ptr->hhp: topcmds_ptr->yhp;

			cli_help_buffer_parse(name, comment);
		}
	
		cmd_node_ptr = cmd_node_ptr->next;
	}
	if(ISSET_CMD_ST(u, CMD_ST_END))
	{
		if(ISSET_CMD_ST(u, CMD_ST_CN))
			vty_output("%s\n", CR_SHOW_CN);
		else
			vty_output("%s\n", CR_SHOW_EN);
	}
	
	return 1;
}

/* 1:done -1:error */
int top_cmdparse_help_show(struct cmd_node *cmd_tree, int argc, char *argv[], struct users *u)
{
	int len = 0, match_cnt = 0;
	char buff[MAX_ARGV_LEN] = {'\0'};
	char *name = NULL, *comment = NULL;
	struct cmd_node *cmd_node_ptr = cmd_tree;
	struct topcmds *topcmds_ptr = NULL;

	if(argc < 1 || argv == NULL || u == NULL)
		return -1;

	len = strstr(argv[0], HELP_SUFFIX) - argv[0];

	/* argv[0] == HELP_SUFFIX */
	if(len == 0)	return 1;
	
	/* Get the buff from argv[0] without '?' flag */
	memset(buff, '\0', sizeof(buff));
	memcpy(buff, argv[0], len);
	while(cmd_node_ptr != NULL)
	{
		topcmds_ptr = cmd_node_ptr->topcmds_entry;

		if(cli_check_cmd_privilege(topcmds_ptr->pv_level, u)
			&& strncasecmp(buff, topcmds_ptr->name, len) == 0
			&& !cli_check_topmask(topcmds_ptr->name, u))
		{
			name = topcmds_ptr->name;
			comment = ISSET_CMD_ST(u, CMD_ST_CN)? topcmds_ptr->hhp: topcmds_ptr->yhp;
				
			cli_help_buffer_parse(name, comment);
			
			match_cnt += 1;
		}

		cmd_node_ptr = cmd_node_ptr->next;
	}

	/* No match */
	if(match_cnt == 0)
	{
		SET_ERR_NO(u, CLI_ERR_CMD_ERR);
		return -1;
	}
	
	return 1;
}

int top_cmdparse_tab(struct cmd_node *cmd_tree, int argc, char *argv[], struct users *u)
{
	char buff[MAX_ARGV_LEN] = {'\0'};
	
	if(argc < 1 || argv == NULL || u == NULL)
		return -1;

	/* Only one topcmds */
	if(cmd_tree->next == NULL)
	{
		/* Fill the line buffer for console (add one blank)*/
		sprintf(buff, "%s ", cmd_tree->topcmds_name);
		
		memcpy(&(u->linebuf[u->linelen]), buff, strlen(buff));
		u->linelen = u->linelen + strlen(buff);
	}
	
	return 1;
}

/* 1:done -1:error */
int top_cmdparse_tab_show(struct cmd_node *cmd_tree, int argc, char *argv[], struct users *u)
{
	int len = 0, match_cnt = 0;
	char buff[MAX_ARGV_LEN], buff_tmp[256];	
	struct cmd_node *cmd_node_ptr = cmd_tree;
	struct topcmds *topcmds_ptr = NULL;

	if(argc < 1 || argv == NULL || u == NULL)
		return -1;

	len = strstr(argv[0], TAB_SUFFIX) - argv[0];

	if(len > 0)
	{
		memset(buff_tmp, '\0', sizeof(buff_tmp));
		while(cmd_node_ptr != NULL)
		{
			topcmds_ptr = cmd_node_ptr->topcmds_entry;
			if(cli_check_cmd_privilege(topcmds_ptr->pv_level, u)
				&& strncasecmp(argv[0], topcmds_ptr->name, len) == 0 
				&& !cli_check_topmask(topcmds_ptr->name, u))
			{
				memset(buff, '\0', sizeof(buff));
				sprintf(buff, "%s ", topcmds_ptr->name);
				
				strcat(buff_tmp, buff);
				match_cnt += 1;
			}
			cmd_node_ptr = cmd_node_ptr->next;
		}

		if(match_cnt >= 1)
			cli_tab_buffer_parse(buff_tmp, match_cnt, len, u);
	}
	
	return 1;
}

/* topcmds_entry:done NULL:error */
struct topcmds *search_topcmds(struct cmd_node *cmd_tree, int argc, char *argv[], struct users *u)
{
	int ab_cnt = 0;
	struct cmd_node *cmd_node_ptr = cmd_tree;
	struct topcmds *topcmds_ret = NULL;

	if(argc < 1 || argv == NULL || u == NULL)
		return NULL;
	
	while(cmd_node_ptr != NULL)
	{
		if(cli_check_cmd_privilege(cmd_node_ptr->topcmds_pv_level, u)
			&& strncasecmp(argv[0], cmd_node_ptr->topcmds_name, strlen(argv[0])) == 0
			&& !cli_check_topmask(cmd_node_ptr->topcmds_name, u))
		{
			/* Get topcmds */
			ab_cnt += 1;			
			topcmds_ret = cmd_node_ptr->topcmds_entry;

			/* Accurately match, if more than one, return the first one */
			if(strlen(argv[0]) ==  strlen(cmd_node_ptr->topcmds_name))
			{
				ab_cnt = 1;
				break;
			}
		}
		
		cmd_node_ptr = cmd_node_ptr->next;		
	}

	if(ab_cnt == 1 && topcmds_ret != NULL)
	{
		u->args_offset += 1;
		return topcmds_ret;
	}

	SET_ERR_NO(u, CLI_ERR_CMD_ERR);
	
	return NULL;
}

/* subcmd parse func */
/* 0:done 1:help or tab -1:error */
int sub_cmdparse(struct cmds tab[], int argc, char *argv[], struct users *u)
{
	int retval = -1;
	struct cmds *cmds_ptr = NULL;

	if(u == NULL)		return -1;

	/* Do argc and argv offset */
	argc -= u->args_offset;
	argv += u->args_offset;
	u->args_offset = 0;
	
	/* Check argc and argv */
	if(argc < 1 || argv == NULL)
	{
		if(ISSET_CMD_ST(u, CMD_ST_END))
			return 0;
		else
		{
			SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
			return -1;
		}
	}
	#if 0
	if(strlen(argv[0]) > MAX_ARGV_LEN)
	{
		sprintf(u->err_ptr, "%s: Too long!!\n", argv[0]);
		return -1;
	}
	#endif
	DEBUG_MSG(1, "argc=%d, argv[0]=%s\n", argc, argv[0]);
	
	/* Reset err_no */
	SET_ERR_NO(u, CLI_ERR_NONE);

	/* Check for '?' and 'TAB' flag */
	if(strcmp(argv[0], HELP_SUFFIX) == 0)
	{
		/* argv[0] == HELP_SUFFIX , show cmds tab */
		sub_cmdparse_help(tab, argc, argv, u);
		return 1;
	}
	else if(strcmp(argv[0], TAB_SUFFIX) == 0)
	{
		/* argv[0] == TAB_SUFFIX , show cmds tab */
		sub_cmdparse_tab(tab, argc, argv, u);
		return 1;
	}
	else
	{
		/* Check for NO_BLANK matchmode */
		if(*argv[0] == '\0')
		{
			/* NO_BLANK matchmode end */
			if(ISSET_CMD_ST(u, CMD_ST_END))
				return 0;
			else
			{
				SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
				return -1;
			}
		}
		
		/* Reset the error buffer and err_no */
		if(reset_users_err_ptr(argc, argv, u) < 0)
			DEBUG_MSG(1, "Can't find the pointer of argv[0]!!\n", NULL);

		/* Search cmds */
		cmds_ptr = search_cmds(tab, argc, argv, u);
	}
	
	if(cmds_ptr == NULL)
	{
		/* Check for '?' and 'TAB' flag (No blank) */
		if(strstr(argv[0], HELP_SUFFIX) != NULL)
			retval = sub_cmdparse_help_show(tab, argc, argv, u);
		else if(strstr(argv[0], TAB_SUFFIX) != NULL)
			retval = sub_cmdparse_tab_show(tab, argc, argv, u);
		else
			return -1;
	}
	else
	{			
		/* Change u->cmd_st base on end_flag */
		if((ISSET_CMD_ST(u, CMD_ST_NO) && (cmds_ptr->end_flag & CLI_END_NO))
			|| (ISSET_CMD_ST(u, CMD_ST_DEF) && (cmds_ptr->end_flag & CLI_END_DEF))
			|| (!ISSET_CMD_ST(u, CMD_ST_NO) && !ISSET_CMD_ST(u, CMD_ST_DEF) 
			&& (cmds_ptr->end_flag & CLI_END_FLAG)))
			SET_CMD_ST(u, CMD_ST_END);
		else
			CLEAR_CMD_ST(u, CMD_ST_END);

		/* Change u->cmd_mskbits */
		if(cmds_ptr->cmdmask != 0)
			SET_CMD_MSKBIT(u, cmds_ptr->cmdmask);
	
		/* Process the func */
		if(ISSET_CMD_ST(u, CMD_ST_NO) && cmds_ptr->nopref != NULL)
			retval = cmds_ptr->nopref(argc, argv, u);
		else if(ISSET_CMD_ST(u, CMD_ST_DEF) && cmds_ptr->defpref != NULL)
			retval = cmds_ptr->defpref(argc, argv, u);
		else if(cmds_ptr->func != NULL)
			retval = cmds_ptr->func(argc, argv, u);
		else
			DEBUG_MSG(1, "Error: func, nopref or defpref  is NULL!!\n", NULL);
	}
	
	return retval;
}

/* 1:done -1:error */
int sub_cmdparse_help(struct cmds tab[], int argc, char *argv[], struct users *u)
{
	char *name = NULL, *comment = NULL;
	struct cmds *cmds_ptr = tab;

	if(argc < 1 || argv == NULL || u == NULL)
		return -1;
	
	/* show cmds tab */
	while(cmds_ptr != NULL && cmds_ptr->name != NULL)
	{
		if(cli_check_cmd_privilege(cmds_ptr->pv_level, u)
			&& !cli_check_submask(u->cmd_mskbits, cmds_ptr->cmdmask))
		{
			name = cmds_ptr->name;
			comment = ISSET_CMD_ST(u, CMD_ST_CN)? cmds_ptr->hhp: cmds_ptr->yhp;
				
			cli_help_buffer_parse(name, comment);
		}
		
		cmds_ptr += 1;
	}
	if(ISSET_CMD_ST(u, CMD_ST_END))
	{
		if(ISSET_CMD_ST(u, CMD_ST_CN))
			vty_output("%s\n", CR_SHOW_CN);
		else
			vty_output("%s\n", CR_SHOW_EN);
	}

	return 1;
}

/* 1:done -1:error */
int sub_cmdparse_help_show(struct cmds tab[], int argc, char *argv[], struct users *u)
{
	int len = 0, match_cnt = 0;
	char buff[MAX_ARGV_LEN] = {'\0'}, *err_ptr = NULL;
	struct cmds *cmds_ptr = tab;

	if(argc < 1 || argv == NULL || u == NULL)
		return -1;

	len = strstr(argv[0], HELP_SUFFIX) - argv[0];

	/* argv[0] == HELP_SUFFIX */
	if(len == 0)	return 1;
	
	/* Get the buff from argv[0] without '?' flag */
	memset(buff, '\0', sizeof(buff));
	memcpy(buff, argv[0], len);

	/* Record error pointer */
	err_ptr = u->err_ptr;
	
	while(cmds_ptr != NULL && cmds_ptr->name != NULL)
	{
		/* Reset error pointer */
		u->err_ptr = err_ptr;
		
		/* Check submask */
		if(cli_check_cmd_privilege(cmds_ptr->pv_level, u)
			&& !cli_check_submask(u->cmd_mskbits, cmds_ptr->cmdmask))
		{
			if(sub_cmdparse_help_show_mode(cmds_ptr, buff, u) == 1)
				match_cnt += 1;
		}
		
		cmds_ptr += 1;
	}

	/* No match */
	if(match_cnt == 0)
	{
		if(IS_ERR_NO(u, CLI_ERR_NONE))
		{
			/* Reset error pointer */
			u->err_ptr = err_ptr;

			SET_ERR_NO(u, CLI_ERR_CMD_ERR);
		}
		return -1;
	}
	
	return 1;
}

int sub_cmdparse_help_show_mode(struct cmds *cmds_ptr, char *s, struct users *u)
{
	char *name = NULL, *comment = NULL;
	
	if(cmds_ptr == NULL || s == NULL || u == NULL)
		return -1;

	switch(cmds_ptr->matchmode)
	{
		case CLI_CMD:
		case CLI_CMD_NO_BLANK:
			if(strncasecmp(s, cmds_ptr->name, strlen(s)) != 0)
				return -1;
			break;

		case CLI_CMD_UNUSAL:
			return -1;
			break;
			
		case CLI_CHAR:
			if(strlen(s) != 1)
				return -1;

			if(cmds_ptr->argcmin != 0 || cmds_ptr->argcmax != 0)
			{
				if(*s < cmds_ptr->argcmin || *s > cmds_ptr->argcmax)
					return -1;
			}
			else
			{
				if(*s != *(cmds_ptr->name))
					return -1;
			}
			break;
			
		case CLI_CHAR_NO_BLANK:
		case CLI_CHAR_UNUSAL:
		case CLI_INT_UNUSAL:
			return -1;
			break;
			
		case CLI_INT:
			if(cli_param_int32_format(s, cmds_ptr->argcmin, cmds_ptr->argcmax, u) < 0)
				return -1;
			break;
		case CLI_INT_RANGE:
			if(cli_param_int32_range_format(s, cmds_ptr->argcmin, cmds_ptr->argcmax, u) < 0)
				return -1;
			break;
		case CLI_INT_MULTI:
			if(cli_param_int32_multi_format(s, cmds_ptr->argcmin, cmds_ptr->argcmax, u) < 0)
				return -1;
			break;
			
		case CLI_MAC:
			if(cli_param_mac_format(s, u) < 0)
				return -1;
			break;
			
		case CLI_TIME:
			if(cli_param_time_format(s, u) < 0)
				return -1;
			break;
			
		case CLI_IPV4_MASK:
		case CLI_IPV4:
			if(cli_param_ipv4_format(cmds_ptr->matchmode, s, u) < 0)
				return -1;
			break;
			
		case CLI_IPV6_MASK:
		case CLI_IPV6_NOMASK:
		case CLI_IPV6:
			if(cli_param_ipv6_format(cmds_ptr->matchmode, s, u) < 0)
				return -1;
			break;
				
		case CLI_WORD:
			if(cli_param_word_format(s, cmds_ptr->argcmin, cmds_ptr->argcmax, u) < 0)
				return -1;
			break;
		
		case CLI_LINE:
			/* do nothing */
			return 1;
			break;
		
		default :
			DEBUG_MSG(1, "Unknow matchmode: %d!!\n", cmds_ptr->matchmode);
			return -1;
			break;
	}

	name = cmds_ptr->name;
	comment = ISSET_CMD_ST(u, CMD_ST_CN)? cmds_ptr->hhp: cmds_ptr->yhp;
		
	cli_help_buffer_parse(name, comment);
	
	return 1;
}

int sub_cmdparse_tab(struct cmds tab[], int argc, char *argv[], struct users *u)
{
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct cmds *cmds_ptr = tab;

	if(argc < 1 || argv == NULL || u == NULL)
		return -1;

	/* Only one topcmds */
	if((cmds_ptr+1) == NULL || (cmds_ptr+1)->name == NULL)
	{
		if(cmds_ptr->matchmode == CLI_CMD
			|| cmds_ptr->matchmode == CLI_CMD_UNUSAL
			|| cmds_ptr->matchmode == CLI_CHAR)
		{
			/* Fill the line buffer for console (add one blank)*/
			sprintf(buff, "%s ", cmds_ptr->name);
		
			memcpy(&(u->linebuf[u->linelen]), buff, strlen(buff));
			u->linelen = u->linelen + strlen(buff);
		}
		else if(cmds_ptr->matchmode == CLI_CMD_NO_BLANK
			|| cmds_ptr->matchmode == CLI_CHAR_NO_BLANK
			|| cmds_ptr->matchmode == CLI_CHAR_UNUSAL)
		{
			if(cmds_ptr->argcmin == 0 && cmds_ptr->argcmax== 0)
			{
				/* Fill the line buffer for console */
				sprintf(buff, "%s", cmds_ptr->name);
			
				memcpy(&(u->linebuf[u->linelen]), buff, strlen(buff));
				u->linelen = u->linelen + strlen(buff);
			}
		}
	}
	
	return 1;
}

/* 1:done -1:error */
int sub_cmdparse_tab_show(struct cmds tab[], int argc, char *argv[], struct users *u)
{
	int len = 0, match_cnt = 0;
	char buff[MAX_ARGV_LEN], buff_tmp[256];
	struct cmds *cmds_ptr = tab;
	struct cmds *cmds_record = NULL;

	if(argc < 1 || argv == NULL || u == NULL)
		return -1;

	len = strstr(argv[0], TAB_SUFFIX) - argv[0];

	if(len > 0)
	{
		memset(buff_tmp, '\0', sizeof(buff_tmp));
		while(cmds_ptr != NULL && cmds_ptr->name != NULL)
		{
			if(cli_check_cmd_privilege(cmds_ptr->pv_level, u)
				&& !cli_check_submask(u->cmd_mskbits, cmds_ptr->cmdmask))
			{
				if(cmds_ptr->matchmode == CLI_CMD
					|| cmds_ptr->matchmode == CLI_CMD_NO_BLANK
					|| cmds_ptr->matchmode == CLI_CMD_UNUSAL)
				{
					if(strncasecmp(argv[0], cmds_ptr->name, len) == 0)
					{
						memset(buff, '\0', sizeof(buff));
						sprintf(buff, "%s ", cmds_ptr->name);
						strcat(buff_tmp, buff);
						
						match_cnt += 1;
						cmds_record = cmds_ptr;
					}
				}
			}
			cmds_ptr += 1;
		}

		if(match_cnt == 1 && cmds_record != NULL)
		{
			if(cmds_record->matchmode == CLI_CMD_NO_BLANK)
			{
				/* Fill the line buffer for console */
				memcpy(&(u->linebuf[u->linelen]), (cmds_record->name+ len), (strlen(cmds_record->name) - len));
				u->linelen = u->linelen - len + strlen(cmds_record->name);
			}
			else
			{
				/* Fill the line buffer for console (add one blank)*/
				memcpy(&(u->linebuf[u->linelen]), (buff+ len), (strlen(buff) - len));	
				u->linelen = u->linelen - len + strlen(buff);
			}
		}
		else if(match_cnt > 1)
			cli_tab_buffer_parse(buff_tmp, match_cnt, len, u);
	}

	return 1;
}

/* cmds_entry:done NULL:error */
struct cmds *search_cmds(struct cmds tab[], int argc, char *argv[], struct users *u)
{
	int retval = 0, ab_cnt = 0, unmatch_cnt = 0;
	int line_help_flag = 0;
	int s_len = 0, s_len_ret = 0;
	int args_offset = 0, match_mode = 0;
	uint32_t match_msk = 0x00000000;
	char *err_ptr = NULL;
	
	struct cmds *cmds_ptr = tab;
	struct cmds *cmds_ret = NULL;
	
	struct parameter *param = NULL, *param0 = NULL;

	if(argc < 1 || argv == NULL || u == NULL)
		return NULL;

	DEBUG_MSG(1, "argc=%d, argv[0]=%s\n", argc, argv[0]);

	/* Record error pointer */
	err_ptr = u->err_ptr;
	
	/* Search cmds tab, High priority match_mode should check first */
	while(cmds_ptr != NULL && cmds_ptr->name != NULL)
	{
		//DEBUG_MSG(0, "matchmode=%d, cmdmask=%08x, u:cmd_mskbits=%08x\n", cmds_ptr->matchmode, cmds_ptr->cmdmask, u->cmd_mskbits);
		/* Reset error pointer */
		u->err_ptr = err_ptr;
		
		if(cli_check_cmd_privilege(cmds_ptr->pv_level, u) && !cli_check_submask(u->cmd_mskbits, cmds_ptr->cmdmask))
		{
			if(cmds_ptr->matchmode == CLI_CMD)
			{
				/* argv[0] contains '?' or 'TAB' flag (No blank) */
				if(strstr(argv[0], HELP_SUFFIX) != NULL || strstr(argv[0], TAB_SUFFIX) != NULL)
				{
					cmds_ptr += 1;
					continue;
				}
				
				if(strncasecmp(argv[0],  cmds_ptr->name, strlen(argv[0])) == 0)
				{
					/* Get cmds */
					ab_cnt += 1;
					/* Record cmds_ptr */
					cmds_ret = cmds_ptr;
					
					/* Accurately match, if more than one, return the first one */
					if(strlen(argv[0]) == strlen(cmds_ptr->name))
					{
						ab_cnt = 1;
						break;
					}
				}
				
			}
			else if(cmds_ptr->matchmode == CLI_CMD_NO_BLANK)
			{
				s_len = strlen(cmds_ptr->name);
				while(s_len > 0 && strncasecmp(argv[0], cmds_ptr->name, s_len))
					s_len --;

				/* Should accurately matched */
				if(s_len == strlen(cmds_ptr->name)
					&& strncasecmp(argv[0],  cmds_ptr->name, s_len) == 0)
				{
					/* Get cmds */
					ab_cnt = 1;
					
					/* Record cmds_ptr */
					s_len_ret = s_len;
					cmds_ret = cmds_ptr;

					break;
				}
			}
			else if(cmds_ptr->matchmode == CLI_CMD_UNUSAL)
			{
				/* Checking argv[0] for '?' is no needed.
				     Just should make sure s_len is more zero */
					
				s_len = strlen(cmds_ptr->name);
				while(s_len > 0 && strncasecmp(argv[0], cmds_ptr->name, s_len))
					s_len --;

				if(s_len > 0)
				{
					/* Fill the comand, like as CLI_CMD match_mode */
					if(s_len < strlen(cmds_ptr->name) 
						&& strcmp((argv[0]+s_len), TAB_SUFFIX) == 0)
					{
						cmds_ptr += 1;
						continue;
					}
					
					/* Get cmds */
					ab_cnt += 1;
					
					/* Record s_len and cmds_ptr */
					s_len_ret = s_len;
					cmds_ret = cmds_ptr;
					
					/* Accurately match, if more than one, return the first one */
					if(s_len == strlen(cmds_ptr->name))
					{
						ab_cnt = 1;
						break;
					}
				}
			}
			else if(cmds_ptr->matchmode == CLI_CHAR)
			{
				/* Checking argv[0] for '?' and 'TAB' flag is no needed */
				/* Argv[0] should be one char */
				if(strlen(argv[0]) == 1)
				{
					if(cmds_ptr->argcmin != 0 || cmds_ptr->argcmax != 0)
					{
						if(*argv[0] >= cmds_ptr->argcmin && *argv[0] <= cmds_ptr->argcmax)
						{
							/* Get cmds */
							ab_cnt += 1;
							/* Record cmds_ptr */
							cmds_ret = cmds_ptr;
						}
					}
					else
					{
						if(*argv[0] == *(cmds_ptr->name))
						{
							/* Get cmds */
							ab_cnt += 1;
							/* Record cmds_ptr */
							cmds_ret = cmds_ptr;
						}
					}
				}
			}
			else if(cmds_ptr->matchmode == CLI_CHAR_NO_BLANK
				||cmds_ptr->matchmode == CLI_CHAR_UNUSAL)
			{
				/* Checking argv[0] for '?' and 'TAB' flag is no needed */
				
				if(cmds_ptr->argcmin != 0 || cmds_ptr->argcmax != 0)
				{
					if(*argv[0] >= cmds_ptr->argcmin && *argv[0] <= cmds_ptr->argcmax)
					{
						/* Get cmds */
						ab_cnt += 1;
						/* Record cmds_ptr */
						cmds_ret = cmds_ptr;
					}
				}
				else
				{
					if(*argv[0] == *(cmds_ptr->name))
					{
						/* Get cmds */
						ab_cnt += 1;
						/* Record cmds_ptr */
						cmds_ret = cmds_ptr;
					}
				}
			}
			else
			{
				cmds_ptr += 1;
				continue;
			}
		}
		cmds_ptr += 1;
	}
	
	if(ab_cnt > 1)
	{
		/* Reset error pointer */
		u->err_ptr = err_ptr;
		
		/* Matched cmds are More than one */
		SET_ERR_NO(u, CLI_ERR_CMD_ERR);
		return NULL;
	}
	else if(ab_cnt == 1 && cmds_ret != NULL)
	{
		/* Modify the argv, and change the args_offset */
		if(cmds_ret->matchmode == CLI_CMD)
			u->args_offset += 1;
		else if(cmds_ret->matchmode == CLI_CMD_NO_BLANK)
		{
			/* Wether argv[0] is end or not, don't change args_offset */
			argv[0] += s_len_ret;
		}
		else if(cmds_ret->matchmode == CLI_CMD_UNUSAL)
		{
#ifdef CLI_CMD_UNUSAL_RECORD
			/* Record the first char to users:v_range */
			if(u->s_param.v_range_len < (MAC_V_STR_LEN-1))
			{
				u->s_param.v_range[u->s_param.v_range_len] = *argv[0];
				u->s_param.v_range_len += 1;
			}
#endif
			/* argv[0] is end, change the args_offset */
			if(s_len_ret == strlen(argv[0]))
				u->args_offset += 1;
			else
				argv[0] += s_len_ret;
		}
		else if(cmds_ret->matchmode == CLI_CHAR)
			u->args_offset += 1;
		else if(cmds_ret->matchmode == CLI_CHAR_NO_BLANK)
		{
#ifdef CLI_CHAR_NO_BLANK_RECORD
			/* Record the char to users:v_range */
			if(u->s_param.v_range_len < (MAC_V_STR_LEN-1))
			{
				u->s_param.v_range[u->s_param.v_range_len] = *argv[0];
				u->s_param.v_range_len += 1;
			}
#endif			
			/* Wether argv[0] is end or not, don't change args_offset */
			argv[0] += 1;
		}
		else if(cmds_ret->matchmode == CLI_CHAR_UNUSAL)
		{
#ifdef CLI_CHAR_UNUSAL_RECORD
			/* Record the char to users:v_range */
			if(u->s_param.v_range_len < (MAC_V_STR_LEN-1))
			{
				u->s_param.v_range[u->s_param.v_range_len] = *argv[0];
				u->s_param.v_range_len += 1;
			}
#endif			
			/* argv[0] is end, change the args_offset */
			if(*(++argv[0]) == '\0')
				u->args_offset += 1;
		}
		
		return cmds_ret;
	}

	/* No match, reset the variables */
	ab_cnt = 0;
	match_mode = CLI_END;
	cmds_ptr = tab;
	cmds_ret = NULL;

	/* Malloc space for param0 */
	if((param0 = (struct parameter *)malloc(sizeof(struct parameter))) == NULL)
	{
		DEBUG_MSG(1, "Error: param and param0 malloc failed!!\n", NULL);
		return NULL;
	}
	memset(param0, '\0', sizeof(struct parameter));

	/* Search cmds tab for lower priority match_mode */
	while(cmds_ptr != NULL && cmds_ptr->name != NULL)
	{
		DEBUG_MSG(1, "matchmode=%d, cmdmask=%08x, u:cmd_mskbits=%08x\n", cmds_ptr->matchmode, cmds_ptr->cmdmask, u->cmd_mskbits);

		/* Reset error pointer */
		u->err_ptr = err_ptr;
		
		/* Check if u->cmd_mskbist is set or not */
		if(cli_check_cmd_privilege(cmds_ptr->pv_level, u) && !cli_check_submask(u->cmd_mskbits, cmds_ptr->cmdmask))
		{
			/* Record the args_offset */
			args_offset = u->args_offset;

			/* Convert cmds_ptr to param(malloc, should free) */
			if((param = cli_cmds2param(cmds_ptr)) == NULL)
				continue;

			/* Check match_mode priority */
			if(cli_check_matchmode_priority(match_mode, cmds_ptr->matchmode))
			{
				/* Check the parameter */
				switch(cmds_ptr->matchmode)
				{
					case CLI_CMD:
					case CLI_CMD_NO_BLANK:
					case CLI_CMD_UNUSAL:
					case CLI_CHAR:
					case CLI_CHAR_NO_BLANK:
					case CLI_CHAR_UNUSAL:
						free(param);
						cmds_ptr += 1;
						continue;
						break;

					case CLI_INT_UNUSAL:
					case CLI_INT:
					case CLI_INT_RANGE:
					case CLI_INT_MULTI:
						retval = cli_param_int(argc, argv, u, param);
						break;

					case CLI_MAC:
						retval = cli_param_mac(argc, argv, u, param);
						break;

					case CLI_TIME:
						retval = cli_param_time(argc, argv, u, param);
						break;

					case CLI_IPV4:
					case CLI_IPV4_MASK:
						retval = cli_param_ipv4(argc, argv, u, param);
						break;

					case CLI_IPV6:
					case CLI_IPV6_MASK:
					case CLI_IPV6_NOMASK:
						retval = cli_param_ipv6(argc, argv, u, param);
						break;
						
					case CLI_WORD:
						retval = cli_param_word(argc, argv, u, param);
						break;
									
					case CLI_LINE:
						/* retval:1, "?" or "TAB"  */
						if((retval = cli_param_line(argc, argv, u, param)) == 1)
							line_help_flag = 1;
						break;
					
					default :
						DEBUG_MSG(1, "Unknow cmd_type: %d!!\n", cmds_ptr->matchmode);
						free(param);
						free(param0);
						return NULL;
						break;
				}
			
				/* Process the result of cli_param_xx function.
				    Success:0; Failed:-1; '?' or 'TAB' flag:1*/
				if(retval == 0)
				{
					memset(param0, '\0', sizeof(struct parameter));
					memcpy(param0, param, sizeof(struct parameter));
					u->args_offset -= args_offset;
			
					ab_cnt = 1;
					match_mode = param->type;
					
					cmds_ret = cmds_ptr;
				}
				else if(retval < 0)
				{
					if(!cli_check_matchmode_mask(&match_msk, cmds_ptr->matchmode))
						unmatch_cnt += 1;
				}
			}
			
			/* Free the space get from cli_cmds2param() */
			free(param);
		}
		cmds_ptr += 1;
	}
	
	if(ab_cnt > 0)
	{
		/* if Matched cmds are more than one, Higher priority cmds_ptr will return */
		cli_param_set(STATIC_PARAM, param0, u);
		
		free(param0);
		return cmds_ret;
	}

	/* No match */
	if((IS_ERR_NO(u, CLI_ERR_NONE) && !line_help_flag)	|| unmatch_cnt > 1)
	{
		/* Reset error pointer */
		u->err_ptr = err_ptr;

		/* unmatched is more than one */
		SET_ERR_NO(u, CLI_ERR_CMD_ERR);
	}

	free(param0);
	return NULL;
}

/* parameter parse func*/
/* 0:done 1:help or tab -1:error */
int getparameter(int argc, char *argv[], struct users *u, struct parameter *param)
{
	int retval = -1;

	if(u == NULL)
		return -1;

	/* Do argc and argv offset */
	argc -= u->args_offset;
	argv += u->args_offset;
	
	/* Check argc and argv */
	if(argc < 1 || argv == NULL)
	{
		if(ISSET_CMD_ST(u, CMD_ST_END))
			return 0;
		else
		{
			SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
			return -1;
		}
	}
	#if 0
	if(strlen(argv[0]) > MAX_ARGV_LEN)
	{
		sprintf(u->err_ptr, "%s: Too long!!\n", argv[0]);
		return -1;
	}
	#endif
//	DEBUG("argc=%d, argv[0]=%s\n", argc, argv[0]);
	
	/* Reset err_no */
	SET_ERR_NO(u, CLI_ERR_NONE);

	/* Check for '?' and 'TAB' flag */
	if(strcmp(argv[0], HELP_SUFFIX) == 0)
	{
		/* argv[0] == HELP_SUFFIX , show cmds tab */
		getparameter_help(argc, argv, u, param);
		return 1;
	}
	else if(strcmp(argv[0], TAB_SUFFIX) == 0)
		return 1;
	else
	{
		/* Check for NO_BLANK matchmode */
		if(*argv[0] == '\0')
		{
			/* NO_BLANK matchmode end */
			if(ISSET_CMD_ST(u, CMD_ST_END))
				return 0;
			else
			{
				SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
				return -1;
			}
		}
		
		/* Reset the error buffer and err_no */
		if(reset_users_err_ptr(argc, argv, u) < 0)
			DEBUG_MSG(1, "Can't find the pointer of argv[0]!!\n", NULL);

		/* Search the parameter */
		retval = search_parameter(argc, argv, u, param);
	}
	
	if(retval != 0)
	{
		/* Check for '?' and 'TAB' flag (No blank) */
		if(strstr(argv[0], HELP_SUFFIX) != NULL)
			retval = getparameter_help_show(argc, argv, u, param);
		else if(strstr(argv[0], TAB_SUFFIX) != NULL)
			retval = 1;
		else
			return -1;
	}
	else
	{
		/* Change u->cmd_st base on end_flag */
		if((ISSET_CMD_ST(u, CMD_ST_NO) && (param->flag & CLI_END_NO))
			|| (ISSET_CMD_ST(u, CMD_ST_DEF) && (param->flag & CLI_END_DEF))
			|| (!ISSET_CMD_ST(u, CMD_ST_NO) && !ISSET_CMD_ST(u, CMD_ST_DEF) 
			&& (param->flag & CLI_END_FLAG)))
			SET_CMD_ST(u, CMD_ST_END);
		else
			CLEAR_CMD_ST(u, CMD_ST_END);	
	}
	
	return retval;
}

int getparameter_help(int argc, char *argv[], struct users *u, struct parameter *param)
{
	char *name = NULL, *comment = NULL;
	
	if(argc < 1 || argv == NULL || u == NULL)
		return -1;
	
	/* show parameter info */
	name = param->name;
	comment = ISSET_CMD_ST(u, CMD_ST_CN)? param->hlabel: param->ylabel;
		
	cli_help_buffer_parse(name, comment);

	return 1;
}

int getparameter_help_show(int argc, char *argv[], struct users *u, struct parameter *param)
{
	int len = 0, match_cnt = 0;
	char buff[MAX_ARGV_LEN];

	if(argc < 1 || argv == NULL || u == NULL || param == NULL )
		return -1;

	len = strstr(argv[0], HELP_SUFFIX) - argv[0];

	/* argv[0] == HELP_SUFFIX */
	if(len == 0)	return 1;

	/* Get the buff from argv[0] without '?' flag */
	memset(buff, '\0', sizeof(buff));
	memcpy(buff, argv[0], len);
	
	/* Check incomplete parameter */
	if(getparameter_help_show_mode(param, buff, u) == 1)
		match_cnt += 1;

	/* No match */
	if(match_cnt == 0)
	{
		if(IS_ERR_NO(u, CLI_ERR_NONE))
			SET_ERR_NO(u, CLI_ERR_CMD_ERR);	
		return -1;
	}

	return 1;
}

/* done:1 failed:-1 */
int getparameter_help_show_mode(struct parameter *param, char *s, struct users *u)
{
	int match_flag = 0;
	
	struct cmds *cmds_ptr = NULL;
	
	if((cmds_ptr = cli_param2cmds(param)) == NULL)
		return -1;
	
	if(sub_cmdparse_help_show_mode(cmds_ptr, s, u) == 1)
		match_flag = 1;
	else
		match_flag = -1;

	free(cmds_ptr);

	return match_flag;
}

/* parameter parse func */
/* 0:done 1:help or tab -1:error */
int search_parameter(int argc, char *argv[], struct users *u, struct parameter *param)
{
	int retval = -1;

	if(argc < 1 || argv == NULL || u == NULL || param == NULL )
		return -1;
	
	switch(param->type)
	{
		case CLI_CMD:
		case CLI_CMD_NO_BLANK:
		case CLI_CMD_UNUSAL:
		case CLI_CHAR:
		case CLI_CHAR_NO_BLANK:
		case CLI_CHAR_UNUSAL:
			DEBUG_MSG(1, "Can't getparameter of this type: %d!!\n", param->type);
			retval = -1;
			break;
		
		case CLI_INT_UNUSAL:
		case CLI_INT:
		case CLI_INT_RANGE:
		case CLI_INT_MULTI:
			retval = cli_param_int(argc, argv, u, param);
			break;
		
		case CLI_MAC:
			retval = cli_param_mac(argc, argv, u, param);
			break;
		
		case CLI_TIME:
			retval = cli_param_time(argc, argv, u, param);
			break;
		
		case CLI_IPV4:
		case CLI_IPV4_MASK:
			retval = cli_param_ipv4(argc, argv, u, param);
			break;
		
		case CLI_IPV6:
		case CLI_IPV6_MASK:
		case CLI_IPV6_NOMASK:
			retval = cli_param_ipv6(argc, argv, u, param);
			break;
			
		case CLI_WORD:
			retval = cli_param_word(argc, argv, u, param);
			break;
						
		case CLI_LINE:
			retval = cli_param_line(argc, argv, u, param);
			break;
		
		default :
			DEBUG_MSG(1, "Unknow param->type: %d!!\n", param->type);
			break;		
	}

	if(retval < 0 && IS_ERR_NO(u, CLI_ERR_NONE))
		SET_ERR_NO(u, CLI_ERR_CMD_ERR);
	
	return retval;
}

/* cmderror parse func*/
/* 0:end 1:help or tab -1:error */
int cmdend(struct cmds tab[], int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if(u == NULL)
		return -1;

	/* Do argc and argv offset */
	argc -= u->args_offset;
	argv += u->args_offset;
	
	if(argc < 0 || argv == NULL)
	{
		/* Error occured, Incomplete Command */
		SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
		return -1;
	}
	DEBUG_MSG(1, "argc=%d, argv[0]=%s\n", argc, argv[0]);
	
	/* Reset err_no */
	SET_ERR_NO(u, CLI_ERR_NONE);

	/* Check cmdend */
	if(argc == 0)
	{
		if(ISSET_CMD_ST(u, CMD_ST_END))
			return 0;
		else
		{
			/* Error occured, Incomplete Command */
			SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
			return -1;
		}
	}
	else if(argc == 1)
	{
		/* Check for NO_BLANK matchmode */
		if(*argv[0] == '\0')
		{
			/* NO_BLANK matchmode end */
			if(ISSET_CMD_ST(u, CMD_ST_END))
				return 0;
			else
			{
				SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
				return -1;
			}
		}
		
		/* Reset the error buffer and err_no */
		if(reset_users_err_ptr(argc, argv, u) < 0)
			DEBUG_MSG(1, "Can't find the pointer of argv[0]!!\n", NULL);
		
		/* Check for '?' and 'TAB' flag */
		if(strcmp(argv[0], HELP_SUFFIX) == 0)
		{
			/* argv[0] == HELP_SUFFIX , show cmds tab */
			sub_cmdparse_help(tab, argc, argv, u);
			return 1;
		}
		else if(strcmp(argv[0], TAB_SUFFIX) == 0)
		{
			/* argv[0] == TAB_SUFFIX , show cmds tab */
			sub_cmdparse_tab(tab, argc, argv, u);
			return 1;
		}
		
		if(strstr(argv[0], HELP_SUFFIX) != NULL)
			retval = sub_cmdparse_help_show(tab, argc, argv, u);
		else if(strstr(argv[0], TAB_SUFFIX) != NULL)
			retval = sub_cmdparse_tab_show(tab, argc, argv, u);
		else
			SET_ERR_NO(u, CLI_ERR_CMD_ERR);

		return retval;
	}
	else
		SET_ERR_NO(u, CLI_ERR_CMD_ERR);
	
	return -1;
}

/* cmderror parse func*/
/* 0:end 1:help or tab -1:error */
int cmdend2(int argc, char *argv[], struct users *u)
{
	if(u == NULL)
		return -1;

	/* Do argc and argv offset */
	argc -= u->args_offset;
	argv += u->args_offset;
	
	/* Check argc and argv */
	if(argc < 0 || argv == NULL)
	{
		/* Error occured, Incomplete Command */
		SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
		return -1;
	}

	/* Reset err_no */
	SET_ERR_NO(u, CLI_ERR_NONE);

	/* Check cmdend */
	if(argc == 0)
	{
		DEBUG_MSG(1, "argc=%d, command is end\n", argc);

		/* Check cmd_st end_flag */
		if(ISSET_CMD_ST(u, CMD_ST_END))
			return 0;
		else
		{
			SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
			return -1;
		}
	}
	else if(argc == 1)
	{
		DEBUG_MSG(1, "argc=%d, argv[0]=%s\n", argc, argv[0]);

		/* Check for NO_BLANK matchmode */
		if(*argv[0] == '\0')
		{
			/* NO_BLANK matchmode end */
			if(ISSET_CMD_ST(u, CMD_ST_END))
				return 0;
			else
			{
				SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
				return -1;
			}
		}
		
		/* Reset the error buffer and err_no */
		if(reset_users_err_ptr(argc, argv, u) < 0)
			DEBUG_MSG(1, "Can't find the pointer of argv[0]!!\n", NULL);
		
		/* Check for '?' and 'TAB' flag */
		if(strcmp(argv[0], HELP_SUFFIX) == 0)
		{
			/* argv[0] == HELP_SUFFIX , show CR */
			if(ISSET_CMD_ST(u, CMD_ST_CN))
				vty_output("%s\n", CR_SHOW_CN);
			else
				vty_output("%s\n", CR_SHOW_EN);

			return 1;
		}
		else if(strcmp(argv[0], TAB_SUFFIX) == 0)
		{
			/* argv[0] == TAB_SUFFIX , do nothing */
			return 1;
		}
		else
		{
			SET_ERR_NO(u, CLI_ERR_CMD_ERR);
			return -1;
		}
	}
	else if(argc > 1)
	{
		/* Reset the error buffer and err_no */
		if(reset_users_err_ptr(argc, argv, u) < 0)
			DEBUG_MSG(1, "Can't find the pointer of argv[0]!!\n", NULL);

		SET_ERR_NO(u, CLI_ERR_CMD_ERR);
		return -1;
	}
	
	SET_ERR_NO(u, CLI_ERR_CMD_ERR);
	return -1;
}

/* cmderror parse func*/
int cmderror(struct users *u)
{
	int err_offset = 0, err_flag = 0, linelen = 0;
	char *linebuf = NULL;

	if(u == NULL)
		return -1;
	
	DEBUG_MSG(1, "err_no=%d, err_ptr=%s\n", u->err_no, u->err_ptr);

	/* No err_no */
	if(u->err_no == CLI_ERR_NONE)
		return 0;

	/* System error, such as malloc or select and so no */
	if(u->err_no == CLI_ERR_SYS_ERR)
	{
		vty_output("Serious error, Check DEBUG_MSG()!!\n");
		return 0;
	}

	/* Incomplete Command */
	if(u->err_no == CLI_ERR_INCOMPLETE_CMD)
	{
		vty_output("Incomplete Command!!\n");
		return 0;
	}
		
	/* Get the error offset */
	err_offset = u->err_ptr - u->linebuf;

	/* Print the error info */
	linelen = u->linelen;
	linebuf = u->linebuf;

	while(1)
	{
		vty_output("%-80.80s\n", linebuf);

		if(err_offset > 80)
			err_offset -= 80;
		else
		{
			if(err_flag == 0)
			{
				if(err_offset == 0)
					vty_output("^\n");
				else
					vty_output("\033[%dC^\n", err_offset);

				err_flag = 1;
			}
		}

		if(linelen > 80)
		{
			linebuf += 80;
			linelen -= 80;
		}
		else
			break;
	}

	if(ISSET_CMD_ST(u, CMD_ST_CN))
	{		
		/* Print the error type */
		switch(u->err_no)
		{
			case CLI_ERR_CMD_ERR:
				vty_output("命令错误!!\n");
				break;
			case CLI_ERR_UNKNOW_CMD:
				vty_output("未知命令!!\n");
				break;
			case CLI_ERR_INT_FORMAT:
				vty_output("无效的整型格式!!\n");
				break;
			case CLI_ERR_INT_RANGE:
				vty_output("这个整数不在当前范围!!\n");
				break;
			case CLI_ERR_WORD_LENTH:
				vty_output("字长是无效的!!\n");
				break;
			case CLI_ERR_MAC_FORMAT:
				vty_output("非法 MAC 地址格式!!\n");
				break;
			case CLI_ERR_TIME_FORMAT:
				vty_output("非法的时间格式!!\n");
				break;
			case CLI_ERR_IPV4_FORMAT:
				vty_output("非法 IPv4 地址格式!!\n");
				break;
			case CLI_ERR_IPV4_NETMASK_FORMAT:
				vty_output("非法 IPv4 子网掩码格式!!\n");
				break;
			case CLI_ERR_IPV6_FORMAT:
				vty_output("非法 IPv6 地址格式!!\n");
				break;
			case CLI_ERR_IPV6_NOMASK:
				vty_output("不需要  IPv6 子网掩码!!\n");
				break;
			case CLI_ERR_IPV6_MASK:
				vty_output("非法 IPv6 子网掩码!!\n");
				break;
			case CLI_ERR_GIGAPORT_UNSUPPORT:
				vty_output("千兆口上不支持的配置属性!!\n");
				break;
			default :
				break;
		}
	} 
	else
	{	
		/* Print the error type */
		switch(u->err_no)
		{
			case CLI_ERR_CMD_ERR:
				vty_output("Command Error!!\n");
				break;
			case CLI_ERR_UNKNOW_CMD:
				vty_output("Unknow Command!!\n");
				break;
			case CLI_ERR_INT_FORMAT:
				vty_output("Invalid integer format!!\n");
				break;
			case CLI_ERR_INT_RANGE:
				vty_output("The integer is not in the current range!!\n");
				break;
			case CLI_ERR_WORD_LENTH:
				vty_output("Length of WORD is invalid!!\n");
				break;
			case CLI_ERR_MAC_FORMAT:
				vty_output("Invalid MAC address format!!\n");
				break;
			case CLI_ERR_TIME_FORMAT:
				vty_output("Invalid time format!!\n");
				break;
			case CLI_ERR_IPV4_FORMAT:
				vty_output("Invalid IPv4 address format!!\n");
				break;
			case CLI_ERR_IPV4_NETMASK_FORMAT:
				vty_output("Invalid IPv4 netmask address format!!\n");
				break;
			case CLI_ERR_IPV6_FORMAT:
				vty_output("Invalid IPv6 address format!!\n");
				break;
			case CLI_ERR_IPV6_NOMASK:
				vty_output("Don't need IPv6 mask!!\n");
				break;
			case CLI_ERR_IPV6_MASK:
				vty_output("Invalid IPv6 Netmask!!\n");
				break;
			case CLI_ERR_GIGAPORT_UNSUPPORT:
				vty_output("Unsupport Configure Type in GigaEthernet!!\n");
				break;
			default :
				break;
		}
	}
	return 0;
}

