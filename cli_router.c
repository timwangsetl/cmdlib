/*
 * Copyright 2016 by Kuaipao Corporation
 *
 * All Rights Reserved
 *
 * File name  : cli_router.c
 * Function   : router command function
 * Auther     : xi.chen
 * Version    : 1.0
 * Date       : 2011/11/9
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

#include "cli_router.h"
#include "cli_router_func.h"

static struct topcmds router_topcmds[] = {
	{ TOPCMDS_END }
};

static struct cmds router_cmds[] = {
	{ CMDS_END }
};

static struct topcmds ospf_topcmds[] = {
	{ TOPCMDS_END }
};

static struct cmds bfd_ospf_cmds[] =
{
	{ CMDS_END }
};

static struct cmds ospf_id_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds ospf_network_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds ospf_network_ip_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds ospf_network_ip_mask_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds ospf_network_ip_mask_area_cmds[] =
{
	{ CMDS_END  }//CLI_IPV4_MASK
};

static struct cmds ospf_network_ipv6_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds ospf_network_ipv6_area_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds ospf_network_ip_mask_area_id_cmds[] =
{
	{ CMDS_END  }
};

// Modified by kimilmin 20160703
static struct cmds ospf_network_ip_mask_area_mask_cmds[] =
{
	{ CMDS_END  }
};
///////////////////////////////////

static struct topcmds rip_topcmds[] = {
	{ TOPCMDS_END }
};

static struct cmds rip_default_cmds[] =
{
	{ CMDS_END  }
};


static struct cmds ospf_default_cmds[] =
{
	{ CMDS_END  }
};


static struct cmds bgp_default_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds rip_network_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds rip_network_ip_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds rip_version_cmds[] =
{
	{ CMDS_END  }
};

static struct topcmds isis_topcmds[] = {
	{ TOPCMDS_END }
};

static struct cmds isis_net_cmds[] = {
	{ CMDS_END }
};

static struct cmds isis_type_cmds[] =
{
	{ CMDS_END  }
};

static struct topcmds bgp_topcmds[] = {
	{ TOPCMDS_END }
};


static struct cmds bgp_id_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds bgp_neighbor_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds bgp_neighbor_ip_cmds[] =
{
	{ CMDS_END  }
};


static struct cmds bgp_neighbor_ipv6_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds bgp_neighbor_ip_remote_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds bgp_neighbor_ipv6_remote_cmds[] =
{
	{ CMDS_END  }
};

static struct cmds bgp_network_cmds[] =
{
	{ CMDS_END  }
};

/*
 *  Function:  do_router
 *  Purpose:  router topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
 
static int do_router(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(router_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  no_router
 *  Purpose:  router topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/7
 */
 
static int no_router(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* parse next sub command */
	retval = sub_cmdparse(router_cmds, argc, argv, u);

	return retval;
}

/*
 *  Function:  do_router_bgp
 *  Purpose:   router bgp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int do_router_bgp(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_INT;
	param.name = "<1-2147483647>";
	param.ylabel = "Autonomous system number";
	param.hlabel = "系统号";
	param.flag = CLI_END_FLAG;
	param.min = 1;
	param.max = 2147483647;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(func_router_bgp(u) < 0)
			return -1;

		if((retval = change_con_level(ROUTER_BGP_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "Router_bgp");

			DEBUG_MSG(1, "u->promptbuf=%s\n", u->promptbuf);
		}
	}

	return retval;
}

/*
 *  Function:  no_router_bgp
 *  Purpose:   router bgp command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int no_router_bgp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_router_bgp(u);
	}

	return retval;
}

/*
 *  Function:  do_router_isis
 *  Purpose:   router isis command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int do_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_INT;
	param.name = "<1-65535>";
	param.ylabel = "isis-id";
	param.hlabel = "IS-IS号";
	param.flag = CLI_END_FLAG;
	param.min = 1;
	param.max = 65535;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(func_router_isis(u) < 0)
			return -1;

		if((retval = change_con_level(ROUTER_ISIS_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "Router_isis");

			DEBUG_MSG(1, "u->promptbuf=%s\n", u->promptbuf);
		}
	}

	return retval;
}

/*
 *  Function:  no_router_isis
 *  Purpose:   router isis command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int no_router_isis(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_router_isis(u);
	}

	return retval;
}

/*
 *  Function:  do_router_ospf
 *  Purpose:   router ospf command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_router_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	param.type = CLI_INT;
	param.name = "<1-65535>";
	param.ylabel = "Process-id";
	param.hlabel = "进程号";
	param.flag = CLI_END_FLAG;
	param.min = 1;
	param.max = 65535;

	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	cli_param_set(DYNAMIC_PARAM, &param, u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(func_router_ospf(u) < 0)
			return -1;

		if((retval = change_con_level(ROUTER_OSPF_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "Router_ospf");

			DEBUG_MSG(1, "u->promptbuf=%s\n", u->promptbuf);
		}
	}

	return retval;
}

/*
 *  Function:  no_router_ospf
 *  Purpose:   router isis command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_router_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_router_ospf(u);
	}

	return retval;
}

/*
 *  Function:  do_ospf_id
 *  Purpose:   ospf route id command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ospf_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(ospf_id_cmds, argc, argv, u);
	
	return retval;
}

static int do_ospf_id_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ospf_id(u);
	}

	return retval;
}

/*
 *  Function:  no_ospf_id
 *  Purpose:   router isis command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ospf_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ospf_id(u);
	}

	return retval;
}

/*
 *  Function:  do_ospf_network
 *  Purpose:   ospf network command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ospf_network(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(ospf_network_cmds, argc, argv, u);
	
	return retval;
}

static int do_ospf_network_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(ospf_network_ip_cmds, argc, argv, u);
	
	return retval;
}

static int do_ospf_network_ip_mask(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(ospf_network_ip_mask_cmds, argc, argv, u);
	
	return retval;
}

static int do_ospf_network_ip_mask_area(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(ospf_network_ip_mask_area_cmds, argc, argv, u);
	
	return retval;
}

static int do_ospf_network_ip_mask_area_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ospf_network(u);
	}
	else
	{		
		retval = sub_cmdparse(ospf_network_ip_mask_area_id_cmds, argc, argv, u);
	}

	return retval;
}

// modified by kimilmin 20160703
static int do_ospf_network_ip_mask_area_mask(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ospf_network_mask(u);
	}
	else
	{		
		retval = sub_cmdparse(ospf_network_ip_mask_area_mask_cmds, argc, argv, u);
	}

	return retval;
}

static int do_ospf_network_ip_mask_area_id_ad(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ospf_network_ad(u);
	}

	return retval;
}

static int do_ospf_network_ip_mask_area_id_nad(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ospf_network_nad(u);
	}

	return retval;
}

/*
 *  Function:  no_ospf_network
 *  Purpose:   router isis command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ospf_network(int argc, char *argv[], struct users *u)
{
	int retval = -1;

//	if((retval = cmdend2(argc, argv, u)) == 0)
//	{
//		/* Do application */
//		nfunc_ospf_network(u);
//	}

	if(argc == 1)
	    nfunc_ospf_network(u);
	else   
	    retval = sub_cmdparse(ospf_network_cmds, argc, argv, u);  
	    
	return retval;
}

/*
 *  Function:  do_router_rip
 *  Purpose:   router rip command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_router_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	char buff[MAX_ARGV_LEN] = {'\0'};

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		if(func_router_rip(u) < 0)
			return -1;

		if((retval = change_con_level(ROUTER_RIP_TREE, u)) == 0)
		{
			memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "rip");

			DEBUG_MSG(1, "u->promptbuf=%s\n", u->promptbuf);
		}
	}

	return retval;
}

/*
 *  Function:  no_router_rip
 *  Purpose:   router isis command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_router_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_router_rip(u);
	}

	return retval;
}


static int do_router_pim_sm(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_router_pimsm(u);
	}

	return retval;
}

static int do_router_pim_dm(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_router_pimdm(u);
	}

	return retval;
}
static int no_router_pim_dm(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_router_pimsm(u);
	}

	return retval;
}


/*
 *  Function:  do_rip_auto_summary
 *  Purpose:   router rip auto summary command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_rip_auto_summary(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_rip_auto_summary(u);
	}

	return retval;
}

/*
 *  Function:  no_rip_auto_summary
 *  Purpose:   router rip auto summary command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_rip_auto_summary(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_rip_auto_summary(u);
	}

	return retval;
}

/*
 *  Function:  do_rip_default
 *  Purpose:   rip default inforamtion command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_rip_default(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(rip_default_cmds, argc, argv, u);
	
	return retval;
}

static int do_rip_default_originate(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_rip_default_originate(u);
	}

	return retval;
}

/*
 *  Function:  no_rip_default
 *  Purpose:   rip default inforamtion command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_rip_default(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(rip_default_cmds, argc, argv, u);
	
	return retval;
}

static int do_ospf_default(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(ospf_default_cmds, argc, argv, u);
	
	return retval;
}

static int no_ospf_default(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(ospf_default_cmds, argc, argv, u);
	
	return retval;
}

int do_bgp_default(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(bgp_default_cmds, argc, argv, u);
	
	return retval;
}

int no_bgp_default(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(bgp_default_cmds, argc, argv, u);
	
	return retval;
}

static int no_rip_default_originate(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_rip_default_originate(u);
	}

	return retval;
}

static int do_rip_default_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_rip_default_static(u);
	}

	return retval;
}

static int no_rip_default_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_rip_default_static(u);
	}

	return retval;
}

static int do_rip_default_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_rip_default_ospf(u);
	}

	return retval;
}

static int no_rip_default_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_rip_default_ospf(u);
	}

	return retval;
}

static int do_rip_default_bgp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_rip_default_bgp(u);
	}

	return retval;
}

static int no_rip_default_bgp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_rip_default_bgp(u);
	}

	return retval;
}

static int do_ospf_default_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ospf_default_static(u);
	}

	return retval;
}

static int no_ospf_default_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ospf_default_static(u);
	}

	return retval;
}

static int do_ospf_default_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ospf_default_rip(u);
	}

	return retval;
}

static int no_ospf_default_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ospf_default_rip(u);
	}

	return retval;
}

static int do_ospf_default_bgp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ospf_default_bgp(u);
	}

	return retval;
}

static int no_ospf_default_bgp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ospf_default_bgp(u);
	}

	return retval;
}

int do_bgp_default_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bgp_default_static(u);
	}

	return retval;
}

int no_bgp_default_static(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bgp_default_static(u);
	}

	return retval;
}

int do_bgp_default_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bgp_default_rip(u);
	}

	return retval;
}

int no_bgp_default_rip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bgp_default_rip(u);
	}

	return retval;
}

int do_bgp_default_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bgp_default_ospf(u);
	}

	return retval;
}

int no_bgp_default_ospf(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bgp_default_ospf(u);
	}

	return retval;
}

static int do_rip_connected(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_rip_connected(u);
	}

	return retval;
}

static int no_do_rip_connected(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_rip_connected(u);
	}

	return retval;
}

static int do_ospf_connected(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ospf_connected(u);
	}

	return retval;
}

static int no_do_ospf_connected(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ospf_connected(u);
	}

	return retval;
}

int do_bgp_connected(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bgp_connected(u);
	}

	return retval;
}

static int no_do_bgp_connected(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bgp_connected(u);
	}

	return retval;
}


/*
 *  Function:  do_rip_network
 *  Purpose:   rip network command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_rip_network(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(rip_network_cmds, argc, argv, u);
	
	return retval;
}

static int do_rip_network_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_rip_network_ip(u);
	}
	else
	{		
		retval = sub_cmdparse(rip_network_ip_cmds, argc, argv, u);
	}

	return retval;
}

static int do_rip_network_ip_mask(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_rip_network_ip_mask(u);
	}

	return retval;
}

/*
 *  Function:  no_rip_network
 *  Purpose:   rip network command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_rip_network(int argc, char *argv[], struct users *u)
{
	int retval = -1;

//	if((retval = cmdend2(argc, argv, u)) == 0)
//	{
//		/* Do application */
//		nfunc_rip_network(u);
//	}
	
    if(argc == 1)
	    nfunc_rip_network(u);
	else   
	    retval = sub_cmdparse(rip_network_cmds, argc, argv, u);  

	return retval;
}

/*
 *  Function:  do_rip_version
 *  Purpose:   rip version command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_rip_version(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(rip_version_cmds, argc, argv, u);
	
	return retval;
}

static int do_rip_version_1(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_rip_version_1(u);
	}

	return retval;
}
static int do_rip_version_2(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_rip_version_2(u);
	}

	return retval;
}

/*
 *  Function:  no_rip_version
 *  Purpose:   rip version command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_rip_version(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_rip_version(u);
	}

	return retval;
}

/*
 *  Function:  do_isis_net
 *  Purpose:   isis net command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int do_isis_net(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(isis_net_cmds, argc, argv, u);
	
	return retval;
}

int do_isis_net_str(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_isis_net(u);
	}

	return retval;
}

/*
 *  Function:  no_isis_net
 *  Purpose:   isis net command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int no_isis_net(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_isis_net(u);
	}

	return retval;
}

/*
 *  Function:  do_isis_type
 *  Purpose:   isis type command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int do_isis_type(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(isis_type_cmds, argc, argv, u);
	
	return retval;
}

int do_isis_type_1(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_isis_type_1(u);
	}

	return retval;
}

int do_isis_type_2(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_isis_type_2(u);
	}

	return retval;
}

int do_isis_type_1_2(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_isis_type_1_2(u);
	}

	return retval;
}

/*
 *  Function:  no_isis_type
 *  Purpose:   isis type command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int no_isis_type(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_isis_type(u);
	}

	return retval;
}

/*
 *  Function:  do_bgp_neighbor
 *  Purpose:   bgp neighbor command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int do_bgp_neighbor(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(bgp_neighbor_cmds, argc, argv, u);
	
	return retval;
}

int do_bgp_neighbor_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(bgp_neighbor_ip_cmds, argc, argv, u);
	
	return retval;
}

int do_bgp_neighbor_ip_remote(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(bgp_neighbor_ip_remote_cmds, argc, argv, u);
	
	return retval;
}

int do_bgp_neighbor_ip_remote_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bgp_neighbor(u);
	}

	return retval;
}

/*
 *  Function:  no_bgp_neighbor
 *  Purpose:   bgp neighbor command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int no_bgp_neighbor(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(bgp_neighbor_cmds, argc, argv, u);
	
	return retval;
}

int no_bgp_neighbor_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bgp_neighbor(u);
	}

	return retval;
}

/*
 *  Function:  do_bgp_neighbor_ip_activate
 *  Purpose:   bgp neighbor ip activate command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int do_bgp_neighbor_ip_activate(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bgp_neighbor_activate(u);
	}

	return retval;
}

/*
 *  Function:  do_bgp_network
 *  Purpose:   bgp network command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int do_bgp_network(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(bgp_network_cmds, argc, argv, u);
	
	return retval;
}

int do_bgp_network_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bgp_network(u);
	}

	return retval;
}

int do_no_bgp_network_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bgp_network_sub(u);
	}

	return retval;
}

/*
 *  Function:  no_bgp_network
 *  Purpose:   bgp network command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int no_bgp_network(int argc, char *argv[], struct users *u)
{
    char * p;
	int retval = -1;

	if(argc == 1)
	    nfunc_bgp_network(u);
	else   
	    retval = sub_cmdparse(bgp_network_cmds, argc, argv, u);  

	return retval;
}

static int no_rip_network_ip(int argc, char *argv[], struct users *u)
{
    char * p;
	int retval = -1;

//	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_rip_network_sub(u);
	}

	return retval;
}

static int no_ospf_network_ip(int argc, char *argv[], struct users *u)
{
    char * p;
	int retval = -1;
	
//	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ospf_network_sub(u);
	}

	return retval;
}


static int do_rip_network_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_rip_network_ipv6(u);
	}

	return retval;
}

static int no_rip_network_ipv6(int argc, char *argv[], struct users *u)
{
    char * p;
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{ 
		/* Do application */
		nfunc_rip_network_ipv6(u);
	}

	return retval;
}

static int do_ospf_network_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(ospf_network_ipv6_cmds, argc, argv, u);
	
	return retval;
}

static int do_ospf_network_ipv6_area(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(ospf_network_ipv6_area_cmds, argc, argv, u);
	
	return retval;
}

static int do_ospf_network_ipv6_area_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_ospf_network_ipv6(u);
	}

	return retval;
}

static int no_ospf_network_ipv6(int argc, char *argv[], struct users *u)
{
    char * p;
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_ospf_network_ipv6(u);
	}

	return retval;
}

static int do_bgp_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(bgp_id_cmds, argc, argv, u);
	
	return retval;
}

static int do_bgp_id_ip(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bgp_id(u);
	}

	return retval;
}

static int no_bgp_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bpg_id(u);
	}

	return retval;
}

int do_bgp_neighbor_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(bgp_neighbor_ipv6_cmds, argc, argv, u);
	
	return retval;
}

int do_bgp_neighbor_ipv6_remote(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	retval = sub_cmdparse(bgp_neighbor_ipv6_remote_cmds, argc, argv, u);
	
	return retval;
}

int do_bgp_neighbor_ipv6_remote_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bgp_ipv6_neighbor(u);
	}

	return retval;
}

int no_bgp_neighbor_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bgp_ipv6_neighbor(u);
	}

	return retval;
}

int do_bgp_network_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bgp_network_ipv6(u);
	}

	return retval;
}

int no_bgp_network_ipv6(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bgp_network_ipv6(u);
	}

	return retval;
}

/*
 *  Function:  do_bfd
 *  Purpose:   do_bfd command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int do_ospf_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(bfd_ospf_cmds, argc, argv, u);

	return retval;
}

static int do_bfd_ospf_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bfd_ospf_enable(1);
	}
	return retval;
}

/*
 *  Function:  no_bfd
 *  Purpose:   no_bfd command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
static int no_ospf_bfd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(bfd_ospf_cmds, argc, argv, u);

	return retval;
}

static int no_bfd_ospf_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		func_bfd_ospf_enable(0);
	}
	return retval;
}

static int no_bfd_all(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application */
		nfunc_bfd_all(u);
	}
	return retval;
}


/*
 *  Function:  init_cli_router
 *  Purpose:  Register router function command
 *  Parameters:
 *     void
 *  Returns:
 *     retval
 *  Author:   xi.chen
 *  Date:    2011/11/10
 */
int init_cli_router(void)
{
	int retval = -1;

	DEBUG_MSG(1, "init_cli_router retval = %d\n", retval);

	return retval;
}
