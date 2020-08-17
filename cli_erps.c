/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_clock.c
 * Function   : show command function
 * Auther     : jialong.chu
 * Version    : 1.0
 * Date       : 2011/11/4
 *
 *********************Revision History****************
 Date       Version     Modifier            Command
 2011/11/7  1.01        yunchang.xuan       clock set hh:mm:ss day month year
                                            CONFIG_TREE:
                                            clock timezone WORD <-12 - +12> <cr>
                                            
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

#include "cli_erps.h"
#include "cli_erps_func.h"

static char *_strlwr(char *string)
{
	unsigned char i, len = 0;
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

/* top command struct*/
 static struct topcmds ring_topcmds[] = {
	 { "erps", 0, CONFIG_TREE, do_erps, do_no_erps, NULL, CLI_END_FLAG | CLI_END_NO, 0, 0,
		 "Config ERPS RING", "配置ERPS环网" },
	 { TOPCMDS_END }
 };

 static struct cmds erps_ring_id_cmds[] = {
	 { "ring", 0, 0, 0, do_erps_ring_id_mode, no_erps_ring_id_mode, NULL, CLI_END_NONE, 0, 0,
		 "Config ERPS ID ", "配置ERPS环网ID" },
	  { "instance", 0, 0, 0, do_erps_ring_instance_id, no_erps_ring_instance_id, NULL, CLI_END_NONE, 0, 0,
		 "Config ERPS instance", "配置ERPS实例" }, 	 
	 { CMDS_END }
 };
 static struct cmds erps_ring_cmds[] = {
	 { "<1-32>", CLI_INT, 0, 0, do_erp_ring_east_port, no_erp_ring_id, NULL, CLI_END_NONE | CLI_END_NO, 1, 32,
		 "Config RING id", "配置ERPS环网编号" },
	 { CMDS_END }
 };

 static struct cmds erps_instance_cmds[] = {
	 { "<1-16>", CLI_INT, 0, 0, do_erps_mst_configuration, no_erps_mst_configuration, NULL, CLI_END_FLAG|CLI_END_NO, 1, 16,
		 "Config ERPS instance id", "配置ERPS实例编号" },
	 { CMDS_END }
 };
 
 static struct cmds erps_ring_east_cmds[] = {
	 { "east-interface", 0, 0, 0, do_interface_erps_east_ethernet, NULL, NULL, CLI_END_NO ,0 ,0,
		 "Config ERPS RING PORT", "配置ERPS环网东接口" },		 
	 { CMDS_END }
 };

 
 /* interface fast port */
 static struct cmds interface_erps_cmds[] = {
	  { "<1-28>", CLI_INT, 0, 0, do_erp_ring_west_port, NULL, NULL, CLI_END_NONE | CLI_END_NO, 1, 28,
		 "Interface number", "妲藉彿" },
	 { CMDS_END }
 };

  static struct cmds interface_erps_west_cmds[] = {
	 { "<1-28>", CLI_INT, 0, 0, do_erps_ring_config, NULL, NULL,  CLI_END_FLAG, 1, 28,
		 "Interface number", "妲藉彿" },
	 { CMDS_END }
 };
static struct cmds erps_inst_wait_to_time_cmds[] = {
	 { "<1-12>", CLI_INT, 0, 0, do_erps_instance_set_wait_to_restort, NULL, NULL, CLI_END_FLAG , 1, 12,
		 "Config ERPS RING PORT", "配置ERPS环网西接口" },
	 { "default", 0, 0, 0, do_erps_instance_default_wait_to_restort, NULL, NULL, CLI_END_FLAG , 0, 0,
		 "300 s", "300 s" },	 
	 { CMDS_END }
 };
 static struct cmds erps_inst_hold_off_cmds[] = {
	  { "<0-10000>", CLI_INT, 0, 0, do_erps_instance_set_hold_off, NULL, NULL, CLI_END_FLAG , 0, 10000,
		  "Config ERPS RING PORT", "配置ERPS环网西接口" },
	  { "default", 0, 0, 0, do_erps_instance_default_hold_off, NULL, NULL, CLI_END_FLAG , 0, 0,
		  "0 ms", "0 ms" },	  
	  { CMDS_END }
  };
static struct cmds erps_inst_guard_timer_cmds[] = {
   { "<1-2000>", CLI_INT, 0, 0, do_erps_instance_set_guard_timer, NULL, NULL, CLI_END_FLAG , 1, 2000,
	   "Config ERPS guard time", "配置ERPS guard time" },
   {"default", 0, 0, 0, do_erps_instance_default_guard_timer, NULL, NULL, CLI_END_FLAG , 0, 0,
	   "500ms", "500 ms" },    
   { CMDS_END }
};


 static struct cmds erps_inst_timer_cmds[] = {
	 { "wait-to-restore", 0, 0, 0, do_erps_instance_wait_to_restort, NULL, NULL, CLI_END_NONE, 0, 0,
		 "Configuration wait to time", "配置WTR定时器" },
	 { "hold-off", 0, 0, 0, do_erps_instance_hold_off, NULL, NULL, CLI_END_NONE, 0, 0,
		 "Configuration hold off", "配置Hold off 定时器" },
	 { "guard-timer", 0, 0, 0, do_erps_instance_guard_timer, NULL, NULL, CLI_END_NONE, 0, 0,
		 "Configuration guard timer", "配置錑uard time 定时器" }, 	 
	 { CMDS_END }
 };

 static struct cmds erps_ring_west_cmds[] = {
	 { "west-interface", 0, 0, 0, do_interface_erps_west_ethernet, NULL, NULL, CLI_END_NO ,0 ,0,
		 "Config ERPS RING PORT", "配置ERPS环网东接口" },	
	 { CMDS_END }
 };

 
 static struct topcmds config_erps_topcmds[] = {
 { "raps-channel", 0, CONFIG_ERPS_TREE, do_erps_instance_rapl, no_erps_instance_rapl, NULL, CLI_END_NONE, 0, 0,
   "control vlan", "配置控制VLAN" },
 { "profile", 0, CONFIG_ERPS_TREE, do_erps_instance_profile, do_erps_instance_profile_default_config, NULL, CLI_END_NO, 0, 0,
   "Set configuration name(the max length of name is 32 chars)", "设置配置名称(最大长度不能超过32个字符)" },
 { "ring", 0, CONFIG_ERPS_TREE, do_erps_instance_ring_id, no_erps_instance_ring_id, NULL, CLI_END_NO, 0, 0,
   "Set configuration revision level", "设置配置环ID" },
 { "level", 0, CONFIG_ERPS_TREE, do_erps_instance_level, no_erps_instance_level, NULL, CLI_END_NO, 0, 0,
   "Set configuration CFM level", "设置配置修订级别" },  
 { "rpl-role", 0, CONFIG_ERPS_TREE, do_erps_instance_rpl_role, no_erps_instance_rpl_role, NULL, CLI_END_NO, 0, 0,
   "Set erps rpl-role", "设置配端口角色" },
 { "timer", 0, CONFIG_ERPS_TREE, do_erps_instance_timer, NULL, NULL, CLI_END_NO, 0, 0,
   "Set erps timer", "设置配置定时器" },  
 { "id", 0, CONFIG_ERPS_TREE, do_erps_instance_mst_id, no_erps_instance_mst_id, NULL, CLI_END_NO, 0, 0,
   "MST instance id", "设置配置实例" },    
 { "sub-ring", 0, CONFIG_ERPS_TREE, do_erps_instance_sub_ring, no_erps_instance_mst_id, NULL, CLI_END_NO, 0, 0,
   "Set configuration sub-ring", "设置配置子环" },
 { "virtual-channel", 0, CONFIG_ERPS_TREE, do_erps_instance_virtual_channel, no_erps_instance_mst_id, NULL, CLI_END_NO, 0, 0,
   "Set configuration virtual-channel", "设置配置虚拟通道" },  
 { "revertive", 0, CONFIG_ERPS_TREE, do_erps_instance_revertive_config, do_erps_instance_none_revertive_config, NULL, CLI_END_FLAG |CLI_END_NO, 0, 0,
   "Set configuration revertive", "设置配置反转" }, 
 { "enable", 0, CONFIG_ERPS_TREE, do_erps_instance_enable_config, NULL, NULL, CLI_END_FLAG, 0, 0,
   "enable instance", "设置配置修订级别" },  
 { "disable", 0, CONFIG_ERPS_TREE, do_erps_instance_disable_config, NULL, NULL, CLI_END_FLAG, 0, 0,
   "disable instance", "设置配置修订级别" },  
 { TOPCMDS_END }
 };


static struct cmds erps_inst_virtual_cmds[] = {
	{ "<2-4094>", CLI_INT, 0, 0, do_erps_instance_virtual_channel_id, no_erps_instance_mst_config, NULL, CLI_END_NONE, 0, 16,
		"MST instance id", "配置修订级别" },
	{ CMDS_END }
};

static struct cmds erps_inst_virtual_vlan_cmds[] = {
	{ "attached-to-instance", 0, 0, 0, do_erps_instance_virtual_channel_attached_instance, no_erps_instance_mst_config, NULL, CLI_END_NONE, 0, 16,
		"MST instance id", "配置修订级别" },
	{ CMDS_END }
};
static struct cmds erps_inst_virtual_instance_cmds[] = {
	{ "<0-16>", CLI_INT, 0, 0, do_erps_instance_virtual_channel_config, no_erps_instance_mst_config, NULL, CLI_END_FLAG, 0, 16,
		"MST instance id", "配置修订级别" },
	{ CMDS_END }
};


static struct cmds erps_inst_mst_id_cmds[] = {
	{ "<0-16>", CLI_INT, 0, 0, do_erps_instance_mst_config, no_erps_instance_mst_config, NULL, CLI_END_FLAG, 0, 16,
		"MST instance id", "配置修订级别" },
	{ CMDS_END }
};


static struct cmds erps_inst_vlan_cmds[] = {
	{ "<1-4094>", CLI_INT, 0, 0, do_erps_instance_rapl_vlan, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },
	{ CMDS_END }
};

static struct cmds erps_inst_vlan_name_cmds[] = {
	{ "vlan",0 , 0, 0, do_erps_instance_rapl_vlan_id, NULL, NULL, CLI_END_NO, 0, 0,
		"Configuration raps vlan", "配置修订级别" },
	{ CMDS_END }
};


static struct cmds erps_inst_ring_cmds[] = {
	{ "<1-16>", CLI_INT, 0, 0, do_erps_instance_ring_config, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },
	{ CMDS_END }
};

static struct cmds erps_inst_ring_id_cmds[] = {
	{ "<1-16>", CLI_INT, 0, 0, do_erps_instance_rapl_vlan, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },
	{ CMDS_END }
};

static struct cmds erps_inst_level_cmds[] = {
	{ "<0-7>", CLI_INT, 0, 0, do_erps_instance_level_config, NULL, NULL, CLI_END_FLAG, 0, 7,
		"Configuration map level", "配置修订级别" },
	{ CMDS_END }
};


static struct cmds erps_inst_rpl_neighbor_cmds[] = {
	{ "east-interface", 0, 0, 0, do_erps_instance_neighbor_east, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },
	{ "west-interface", 0, 0, 0, do_erps_instance_neighbor_west, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },	
	{ CMDS_END }
};

static struct cmds erps_inst_rpl_next_neighbor_cmds[] = {
	{ "east-interface", 0, 0, 0, do_erps_instance_next_neighbor_east, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },
	{ "west-interface", 0, 0, 0, do_erps_instance_next_neighbor_west, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },	
	{ CMDS_END }
};

static struct cmds erps_inst_rpl_owner_cmds[] = {
	{ "east-interface", 0, 0, 0, do_erps_instance_owner_east, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },
	{ "west-interface", 0, 0, 0, do_erps_instance_owner_west, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },	
	{ CMDS_END }
};

static struct cmds erps_inst_rpl_none_owner_cmds[] = {
	{ "east-interface", 0, 0, 0, do_erps_instance_none_owner_east, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },
	{ "west-interface", 0, 0, 0, do_erps_instance_none_owner_west, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },	
	{ CMDS_END }
};

static struct cmds erps_inst_rpl_sub_ring_block_cmds[] = {
	{ "block", 0, 0, 0, do_erps_instance_sub_ring_block, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },		
	{ CMDS_END }
};

static struct cmds erps_inst_rpl_sub_ring_block_port_cmds[] = {
	{ "east-interface", 0, 0, 0, do_erps_instance_sub_ring_block_east, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },
	{ "west-interface", 0, 0, 0, do_erps_instance_sub_ring_block_west, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"Configuration raps vlan", "配置修订级别" },	
	{ CMDS_END }
};



static struct cmds erps_inst_rpl_role_cmds[] = {
	{ "neighbor", 0, 0, 0, do_erps_instance_neighbor, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"neighbor", "配置修订级别" },
	{ "next-neighbor", 0, 0, 0, do_erps_instance_next_neighbor, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"next-neighbor", "配置修订级别" },
	{ "non-owner", 0, 0, 0, do_erps_instance_rpl_none_owner, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"non-owner", "配置修订级别" },
	{ "owner", 0, 0, 0, do_erps_instance_rpl_owner, NULL, NULL, CLI_END_FLAG, 1, 4094,
		"owner", "配置修订级别" },	
		
	{ CMDS_END }
};

static struct cmds erps_inst_profile_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_erps_instance_profile_config, NULL, NULL, CLI_END_FLAG|CLI_END_NO, 0, 32,
		"Configuration profile", "配置 profile 模板" },
	{ CMDS_END }
};

/*
 *  sub command struct
 *
 ****************Revision History****************
 Date       Version    Modifier         Modifications
 2011/11/7  1.01       yunchang.xuan    add clock_set[]
                                            clock_curtime[]
                                            clock_day[]
                                            clock_month[]
                                            clock_year[]
                                            clock_timezone[]
                                            timezone_name[]
                                            name_offset[]
 */
/*
 *  Function:  do_clock
 *  Purpose:   clock topcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_erps(int argc, char *argv[], struct users *u)
{
	int retval = -1;
    if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nvram_set("erps_enable","1");
		nvram_commit();
		system("rc erps restart");
		vty_output("Enable ERPS successfully\r\n");
	}
	retval = sub_cmdparse(erps_ring_id_cmds, argc, argv, u);
	
	return retval;
}
static int do_no_erps(int argc, char *argv[], struct users *u)
{
	int retval = -1;

    if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nvram_set("erps_enable","0");
		nvram_commit();
		system("rc erps stop");
		vty_output("Disable ERPS successfully\r\n");
	}
	retval = sub_cmdparse(erps_ring_id_cmds, argc, argv, u);
	
	return retval;
}

static int do_erps_instance_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_timer_cmds, argc, argv, u);

	return retval;
}
static int do_erps_instance_wait_to_restort(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_wait_to_time_cmds, argc, argv, u);

	return retval;
}
static int do_erps_instance_set_wait_to_restort(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_erps_inst_time_wait_to_config(u);
	}
}
static int do_erps_instance_default_wait_to_restort(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_erps_inst_time_wait_to_default_config(u);
	}
}


static int do_erps_instance_hold_off(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_hold_off_cmds, argc, argv, u);

	return retval;
}
static int do_erps_instance_set_hold_off(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_erps_inst_time_hold_off_config(u);
	}
}
static int do_erps_instance_default_hold_off(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		 func_erps_inst_time_hold_off_default_config(u);
	}
}



static int do_erps_instance_guard_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_guard_timer_cmds, argc, argv, u);

	return retval;
}

static int do_erps_instance_set_guard_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_time_guand_time_config(u);
	}
	 
}
static int do_erps_instance_default_guard_timer(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		
		func_erps_inst_time_guand_time_default_config(u);
	}
	 //printf("commade ok2  :%d",retval);
}


/*
 *  Function:  do_clock_set
 *  Purpose:   set subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_erps_ring_id_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_ring_cmds, argc, argv, u);

	return retval;
}

static int no_erps_ring_id_mode(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_ring_cmds, argc, argv, u);

	return retval;
}

static int do_erps_ring_instance_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_instance_cmds, argc, argv, u);

	return retval;
}

static int no_erps_ring_instance_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_instance_cmds, argc, argv, u);

	return retval;
}

static int do_erps_mst_configuration(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		retval = change_con_level(CONFIG_ERPS_TREE, u);
		if(0 == retval)
		{
		    memset(u->promptbuf, '\0', sizeof(u->promptbuf));
			sprintf(u->promptbuf, "%s%d", _strlwr(u->s_param.v_range), u->s_param.v_int[0]);
			
		}
	}

	return retval;
}

static int no_erps_mst_configuration(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) {
		func_erps_inst_delete_config(u);
	}

	return retval;
}



/*
 *  Function:  do_clock_set_curtime
 *  Purpose:   curtime subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
/* interface fast port */
static int do_interface_erps_east_ethernet(int argc, char *argv[], struct users *u)
{
	int retval = -1;
    #if 0
    int i ;
	for(i = 0 ; i < argc;i++)
	{
	    printf("cmd33 :%s\r\n",argv[i]);
	}
	#endif
	retval = sub_cmdparse(interface_erps_cmds, argc, argv, u);
   
	return retval;
} 
static int do_interface_erps_west_ethernet(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(interface_erps_west_cmds, argc, argv, u);
    // printf("commade ok :%d",retval);
	return retval;
} 

static int do_erp_ring_east_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_ring_east_cmds, argc, argv, u);

	return retval;
}
static int no_erp_ring_id(int argc, char *argv[], struct users *u)
{
    int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_no_ring_config(u);
	}
}


/*
 *  Function:  do_clock_set_day
 *  Purpose:   day subcmd parse function
 *  Parameters:
 *     argc  -  Param count
 *     argv  -  Param value
 *  Returns:
 *  
 *  Author:   yunchang.xuan
 *  Date:    2011/11/7
 */
static int do_erp_ring_west_port(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_ring_west_cmds, argc, argv, u);
     //printf("commade ok :%d",retval);
	return retval;
}

static int do_erps_ring_config(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		 //printf("commade ok :%d",retval);
		func_erps_ring_config(u);
	}
	
	return retval;
}

//instance
static int do_erps_instance_ring(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_ring_cmds, argc, argv, u);

	return retval;
}
//instance
static int do_erps_instance_rapl(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_vlan_name_cmds, argc, argv, u);

	return retval;
}
static int do_erps_instance_rapl_vlan_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_vlan_cmds, argc, argv, u);

	return retval;
}

static int no_erps_instance_rapl(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_vlan_cmds, argc, argv, u);

	return retval;
}

static int do_erps_instance_rapl_vlan(int argc, char *argv[], struct users *u)
{
   int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_raps_vlan_config(u);
	}
	
	return retval;
     
}

static int do_erps_instance_level_config(int argc, char *argv[], struct users *u)
{
   int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		 
		func_erps_inst_level_config(u);
	}
	
	return retval;
     
}

static int do_erps_instance_profile_config(int argc, char *argv[], struct users *u)
{
   int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_erps_inst_profile_config(u);
	}
	
	return retval;
     
}
static int do_erps_instance_profile_default_config(int argc, char *argv[], struct users *u)
{
   int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_erps_inst_profile_default_config(u);
	}
	
	return retval;
     
}

static int do_erps_instance_neighbor(int argc, char *argv[], struct users *u)
{
    int retval = -1;

	retval = sub_cmdparse(erps_inst_rpl_neighbor_cmds, argc, argv, u);

	return retval;
     
}

static int do_erps_instance_next_neighbor(int argc, char *argv[], struct users *u)
{
    int retval = -1;

	retval = sub_cmdparse(erps_inst_rpl_next_neighbor_cmds, argc, argv, u);

	return retval;
     
}


static int do_erps_instance_rpl_owner(int argc, char *argv[], struct users *u)
{
    int retval = -1;

	retval = sub_cmdparse(erps_inst_rpl_owner_cmds, argc, argv, u);

	return retval;
     
}

static int do_erps_instance_rpl_none_owner(int argc, char *argv[], struct users *u)
{
    int retval = -1;

	retval = sub_cmdparse(erps_inst_rpl_none_owner_cmds, argc, argv, u);

	return retval;
     
}

static int do_erps_instance_subring_block(int argc, char *argv[], struct users *u)
{
    int retval = -1;

	retval = sub_cmdparse(erps_inst_rpl_sub_ring_block_cmds, argc, argv, u);

	return retval;
     
}



static int do_erps_instance_rpl_role_config(int argc, char *argv[], struct users *u)
{
   int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_raps_vlan_config(u);
	}
	
	return retval;
     
}


static int do_erps_instance_ring_config(int argc, char *argv[], struct users *u)
{
   int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_ring_id_config(u);
	}
	
	return retval;
     
}

static int do_erps_instance_ring_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_ring_cmds, argc, argv, u);

	return retval;
}
static int no_erps_instance_ring_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_ring_id_cmds, argc, argv, u);

	return retval;
}

static int do_erps_instance_level(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_level_cmds, argc, argv, u);

	return retval;
}
static int no_erps_instance_level(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_level_cmds, argc, argv, u);

	return retval;
}

static int do_erps_instance_rpl_role(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_rpl_role_cmds, argc, argv, u);

	return retval;
}
static int no_erps_instance_rpl_role(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_rpl_role_cmds, argc, argv, u);

	return retval;
}
static int do_erps_instance_profile(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_profile_cmds, argc, argv, u);

	return retval;
}
static int no_erps_instance_profile(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_profile_cmds, argc, argv, u);

	return retval;
}

static int do_erps_instance_mst_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_mst_id_cmds, argc, argv, u);

	return retval;
}

static int no_erps_instance_mst_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_mst_id_cmds, argc, argv, u);

	return retval;
}

static int do_erps_instance_mst_config(int argc, char *argv[], struct users *u)
{
   int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		
		func_erps_inst_mst_id_config(u);
	}
	
	return retval;
     
}
static int no_erps_instance_mst_config(int argc, char *argv[], struct users *u)
{
    int retval = -1;
	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_raps_vlan_config(u);
	}
	
	return retval;
     
}
static int do_erps_instance_sub_ring(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_rpl_sub_ring_block_cmds, argc, argv, u);

	return retval;
}
static int do_erps_instance_sub_ring_block(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_rpl_sub_ring_block_port_cmds, argc, argv, u);

	return retval;
}
static int do_erps_instance_sub_ring_block_east(int argc, char *argv[], struct users *u)
{
	 int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_sub_ring_east_config(u);
	}
	
	return retval;
}
static int do_erps_instance_sub_ring_block_west(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_sub_ring_west_config(u);
	}
	
	return retval;
}

static int do_erps_instance_neighbor_east(int argc, char *argv[], struct users *u)
{
	 int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_rpl_neighbor_east_config(u);
	}
	
	return retval;
}
static int do_erps_instance_neighbor_west(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_rpl_neighbor_west_config(u);
	}
	
	return retval;
}

static int do_erps_instance_next_neighbor_east(int argc, char *argv[], struct users *u)
{
	 int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_rpl_next_neighbor_east_config(u);
	}
	
	return retval;
}
static int do_erps_instance_next_neighbor_west(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_rpl_next_neighbor_west_config(u);
	}
	
	return retval;
}

static int do_erps_instance_owner_east(int argc, char *argv[], struct users *u)
{
	 int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		
		func_erps_inst_rpl_owner_east_config(u);
	}
	
	return retval;
}
static int do_erps_instance_owner_west(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		 
		func_erps_inst_rpl_owner_west_config(u);
	}
	
	return retval;
}
static int do_erps_instance_none_owner_east(int argc, char *argv[], struct users *u)
{
	 int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_rpl_none_owner_config(u);
	}
	
	return retval;
}
static int do_erps_instance_none_owner_west(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */		
		func_erps_inst_rpl_none_owner_config(u);
	}
	
	return retval;
}

static int do_erps_instance_virtual_channel(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_virtual_vlan_cmds, argc, argv, u);

	return retval;
}

static int do_erps_instance_virtual_channel_id(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_virtual_vlan_cmds, argc, argv, u);

	return retval;
}
static int do_erps_instance_virtual_channel_attached_instance(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(erps_inst_virtual_instance_cmds, argc, argv, u);

	return retval;
}

static int do_erps_instance_virtual_channel_config(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		
		func_erps_inst_virtual_instance_config(u);
	}
	
	return retval;
}
static int do_erps_instance_enable_config(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nvram_set("erps_enable","enable");
		system("rc erps restart");
		nvram_commit();
	}
	
	return retval;
}

static int do_erps_instance_disable_config(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		nvram_set("erps_enable","disable");
		system("rc erps stop");
		nvram_commit();
	}
	
	return retval;
}

static int do_erps_instance_revertive_config(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_erps_inst_revert_config(u);
		//system("rc erps restart");
	}
	
	return retval;
}
static int do_erps_instance_none_revertive_config(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0) 
	{
		/* Do application function */
		func_erps_inst_none_revert_config(u);
		//system("rc erps restart");
	}
	
	return retval;
}


/*
 *  Function:  init_cli_erps
 *  Purpose:  Register erps function command
 *  Parameters:
 *     void
 *  Returns:
 *  retval  -  The number of registered successfully
 *  Author:   *  Date:    2019/04/30
 */
int init_cli_erps(void)
{
	int retval = -1;
	
	retval = registerncmd(ring_topcmds, (sizeof(ring_topcmds)/sizeof(struct topcmds) - 1));

	retval += registerncmd(config_erps_topcmds, (sizeof(config_erps_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1,"init_cli_clock retval = %d\n", retval);

	return retval;
}


