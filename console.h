#ifndef _CONSOLE_
#define _CONSOLE_

/* Timeout, unit:s */
#define AUTH_TIMEOUT_DEFAULT	120
#define EXEC_TIMEOUT_DEFAULT	600

/* ASCII */
#define ASCII_LN	0x0A
#define ASCII_CR	0x0D
#define ASCII_BS	0x08
#define ASCII_DEL	0x7F
#define ASCII_EOT	0x04
#define ASCII_EXT	0x03
#define ASCII_HT	0x09

#define ASCII_ESC	0x1B
#define ASCII_UP	0x41
#define ASCII_DOWN	0x42
#define ASCII_RIGHT	0x43
#define ASCII_LEFT	0x44

#define HELP_SUFFIX	"?"
#define TAB_SUFFIX	"*"

#define SHOW_LOADING	">>"

/* buff size */
#define SHOW_OFFSET_SIZE	10
/* For '$' and cursor */
#define SHOW_LINE_SIZE		(80 - 2)
#define SHOW_CMD_SIZE(x)	(SHOW_LINE_SIZE-x)

#define CLI_AUTH_SIZE		32
#define REC_BUFF_SIZE		255
#define PROMPT_SIZE			SHOW_LINE_SIZE
#define CMDLINE_SIZE		255

#define MAX_ARGC 		32
#define MAX_ARGV_LEN	64

#define PIPE_BUFF_SIZE	2048

#define MAX_HISENTRY	20

/* users->g_parameter */
#define MAX_V_INT		14
#define MAX_V_IP		8
#define MAX_V_IPV6		2
#define MAX_V_STRING	2
#define MAC_V_STR_LEN	MAX_ARGV_LEN

/* users->con_level */
#define ALL_TREE			0xFFFFFFFF
#define GLOBAL_TREE			0xFFFFFFFE	//exclud view tree
#define PRIVILEGE_TREE		0xFFFFFFFC	//exclud view tree and ena tree
#define VIEW_TREE			0x00000001
#define ENA_TREE			0x00000002
#define CONFIG_TREE			0x00000004
#define VLAN_TREE			0x00000008
#define IF_VLAN_TREE		0x00000010
#define IF_PORT_TREE		0x00000020
#define IF_GPORT_TREE		0x00000040
#define IF_TRUNK_TREE		0x00000080
#define POLICY_MAP_TREE	    0x00000100
#define CLASSIFY_TREE		0x00000200
#define IP_ACL_TREE			0x00000400
#define IPV6_ACL_TREE		0x00000800
#define MAC_ACL_TREE		0x00001000
#define LINE_TREE           0x00002000
#define IP_DHCP_TREE        0x00004000
#define IP_DHCPv6_TREE      0x00008000
#define ROUTER_OSPF_TREE    0x00010000
#define ROUTER_RIP_TREE     0x00020000
#define ROUTER_ISIS_TREE    0x00040000
#define ROUTER_BGP_TREE     0x00080000
#define IF_LOOPBACK_TREE    0x00100000
#define CONFIG_MST_TREE		0x00200000
#define TIME_RANGE_TREE     0x00400000
#define IF_XPORT_TREE		0x00800000
#define CONFIG_ERPS_TREE	0x01000000

#define IF_SUMMARY_TREE		0x000000F0
#define ACL_SUMMARY_TREE	0x00000C00

/* users->cmd_st */
#define CMD_ST_END		0x00000001
#define CMD_ST_NO		0x00000002
#define CMD_ST_DEF		0x00000004
#define CMD_ST_ERR		0x00000008

#define CMD_ST_CONF		0x00000010

#define CMD_ST_C_LV		0x10000000
#define CMD_ST_BLOCK	0x20000000
#define CMD_ST_DPROMPT	0x40000000
#define CMD_ST_CN		0x80000000

#define SET_CMD_ST(u,status)		((u)->cmd_st |= (status))
#define CLEAR_CMD_ST(u,status)	((u)->cmd_st &= ~(status))
#define ISSET_CMD_ST(u,status)	(((u)->cmd_st & (status))?1:0)

#define SET_CMD_MSKBIT(u,msk)		((u)->cmd_mskbits |= (msk))
#define CLEAR_CMD_MSKBIT(u,msk)	((u)->cmd_mskbits &= ~(msk))
#define ISSET_CMD_MSKBIT(u,msk)	(((u)->cmd_mskbits & (msk))?1:0)

#define SET_AUTH_STAT(u,status)	((u)->auth_stat = status)
#define IS_AUTH_STAT(u,status)	(((u)->auth_stat == status)?1:0)

#define SET_ERR_NO(u,id)	((u)->err_no = id)
#define IS_ERR_NO(u,id)	(((u)->err_no == id)?1:0)

typedef enum CLI_AUTH{
	CLI_AUTH_NONE,
	CLI_AUTH_USER,
	CLI_AUTH_PWD,
	CLI_AUTH_SUCCEED,
	CLI_AUTH_FAILED,
}CLI_AUTH;

typedef enum CLI_LOGIN{
	CLI_LOCAL,
	CLI_TELNET,
	CLI_SSH,
}CLI_LOGIN;

typedef enum CLI_PRI{
	CLI_PRI_NONE,
	CLI_PRI_ADMIN,
	CLI_PRI_USER,

	CLI_PRI_0 = 0,
	CLI_PRI_1,
	CLI_PRI_2,
	CLI_PRI_3,
	CLI_PRI_4,
	CLI_PRI_5,
	CLI_PRI_6,
	CLI_PRI_7,
	CLI_PRI_8,
	CLI_PRI_9,
	CLI_PRI_10,
	CLI_PRI_11,
	CLI_PRI_12,
	CLI_PRI_13,
	CLI_PRI_14,
	CLI_PRI_15,
}CLI_PRI;

typedef enum CLI_ERR{
	CLI_ERR_NONE,
	CLI_ERR_SYS_ERR,
	CLI_ERR_CMD_ERR,
	CLI_ERR_UNKNOW_CMD,
	CLI_ERR_INCOMPLETE_CMD,
	CLI_ERR_INT_FORMAT,
	CLI_ERR_INT_RANGE,
	CLI_ERR_WORD_LENTH,
	CLI_ERR_MAC_FORMAT,
	CLI_ERR_TIME_FORMAT,
	CLI_ERR_IPV4_FORMAT,
	CLI_ERR_IPV4_NETMASK_FORMAT,
	CLI_ERR_IPV6_FORMAT,
	CLI_ERR_IPV6_NOMASK,
	CLI_ERR_IPV6_MASK,
	CLI_ERR_GIGAPORT_UNSUPPORT,
}CLI_ERR;

/* structure for history entry */
struct hisentry {
	struct	hisentry *next;	/* link for next entry */
	char	*buffer;				/* allocated memory buffer for history */
};

struct g_param {
	int	v_int[MAX_V_INT+MAX_V_IPV6];			//32byte ,last for ipv6 mask
	int	v_int_cnt;
	
	struct in_addr	v_sin_addr[MAX_V_IP];		//16byte
	int	v_sin_addr_cnt;
	struct in6_addr	v_sin6_addr[MAX_V_IPV6];	//16byte
	int	v_sin6_addr_cnt;
	
	char	v_string[MAX_V_STRING][MAC_V_STR_LEN];	//32byte
	int	v_string_cnt;

	int	v_range_edge;
	char v_range[MAC_V_STR_LEN];				//32byte
	int	v_range_len;
};

struct users {
	CLI_AUTH auth_stat;				/* auth stat */
	int exec_timeout;				/* exec_timeout */

	char username[CLI_AUTH_SIZE+1];	/* username */
	char password[CLI_AUTH_SIZE+1];	/* password */
	
	int vtytype;					/* current vty type*/
	int vtyindex;					/* current vty index*/

	uint32_t cmd_pv;				/* command privilege */
	uint32_t cmd_st;
	
	uint32_t con_level;				/* command executive level */
	uint32_t cur_con_level;

	int	his_count;					/* current history count */
	int	his_index;					/* current history index */
	struct hisentry	*his_head;		/* head pointer for history */
	struct hisentry	*his_tail;		/* tail pointer for history */

	char his_topcmd[MAX_ARGV_LEN];

	int args_offset;
	int argv_length;
	
	uint32_t cmd_mskbits;			/* mask bits for sub command */
	
	struct g_param s_param;			/* storage for static transmissible parameters */
	struct g_param d_param;			/* storage for dynamic transmissible parameters */

	int	linelen; 						/* line length */
	char linebuf[CMDLINE_SIZE + 1]; 	/* line buffer for current running command */
	
	char promptbuf[PROMPT_SIZE + 1];	/* buffer for command prompt */
	char promptdef[PROMPT_SIZE + 1];	/* self definition prompt */

	int err_no;						/* error number */
	char *err_ptr;					/* buffer for error info */
};

#define STARTUP_CONFIG_PATH			"/tmp/vfs_root/startup_config"
#define DEFAULT_STARTUP_CONFIG_PATH	"/etc/startup_config"
#define CLI_PRIVATE_VLAN 1

void debug_print(const char* file, size_t line, const char* func, int enable, const char* fmt, ...);

#define DEBUG_MSG(enable, fmt, ...)  \
	//debug_print(__FILE__, __LINE__, __FUNCTION__, enable, fmt, __VA_ARGS__)
	
#define GENERAL_MSG \
	//printf("%s, %d, %s\n", __FILE__, __LINE__, __FUNCTION__)
	
#define DEBUG_CONSOLE(enable, fmt, ...)\
	//debug_print(__FILE__, __LINE__, __FUNCTION__, enable, fmt, __VA_ARGS__)

/* vty output */
int vty_output(const char* fmt, ...);

/* prompt output */
int prompt_output(struct users *u, const char* fmt, ...);

/* change console level in users */
int change_con_level(uint32_t con_level, struct users *u);

/* extern functions */
extern char* nvram_safe_get(const char *name);

/* extern inital functions */
extern int init_cli_acl(void);
extern int init_cli_arp(void);
extern int init_cli_clear(void);
extern int init_cli_clock(void);
extern int init_cli_config_mst(void);
extern int init_cli_common(void);
extern int init_cli_dot1x(void);
extern int init_cli_errdisable(void);
extern int init_cli_filesys(void);
extern int init_cli_interface(void);
extern int init_cli_ip(void);
extern int init_cli_login(void);
extern int init_cli_mac(void);
extern int init_cli_mirror(void);
extern int init_cli_others(void);
extern int init_cli_ping(void);
extern int init_cli_port(void);
extern int init_cli_qos(void);
extern int init_cli_radius(void);
extern int init_cli_rmon(void);
extern int init_cli_show(void);
extern int init_cli_snmp(void);
extern int init_cli_stp(void);
extern int init_cli_syslog(void);
extern int init_cli_trunk(void);
extern int init_cli_vlan(void);
extern int init_cli_lldp(void);
extern int init_cli_time_range(void);

#define CLI_AAA_MODULE
#ifdef CLI_AAA_MODULE

struct aaa_user_info {
	unsigned char port[2];
	char user[33];
	char service[10];
	struct timeval time;
	char ip[128];
};

#include "aaa.h"
extern int aaa_send_msg(struct cli_msg  *msg);
extern struct aaa_sta_info sta_info;
extern void acct_report_state(int on);

extern int aaa_user_read_config(struct aaa_user_info **aaa_user);
extern void aaa_user_write_config(struct aaa_user_info *aaa_user, int num);
extern void aaa_user_info_add(struct aaa_user_info *item);
extern void aaa_user_info_free(int line);

static void init_cli_param(void);
extern int init_cli_aaa(void);
extern int init_cli_enable(void);
extern int init_cli_line(void);
#endif

#ifdef CLI_SHELL
extern int init_cli_shell(void);
#endif

#endif

