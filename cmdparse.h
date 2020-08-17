#ifndef __CMDPARSE__
#define __CMDPARSE__

#define CLI_CMD_UNUSAL_RECORD
#define CLI_CHAR_NO_BLANK_RECORD
#define CLI_CHAR_UNUSAL_RECORD

#define MAX_COMMAND_ENTRIES 256

#define CMD_MSK_END	NULL, 0, 0
#define TOPCMDS_END	NULL, 0, 0, NULL, NULL, NULL, 0, 0, 0, NULL, NULL
#define CMDS_END		NULL, 0, 0, 0, NULL, NULL, NULL, 0, 0, 0, NULL, NULL

#define CR_SHOW_EN		"  <cr>"
#define CR_SHOW_CN		"  »Ø³µ"

#define CLI_END_NONE	0x00000000
#define CLI_END_FLAG	0x00000001
#define CLI_END_NO		0x00000002
#define CLI_END_DEF		0x00000004

#define MATCH_INT_MSK		0x00000001
#define MATCH_MAC_MSK		0x00000002
#define MATCH_TIME_MSK		0x00000004
#define MATCH_IPV4_MSK		0x00000008
#define MATCH_IPV6_MSK		0x00000010
#define MATCH_PORT_MSK		0x00000020
#define MATCH_VLAN_MSK		0x00000040
#define MATCH_TRUNK_MSK		0x00000080
#define MATCH_LINE_MSK		0x00000100
#define MATCH_WORD_MSK		0x00000200

typedef enum CLI_TYPE{
	CLI_CMD,
	CLI_CMD_NO_BLANK,
	CLI_CMD_UNUSAL,
	CLI_CHAR,
	CLI_CHAR_NO_BLANK,
	CLI_CHAR_UNUSAL,
	CLI_INT_UNUSAL,
	CLI_INT,
	CLI_INT_RANGE,
	CLI_INT_MULTI,
	CLI_MAC,
	CLI_TIME,
	CLI_IPV4_MASK,
	CLI_IPV4,
	CLI_IPV6_MASK,
	CLI_IPV6_NOMASK,
	CLI_IPV6,
	CLI_WORD,
	CLI_LINE,
	CLI_END,
}CLI_TYPE;

struct cmd_node{
	char *topcmds_name;
	uint32_t topcmds_pv_level;
	struct topcmds *topcmds_entry;
	struct cmd_node *next;
};

struct cmd_mask{
	char *cmd_name;		/* cmd name */
	uint32_t cmd_st;				/* cmd state */
	uint32_t con_level;			/* console level */
};

struct topcmds {
	char	 *name;						/* Name of command */

	uint32_t pv_level;					/* privilege */
	uint32_t con_level;					/* console level */

	int (*func)(int argc, char *argv[], struct users *u); 		 /* Function to execute command */
	int (*nopref)(int argc, char *argv[], struct users *u);		/* No-prefixed Function to execute command */
	int (*defpref)(int argc, char *argv[], struct users *u);			/* Default-prefixed Function to execute command */

	uint32_t end_flag;
	
	int 	argcmin;						/* Minimum number of args */
	int		argcmax;						/* maximum number of args */

	char	*yhp;								/* help message in English */
	char	*hhp;								/* help message in Chinese */
};

struct cmds {
	char	*name;						/* Name of command */
	int matchmode;					/* match mode */

	uint32_t pv_level;			/* privilege level */
	uint32_t cmdmask;	 		/* sub command mask bit */

	int (*func)(int argc, char *argv[], struct users *u);		/* Normal Function to execute command */
	int (*nopref)(int argc, char *argv[], struct users *u);		/* No-prefixed Function to execute command */
	int (*defpref)(int argc, char *argv[], struct users *u);		/* Default-prefixed Function to execute command */

	uint32_t end_flag;
	
	int argcmin;					/* Minimum number of args */
	int argcmax;					/* Maximum number of args */

	char	*yhp;						/* help message in English */
	char	*hhp;						/* help message in Chinese */
};

struct parameter {
	uint32_t flag;		
	
	int type;					/* match mode */
	int min;
	int max;
	
	char	*name;
	char	*ylabel;
	char	*hlabel;
	
	union {
		int	v_int;
		char	v_string[MAX_ARGV_LEN];
		struct in_addr v_sin_addr;
		struct in6_addr v_sin6_addr;
	} value, value0;
};

extern int registercmd(struct topcmds *cmd_entry);
extern int registerncmd(struct topcmds *cmd_entry, int num);

int top_cmdparse (int argc, char *argv[], struct users *u);
int top_cmdparse_help(struct cmd_node *cmd_tree, int argc, char *argv[], struct users *u);
int top_cmdparse_help_show(struct cmd_node *cmd_tree, int argc, char *argv[], struct users *u);
int top_cmdparse_tab(struct cmd_node *cmd_tree, int argc, char *argv[], struct users *u);
int top_cmdparse_tab_show(struct cmd_node *cmd_tree, int argc, char *argv[], struct users *u);
struct topcmds *search_topcmds(struct cmd_node *cmd_tree, int argc, char *argv[], struct users *u);

extern int sub_cmdparse(struct cmds tab[], int argc, char *argv[], struct users *u);
extern int sub_cmdparse_help(struct cmds tab [], int argc, char *argv[], struct users *u);
int sub_cmdparse_help_show(struct cmds tab[], int argc, char *argv[], struct users *u);
int sub_cmdparse_help_show_mode(struct cmds *cmds_ptr, char *s, struct users *u);

int sub_cmdparse_tab(struct cmds tab [], int argc, char *argv[], struct users *u);
int sub_cmdparse_tab_show(struct cmds tab[], int argc, char *argv[], struct users *u);
struct cmds *search_cmds(struct cmds tab[], int argc, char *argv[], struct users *u);

extern int getparameter(int argc, char *argv[], struct users *u, struct parameter *param);
int getparameter_help(int argc, char *argv[], struct users *u, struct parameter *param);
int getparameter_help_show(int argc, char *argv[], struct users *u, struct parameter *param);
int getparameter_help_show_mode(struct parameter *param, char *s, struct users *u);
int search_parameter(int argc, char *argv[], struct users *u, struct parameter *param);

extern int cmdend(struct cmds tab[], int argc, char *argv[], struct users *u);
extern int cmdend2(int argc, char *argv[], struct users *u);

extern int cmderror(struct users *u);

extern struct cmd_node *cli_get_cmd_tree(struct users *u);

#endif
