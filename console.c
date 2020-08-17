/*
 * File name  : console.c
 * Function   : console module
 * Auther     : Jialong
 * Version    : 1.0
 * Date       : 2011/11/10
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
#include <sys/un.h>

#include <arpa/inet.h>
#include <sys/wait.h>

#include "console.h"
#include "cmdparse.h"
#include "parameter.h"

#if 1
/* Debug Print Function */
void debug_print(const char* file, size_t line, const char* func, int enable, const char* fmt, ...)
{
	va_list ap;
	if (enable) {
		fprintf(stdout, "%s, %d, %s: ", file, line, func);
		va_start(ap, fmt);
		vfprintf(stdout, fmt, ap);
		va_end(ap);
		//fprintf(stdout, "\n");
		fflush(stdout);
	}
}

/* Vty Output Function */
#define VTY_OUTPUT	1
#define VTY_PATH	"/tmp/vty_output"
char vty_path[MAX_ARGV_LEN] = {'\0'};
int vty_output(const char* fmt, ...)
{
	FILE *fp;
	va_list ap;
	
	if (VTY_OUTPUT) 
	{
		if((fp = fopen(vty_path, "a+")) == NULL)
			return -1;

		va_start(ap, fmt);
		vfprintf(fp, fmt, ap);
		va_end(ap);
		fflush(fp);
		fclose(fp);  
	}
	
	return 0;
}

/* Prompt Output Function */
int prompt_output(struct users *u, const char* fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	memset(u->promptdef, '\0', sizeof(u->promptdef));
	vsnprintf(u->promptdef, sizeof(u->promptdef), fmt, ap);
	va_end(ap);

	SET_CMD_ST(u, CMD_ST_DPROMPT);

	return 0;
}
#endif

/* Global Variables */

/* SIGINT flag */
static int sigint_flag = 0;

/* Child pid */
static pid_t child_pid = -1;

static struct termios stored_settings;

/* Variables for history commands  */
int view_his_count = 0;
struct hisentry *view_his_head = NULL;
struct hisentry *view_his_tail = NULL;

int ena_his_count = 0;
struct hisentry *ena_his_head = NULL;
struct hisentry *ena_his_tail = NULL;

int config_his_count = 0;
struct hisentry *config_his_head = NULL;
struct hisentry *config_his_tail = NULL;

int vlan_his_count = 0;
struct hisentry *vlan_his_head = NULL;
struct hisentry *vlan_his_tail = NULL;

int interface_his_count = 0;
struct hisentry *interface_his_head = NULL;
struct hisentry *interface_his_tail = NULL;

int qos_his_count = 0;
struct hisentry *qos_his_head = NULL;
struct hisentry *qos_his_tail = NULL;

int acl_his_count = 0;
struct hisentry *acl_his_head = NULL;
struct hisentry *acl_his_tail = NULL;

int default_his_count = 0;
struct hisentry *default_his_head = NULL;
struct hisentry *default_his_tail = NULL;

int line_his_count = 0;
struct hisentry *line_his_head = NULL;
struct hisentry *line_his_tail = NULL;

int ip_dhcp_his_count = 0;
struct hisentry *ip_dhcp_his_head = NULL;
struct hisentry *ip_dhcp_his_tail = NULL;

int ipv6_dhcp_his_count = 0;
struct hisentry *ipv6_dhcp_his_head = NULL;
struct hisentry *ipv6_dhcp_his_tail = NULL;

int router_ospf_his_count = 0;
struct hisentry *router_ospf_his_head = NULL;
struct hisentry *router_ospf_his_tail = NULL;

int router_rip_his_count = 0;
struct hisentry *router_rip_his_head = NULL;
struct hisentry *router_rip_his_tail = NULL;

int router_isis_his_count = 0;
struct hisentry *router_isis_his_head = NULL;
struct hisentry *router_isis_his_tail = NULL;

int router_bgp_his_count = 0;
struct hisentry *router_bgp_his_head = NULL;
struct hisentry *router_bgp_his_tail = NULL;

int config_mst_his_count = 0;
struct hisentry *config_mst_his_head = NULL;
struct hisentry *config_mst_his_tail = NULL;

int config_erps_his_count = 0;
struct hisentry *config_erps_his_head = NULL;
struct hisentry *config_erps_his_tail = NULL;
int time_range_his_count = 0;
struct hisentry *time_range_his_head = NULL;
struct hisentry *time_range_his_tail = NULL;

/* Variables for character process */
static char esc_flag = 0;
static char dir_flag = 0;

static int prompt_len = 0;
static int cmd_len = 0;
static int cmd_show_len = 0;

static int cmd_cursor = 0;
static int show_cursor = 0;

static char ascii_f1[2] = {0x4F, 0x50};
static char ascii_f2[2] = {0x4F, 0x51};
static char ascii_f3[2] = {0x4F, 0x52};
static char ascii_f4[2] = {0x4F, 0x53};

static char buff[REC_BUFF_SIZE+1] = {'\0'};

static char prompt[PROMPT_SIZE+1] = {'\0'};
static char cmdline[CMDLINE_SIZE+1] = {'\0'};
static char *cmdline_show = NULL;

static int auth_len = 0;
static char username[CLI_AUTH_SIZE+1] = {'\0'};
static char password[CLI_AUTH_SIZE+1] = {'\0'};

/* Current users info */
struct users cur_user;
static int remote_type = CLI_LOCAL;
static char *remote_ip = NULL, *remote_vty = NULL;

/* Option -s flag */
static int loadstartupconfig = 0;

#ifdef CLI_AAA_MODULE
/* AAA */
struct aaa_sta_info sta_info;

/* liyezhong aaa user info,  20120224 */
int aaa_user_read_config(struct aaa_user_info **aaa_user)
{
	int fd;
	int count, size;
	struct aaa_user_info *tmp;

	fd = open("/tmp/aaa_user_online", O_RDONLY);
	if (fd < 0) {
		*aaa_user = NULL;
		return -1;
	}

	size = lseek(fd, 0, SEEK_END);

	if (size < sizeof(*tmp)) {
		*aaa_user = NULL;
		return -1;
	}

	count = size % sizeof(*tmp);
	if (count != 0) {
		fprintf(stderr, "aaa user info has damage.\n");
		return -1;
	}

	tmp = calloc(1, size);

	lseek(fd, 0, SEEK_SET);
	read(fd, tmp, size);
	close(fd);

	*aaa_user = tmp;
	count = size / sizeof(*tmp);

	return count;
}


void aaa_user_write_config(struct aaa_user_info *aaa_user, int num)
{
	int fd;
	int size;

	fd = open("/tmp/aaa_user_online", O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		perror("aaa user write to  file");
		return;
	}

	size = write(fd, aaa_user, num * sizeof(*aaa_user));
	if (size < (num * sizeof(*aaa_user))) 
		perror("write file");

	close(fd);
}


void aaa_user_info_add(struct aaa_user_info *item)
{
	struct aaa_user_info *aaa_user;
	int num;

	num = aaa_user_read_config(&aaa_user);

	if (num == -1)
		num = 0;

	if (aaa_user == NULL) 
		aaa_user = calloc(1, sizeof(*aaa_user));
	else
		aaa_user = realloc(aaa_user, (num + 1) * sizeof(*aaa_user));

	memcpy(&aaa_user[num++], item, sizeof(*item));
	aaa_user_write_config(aaa_user, num);

	free(aaa_user);
}

static int show_banner()
{
	int retval = 0;
	char *banner = nvram_safe_get("aaa_auth_banner");
	if (*banner) {
		printf("\n\n%s\n\n", banner);
		retval = 0;
	}
	free(banner);
	return retval;
}

void aaa_user_info_free(int line)
{
	struct aaa_user_info *aaa_user;
	int num, i;

	num = aaa_user_read_config(&aaa_user);

	if (aaa_user == NULL)
		return;

	for (i = 0; i < num; i++) {
		if (aaa_user[i].port[1] == line) {
			if (i != num -1)
				memmove(&aaa_user[i], &aaa_user[i + 1], (num - i) * sizeof(*aaa_user));

			num--;
			aaa_user_write_config(aaa_user, num);
			break;
		}
	}

	free(aaa_user);
}


/*  stace user authentication info */
static void aaa_info_init(void)
{
	struct users *u = &cur_user;
	struct reply *reply;
	char *p;
	int ret;

	if (remote_type == CLI_LOCAL) {
		struct aaa_user_info item;
		memset(&item, '\0', sizeof(item));
		item.port[0] = 'c';
		item.port[1] = 0;
		memcpy(item.user, "unknown", 7);
		memcpy(item.service, "exec", 4);
		gettimeofday(&item.time, NULL);
		memcpy(item.ip, "unknown", 7);
		aaa_user_info_add(&item);
	}

	/* init aaa status info */
	memset(&sta_info, '\0', sizeof(sta_info));
	sta_info.user_name = username;
	sta_info.user_passwd = password;
	sta_info.acct_status_type = AAA_ACCT_EXEC_STOP;
	sta_info.level = cur_user.cmd_pv = 1;
	sta_info.nas_port_type = CONSOLE;
	sta_info.pid = getpid();

	if (remote_type != CLI_LOCAL) {
		sta_info.nas_port = atoi(remote_vty);
		sta_info.acct_session_id = atoi(remote_vty);
		sta_info.remote_type = remote_type;
		sta_info.nas_port_type = VIRTUAL;
		memcpy(sta_info.remote_ip, remote_ip, strlen(remote_ip));
	}

	/* login whether need to authication */
	struct cli_msg msg;
	memset(&msg, 0, sizeof(msg));
	msg.nas_port_type = sta_info.nas_port_type;

	switch (remote_type) {
	case CLI_LOCAL:
		/* line -> authen -> author -> acct */
		msg.type = AAA_AUTH_REQUEST_CONSOLE;
		ret = aaa_send_msg(&msg);
		if (ret == AAA_REPLY_SUCCESS) { 
			if (loadstartupconfig) {
				loadstartupconfig = 0;
				init_cli_param();
			}
			SET_AUTH_STAT(u, CLI_AUTH_SUCCEED);
			if (show_banner() == -1) {
				printf("Switch con0 is now available\n");
				printf("\n\n\n\nPress Return to get started.\n\n\n");
			}
		}

		break;
	case CLI_SSH:
		/* XXX: ssh'login is different from telnet or console, 
		 * it need to get username and privilege from aaa */
		msg.type = AAA_AUTH_REQUEST_SSH;
		msg.nas_port = sta_info.nas_port;
		reply = aaa_send_msg_struct_bcm(&msg);

		SET_AUTH_STAT(u, CLI_AUTH_SUCCEED);
		if (show_banner() == -1)
			printf("\n\n\n\nPress Return to get started.\n\n\n");

		if (reply == NULL)
			return;

		if (reply->identify == AAA_REPLY_STR) {
			p = reply->buf;
			strcpy(u->username, strsep(&p, "@"));
			u->cmd_pv = atoi(p);
			if (u->cmd_pv > CLI_PRI_15)
				u->cmd_pv = 1;

			if (u->cmd_pv > CLI_PRI_1) {
				change_con_level(ENA_TREE, u);
				u->con_level = u->cur_con_level;
				SET_CMD_ST(u, CMD_ST_C_LV);
			}
			syslog(LOG_INFO, "[SSH-6-LOGIN]: User login successful - IP:%s Name:%s", remote_ip, u->username);
		}

		break;
	case CLI_TELNET:
		msg.type = AAA_AUTH_REQUEST_TELNET;
		msg.nas_port = sta_info.nas_port;
		ret = aaa_send_msg(&msg);
		if (ret == AAA_REPLY_SUCCESS) {
			SET_AUTH_STAT(u, CLI_AUTH_SUCCEED);
			if (show_banner() == -1)
				printf("\n\n\n\nPress Return to get started.\n\n\n");
		}
		break;
	}
}
#endif

/* Global Functions */
static void reset_termios(void)
{
	tcsetattr(0,TCSANOW,&stored_settings);
	//system("/bin/sh");

	exit(0);
}

static void cleanup(void)
{
	reset_termios();
	return;
}

static int arg_parse(int argc, char **argv)
{
	int c = 0;
	char log_msg[256] = {'\0'};

	for (;;) {
		c = getopt( argc, argv, "c:t:n:s");
		if (c == EOF) break;
		switch (c) {
			case 'c':
				remote_ip = strdup(optarg);
				break;
			case 't':
				remote_type = atoi(optarg);
				break;
			case 'n':
				remote_vty = strdup(optarg);
				break;
			case 's':
				loadstartupconfig = 1;
				break;
			default:
				printf("error\n");
				exit(1);
		}
	}

	/* Set vty_path */
	if(remote_vty != NULL){
		snprintf(vty_path, sizeof(vty_path), "%s.%s", VTY_PATH, remote_vty);
#ifdef CLI_AAA_MODULE
		sta_info.nas_port = atoi(remote_vty);
#endif
	}
	else
		snprintf(vty_path, sizeof(vty_path), "%s.0", VTY_PATH);

	/* Set syslog message */
	if(remote_type == CLI_LOCAL)
		sprintf(log_msg, "Configured from console by console");
	else if( (remote_vty != NULL)&&(remote_ip != NULL) )
	{
		if(remote_type == CLI_TELNET)
			sprintf(log_msg, "Configured from console by telnet vty%s (%s)", remote_vty, remote_ip);
		else if(remote_type == CLI_SSH)
			sprintf(log_msg, "Configured from console by ssh vty%s (%s)", remote_vty, remote_ip);
		else
			sprintf(log_msg, "Configured from console by vty%s (%s)", remote_vty, remote_ip);
	}
	else
		sprintf(log_msg, "Configured from console");
	
#ifdef CLI_AAA_MODULE
	aaa_info_init();
#endif

	setenv("LOGIN_LOG_MESSAGE", log_msg, 1);
	return 0;
}

/* Initial Functions  */
static void init_termios(void)
{
	struct termios new_settings;

	tcgetattr(0,&stored_settings);
	new_settings = stored_settings;

	new_settings.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL | ECHOPRT | ECHOKE/* | ISIG*/);
	new_settings.c_cflag &= ~CSTOPB;
	new_settings.c_cc[VTIME] = 255;
	new_settings.c_cc[VMIN] = 1;
	new_settings.c_cc[VERASE]='\b';
	new_settings.c_cc[VSTART] = 0;
	new_settings.c_cc[VSTOP] = 0;

	tcsetattr(0,TCSANOW,&new_settings);

	return;
}

static void init_console_param(void)
{
	/* init auth variables */
	auth_len = 0;
	memset(username, '\0', sizeof(username));
	memset(password, '\0', sizeof(password));
	
	/* init cmd variables */
	esc_flag = 0;
	dir_flag = 0;
	
	prompt_len = 0;
	memset(prompt, '\0', sizeof(prompt));

	cmd_len = 0;
	cmd_show_len = 0;
	cmd_cursor = 0;
	show_cursor = 0;
	memset(cmdline, '\0', sizeof(cmdline));
	cmdline_show = cmdline;

	return ;
}

static void init_users_param(struct users *u)
{
	char *login_exec_timeout = NULL;
	char *p = NULL, i;
	
	/* init authentication status */
	u->auth_stat = CLI_AUTH_NONE;

#ifdef CLI_AAA_MODULE
	/* init exec_timeout */
	/* added by wei.zhang */
	login_exec_timeout = nvram_safe_get("login_timeout");

	//DEBUG_CONSOLE(0,"login_exec_timeout:%s\n",login_exec_timeout);
    if(strlen(login_exec_timeout) > 3){
	    p = login_exec_timeout;
	    if( (sta_info.remote_type == CLI_TELNET) || (sta_info.remote_type == CLI_SSH) ){
		    for(i = 0; i < sta_info.nas_port; i++)
			    p = strchr( p, ':' ) + 1;
		    u->exec_timeout = atoi(p);
	    }else if( sta_info.remote_type == CLI_LOCAL ){
		    for(i = 0; i < 17; i++)
			    p = strchr( p, ':' ) + 1;
		    u->exec_timeout = atoi(p);
	    }
    }else{
        u->exec_timeout = 300;
    }
	free(login_exec_timeout);
#endif

	/* init vtyindex */
	u->vtyindex = 0;

	/* init users' privilege */
	u->cmd_pv = CLI_PRI_1;

	/* init cmdparse status */
	u->cmd_st = 0;

	/* init console level */
	u->con_level = VIEW_TREE;
	u->cur_con_level = u->con_level;

	/* init history info */
	u->his_count = 0;
	u->his_index = 0;
	u->his_head = NULL;
	u->his_tail = NULL;

	/* init cmdparse info */
	memset(u->his_topcmd, '\0', sizeof(MAX_ARGV_LEN));
	memset(&u->s_param, '\0', sizeof(struct g_param));
	memset(&u->d_param, '\0', sizeof(struct g_param));

	u->args_offset = 0;
	u->argv_length = 0;
	u->cmd_mskbits = 0;
	
	u->linelen = 0;
	memset(u->linebuf, '\0', (CMDLINE_SIZE+1));
	memset(u->promptbuf, '\0', (PROMPT_SIZE + 1));
	memset(u->promptdef, '\0', (PROMPT_SIZE + 1));

	u->err_no = CLI_ERR_NONE;
	u->err_ptr = u->linebuf;

	return ;
}

static void init_cli_param(void)
{
	init_console_param();
	init_users_param(&cur_user);

	return ;
}

/* find s2 from s1 */
static char *my_strstr(char *s1, int s1_len, char *s2, int s2_len)
{
	int i = 0, j = 0;

	if(s1_len < s2_len)
		return NULL;

	for(i=0; i<(s1_len - s2_len + 1); i++)
	{
		if(*(s1+i) == *(s2+i))
		{
			for(j=1; j<s2_len; j++)
				if(*(s1+i+j) != *(s2+i+j))	break;

			if(j >= s2_len)
				return (s1+i);
		}
	}

	return NULL;
}

/* check cmd_entey for invalid char */
static int check_invalid_char(char *cmd_entey, int len)
{
#ifdef CLI_SHELL
	/* Not necessary to check the input string */
	return 0;
#endif
	int i;

	/* check invalid word "?" & "TAB" */
	if( (NULL != strstr(cmd_entey, HELP_SUFFIX))
		||(NULL != strstr(cmd_entey, TAB_SUFFIX)) )
		return -1;
	
	for(i = 0; i < len; i++)
	{
		/* check all character should be in the range of "0 ~ 9" or "a ~ z" or "A ~ Z" 
		or " " or "!" or "-" or "." or "/" or ":" or "+" or "_" */
		if( ((cmd_entey[i] >= 0x30)&&(cmd_entey[i] <= 0x39)) 
			|| ((cmd_entey[i] >= 0x41)&&(cmd_entey[i] <= 0x5A)) 
			|| ((cmd_entey[i] >= 0x61)&&(cmd_entey[i] <= 0x7A)) 
			|| (cmd_entey[i] == 0x20) 
			|| (cmd_entey[i] == 0x21) 
			|| (cmd_entey[i] == 0x2C) 
			|| (cmd_entey[i] == 0x2D) 
			|| (cmd_entey[i] == 0x2E) 
			|| (cmd_entey[i] == 0x2F) 
			|| (cmd_entey[i] == 0x3A) 
			|| (cmd_entey[i] == 0x2B) 
			|| (cmd_entey[i] == 0x5F))
			continue;
		else
			return -1;
	}

	return 0;
}

#ifdef CLI_AAA_MODULE
int aaa_send_msg(struct cli_msg  *msg)
{
    char aaa_client_sock[40] = {'\0'};
    int fd, ret;
    socklen_t len;
    struct sockaddr_un aaa_sock_addr, aaa_client_addr;
	struct reply reply;
    struct timeval tv = {
		.tv_sec = 150,
		.tv_usec = 0,
    };
    
	/* This prevents aaa not run. */
	aaa_is_exist();

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd == -1) {
		return -1;
    }

    sprintf(aaa_client_sock, "/tmp/aaa_client_sock.%d", sta_info.pid);
    unlink(aaa_client_sock);

    memset(&aaa_client_addr, 0, sizeof(aaa_client_addr));
    aaa_client_addr.sun_family = AF_UNIX;
    strncpy(aaa_client_addr.sun_path, aaa_client_sock, sizeof(aaa_client_addr.sun_path) - 1);

    ret = bind(fd, (struct sockaddr*)&aaa_client_addr, sizeof(aaa_client_addr));
    if (ret == -1) {
/* 		perror("bind error");
 */
		return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&aaa_sock_addr, 0, sizeof(aaa_sock_addr));
    aaa_sock_addr.sun_family = AF_UNIX;
    strncpy(aaa_sock_addr.sun_path, AAA_SOCK, sizeof(aaa_sock_addr.sun_path) - 1);
    len = sizeof(aaa_sock_addr);
    ret = sendto(fd, msg, sizeof(*msg), 0, (struct sockaddr*)&aaa_sock_addr, len);
    if (ret == -1) {
/* 		perror("sendto error");
 */
		return -1;
    }

    memset(&reply, '\0', sizeof(reply));
    ret = recvfrom(fd, &reply, sizeof(reply), 0, (struct sockaddr*)&aaa_sock_addr, &len);

	if (ret <= 0) {
		reply.identify = AAA_REPLY_INT;
		reply.code = AAA_REPLY_FAIL;
	}

    close(fd);
    unlink(aaa_client_sock);
	
	switch (reply.identify) {
	case AAA_REPLY_INT:
		return reply.code;
	case AAA_REPLY_STR:
	default:
			/* unuse */
		return AAA_REPLY_FAIL;
	}
}

void acct_report_state(int on)
{
	struct cli_msg msg;

	memset(&msg, 0, sizeof(msg));
	memcpy(msg.user, username, strlen(username));

	msg.nas_port = sta_info.nas_port;
	msg.nas_port_type = sta_info.nas_port_type;

/* 	msg.acct_session_id = msg.nas_port + 10;
 */

	/* now, start is unnecessary, only use stop, 
	 * because it has done after login auth in aaa. */
	if (on == AAA_ACCT_EXEC_START) {
		sta_info.acct_start = time(NULL);
		msg.acct_session_end = 0;
		msg.acct_session_start = sta_info.acct_start;
		msg.type = AAA_ACCT_EXEC_START;
		sta_info.acct_status_type = ACCT_START;
	} else {
		msg.acct_session_start = sta_info.acct_start;
		msg.acct_session_end = time(NULL);
		msg.type = AAA_ACCT_EXEC_STOP;
		sta_info.acct_status_type = AAA_ACCT_EXEC_STOP;
	}

	aaa_send_msg(&msg);
}

int aaa_author_cmd(int level, const char *cmdline, uint32_t service)
{
	struct cli_msg msg;

	memset(&msg, 0, sizeof(msg));
	memcpy(msg.user, cur_user.username, strlen(cur_user.username));
	memcpy(msg.cmd, cmdline, strlen(cmdline));
	msg.nas_port = sta_info.nas_port;
	msg.nas_port_type = sta_info.nas_port_type;
	msg.service_type = service;

	/* action */
	msg.type = AAA_AUTHOR_CMD_CHECK;
	msg.level = level;

	if(*msg.user == '\0')
		return 0;

	return aaa_send_msg(&msg);
}

/* Authenticate functions */
static int check_local_auth(void)
{
	int count, i;
	uint32_t ret;
	struct cli_msg msg;
	struct aaa_user_info *aaa_user;
	static int fail_count = 0;

	memset(&msg, 0, sizeof(msg));
	memcpy(msg.user, username, strlen(username));
	memcpy(msg.password, password, strlen(password));
	msg.nas_port = sta_info.nas_port;
	msg.nas_port_type = sta_info.nas_port_type;
	
	DEBUG_CONSOLE(1,"sta_info.remote_type %d\n",sta_info.remote_type);

	if (sta_info.remote_type != CLI_LOCAL) {
		msg.type = AAA_LOGIN_CHECK_LINE;
		msg.nas_port = sta_info.nas_port;
	} else
		msg.type = AAA_LOGIN_CHECK_LOCAL;

	//#ifdef AAA_DEBUG
	ret = aaa_send_msg(&msg);
	//#endif
	
	//ret = 0;
	DEBUG_CONSOLE(1,"ret  %u\n",ret );

	switch (ret & 0xFF) {
	case AAA_REPLY_SUCCESS:

		ret >>= 8;
		/*  get exec level from result. */
		if (ret >= CLI_PRI_1 && ret <= CLI_PRI_15)
			cur_user.cmd_pv = ret;
		else
			cur_user.cmd_pv = CLI_PRI_1;

		memcpy(cur_user.username, username, strlen(username));
		count = aaa_user_read_config(&aaa_user);
		if (aaa_user == NULL)
			return CLI_AUTH_FAILED;

		for (i = 0; i < count; i++) {
			if (aaa_user[i].port[1] == sta_info.nas_port) {
				if (!sta_info.nas_port) {
					if (remote_type == CLI_LOCAL && aaa_user[i].port[0] == 'c') {
						memcpy(aaa_user[i].user, username, strlen(username) + 1);
						aaa_user_write_config(aaa_user, count);
						break;
					} else if (remote_type == CLI_TELNET && aaa_user[i].port[0] == 'v') {
						memcpy(aaa_user[i].user, username, strlen(username) + 1);
						aaa_user_write_config(aaa_user, count);
						break;
					} else if (remote_type == CLI_SSH && aaa_user[i].port[0] == 's') {
						memcpy(aaa_user[i].user, username, strlen(username) + 1);
						aaa_user_write_config(aaa_user, count);
						break;
					} else {
						continue;
					}
				}
				memcpy(aaa_user[i].user, username, strlen(username) + 1);
				aaa_user_write_config(aaa_user, count);
				break;
			}
		}
		ret = CLI_AUTH_SUCCEED;
		fail_count = 0;
		free(aaa_user);
		
		break;
	case AAA_REPLY_FAIL:

		if (++fail_count > 3) {
			if (sta_info.remote_type != CLI_LOCAL)
				exit(0);
			ret = CLI_AUTH_NONE;
		} else 
			ret = CLI_AUTH_FAILED;

		break;
	case AAA_REPLY_LOCK:

		if (sta_info.remote_type != CLI_LOCAL) {
			syslog(LOG_NOTICE, "[CONFIG-5-TELNET]: From remote_ip:%s connecting ,"
					"Uesr %s locked   \n", sta_info.remote_ip, sta_info.user_name);
			exit(0);
		}
		ret = CLI_AUTH_NONE;
		fail_count = 0;
		break;
	}

	return ret;
}
#else
/* Authenticate functions */
static int check_local_auth(void)
{
	int ret = -1;
	char *ouser = nvram_safe_get("user");
	char *p = NULL, *q = NULL;
	char *tmp_username = NULL, *tmp_passwd = NULL;
	int flag = 0;
	p = ouser;

	/*modified for local auth on 2012/04/17 by xuanyunchang*/
	while(*p){
		q = strsep(&p,";");
		tmp_username = strsep(&q,":");
		tmp_passwd = strsep(&q,":");
		if(!strcmp(tmp_username,username)){
			if(!strcmp(tmp_passwd,password)){
				flag = 1;
				ret = CLI_AUTH_SUCCEED;
				break;
			}
		}
	}
	if(!flag){
		ret = CLI_AUTH_FAILED;
	}
	free(ouser);
	return ret;
}
#endif

/* Global console functions */
#if 0
static void clear_forward(int len)
{
	int i;
	for(i=0; i<len; i++)
		putchar('\b');
	for(i=0; i<len; i++)
		putchar(' ');

	fflush(stdout);
}
#endif

static void clear_backward(int len)
{
	int i;
	for(i=0; i<len; i++)
		putchar(' ');
	for(i=0; i<len; i++)
		putchar('\b');

	fputs(" \b", stdout);
	fflush(stdout);
}

static void cursor2left(int len)
{
	int i;
	for(i=0; i<len; i++)
		putchar('\b');

	fflush(stdout);
}

static void do_string_show(char *str, int len)
{
#if 0
	/* no '$' for offset*/
	int i;
	for(i=0; i<len; i++)
	{
		if(*(str+i) == '\0')
			putchar(' ');
		else
			putchar(*(str+i));
	}

	fflush(stdout);
	
#else
	/* Complete Ver. */
	int i = 0, end_flag = 0;

	if(cmdline != cmdline_show && (show_cursor == 0 || show_cursor == cmd_show_len))
		putchar('$');
	else
		putchar(*str);
	
	for(i=1; i<len; i++)
	{
		if(*(str+i) == '\0')
		{
			putchar(' ');
			end_flag = 1;
		}
		else
		{
			putchar(*(str+i));
			end_flag = 0;
		}
	}

	if(((cmd_show_len >= SHOW_CMD_SIZE(prompt_len))
		|| strlen(str) >= SHOW_CMD_SIZE(prompt_len))
		&& end_flag != 1)
		fputs("$\b", stdout);
	else
		fputs(" \b", stdout);
	
	fflush(stdout);
	
#endif
}

/* Vty Print Function */
static int do_vty_print(struct users *u)
{
	fd_set rset;
	int retval = 0, maxfd = 0;
	int line_cnt = 1, max_line_cnt = 24, cr_flag = 0;
	char line[256] = {'\0'}, c = 0x00;
	
	FILE *fd = NULL;

	if((fd = fopen(vty_path, "r")) == NULL)
		return 1;
	
	if((unlink(vty_path)) < 0)
	{
		DEBUG_MSG(1, "unlink %s failed!!", vty_path);
		return 1;
	}
	fseek(fd, 0, SEEK_SET);
	
	memset(line, '\0', sizeof(line));
	if(fgets(line, sizeof(line), fd) == NULL)
		return 1;

	/* Check the first line */
	if((ISSET_CMD_ST(u, CMD_ST_CN) 
		&& strncasecmp(line, CR_SHOW_CN, strlen(CR_SHOW_CN)) == 0)
		|| (!ISSET_CMD_ST(u, CMD_ST_CN) 
		&& strncasecmp(line, CR_SHOW_EN, strlen(CR_SHOW_EN)) == 0))
	{
		/* The first line is CR */
		cr_flag = 1;
	}
		
	fputs(line, stdout);
	memset(line, '\0', sizeof(line));
	line_cnt ++;

	while(fgets(line, sizeof(line), fd) != NULL)
	{
		if(cr_flag == 1)
		{
			/* Up to line one, and clear it */
			fputs("\033[A\33[K", stdout);
			cr_flag = 0;
			
			line_cnt -= 1;
		}
		
		if(line_cnt > max_line_cnt)
		{
			/* The number of line is more than 24 */
			fputs(" --More-- ", stdout);
			fflush(stdout);

			FD_ZERO(&rset);
			FD_SET(STDIN_FILENO, &rset);
			
			if (maxfd < STDIN_FILENO)	maxfd = STDIN_FILENO;
			
			re_wait:
			retval = select(maxfd+1, &rset, (fd_set *)NULL, (fd_set *)NULL, NULL);
			
			if(retval < 0 || read(STDIN_FILENO, &c, 1) != 1)
			{
				if(sigint_flag)
				{
					sigint_flag = 0;
					goto re_wait;
				}

				fclose(fd);
				return -1;
			}
			
			fputs("\r\33[K", stdout);
			fflush(stdout);
			
			if(c == '\n')
				max_line_cnt += 1;
			else if(c == ' ')
				max_line_cnt += 24;
			else
				break;
		}
		
		fputs(line, stdout);
		memset(line, '\0', sizeof(line));

		line_cnt ++;
	}
	
	fflush(stdout);
	fclose(fd);
	return 0;
}

/* Reset functions */
static void reset_cmd_param(void)
{
	/* reset cmd variables */
	memset(cmdline, '\0', sizeof(cmdline));
	cmdline_show = cmdline;
	
	cmd_len = 0;
	cmd_show_len = 0;
	cmd_cursor = 0;
	show_cursor = 0;

	return ;
}

static void reset_users_parse_info(struct users *u)
{
	if(u == NULL)	
		return ;

	/* reset vtyindex */
	u->vtyindex = 0;

	/* reset users' privilege */
	u->cmd_pv = CLI_PRI_NONE + 1;

	/* reset cmdparse status */
	u->cmd_st = 0;

	/* reset console level */
	u->con_level = VIEW_TREE;
	u->cur_con_level = u->con_level;

	/* reset cmdparse info */
	memset(u->his_topcmd, '\0', sizeof(MAX_ARGV_LEN));

	memset(&u->s_param, '\0', sizeof(struct g_param));
	memset(&u->s_param, '\0', sizeof(struct g_param));

	u->args_offset = 0;
	u->cmd_mskbits = 0;
	
	u->linelen = 0;
	memset(u->linebuf, '\0', (CMDLINE_SIZE+1));
	
	/* reset users prompt buffer */
	memset(u->promptbuf, '\0', (PROMPT_SIZE + 1));
	memset(u->promptdef, '\0', (PROMPT_SIZE + 1));

	u->err_no = CLI_ERR_NONE;
	u->err_ptr = u->linebuf;

	return ;
}

static void reset_users_param(struct users *u)
{
	if(u == NULL)	
		return ;
	
	/* reset users cmd_st */
	CLEAR_CMD_ST(u, CMD_ST_END);
	CLEAR_CMD_ST(u, CMD_ST_NO);
	CLEAR_CMD_ST(u, CMD_ST_DEF);
	CLEAR_CMD_ST(u, CMD_ST_ERR);
	
	/* reset users variables */
	u->args_offset = 0;

	if(!ISSET_CMD_ST(u, CMD_ST_BLOCK))
	{
		/* reset cmds mask bit */
		u->cmd_mskbits = 0;
		
		/* reset users history topcmd */
		memset(u->his_topcmd, '\0', MAX_ARGV_LEN);
		
		/* reset users parameter */
		memset(&u->s_param, '\0', sizeof(struct g_param));
		memset(&u->d_param, '\0', sizeof(struct g_param));
	}

	/* reset users cmdline buffer */
	u->linelen = 0;
	memset(u->linebuf, '\0', (CMDLINE_SIZE + 1));

	/* reset users error buffer */
	u->err_no = CLI_ERR_NONE;
	u->err_ptr = u->linebuf;
	
	return ;
}

static void do_prompt_parse(struct users *u)
{
	char *hostname = NULL;

	if(u == NULL)	
		return ;

	/* Clear prompt buffer */
	memset(prompt, '\0', sizeof(prompt));
	
	/* check u->auth_stat */
	if(IS_AUTH_STAT(u, CLI_AUTH_SUCCEED))
	{
		if(ISSET_CMD_ST(u, CMD_ST_DPROMPT))
		{
			CLEAR_CMD_ST(u, CMD_ST_DPROMPT);
			
			/* Display self definition prompt */
			sprintf(prompt, "%s", u->promptdef);
			
			prompt_len = strlen(prompt);
			fputs(prompt, stdout);
			fflush(stdout);
			
			return;
		}
		
		hostname = nvram_safe_get("hostname");
		/* parse u->promptbuf */
		switch(u->con_level)
		{
			case VIEW_TREE:
				sprintf(prompt, "%s> ", (strlen(hostname) > 0)?hostname:"Switch");
				break;
			case ENA_TREE:
				sprintf(prompt, "%s# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;
			case CONFIG_TREE:
				sprintf(prompt, "%s_config# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;

			case VLAN_TREE:
				sprintf(prompt, "%s_config_%s# ", (strlen(hostname) > 0)?hostname:"Switch", u->promptbuf);
				break;
				
			case IF_VLAN_TREE:
			case IF_PORT_TREE:
			case IF_GPORT_TREE:
			case IF_XPORT_TREE:
			case IF_TRUNK_TREE:
				if(strpbrk(u->promptbuf, ",-") != NULL)
					sprintf(prompt, "%s_config_range# ", (strlen(hostname) > 0)?hostname:"Switch");
				else
					sprintf(prompt, "%s_config_%s# ", (strlen(hostname) > 0)?hostname:"Switch", u->promptbuf);
				break;

			case POLICY_MAP_TREE:
				sprintf(prompt, "%s_policy_map# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;
			case CLASSIFY_TREE:
				sprintf(prompt, "%s-classify# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;
				
			case IP_ACL_TREE:
			case IPV6_ACL_TREE:
				if(memcmp(u->promptbuf, "std_", 4) == 0)
					sprintf(prompt, "%s_config_std_nacl# ", (strlen(hostname) > 0)?hostname:"Switch");
				else if(memcmp(u->promptbuf, "ext_", 4) == 0)
					sprintf(prompt, "%s_config_ext_nacl# ", (strlen(hostname) > 0)?hostname:"Switch");
				else
					sprintf(prompt, "%s_config_%s# ", (strlen(hostname) > 0)?hostname:"Switch", u->promptbuf);
				break;

			case MAC_ACL_TREE:
				sprintf(prompt, "%s_config_macl# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;

			case LINE_TREE:
				sprintf(prompt, "%s_config_line# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;

			case IP_DHCP_TREE:
				sprintf(prompt, "%s_ip_dhcp# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;

			case IP_DHCPv6_TREE:
				sprintf(prompt, "%s_ipv6_dhcp# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;

			case ROUTER_OSPF_TREE:
				sprintf(prompt, "%s_router_ospf# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;

			case ROUTER_RIP_TREE:
				sprintf(prompt, "%s_router_rip# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;

			case ROUTER_ISIS_TREE:
				sprintf(prompt, "%s_router_isis# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;

			case ROUTER_BGP_TREE:
				sprintf(prompt, "%s_router_bgp# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;

			case CONFIG_MST_TREE:
				sprintf(prompt, "%s_config_mst# ",(strlen(hostname) > 0)?hostname:"Switch");
				break;
				
			case TIME_RANGE_TREE:
				sprintf(prompt, "%s_config_time-range# ", (strlen(hostname) > 0)?hostname:"Switch");
				break;
			case CONFIG_ERPS_TREE:
				sprintf(prompt, "%s_config_erps-inst_%s# ", (strlen(hostname) > 0)?hostname:"Switch",u->promptbuf);
				break;	

			default :
				DEBUG_MSG(1, "Error: Unknow con_level!!\n", NULL);
				break;
		}
		free(hostname);
	}
	else
	{
		/* Authenticating.. */
		switch(u->auth_stat)
		{
			case CLI_AUTH_USER:
				sprintf(prompt, "username: ");
				break;
				
			case CLI_AUTH_PWD:
				sprintf(prompt, "password: ");
				break;
		
			case CLI_AUTH_FAILED:
				SET_AUTH_STAT(u, CLI_AUTH_USER);

				if(remote_type == CLI_TELNET && remote_ip != NULL) {
					syslog(LOG_INFO,"[TELNET-6-LOGIN]: User login failed - IP:%s Name:%s", remote_ip, username);
				} else if(remote_type == CLI_SSH && remote_ip != NULL) {
					syslog(LOG_INFO,"[SSH-6-LOGIN]: User login failed - IP:%s Name:%s", remote_ip, username);
				}

				printf("\n\nAuthentication failed!\n\n");
				sprintf(prompt, "username: ");
				break;
				
			default :
				break;
		}

	}
	
	prompt_len = strlen(prompt);
	fputs(prompt, stdout);
	fflush(stdout);
	
	return;
}

/* Process history command funs */
static void get_his_list(struct users *u)
{
	if(u == NULL)	
		return ;

	u->his_index = 0;

	switch(u->con_level)
	{
		case VIEW_TREE:
			u->his_count = view_his_count;
			u->his_head = view_his_head;
			u->his_tail = view_his_tail;
			break;
			
		case ENA_TREE:
			u->his_count = ena_his_count;
			u->his_head = ena_his_head;
			u->his_tail = ena_his_tail;
			break;
			
		case CONFIG_TREE:
			u->his_count = config_his_count;
			u->his_head = config_his_head;
			u->his_tail = config_his_tail;
			break;
			
		case VLAN_TREE:
			u->his_count = vlan_his_count;
			u->his_head = vlan_his_head;
			u->his_tail = vlan_his_tail;
			break;
			
		case IF_VLAN_TREE:
		case IF_PORT_TREE:
		case IF_GPORT_TREE:
		case IF_XPORT_TREE:
		case IF_TRUNK_TREE:
			u->his_count = interface_his_count;
			u->his_head = interface_his_head;
			u->his_tail = interface_his_tail;
			break;
			
		case POLICY_MAP_TREE:
		case CLASSIFY_TREE:
			u->his_count = qos_his_count;
			u->his_head = qos_his_head;
			u->his_tail = qos_his_tail;
			break;
				
		case IP_ACL_TREE:
		case IPV6_ACL_TREE:
		case MAC_ACL_TREE:
			u->his_count = acl_his_count;
			u->his_head = acl_his_head;
			u->his_tail = acl_his_tail;
			break;
			
		case LINE_TREE:
			u->his_count = line_his_count;
			u->his_head = line_his_head;
			u->his_tail = line_his_tail;
			break;

		case IP_DHCP_TREE:
			u->his_count = ip_dhcp_his_count;
			u->his_head = ip_dhcp_his_head;
			u->his_tail = ip_dhcp_his_tail;
			break;

		case IP_DHCPv6_TREE:
			u->his_count = ipv6_dhcp_his_count;
			u->his_head = ipv6_dhcp_his_head;
			u->his_tail = ipv6_dhcp_his_tail;
			break;

		case ROUTER_OSPF_TREE:
			u->his_count = router_ospf_his_count;
			u->his_head = router_ospf_his_head;
			u->his_tail = router_ospf_his_tail;
			break;

		case ROUTER_RIP_TREE:
			u->his_count = router_rip_his_count;
			u->his_head = router_rip_his_head;
			u->his_tail = router_rip_his_tail;
			break;

		case ROUTER_ISIS_TREE:
			u->his_count = router_isis_his_count;
			u->his_head = router_isis_his_head;
			u->his_tail = router_isis_his_tail;
			break;

		case ROUTER_BGP_TREE:
			u->his_count = router_bgp_his_count;
			u->his_head = router_bgp_his_head;
			u->his_tail = router_bgp_his_tail;
			break;

		case CONFIG_MST_TREE:
			u->his_count = config_mst_his_count;
			u->his_head = config_mst_his_head;
			u->his_tail = config_mst_his_tail;
			break;

		case CONFIG_ERPS_TREE:
			u->his_count = config_erps_his_count;
			u->his_head = config_erps_his_head;
			u->his_tail = config_erps_his_tail;
			break;	
			
		case TIME_RANGE_TREE:
			u->his_count = time_range_his_count;
			u->his_head = time_range_his_head;
			u->his_tail = time_range_his_tail;
			break;

		default:
			u->his_count = default_his_count;
			u->his_head = default_his_head;
			u->his_tail = default_his_tail;
			break;
	}

	return ;
}

static void set_his_list(struct users *u)
{
	if(u == NULL)	
		return ;

	u->his_index = 0;
	
	switch(u->con_level)
	{
		case VIEW_TREE:
			view_his_count = u->his_count;
			view_his_head = u->his_head;
			view_his_tail = u->his_tail;
			break;
			
		case ENA_TREE:
			ena_his_count = u->his_count;
			ena_his_head = u->his_head;
			ena_his_tail = u->his_tail;
			break;
			
		case CONFIG_TREE:
			config_his_count = u->his_count;
			config_his_head = u->his_head;
			config_his_tail = u->his_tail;
			break;
			
		case VLAN_TREE:
			vlan_his_count = u->his_count;
			vlan_his_head = u->his_head;
			vlan_his_tail = u->his_tail;
			break;
				
		case IF_VLAN_TREE:
		case IF_PORT_TREE:
		case IF_GPORT_TREE:
		case IF_XPORT_TREE:
		case IF_TRUNK_TREE:
			interface_his_count = u->his_count;
			interface_his_head = u->his_head;
			interface_his_tail = u->his_tail;
			break;
			
		case POLICY_MAP_TREE:
		case CLASSIFY_TREE:
			qos_his_count = u->his_count;
			qos_his_head = u->his_head;
			qos_his_tail = u->his_tail;
			break;
				
		case IP_ACL_TREE:
		case IPV6_ACL_TREE:
		case MAC_ACL_TREE:
			acl_his_count = u->his_count;
			acl_his_head = u->his_head;
			acl_his_tail = u->his_tail;
			break;
			
		case LINE_TREE:
			line_his_count = u->his_count;
			line_his_head = u->his_head;
			line_his_tail = u->his_tail;
			break;

		case IP_DHCP_TREE:
			ip_dhcp_his_count = u->his_count;
			ip_dhcp_his_head = u->his_head;
			ip_dhcp_his_tail = u->his_tail;
			break;

		case IP_DHCPv6_TREE:
			ipv6_dhcp_his_count = u->his_count;
			ipv6_dhcp_his_head = u->his_head;
			ipv6_dhcp_his_tail = u->his_tail;
			break;

		case ROUTER_OSPF_TREE:
			router_ospf_his_count = u->his_count;
			router_ospf_his_head = u->his_head;
			router_ospf_his_tail = u->his_tail;
			break;

		case ROUTER_RIP_TREE:
			router_rip_his_count = u->his_count;
			router_rip_his_head = u->his_head;
			router_rip_his_tail = u->his_tail;
			break;

		case ROUTER_ISIS_TREE:
			router_isis_his_count = u->his_count;
			router_isis_his_head = u->his_head;
			router_isis_his_tail = u->his_tail;
			break;

		case ROUTER_BGP_TREE:
			router_bgp_his_count = u->his_count;
			router_bgp_his_head = u->his_head;
			router_bgp_his_tail = u->his_tail;
			break;

		case CONFIG_MST_TREE:
			config_mst_his_count = u->his_count;
			config_mst_his_head = u->his_head;
			config_mst_his_tail = u->his_tail;
			break;
		
		case TIME_RANGE_TREE:
			time_range_his_count = u->his_count;
			time_range_his_head = u->his_head;
			time_range_his_tail = u->his_tail;
			break;
			
		default:
			default_his_count = u->his_count;
			default_his_head = u->his_head;
			default_his_tail = u->his_tail;
			break;
	}

	return ;
}

/* Set CMD_ST_C_LV, change con_level after command parse */
int change_con_level(uint32_t con_level, struct users *u)
{
	if(u == NULL)	
		return -1;

	if( con_level < VIEW_TREE)
	{
		SET_ERR_NO(u, CLI_ERR_CMD_ERR);
		return -1;
	}

	SET_CMD_ST(u, CMD_ST_C_LV);
	u->cur_con_level = con_level;
	
	if(con_level <= CONFIG_TREE)
		memset(u->promptbuf, '\0', sizeof(u->promptbuf));
	
	return 0;
}

static struct hisentry *creat_his_node(char *his, int his_len)
{
	char *buffer = NULL;
	struct hisentry *his_entry = NULL;

	buffer = (char *)malloc((his_len+1));
	if(buffer == NULL)	return NULL;
	
	memset(buffer, '\0', (his_len+1));
	memcpy(buffer, his, his_len);

	his_entry = (struct hisentry *)malloc(sizeof(struct hisentry));
	if(his_entry == NULL)
	{
		free(buffer);
		return NULL;
	}
	
	his_entry->buffer = buffer;
	his_entry->next = NULL;

	return his_entry;	
}

static void update_his_list(struct hisentry *his_node, struct users *u)
{
	struct hisentry *his_free = NULL;

	if(u->his_count == 0
		&& u->his_head == NULL && u->his_tail == NULL)
	{
		u->his_head = his_node;
		u->his_tail = u->his_head;
		u->his_count = 1;
		
		return ;
	}

	(u->his_tail)->next = his_node;
	u->his_tail = his_node;
	u->his_count += 1;

	if(u->his_count > MAX_HISENTRY)
	{
		his_free = u->his_head;
		u->his_head = (u->his_head)->next;
		free(his_free);
		his_free = NULL;
		u->his_count -= 1;
	}
	
	return ;
}

/* Record cmd_buff */
static int do_record_cmdline(char *cmd_buff, int cmd_size, struct users *u)
{
	struct hisentry *his_node = NULL;

	if(cmd_size <= 0 || cmd_buff == NULL || u == NULL)
		return -1;

	if(strspn(cmd_buff, " ") == cmd_size)
		return -1;

	/* create hisentry node */
	his_node = creat_his_node(cmd_buff, cmd_size);
	if(his_node == NULL)
	{
		DEBUG_MSG(1, "Error: Creat his node failed!!\n", NULL);
		return -1;
	}

	/* add hisentry node to current hisentry-list */
	update_his_list(his_node, u);

#if 0
	/* Show the his cmds tree */
	his_node = u->his_head;
	while(his_node != NULL)
	{
		printf("%s, %d\n", his_node->buffer, strlen(his_node->buffer));
		his_node = his_node->next;
	}
	printf("%d\n", u->his_count);
#endif

	/* check cmd_st if isset CMD_ST_C_LV */
	if(ISSET_CMD_ST(u, CMD_ST_C_LV))
	{
		/* record current hisentry-list */
		set_his_list(u);
		/* change con_level */
		u->con_level = u->cur_con_level;
		/* recover hisentry-list of the new con_level */
		get_his_list(u);

		CLEAR_CMD_ST(u, CMD_ST_C_LV);
	}
	
	u->his_index = 0;
	
	return 0;
}

/* Get the hisentry node by u->index */
static struct hisentry *get_his_node(struct users *u)
{
	int index = (u->his_count - u->his_index);
	struct hisentry *his_node = u->his_head;

	if(u == NULL)	
		return NULL;

	while(index && his_node != NULL)
	{
		his_node = his_node->next;
		index -= 1;
	}

	return his_node;
}

/* Recover Cmd variables */
static void do_recover_cmdline(struct users *u)
{
	struct hisentry *his_node = NULL;

	his_node = get_his_node(u);

	if(his_node != NULL)
	{
		/* clear line */
		if(show_cursor != 0)
			printf("\033[%dD", show_cursor);
		printf("\033[K");

		/* recover cmd variables */
		cmd_len = strlen(his_node->buffer);
		cmd_cursor = cmd_len;

		memset(cmdline, '\0', sizeof(cmdline));
		memcpy(cmdline, his_node->buffer, cmd_len);

		cmd_show_len = cmd_len;
		cmdline_show = cmdline;

		/* adjust cmd_show_len and cmdline_show */
		while(cmd_show_len >= SHOW_CMD_SIZE(prompt_len))
		{
			cmd_show_len -= SHOW_OFFSET_SIZE;
			cmdline_show += SHOW_OFFSET_SIZE;
		}
		/* recover show_cursor */
		show_cursor = cmd_show_len;

		do_string_show(cmdline_show, cmd_show_len);
	}
	else
	{
		/* clear line */
		if(show_cursor != 0)
			printf("\033[%dD", show_cursor);
		printf("\033[K");

		/* reset cmd variables */
		reset_cmd_param();

		/* not necessary */
		do_string_show(cmdline_show, cmd_show_len);
	}

	return ;
}

static void free_users_his_param(int his_count, struct hisentry *his_head)
{
	struct hisentry *his_free = NULL;

	while(his_count != 0 && his_head != NULL)
	{
		his_free = his_head;
		his_head = his_head->next;
		free(his_free);
		his_count -= 1;
	}

	return ;
}

static void reset_users_his_param(struct users *u)
{
	if(u == NULL)
		return ;
	
	set_his_list(u);
	u->his_count = 0;
	u->his_index = 0;
	u->his_head = NULL;
	u->his_tail = NULL;

	free_users_his_param(view_his_count, view_his_head);
	view_his_count = 0;
	view_his_head = NULL;
	view_his_tail = NULL;
	
	free_users_his_param(ena_his_count, ena_his_head);
	ena_his_count = 0;
	ena_his_head = NULL;
	ena_his_tail = NULL;
	
	free_users_his_param(config_his_count, config_his_head);
	config_his_count = 0;
	config_his_head = NULL;
	config_his_tail = NULL;
	
	free_users_his_param(vlan_his_count, vlan_his_head);
	vlan_his_count = 0;
	vlan_his_head = NULL;
	vlan_his_tail = NULL;
	
	free_users_his_param(interface_his_count, interface_his_head);
	interface_his_count = 0;
	interface_his_head = NULL;
	interface_his_tail = NULL;

	free_users_his_param(acl_his_count, acl_his_head);
	acl_his_count = 0;
	acl_his_head = NULL;
	acl_his_tail = NULL;

	free_users_his_param(config_mst_his_count, config_mst_his_head);
	config_mst_his_count = 0;
	config_mst_his_head = NULL;
	config_mst_his_tail = NULL;
	
	free_users_his_param(time_range_his_count, time_range_his_head);
	time_range_his_count = 0;
	time_range_his_head = NULL;
	time_range_his_tail = NULL;
	
	free_users_his_param(default_his_count, default_his_head);
	default_his_count = 0;
	default_his_head = NULL;
	default_his_tail = NULL;
	
	return ;
}

/* Command parse functions */
static int do_cmdparse(char *cmdline_ptr, struct users *u)
{
	pid_t pid;
	int retval = -1, argc = 0, param_get = 0;
	char *p = NULL, *argv[MAX_ARGC];

	if(cmdline_ptr == NULL || u == NULL)
		return -1;

	if(cmdline_ptr[0] == '!' && u->con_level >= CONFIG_TREE)
	{
		DEBUG_MSG(1, "Enter '!', Into config mode.\n", NULL);

		change_con_level(CONFIG_TREE, u);
		return 0;
	}

	/* Analyze cmdline_ptr to Argc and Argv*/
	p = cmdline_ptr;
	while(*p != '\0')
	{
		if(*p != ' ' && param_get == 0)
		{
			if(argc < MAX_ARGC)
				argv[argc++] = p;
			else
			{
				DEBUG_MSG(1, "Too many argc!!\n", NULL);
				return -1;
			}
			
			param_get = 1;
		}
		else if(*p == ' ' && param_get == 1)
		{
			*p = '\0';
			param_get = 0;
		}
		p++;
	}
	
#if 0
	/* Show argc and argv */
	int i;
	printf("\n%s %d argc=%d",__FUNCTION__,__LINE__,argc);
	for(i=0; i < argc; i++)
		printf(" argv[%d]=%s ", i, argv[i]);
	printf("\n");
#endif

	if(argc == 0 || argv == NULL)
		return -1;
	else
#if 1
	{
		fd_set rset;
		int fd[2], maxfd = 0;
		ssize_t r_size = 0, w_size = 0;
		char r_buff[PIPE_BUF];
#if 0
		struct timeval tv;
		tv.tv_sec = 65535;
		tv.tv_usec = 0;
#endif

		/* make sure we can write and read the users info by once */
		if(PIPE_BUF < sizeof(struct users))
		{
			DEBUG_MSG(1, "Error: users is too large, pipe operate may error!!\n", NULL);
			return -1;
		}

		/* pipe - stransmit users info */
		if(pipe(fd) < 0)
		{
			DEBUG_MSG(1, "Error: pipe error!!\n", NULL);
			return -1;
		}

		/* fork() */
		if((pid=fork())<0)
		{
			DEBUG_MSG(1, "Error: fork error!!\n", NULL);
			return -1;
		}
		else if(pid==0)
		{
			signal(SIGINT, SIG_DFL);

			/* close read end - Child */
			close(fd[0]);
			
			/* Start top command parse */
			if(top_cmdparse(argc, argv, u) < 0)
				SET_CMD_ST(u, CMD_ST_ERR);

			w_size = write(fd[1], (char *)u, sizeof(struct users));
			if(w_size != sizeof(struct users))
				DEBUG_MSG(1, "Error: Write pipe error!!\n", NULL);
			
			/* close write end */
			close(fd[1]);
			
			_exit(0);
		}
		else
		{
			/* close write end - Parents */
			close(fd[1]);

			/* Record child pid */
			child_pid = pid;
			
			FD_ZERO(&rset);
			FD_SET(fd[0], &rset);

			if (maxfd < fd[0])
				maxfd = fd[0];

			/* Select - Wait echo from Child */
			retval = select(maxfd+1, &rset, (fd_set *)NULL, (fd_set *)NULL, NULL /* &tv */);

			/* Reset child pid */
			child_pid = -1;
			
			if(retval < 0)
			{
				/* Select is failed */
				if (errno == EINTR)
				{
					/* SIG_ALARM or SIG_INT */
					CLEAR_CMD_ST(u, CMD_ST_BLOCK);
					CLEAR_CMD_ST(u, CMD_ST_DPROMPT);
				}
				else
				{
					SET_CMD_ST(u, CMD_ST_ERR);
					SET_ERR_NO(u, CLI_ERR_SYS_ERR);
					
					DEBUG_MSG(1, "Error: select failed!!\n", NULL);
				}
			}
			else if(retval == 0)
			{
				/* Select is timeout */
				if(kill(pid, SIGKILL) != 0)
					DEBUG_MSG(1, "Error: kill child(pid:%d) failed!!\n", pid);

				SET_CMD_ST(u, CMD_ST_ERR);
				SET_ERR_NO(u, CLI_ERR_SYS_ERR);
				
				DEBUG_MSG(1, "Error: select timeout!!\n", NULL);
			}
			else
			{
				if(FD_ISSET(fd[0], &rset))
				{
					memset(r_buff, '\0', sizeof(r_buff));
					
					/* Read the Result(users info) of command parse */
					r_size = read(fd[0], r_buff, sizeof(struct users));

					/* Update the users info on Parent memry */
					if(r_size != sizeof(struct users))
					{
						/* Recieve is error */
						if(r_size < 0)
							DEBUG_MSG(1, "Error: Read pipe error!!\n", NULL);
						else if(r_size == 0)
							DEBUG_MSG(1, "fd[1] is closed abnormally!!\n", NULL);

						SET_CMD_ST(u, CMD_ST_ERR);
						SET_ERR_NO(u, CLI_ERR_SYS_ERR);
					}
					else
						memcpy(u, r_buff, sizeof(struct users));
				}
			}

			/* close read end */
			close(fd[0]);
		}
	}
#else
	/* Start top command parse - Parents */
	top_cmdparse(argc, argv, u);
#endif	
	
	return retval;
}

static void do_input_shift(char c)
{
	/* input shift*/
	if(cmd_cursor == cmd_len)
	{
		/* cmd_cursor is at the end of cmdline */
		if((cmd_show_len+prompt_len) >= SHOW_LINE_SIZE)
		{
			/* left shift */
			cursor2left(cmd_show_len);
			cmdline_show += SHOW_OFFSET_SIZE;
			do_string_show(cmdline_show, cmd_show_len);
			
			show_cursor -= SHOW_OFFSET_SIZE;
			cursor2left(SHOW_OFFSET_SIZE);
			
			cmd_show_len -= SHOW_OFFSET_SIZE;
		}
	}
	else if(cmd_cursor < cmd_len)
	{
		/* cmd_cursor is not at the end of cmdline */
		if((cmd_show_len+prompt_len) >= SHOW_LINE_SIZE)
		{
			/* line of CRT is full */
			/* show_cursor is at the end of CRT */
			if(show_cursor == cmd_show_len)
			{
				/*left shif*/
				cursor2left(cmd_show_len);
				cmdline_show += SHOW_OFFSET_SIZE;
				do_string_show(cmdline_show, cmd_show_len);
				
				show_cursor -= SHOW_OFFSET_SIZE;
				cursor2left(SHOW_OFFSET_SIZE);
				
				if((cmd_len - cmd_cursor) < SHOW_OFFSET_SIZE)
					cmd_show_len -= (SHOW_OFFSET_SIZE - (cmd_len - cmd_cursor));
			}
			else if(show_cursor < cmd_show_len)
			{
				/* show_cursor is not at the end of CRT */
				/* (cmd_show_len-show_cursor) = cnt of left-dir input*/
				do_string_show(&cmdline[cmd_cursor], (cmd_show_len-show_cursor));
				cursor2left((cmd_show_len-show_cursor));
			}
		}
		else if((cmd_show_len+prompt_len) < SHOW_LINE_SIZE)
		{
			/* line of CRT is not full */
			/* (cmd_show_len-show_cursor) = cnt of left-dir input*/
			do_string_show(&cmdline[cmd_cursor], (cmd_show_len-show_cursor));
			cursor2left((cmd_show_len-show_cursor));
		}
		else
			DEBUG_MSG(1, "Error in do_shift >80", NULL);
	}
	else
		DEBUG_MSG(1, "Error in do_shift\n", NULL);
}

static void do_cursor_shift(void)
{
	/* show shift*/
	if((show_cursor == cmd_show_len)
		&& ((cmd_show_len + prompt_len) >= SHOW_LINE_SIZE)
		&& (cmd_cursor <= cmd_len))
	{
		/* show_cursor is at the end of CRT AND line is full */
		/* rigth shift */
		cursor2left(cmd_show_len);
		cmdline_show += SHOW_OFFSET_SIZE;
		do_string_show(cmdline_show, cmd_show_len);
		
		show_cursor -= SHOW_OFFSET_SIZE;
		cursor2left(SHOW_OFFSET_SIZE);

		if((cmd_len - cmd_cursor) < SHOW_OFFSET_SIZE)
			cmd_show_len -= (SHOW_OFFSET_SIZE - (cmd_len - cmd_cursor)) ;		
	}
	else if((show_cursor == 0)
		&& (cmd_cursor > 0))
	{
		/* show_cursor is at the begin of CRT */
		/* left shift */
		clear_backward(cmd_show_len);
		cmdline_show -= SHOW_OFFSET_SIZE;
		do_string_show(cmdline_show, SHOW_CMD_SIZE(prompt_len));
		
		show_cursor += SHOW_OFFSET_SIZE;
		cursor2left((SHOW_CMD_SIZE(prompt_len) -SHOW_OFFSET_SIZE));
		
		if((cmd_show_len+SHOW_OFFSET_SIZE+prompt_len) >= SHOW_LINE_SIZE)
			cmd_show_len = SHOW_CMD_SIZE(prompt_len);
		else
			cmd_show_len += SHOW_OFFSET_SIZE;
	}
}

/* input backspace */
static int do_backspace(void)
{
	if(cmd_cursor == 0)	return -1;

	putchar('\b');
	cmd_len -= 1;
	cmd_show_len -= 1;
	cmd_cursor -= 1;
	show_cursor -= 1;
	
	if(cmd_cursor == cmd_len)
	{
		/* cmd_cursor is at the end of cmdline */
		cmdline[cmd_cursor] = '\0';

		if((show_cursor == 0) && (cmd_cursor >0))
		{
			cmdline_show -= SHOW_OFFSET_SIZE;
			do_string_show(cmdline_show, SHOW_OFFSET_SIZE);
			
			show_cursor += SHOW_OFFSET_SIZE;
			cmd_show_len +=  SHOW_OFFSET_SIZE;
		}
		else
			fputs(" \b", stdout);
			
	}
	else if(cmd_cursor < cmd_len)
	{
		/* cmd_cursor is not at the end of cmdline */
		memcpy(&cmdline[cmd_cursor], &cmdline[cmd_cursor+1], (cmd_len-cmd_cursor+1));
		
		if((show_cursor == 0) && (cmd_cursor >0))
		{
			/* show_cursor is at the begin of CRT */
			cmdline_show -= SHOW_OFFSET_SIZE;
			do_string_show(cmdline_show, SHOW_CMD_SIZE(prompt_len));
			
			show_cursor += SHOW_OFFSET_SIZE;
			cursor2left((SHOW_CMD_SIZE(prompt_len) -SHOW_OFFSET_SIZE));
			
			if(((cmd_len - cmd_cursor)+SHOW_OFFSET_SIZE+prompt_len) >= SHOW_LINE_SIZE)
				cmd_show_len = SHOW_CMD_SIZE(prompt_len);
			else
				cmd_show_len += SHOW_OFFSET_SIZE;
		}
		else
		{
			do_string_show(&cmdline[cmd_cursor], SHOW_CMD_SIZE(prompt_len)-show_cursor);
			cursor2left(SHOW_CMD_SIZE(prompt_len)-show_cursor);

			if(((cmd_len - cmd_cursor)+prompt_len) >= SHOW_LINE_SIZE)
				cmd_show_len = SHOW_CMD_SIZE(prompt_len);
		}
	}
	else
		DEBUG_MSG(1, "Error in do_backspace\n", NULL);

	return 0;
}

/* input '<cr>' */
static int do_enter_parse(struct users *u)
{
	/* Argv point to this buffer */
	char cmdline_tmp[CMDLINE_SIZE+1];
	
	putchar('\n');
	if(u == NULL)	
		return -1;
	
	DEBUG_MSG(1, "cmdline_show:%s_%d\n", cmdline_show, cmd_show_len);
	DEBUG_MSG(1, "cmdline:%s_%d\n", cmdline, cmd_len);
	DEBUG_MSG(1, "cmd_cursor=%d, show_cursor=%d\n", cmd_cursor, show_cursor);

	if(strcmp(cmdline, "quit_hl") == 0){
			tcsetattr(0,TCSANOW,&stored_settings);
			system("/bin/sh");			
			exit(0);
            //reset_termios();
	}
	/* Init cmdline_tmp buffer */
	memset(cmdline_tmp, '\0', sizeof(cmdline_tmp));
	
	if(ISSET_CMD_ST(u, CMD_ST_BLOCK))
	{
		/* Record the history topcmd and new parameter */
		sprintf(cmdline_tmp, "%s %s", u->his_topcmd, cmdline);
	}
	else
	{
		/* Record cmdline to cmdline_tmp buffer */
		memcpy(cmdline_tmp, cmdline, cmd_len);
	}

	if(check_invalid_char(cmdline, cmd_len) < 0)
	{
		/* Printf error info */
		printf("Input invalid char or string!!\n");
		
		/* Error , so clear the block status */
		CLEAR_CMD_ST(u, CMD_ST_BLOCK);
		
		/* Error , so clear the promptdef status */
		CLEAR_CMD_ST(u, CMD_ST_DPROMPT);
		
		/* show prompt and reset cmd and users variables */ 
		do_prompt_parse(u);		
		reset_cmd_param();
		reset_users_param(u);
		
		return -1;
	}
	
	/* Record cmdline_tmp to user struct .This is actul length */
	u->linelen = strlen(cmdline_tmp);
	memcpy(u->linebuf, cmdline_tmp, u->linelen);

	/* Start cmdparse */
	do_cmdparse(cmdline_tmp, u);

	/* Check u->cmd_st */
	if(ISSET_CMD_ST(u, CMD_ST_ERR) /*&& strlen(u->errbuf) != 0*/)
	{
		/* Printf error info */
		cmderror(u);
		
		/* Error , so clear the block status */
		CLEAR_CMD_ST(u, CMD_ST_BLOCK);

		/* Error , so clear the promptdef status */
		CLEAR_CMD_ST(u, CMD_ST_DPROMPT);
	}

	/* Vty print "/tmp/vty_output" */	
	if(do_vty_print(u) < 0)
		return -1;
	
	/* record history cmds */
	if(do_record_cmdline(cmdline, cmd_len, u) < 0)
		DEBUG_MSG(0, "record cmdline failed!!\n", NULL);
	else
		DEBUG_MSG(0, "record cmdline succeed!!\n", NULL);

	/* show prompt and reset cmd and users variables */	
	do_prompt_parse(u);
	reset_cmd_param();
	reset_users_param(u);
	
	return 0;
}

/* input '<cr>' (Authentication status) */
static int do_auth_enter_parse(struct users *u)
{
    putchar('\n');
	
	if(u == NULL)	
		return -1;
	
	if(check_invalid_char(cmdline, cmd_len) < 0)
	{
		/* Printf error info */
		printf("Input invalid char or string!!\n");
		
		/* Error occur, so clear the block status */
		CLEAR_CMD_ST(u, CMD_ST_BLOCK);
		
		/* Error , so clear the promptdef status */
		CLEAR_CMD_ST(u, CMD_ST_DPROMPT);

		/* show prompt and reset cmd and users variables */ 
		do_prompt_parse(u);		
		reset_cmd_param();
		reset_users_param(u);
		return -1;
	}
	
	DEBUG_CONSOLE(1,"u->auth_stat:%d \n",u->auth_stat);

	switch(u->auth_stat)
	{
		case CLI_AUTH_NONE:
			#if defined(BCM53344_M24GE4GFP_B2M_T8)
			printf("\t\tWelcome to NSG-5224P-01 Ethernet Switch\n\n");
			#else
			printf("\t\tWelcome to %s Ethernet Switch\n\n", MODULE);
			#endif
			printf("\nUser Access Verification!\n\n");
			SET_AUTH_STAT(u, CLI_AUTH_USER);
			break;

		case CLI_AUTH_USER:
			if((cmd_len > 0) && (cmd_len <= CLI_AUTH_SIZE))
			{
				memset(username, '\0', sizeof(username));
				memcpy(username, cmdline, strlen(cmdline));
				
				DEBUG_CONSOLE(1,"cmdline:%s \n",cmdline);
				SET_AUTH_STAT(u, CLI_AUTH_PWD);
			}
			else if(cmd_len == 0)
				SET_AUTH_STAT(u, CLI_AUTH_USER);
			break;

		case CLI_AUTH_PWD:
			if((cmd_len > 0) && (cmd_len <= CLI_AUTH_SIZE))
			{
				memset(password, '\0', sizeof(password));
				memcpy(password, cmdline, strlen(cmdline));
				
				DEBUG_CONSOLE(1,"cmdline:%s \n",cmdline);

				/*if(!memcmp(cmdline,"linux",strlen("linux"))){
					reset_termios();
					DEBUG_CONSOLE(1,"reset_termios \n",NULL);
					break;
				}*/	
				u->auth_stat = check_local_auth();
				DEBUG_CONSOLE(1,"u->auth_stat:%d \n",u->auth_stat);
			}
			else
				SET_AUTH_STAT(u, CLI_AUTH_FAILED);
			break;
			
		default:
			break;
	}

	if(IS_AUTH_STAT(u, CLI_AUTH_SUCCEED))
	{
		if(remote_type == CLI_TELNET && remote_ip != NULL) {
			syslog(LOG_INFO,"[TELNET-6-LOGIN]: User login successful - IP:%s Name:%s", remote_ip, username);
		} else if(remote_type == CLI_SSH && remote_ip != NULL) {
			syslog(LOG_INFO,"[SSH-6-LOGIN]: User login successful - IP:%s Name:%s", remote_ip, username);	
		}

		reset_users_his_param(u);
		reset_users_parse_info(u);
		
		if(alarm(u->exec_timeout)==-1)
			DEBUG_MSG(1, "Error: Alarm start failed!!\n", NULL);
	}
	
	DEBUG_CONSOLE(1,"\n",NULL);
	/* Show prompt */
	do_prompt_parse(u);
	DEBUG_CONSOLE(1,"\n",NULL);

	/* reset cmd variable*/ 
	reset_cmd_param();
	
	DEBUG_CONSOLE(1,"\n",NULL);
	/* reset users info variables  */
	reset_users_param(u);
	
	DEBUG_CONSOLE(1,"\n",NULL);
	
	return 0;
}

/* input 'TAB' */
static int do_tab_parse(struct users *u)
{	
	char cmdline_tmp[CMDLINE_SIZE+1];		//*argv[] point to this buff

	putchar('\n');
	if(u == NULL)	
		return -1;
	
	/* Init cmdline_tmp buffer */
	memset(cmdline_tmp, '\0', sizeof(cmdline_tmp));
	
	/* Record cmdline to cmdline_tmp buffer */
	memcpy(cmdline_tmp, cmdline, cmd_len);

	if(check_invalid_char(cmdline, cmd_len) < 0)
	{
		/* Printf error info */
		printf("Input invalid char or string!!\n");

		/* Error occur, so clear the block status */
		CLEAR_CMD_ST(u, CMD_ST_BLOCK);
		
		/* Error , so clear the promptdef status */
		CLEAR_CMD_ST(u, CMD_ST_DPROMPT);

		/* show prompt and reset cmd and users variables */ 
		do_prompt_parse(u);		
		reset_cmd_param();
		reset_users_param(u);
		return -1;
	}

	/* Add tab flag "TAB" at the end of cmdline_tmp */
	if(cmd_len < (CMDLINE_SIZE-strlen(TAB_SUFFIX)))
		memcpy(&cmdline_tmp[cmd_len], TAB_SUFFIX, strlen(TAB_SUFFIX));

	/* Record cmdline to user struct */
	u->linelen = cmd_len;
	memcpy(u->linebuf, cmdline, strlen(cmdline));
	
	/* Start cmdparse */
	do_cmdparse(cmdline_tmp, u);

	/* Vty print "/tmp/vty_output" */	
	if(do_vty_print(u) < 0)
		return -1;

	/* Show prompt */
	do_prompt_parse(u);

	/* cmdline is changed by CLI parse */
	if(cmd_len <= u->linelen)
	{
		/* fix the variables of CLI*/
		memcpy(cmdline, u->linebuf, u->linelen);
		cmd_show_len += (u->linelen - cmd_len);
		cmd_len = u->linelen;
	}
	else
		DEBUG_MSG(1, "do_tab_parse() error!!\n", NULL);

	/* cmd_show_len is too long */
	if(cmd_show_len >= SHOW_CMD_SIZE(prompt_len))
	{
		cmd_show_len -= SHOW_OFFSET_SIZE;
		cmdline_show += SHOW_OFFSET_SIZE;
	}

	/* check for offset */
	if(cmdline != cmdline_show)
	{
		putchar('$');
		fputs(cmdline_show + 1, stdout);
	}
	else
		fputs(cmdline_show, stdout);

	/* fix the cursor */
	cmd_cursor = cmd_len;
	show_cursor = cmd_show_len;
	fflush(stdout);

	/* reset users info variables  */
	reset_users_param(u);

	return 0;
}

/* input '?' */
static int do_help_parse(struct users *u)
{
	char cmdline_tmp[CMDLINE_SIZE+1];		//*argv[] point to this buff

	fputs("?\n", stdout);
	if(u == NULL)	
		return -1;
	
	/* Init cmdline_tmp buffer */
	memset(cmdline_tmp, '\0', sizeof(cmdline_tmp));
	
	/* Record cmdline to cmdline_tmp buffer */
	memcpy(cmdline_tmp, cmdline, cmd_len);

	if(check_invalid_char(cmdline, cmd_len) < 0)
	{
		/* Printf error info */
		printf("Input invalid char or string!!\n");

		/* Error occur, so clear the block status */
		CLEAR_CMD_ST(u, CMD_ST_BLOCK);
		
		/* Error , so clear the promptdef status */
		CLEAR_CMD_ST(u, CMD_ST_DPROMPT);

		/* show prompt and reset cmd and users variables */ 
		do_prompt_parse(u); 	
		reset_cmd_param();
		reset_users_param(u);
		return -1;
	}

	/* Add help flag "?" at the end of cmdline_tmp */
	if(cmd_len < (CMDLINE_SIZE-strlen(HELP_SUFFIX)))
		memcpy(&cmdline_tmp[cmd_len], HELP_SUFFIX, strlen(HELP_SUFFIX));

	/* Record cmdline to user struct */
	u->linelen = cmd_len;
	memcpy(u->linebuf, cmdline, strlen(cmdline));
	
	/* Start cmdparse */
	do_cmdparse(cmdline_tmp, u);

	/* Check u->cmd_st */
	if(ISSET_CMD_ST(u, CMD_ST_ERR) /*&& strlen(u->errbuf) != 0*/)
	{
		/* Printf error info */
		cmderror(u);
		
		/* Error , so clear the block status */
		CLEAR_CMD_ST(u, CMD_ST_BLOCK);
		
		/* Error , so clear the promptdef status */
		CLEAR_CMD_ST(u, CMD_ST_DPROMPT);
	}
	
	/* Vty print "/tmp/vty_output" */	
	if(do_vty_print(u) < 0)
		return -1;
	
	/* Show prompt */
	do_prompt_parse(u);

	/* check for offset */
	if(cmdline != cmdline_show)
	{
		putchar('$');
		fputs(cmdline_show + 1, stdout);
	}
	else
		fputs(cmdline_show, stdout);

	/* fix the cursor */
	cmd_cursor = cmd_len;
	show_cursor = cmd_show_len;
	fflush(stdout);

	/* reset users info variables  */
	reset_users_param(u);
	
	return 0;
}

static int do_characters_parse(char c, struct users *u)
{
	int max_input_len = 0;
	char buff_tmp[CMDLINE_SIZE + 1];
	
	if(u == NULL)	
		return -1;

	/* max input length */
	if(IS_AUTH_STAT(u, CLI_AUTH_SUCCEED))
	{
		if(ISSET_CMD_ST(u, CMD_ST_BLOCK))
		{
			/* When CMD_ST_BLOCK is set, the max_input_len just be one arg's legth */
			max_input_len = MAX_ARGV_LEN;
		}
		else
		{
			/* Reserve space for the flag */
			max_input_len = CMDLINE_SIZE-SHOW_OFFSET_SIZE;
		}
	}
	else
		max_input_len = CLI_AUTH_SIZE;
	
	/* Valid Characters */
	if(c >= 0x20 && c <= 0x7E)
	{
		if(cmd_len < max_input_len)
		{
			/* input passwd */
			if(IS_AUTH_STAT(u, CLI_AUTH_PWD))
				putchar('*');
			else
				putchar(c);

			if(cmd_cursor == cmd_len)
			{
				/* input at the end of cmdline */
				cmdline[cmd_cursor] = c;
			}
			else
			{
				/* input in the middle of cmdline */
				memset(buff_tmp, '\0', sizeof(buff_tmp));
				memcpy(buff_tmp, &cmdline[cmd_cursor], (cmd_len-cmd_cursor));
				memcpy(&cmdline[cmd_cursor+1], buff_tmp, (cmd_len-cmd_cursor));
				
				cmdline[cmd_cursor] = c;
			}
			
			cmd_len += 1;
			if(cmd_show_len + prompt_len < SHOW_LINE_SIZE)
				cmd_show_len += 1;
			
			cmd_cursor += 1;
			show_cursor += 1;

			/* do input shift */
			do_input_shift(c);
		}
		else
			return 0;
	}
	else
		return 0;

	return 1;
}

/* Parse KEY left right up and down */
static int do_direction_parse(char c, struct users *u)
{
	int ret = 1;
	
	if(u == NULL)	
		return -1;

	switch(c)
	{
		case ASCII_UP:
#if 0
			printf("\033[A");
#else
			if(u->his_index < u->his_count
				&& IS_AUTH_STAT(u, CLI_AUTH_SUCCEED))
			{
				u->his_index += 1;
				do_recover_cmdline(u);
			}
#endif
			break;
			
		case ASCII_DOWN:
#if 0
			printf("\033[B");
#else
			if(u->his_index > 0
				&& IS_AUTH_STAT(u, CLI_AUTH_SUCCEED))
			{
				u->his_index -= 1;
				do_recover_cmdline(u);
			}
#endif
			break;
			
		case ASCII_RIGHT:
			if(show_cursor < cmd_show_len)	
			{
				printf("\033[C");
				show_cursor += 1;
				cmd_cursor += 1;
				do_cursor_shift();
			}
			break;
			
		case ASCII_LEFT:
			if(show_cursor > 0) 
			{
				printf("\033[D");
				show_cursor -= 1;
				cmd_cursor -= 1;
				do_cursor_shift();
			}
			break;
			
		default:
			ret = 0;
			break;
	}
	
	return ret;
}

/* Parse input char */
static int do_input_characters(struct users *u)
{
	int retval = -1, len = 0, i = 0;
	char *ptr = NULL;
	
	memset(&buff,'\0',sizeof(buff));
	if((len = read(STDIN_FILENO, buff, sizeof(buff))) < 0)
		return -1;
	
	if(u == NULL)	
		return -1;

	ptr = buff;

	if(len ==2){// PC telnet cmd send 2 ASCII_LN
		if((*ptr == ASCII_LN) &&(*(ptr+1) == ASCII_LN))
			len = 1;
	}
	for(i=0; i<len; i++)
	{
		/* Wait for cr */
		if(IS_AUTH_STAT(u, CLI_AUTH_NONE))
		{
			if(*ptr == '\n')
			{
				/* Start auth_timeout timer */
				if(alarm(AUTH_TIMEOUT_DEFAULT)==-1)
					DEBUG_MSG(1, "Error: Alarm start failed!!\n", NULL);
			}
			else
				continue;
		}
		
		/* Do input characters */
		
		switch(*ptr)
		{
			case ASCII_CR://enter
				if(*(ptr + 1) == ASCII_LN)
					ptr += 1;
			case ASCII_LN://换行
				if(IS_AUTH_STAT(u, CLI_AUTH_SUCCEED))
					retval = do_enter_parse(u);
				else
					retval = do_auth_enter_parse(u);

				ptr += 1;
				esc_flag = 0;
				dir_flag = 0;
				break;
				
			case ASCII_BS:
			case ASCII_DEL:
				retval = do_backspace();
				
				ptr += 1;
				esc_flag = 0;
				dir_flag = 0;
				break;
				
			case ASCII_EOT:
//				fprintf(stderr, "ASCII_EOT\n");
				ptr += 1;
				esc_flag = 0;
				dir_flag = 0;
				
				break;
				
			case ASCII_EXT://正文结束
				//reset_termios();
				ptr += 1;
				esc_flag = 0;
				dir_flag = 0;
				break;
				
			case ASCII_HT://水平制表符 tab键
				//fputs("ASCII_HT", stdout);
				if(IS_AUTH_STAT(u, CLI_AUTH_SUCCEED) && !ISSET_CMD_ST(u, CMD_ST_BLOCK))
					retval = do_tab_parse(u);

				ptr += 1;
				esc_flag = 0;
				dir_flag = 0;
				break;
				
			case '?':
				//putchar(*ptr);
				if(IS_AUTH_STAT(u, CLI_AUTH_SUCCEED)
					&& !ISSET_CMD_ST(u, CMD_ST_BLOCK))
					retval = do_help_parse(u);
				
				ptr += 1;
				esc_flag = 0;
				dir_flag = 0;
				break;

			case ASCII_ESC:
				esc_flag = 1;
				ptr += 1;
				break;
				
			case '[':
				if(esc_flag)
					dir_flag = 1;
				else
				{
					dir_flag = 0;
					retval = do_characters_parse(*ptr, u);
				}
				ptr += 1;
				break;
				
			default:
				if(esc_flag && dir_flag && do_direction_parse(*ptr, u))
					ptr += 1;
				else
				{
					if(my_strstr(ptr, sizeof(ascii_f1), ascii_f1, sizeof(ascii_f1)) != NULL)
						ptr += sizeof(ascii_f1);
					else if(my_strstr(ptr, sizeof(ascii_f2), ascii_f2, sizeof(ascii_f2)) != NULL)
						ptr += sizeof(ascii_f2);
					else if(my_strstr(ptr, sizeof(ascii_f3), ascii_f3, sizeof(ascii_f3)) != NULL)
						ptr += sizeof(ascii_f3);
					else if(my_strstr(ptr, sizeof(ascii_f4), ascii_f4, sizeof(ascii_f4)) != NULL)
						ptr += sizeof(ascii_f4);
					else
					{
						retval = do_characters_parse(*ptr, u);
						ptr += 1;
					}
				}
				
				esc_flag = 0;
				dir_flag = 0;
				break;
		}

	}

	fflush(stdout);
	return retval;
}

/* SIG_ALARM */
static void ring_tick(void)
{
	if (remote_type != CLI_LOCAL){
		printf("Timeout expired!\n");
		tcsetattr(0,TCSANOW,&stored_settings);
		
		exit(0);

		//cleanup();//cleanup add bin/sh will cause  timeout go to unexpected status
	}

	if (alarm(0)==-1)
		DEBUG_MSG(1, "Error: Alarm stop failed!!\n", NULL);

	#ifdef CLI_AAA_MODULE 
	/* accounting close! */
	acct_report_state(AAA_ACCT_EXEC_STOP);
	#endif

	reset_users_his_param(&cur_user);

	printf("\n\n\n");
	printf("Switch con0 is now available\n");
	printf("\n\n\n\nPress Return to get started.\n\n\n");

	init_cli_param();

	return;
}

/* SIG_INT */
static void sigint_func(void)
{
	int status;

	sigint_flag = 1;
	
	if(child_pid != -1)
	{
		/*No child*/
		if(waitpid(child_pid, &status, WNOHANG) < 0)
		{
			child_pid = -1;
			return ;
		}
		
		if(kill(child_pid, SIGINT) != 0)
			DEBUG_MSG(1, "Error: kill child(pid:%d) failed!!\n", child_pid);

		/* Waiting for child */
		usleep(100000);

		if(access(vty_path, F_OK) == 0)
		{
			/* Delete vty_path file */
			if((unlink(vty_path)) < 0)
				DEBUG_MSG(1, "unlink %s failed!!", vty_path);
		}

		child_pid = -1;	
	}

	return;
}

static void recive_character(struct users *u)
{
	int maxfd, retval;
	fd_set rset;

	/* Set up the signal catcher for the alarm clock */
	signal(SIGALRM, (void *)ring_tick);
	if(alarm(u->exec_timeout)==-1)
		DEBUG_MSG(1, "Error: Alarm start failed!!\n", NULL);

	if(IS_AUTH_STAT(u, CLI_AUTH_NONE))
	{
		if (remote_type == CLI_LOCAL) 
		{
			printf("Switch con0 is now available\n");
			printf("\n\n\n\nPress Return to get started.\n\n\n");
		} 
		else 
		{
			printf("\n\n\n\nPress Return to get started.\n\n\n");
		}
	}
	fflush(stdout);

	cmdline_show = cmdline;
	while(1)
	{
		FD_ZERO(&rset);
		FD_SET(STDIN_FILENO, &rset);
		
		if (maxfd < STDIN_FILENO)	maxfd = STDIN_FILENO;
		retval =  select(maxfd+1, &rset, (fd_set *)NULL, (fd_set *)NULL, NULL);

		if (retval < 0) 
		{
			if (errno == EINTR) {
				/* Check if this is because of our SIG_ALARM. */
			} else {
				/* Failure - Select failed. */
				DEBUG_MSG(1, "Error: select failed!!\n", NULL);
				
				if(alarm(0)==-1)
					DEBUG_MSG(1, "alarm stop failed\n", NULL);
				
				signal(SIGALRM, SIG_IGN);
				break;
			}
		}
		else if(retval == 0)
			DEBUG_MSG(1, "Error: select timeout!!\n", NULL);
		else
		{
			if ( FD_ISSET(STDIN_FILENO, &rset) ) {
				if(IS_AUTH_STAT(u, CLI_AUTH_SUCCEED))
				{
					if(alarm(u->exec_timeout)==-1)
						DEBUG_MSG(1, "Error: Alarm start failed!!\n", NULL);
				}
				else if(!IS_AUTH_STAT(u, CLI_AUTH_NONE))
				{
					if(alarm(AUTH_TIMEOUT_DEFAULT)==-1)
						DEBUG_MSG(1, "Error: Alarm start failed!!\n", NULL);
				}
				
				do_input_characters(u);
			}
		}
    }

    return;
}

/* Register All top commands */
static int init_cmdparse(void)
{
	int retval = -1;
	
	retval += init_cli_acl();
	retval += init_cli_arp();
	retval += init_cli_clear();
	retval += init_cli_clock();
	retval += init_cli_config_mst();
	retval += init_cli_common();
	retval += init_cli_dot1x();
	retval += init_cli_errdisable();
	retval += init_cli_filesys();
	retval += init_cli_interface();
	retval += init_cli_ip();
	retval += init_cli_login();
	retval += init_cli_mac();
	retval += init_cli_mirror();
	retval += init_cli_others();
	retval += init_cli_ping();
	retval += init_cli_port();
	retval += init_cli_qos();
	retval += init_cli_radius();
	retval += init_cli_rmon();
	retval += init_cli_show();
	retval += init_cli_snmp();
	retval += init_cli_stp();
	retval += init_cli_syslog();
	retval += init_cli_trunk();
	retval += init_cli_vlan();
	retval += init_cli_router();
	retval += init_cli_dhcp();
	retval += init_cli_lldp();
	retval += init_cli_time_range();
	retval += init_cli_erps();

#ifdef CLI_AAA_MODULE
	retval += init_cli_aaa();
	retval += init_cli_enable();
	retval += init_cli_line();
#endif

#ifdef CLI_SHELL
	retval += init_cli_shell();
#endif

	DEBUG_MSG(1, "Init topcmds %d!!\n", retval);

	return retval;
}

static int init_startup_config(void)
{
	char line[CMDLINE_SIZE+1] = {'\0'}, *c = NULL;
	FILE *fd = NULL;

	if(!loadstartupconfig)
		return 0;		

	if(access(STARTUP_CONFIG_PATH, F_OK) == 0)
		fd = fopen(STARTUP_CONFIG_PATH, "r");
	else
		fd = fopen(DEFAULT_STARTUP_CONFIG_PATH, "r");

	if(fd == NULL)
	{
		DEBUG_MSG(1, "open startup-config failed\n", NULL);
		return -1;
	}
	fseek(fd, 0, SEEK_SET);

	/* Change console level to config direct */
	cur_user.con_level = CONFIG_TREE;
	SET_CMD_ST(&cur_user, CMD_ST_CONF);

	int line_cnt = 0, loading_cnt = 0;
	loading_cnt = SHOW_LINE_SIZE/strlen(SHOW_LOADING);
	memset(line, '\0', sizeof(line));
	while(fgets(line, sizeof(line), fd) != NULL)
	{
		c = line;
		while(*c != '\0')
		{
			if(*c == '\n' || *c == '\r')
				*c = '\0';
			c ++;
		}

		/* Check cmdline */
		if(strlen(line) < 1 || (check_invalid_char(line, strlen(line)) < 0))
		{
			/* Reset cmdline buffer */
			memset(line, '\0', sizeof(line));
			continue;
		}

		/* Change console level */
		if(line[0] == '!')
		{
			/* Print loading process */
			if(((line_cnt++) % loading_cnt) == 0)
				fputs("\n", stdout);
			fputs(SHOW_LOADING, stdout);
			fflush(stdout);
			usleep(10);

			/* Into config mode */
			cur_user.con_level = CONFIG_TREE;

			/* Reset cmdline buffer */
			memset(line, '\0', sizeof(line));
			continue;
		}

		/* Print loading process */
		if(((line_cnt++) % loading_cnt) == 0)
			fputs("\n", stdout);
		fputs(SHOW_LOADING, stdout);
		fflush(stdout);

		/* Record cmdline to user struct .This is actul length */
		cur_user.linelen = strlen(line);
		memcpy(cur_user.linebuf, line, cur_user.linelen);
		
		/* Start cmdparse */
		do_cmdparse(line, &cur_user);

		if(ISSET_CMD_ST(&cur_user, CMD_ST_C_LV))
		{
			/* change console level */
			cur_user.con_level = cur_user.cur_con_level;
		
			CLEAR_CMD_ST(&cur_user, CMD_ST_C_LV);
		}

		/* Reset users struct */
		reset_users_param(&cur_user);

		/* Reset cmdline buffer */
		memset(line, '\0', sizeof(line));
	}
	printf("\n\n\n");
	
	/* Reset console level */
	cur_user.con_level = 0;
	CLEAR_CMD_ST(&cur_user, CMD_ST_CONF);

	if(access(vty_path, F_OK) == 0)
	{
		/* Delete vty_path file */
		if((unlink(vty_path)) < 0)
			DEBUG_MSG(1, "unlink %s failed!!", vty_path);
	}
	
	return 0;
}

int main(int argc, char **argv)
{
	signal(SIGINT, (void *)sigint_func);
	signal(SIGTERM, (void *)cleanup);
	signal(SIGCHLD, SIG_IGN);
	
	signal(SIGUSR1, SIG_DFL);
	signal(SIGUSR2, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGCONT, SIG_DFL);
	signal(SIGSTOP, SIG_DFL);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);

	/* add telnet login remote ip address by eagles.zhou*/
	arg_parse(argc, argv);//
	
	/* init tty variables */
	init_termios();

	/* init struct user */
	init_cli_param();

	/* init cmd_tree*/
	init_cmdparse();

	/* load startup-config */
	init_startup_config();
	
	/* enable forwarding for all ports */
//	system("/usr/bin/killall -SIGUSR2 err_disable > /dev/null 2>&1");

	/* start syslog output */
//	system("/usr/bin/killall -SIGUSR1 syslogd > /dev/null 2>&1");
	while(1)
		recive_character(&cur_user);
		    		
    return 0;			   
}

