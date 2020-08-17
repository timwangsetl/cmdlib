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
#include<sys/un.h>
#include<errno.h>

#include <arpa/inet.h>

#include "console.h"
#include "aaa.h"
#include "cmdparse.h"
#include "parameter.h"

#include "cli_common_func.h"
#include "bcmutils.h"

#define K_RIGHT        '\xd8'
#define K_LEFT         '\xd9'
#define K_DELETE       '\xd1'

/* control key */ 
#define K_BACKSPACE    '\x08'
#define K_TAB          '\x09'
#define K_ENTER        '\x0d'
#define K_ESCAPE       '\x1b'

#define K_CTRL_A       '\x01'
#define K_CTRL_B       '\x02'
#define K_CTRL_E       '\x05'
#define K_CTRL_F       '\x06'

struct cmdline {
	char username[MAXSIZE];
	char password[MAXSIZE];
	char *p;
	int  len;
	int  offset;
};

struct enable {
	char user[10];
	char passwd[MAXSIZE];
	int is_encrypted;
};

struct enable_info {
	struct enable enable_passwd_list;
	struct enable enable_secret_list[16];
};

struct auth_source {
	char method[5][MAXSIZE];
};

static struct enable_info *enable_read()
{
	/* format:
	 * aaa_local_enable=$enab0$|<passwd>|1;$enab1$|<passwd>|1; ... $enab$15$|<passwd>|1;$enab16$|<passwd>|0;*/
	char *enable = nvram_safe_get("aaa_local_enable");
	char *entry, *p;
	int i = 0;
	struct enable_info *info;

	info = (struct enable_info *)malloc(sizeof(*info));
	memset(info, '\0', sizeof(*info));

	p = enable;

	if (*enable) {
		for (i = 0; i < 16; i++) {
			entry = strsep(&p, ";");
			strcpy(info->enable_secret_list[i].user, strsep(&entry, "|"));
			strcpy(info->enable_secret_list[i].passwd, strsep(&entry, "|"));
			info->enable_secret_list[i].is_encrypted = atoi(entry);
		}
		entry = strsep(&p, ";");
		strcpy(info->enable_passwd_list.user, strsep(&entry, "|"));
		strcpy(info->enable_passwd_list.passwd, strsep(&entry, "|"));
		info->enable_passwd_list.is_encrypted = atoi(entry);
	} else {
		for (i = 0; i < 16; i++) {
			sprintf(info->enable_secret_list[i].user, "$enab%d$", i);
			info->enable_secret_list[i].is_encrypted = AAA_UNENCRYPTED;
		}
		strcpy(info->enable_passwd_list.user, "$enab16$");
		info->enable_passwd_list.is_encrypted = AAA_UNENCRYPTED;
	}

	free(enable);
	return info;
}

static struct auth_source *get_enable_list()
{
	char *p, *data = nvram_safe_get("aaa_auth_enable");
	struct auth_source *src;
	
	src = (struct auth_source *)malloc(sizeof(*src));
	memset(src, '\0', sizeof(*src));

	p = data;
	strsep(&p, "@");
	if (!p) {
		free(data);
		return src;
	}

	*strchr(p, ';') = '\0';

	int i = 0;
	for (i = 0; p && i < 4; i++)
		strcpy(src->method[i] , strsep(&p, "|"));

	free(data);
	return src;
}

static int is_tacacs_config()
{
	char *server = nvram_safe_get("tacacs_servers");
	char *prekey = nvram_safe_get("tacacs_prekey");
	int retval = -1;

	if (*server && *prekey)
		retval = 0;

	free (server);
	free (prekey);
	return retval;
}

static int is_radius_config()
{
	char *server = nvram_safe_get("radius_server");
	char *prekey = nvram_safe_get("radius_prekey");
	int retval = -1;

	if (*server && *prekey)
		retval = 0;

	free (server);
	free (prekey);
	return retval;
}

static int passwd_check(struct users *u, struct cmdline *user, int level)
{
	struct cli_msg msg;

	memset(&msg, 0, sizeof(msg));
	if (*u->username)
		strcpy(msg.user, u->username);
	else
		strcpy(msg.user, user->username);

	memcpy(msg.password, user->password, strlen(user->password));
	msg.nas_port = sta_info.nas_port;
	msg.level = level;
	msg.nas_port_type = sta_info.nas_port_type;

	if (sta_info.remote_type == CLI_LOCAL)
		msg.type = AAA_ENABLE_LOCAL | AAA_ENABLE_CHECK;
	else
		msg.type = AAA_ENABLE_LINE | AAA_ENABLE_CHECK;

	return aaa_send_msg(&msg);
}

static inline void cmdline_init(struct cmdline *cmdline)
{
	memset(cmdline, '\0', sizeof(*cmdline));
	cmdline->p = cmdline->username;
	cmdline->offset = 1;
}

/* Cmdline dump. TODO: here should be optimized in the future. */
static void cmdline_dump(struct cmdline *cmdline)
{
	int i;
	
	printf("\r\033[K");

	if (cmdline->p == cmdline->username) {
		/* print username */
		printf("Username: %s", cmdline->p);
	} else {
		/* print password */
		printf("Password: ");
		for (i = 0; i < cmdline->len; i++)
			printf("*");
	}

	for (i = 0; i <= cmdline->len - cmdline->offset; i++)
		printf("\b");

	fflush(stdout);
}

static void select_read(char *kbuf)
{
	int retval;
	fd_set rset;
	FD_ZERO(&rset);
	FD_SET(STDIN_FILENO, &rset);
	struct timeval tv = {.tv_sec = 1,};

	retval = select(STDIN_FILENO + 1, &rset, NULL, NULL, &tv);
	if (retval > 0)
		read(STDIN_FILENO, kbuf, 5);
}

/* KEY_RIGHT */
static inline void key_right(struct cmdline *cmdline)
{
	if (cmdline->offset <= cmdline->len)
		cmdline->offset++;
}

/* KEY_LEFT */
static inline void key_left(struct cmdline *cmdline)
{
	if (cmdline->offset > 1)
		cmdline->offset--;
}

/* KEY_DELETE */
static inline void key_del(struct cmdline *cmdline)
{
	if (cmdline->offset > cmdline->len)
		return;
	memmove(&cmdline->p[cmdline->offset - 1],
				&cmdline->p[cmdline->offset], 
				strlen(&cmdline->p[cmdline->offset]) + 1);
	cmdline->len--;
}

/* KEY_BACKSPACE */
static inline void key_backspace(struct cmdline *cmdline)
{
	if (cmdline->len == 0 || cmdline->offset == 1)
		return;
	if (cmdline->offset <= cmdline->len)
		memmove(&cmdline->p[cmdline->offset - 2],
				&cmdline->p[cmdline->offset - 1], 
				strlen(&cmdline->p[cmdline->offset -1]) + 1);
	else
		cmdline->p[cmdline->len - 1] = '\0';
	cmdline->offset--;
	cmdline->len--;
}

/* KEY_CTRL_A */
static inline void key_ctrl_a(struct cmdline *cmdline)
{
	cmdline->offset = 1;
}

/* KEY_CTRL_B */
static inline void key_ctrl_b(struct cmdline *cmdline)
{
	if (cmdline->offset > 1)
		cmdline->offset--;
}

/* KEY_CTRL_E */
static inline void key_ctrl_e(struct cmdline *cmdline)
{
	cmdline->offset = cmdline->len + 1;
}

/* KEY_CTRL_F */
static inline void key_ctrl_f(struct cmdline *cmdline)
{
	if (cmdline->offset <= cmdline->len)
		cmdline->offset++;
}

/* KEY_TAB */
static inline void key_tab(struct cmdline *cmdline)
{
	cmdline->offset = cmdline->len + 1;
}

/* FIXME: this function has some bug. fix in this future. */
static int parser_key(struct cmdline *cmdline, char *key)
{
	/* KEY_ESC */
	if (*key == 0x1b) {
		if (!memcmp(key, "\x1b", 2))
			select_read(key + strlen(key));
		if (!memcmp(key, "\x1b[", 3)) 
			select_read(key + strlen(key));
		if (!memcmp(key, "\x1b[\x33", 4))
			select_read(key + strlen(key));

		if (!memcmp(key, "\x1b[C", 4)) {
			/* KEY_RIGHT */
			key_right(cmdline);
		} else if (!memcmp(key, "\x1b[D", 4)) {
			/* KEY_LEFT */
			key_left(cmdline);
		} else if (!memcmp(key, "\x1b\x5b\x33\x7e", 5)) {
			/* KEY_DEL */
			key_del(cmdline);
		}
		return 0;
	}

	if (strlen(key) == 1) {
		static char hashtab[] = 
			"1234567890"
			"abcdefghigklmnoqprstuvwxyz"
			"ABCDEFGHIGKLMNOQPRSTUVWXYZ"
			" _.+=(){}@#\'\"\\/<>$^&";

		if (strchr(hashtab, *key)) {
			if (cmdline->len >= 32) {
				printf("\n%% Access denied\n\n");
				return -1;
			}

			if (cmdline->offset <= cmdline->len) {
				memmove(&cmdline->p[cmdline->offset],
					&cmdline->p[cmdline->offset - 1], strlen(&cmdline->p[cmdline->offset - 1]) + 1);
				cmdline->p[cmdline->offset - 1] = *key;
			} else {
				cmdline->p[cmdline->len] = *key;
			}
			cmdline->offset++;
			cmdline->len++;
		} else {
			switch (*key) {
			case K_BACKSPACE: /* KEY_BACKSPACE */
				key_backspace(cmdline);
				break;
			case K_LEFT: /* KEY_LEFT */
				key_left(cmdline);
				break;
			case K_RIGHT: /* KEY_LEFT */
				key_right(cmdline);
				break;
			case '\x7f':
			case K_DELETE:
				key_del(cmdline);
				break;
			case K_CTRL_A:
				key_ctrl_a(cmdline);
				break;
			case K_CTRL_E:
				key_ctrl_e(cmdline);
				break;
			case K_TAB:
				key_tab(cmdline);
				break;
			case K_CTRL_B:
				key_ctrl_b(cmdline);
				break;
			case K_CTRL_F:
				key_ctrl_f(cmdline);
				break;
			}
		}
	}

	return 0;
}

#define __strlen(s) strlen((const char *)s)

static inline unsigned char *__strchr(unsigned char *s, unsigned char c)
{
	while (*s && *s != c)
		s++;

	return *s ? s : NULL;
}

static int  __strtohex(unsigned char *str)
{
	unsigned char high, low;
	unsigned char *p1, *p2;
	static unsigned char hex[] = "0123456789abcdefABCDEF";

	if (!(p1 = __strchr(hex, str[0])) || !(p2 = __strchr(hex, str[1])))
		return -1;

	high = p1 - hex;
	if (high > 0xf)
		high = high - 16 + 10;
	low = p2 - hex;
	if (low > 0xf)
		low = low - 16 + 10;

	return (int)(high * 16 + low);
}

int func_set_dot1x_username(char *name, char *password)
{
	char buf[256] = {0}, *user, *ptr_user, *ptr_passwd;
	char *pos, *p, p1;
	int flag = 0;
	FILE *fp;

	fp = fopen("/etc/hostapd.eap_user", "w");
	if (fp == NULL) 
		return -1;

	user = nvram_safe_get("dot1x_user");
	pos = user;
	p1 = user;

	memcpy(buf, name, strlen(name));
	buf[strlen(name)] = ':';

	char *ptr;
	ptr = strstr(user, buf);

	if (ptr) {
		sprintf(buf, "%s:%s", name, password);
		p = strstr(ptr, buf);
		if (p){
			fclose(fp);
			free(user);
			return 0;
		}
		else {
			*ptr = '\0';
			memset(buf, '\0', 256);
			memcpy(buf, user, strlen(user) );
			strcat(buf, name);
			strcat(buf, ":");
			strcat(buf, password);
			strcat(buf, ";");
			ptr = strchr(ptr + 1, ';');
			ptr++;
			strcat(buf, ptr);
		}
	} else {
		sprintf(buf, "%s%s:%s;", user, name, password);
	}
	nvram_set("dot1x_user", buf);

	ptr = buf;

/* 	fprintf(stdout,"         MD5     \n");
 */
	while (strlen(ptr)) {
		p = strsep(&ptr, ";");
		ptr_user  = strsep(&p, ":");
		ptr_passwd  = p;
		fprintf(fp,"\"%s\"          MD5     \"%s\"\n", ptr_user, ptr_passwd);
/* 		fprintf(stdout,"\"%s\"          MD5     \"%s\"\n", ptr_user, ptr_passwd);
 */
	}

	fclose(fp);
	free(user);
	return 0;
}

#ifdef CLI_AAA_MODULE
int func_username(struct users *u)
{
	int level = -1;
	char name[32] = {'\0'};
	char *tmp;

	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);

	struct cli_msg msg;

	memset(&msg, 0, sizeof(msg));
	strcpy(msg.user, name);
	msg.type = AAA_UNENCRYPTED;

	aaa_send_msg(&msg);
	return 0;	
}


int func_username_privilege(struct users *u)
{
	int level, ret;
	char name[64] = {'\0'};
	char *line;
	struct cli_msg msg;

	cli_param_get_int(DYNAMIC_PARAM, 0, &level, u);
	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);

	if (strlen(name) > 32) {
		vty_output("The length of username should be less than 32!!!\n");
		return -1;
	}
	
	memset(&msg, 0, sizeof(msg));
	msg.type = AAA_LOGIN_SET_LEVEL;
	msg.level = level;
	strcpy(msg.user, name);

	ret = aaa_send_msg(&msg);
 	if (ret == AAA_REPLY_FAIL) 
		vty_output("%s is not exist!\n", name);
		
	return 0;
}


void switch_encrypted(unsigned char *src, unsigned char *hash)
{
	/* ax^5 + bx^3 + cx */
	int i, len;
	unsigned int value, crc = 0;
	unsigned char tmp;  
	unsigned char hash_t[100] = {0};

	len = __strlen(src);

	for (i = 0; i < len; i++) {
		tmp = (src[i] * src[i]) & 0xff;
		value = (tmp * tmp) & 0xff; 
		value *= src[i] * (i + 3);
		value += (i + 2) * tmp  * src[i] >> 8 & 0xff; 
		value += src[i] + i; 
		value &= 0xff; 
		if (i % 2) {
			value += ~i * len - 1;
		} else
			value += (i + 1);

		value &= 0xff; 
		crc += (value * (i + 1)) & 0xff;
		sprintf((char *)hash_t, "%s%02x", hash_t, value);
	}

	crc >>= 8;
	crc &= 0xff;
	sprintf((char *)hash_t, "%s%02x", hash_t, crc);
	memset(hash, '\0', len * 2 + 1);
	memcpy(hash, hash_t, __strlen(hash_t));
}

/* return:
 * 0, success
 * 1, fail */
int switch_crc(unsigned char *src)
{
	int value = 0;
	int ret, len, i, crc;

	if (src == NULL)
		return -1;
	len = __strlen(src);
	if (len == 0 || len % 2 != 0 || len < 4)
		return -1;

	for (i = 0; i < len - 2; i += 2) {
		ret = __strtohex(&src[i]);
		if (ret == -1)
			return -1;

		value += ret * (i / 2 + 1) & 0xff;
	}

	crc = __strtohex(&src[i]);
	if (crc == -1)
		return -1;

	value >>= 8;
	value &= 0xff;

	return (value == crc) ? 0 : 1;
}

void disable_ctrl_c(int sig)
{
	/**/
}

int func_enable(struct users *u)
{
	int retval, level, i;
	struct cmdline user;
	cmdline_init(&user);

	struct auth_source *src = get_enable_list();
	struct enable_info *info = enable_read();

	cli_param_get_int(STATIC_PARAM, 0, &level, u);

	if (!level)
		level = CLI_PRI_15;

	if (*src->method[0] == '\0') {
		if (level == CLI_PRI_15) {
			if (*info->enable_secret_list[CLI_PRI_15].passwd == '\0' 
					&& *info->enable_passwd_list.passwd == '\0') {
				if (sta_info.remote_type == CLI_LOCAL || sta_info.remote_type == CLI_TELNET) {
					u->cmd_pv = level;
					free(src);
					free(info);
					return change_con_level(ENA_TREE, u);
				} else {
					printf("%% Error in authentication.\n\n");
					free(src);
					free(info);
					return -1;
				}
			}
		} else {
			if (*info->enable_secret_list[level].passwd == '\0') {
				if (sta_info.remote_type == CLI_LOCAL || sta_info.remote_type == CLI_TELNET) {
					free(src);
					free(info);
					u->cmd_pv = level;
					if (level == 1)
						return 0;
					return change_con_level(ENA_TREE, u);
				} else {
					printf("%% Error in authentication.\n\n");
					free(src);
					free(info);
					return -1;
				}
			}
		}
	}

	for (i = 0; i < 5; i++) {
		if (!strcmp(src->method[i], "none")) {
			free(src);
			free(info);
			if (level == 1)
				return 0;
			u->cmd_pv = level;
			return change_con_level(ENA_TREE, u);
		} else if (!strcmp(src->method[i], "enable")) {
			user.p = user.password;
			break;
		} else if (!strcmp(src->method[i], "radius")) {
			if (level == 1) {
				free(src);
				free(info);
				return 0;
			}
			if (is_radius_config())
				continue;
			user.p = user.password;
			break;
		} else if (!strcmp(src->method[i], "tacacs+")) {
			if (level == 1) {
				free(src);
				free(info);
				return 0;
			}
			if (is_tacacs_config())
				continue;
			if (*u->username)
				user.p = user.password;
			break;
		} else {
			user.p = user.password;
			break;
		}
	}

	char buf[8];
	int len;

	fd_set rset;

	memcpy(user.username, u->username, strlen(u->username) + 1);
	if (user.username == user.p)
		printf("Username: ");
	else
		printf("Password: ");
	fflush(stdout);

	signal(SIGINT, disable_ctrl_c);

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(STDIN_FILENO, &rset);
		struct timeval tv = {
			.tv_sec = 30,
			.tv_usec = 0,
		};

		retval =  select(STDIN_FILENO + 1, &rset, NULL, NULL, &tv);
		
		if (retval > 0) {
			memset(buf, '\0', sizeof(buf));
			len = read(STDIN_FILENO, buf, sizeof(buf) - 1);
			if (len < 0) {
				printf("%% Error in authentication.\n\n");
				break;
			}
			if (*buf == '\r' || *buf == '\n') {
				if (user.username == user.p) {
					if (*user.username == '\0') {
						printf("\n%% Error in authentication.\n\n");
						break;;
					}
					user.p = user.password;
					user.offset = 1;
					user.len = 0;
					printf("\n");
					printf("Password: ");
					fflush(stdout);
					continue;
				} else {
					if (*user.password == '\0') {
						printf("\n%% Error in authentication.\n\n");
						break;;
					}
					printf("\n");
				}
				
				retval = passwd_check(u, &user, level);
				if (!retval) {
					printf("\n");
					u->cmd_pv = level;
					free(src);
					free(info);
					if (level == 1)
						return 0;
					return change_con_level(ENA_TREE, u);
				} else 
					printf("\n%% Access denied\n\n");
				break;
			}
			if (!parser_key(&user, buf)) {
				cmdline_dump(&user);
			} else {
				break;
			}
		} else if (retval == 0) {
			/* timeout */
			printf("\n%% timeout expired!\n");
			printf("%% Error in authentication.\n\n");
			break;
		} else {
			/* select was interrupted */
			printf("\n%% Error in authentication.\n\n");
			break;
		}
	}

	free(src);
	free(info);
	return -1;
}

static int set_passwd(char *passwd, int length, int level, int is_encrypted, char *name)
{
	struct cli_msg msg;
	char *password_encrypt;
	char hash[33] = {'\0'};
	int ret;
	
	if (level == 0) 
		level = 15;
	
	memset(&msg, 0, sizeof(msg));
	strcpy(msg.user, name);
			
	msg.level = level;
	password_encrypt = nvram_safe_get("password_encryption");
	
	if (is_encrypted) {	
		if (switch_crc(passwd) || length > 32) {
			vty_output("Invalid encrypted password: %s\n", passwd);
			free(password_encrypt);
			return -1;
		}
		strcpy(hash, passwd);
		msg.type = AAA_LOGIN_SET_ENCRYPTED;
	} else {	
		if (length > 15) {
			vty_output("password: %s, the length should be less 15.\n", passwd);
			free(password_encrypt);
			return -1;
		}
		if (atoi(password_encrypt)) {
			switch_encrypted(passwd, hash); 
			msg.type = AAA_LOGIN_SET_ENCRYPTED;
		} else {
			strcpy(hash, passwd);
			msg.type = AAA_LOGIN_SET_UNENCRYPTED;
		}
	}
	
	memcpy(msg.password, hash, strlen(hash));
	
	free(password_encrypt);
	
	ret = aaa_send_msg(&msg);
	if (ret == AAA_REPLY_FAIL)
		vty_output("The amount of users should not be more than 32!\n");
	return ret;
}

int func_username_passwd_line(struct users *u)
{
	int flag, level,i;
	char name[64] = {'\0'};
	char *line;

	cli_param_get_int(DYNAMIC_PARAM, 0, &level, u);
	cli_param_get_int(DYNAMIC_PARAM, 1, &flag, u);	

	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);

	if (strlen(name) > 32) {
		vty_output("The length of username should be less than 32!!!\n");
		return -1;
	}

    cli_param_get_int(STATIC_PARAM, 0, (int *)&line, u);	
	//vty_output("user passwd:%s-%s-%d-%d\n",name,line,level,flag);
	for(i=0;i< strlen(line);i++){
		if(*(line+i)==' '){
			vty_output("The password %d character is invalid!!!\n",i+1);
			return -1;
		}
	}
	return set_passwd(line, strlen(line), level, !flag, name);
}


int nfunc_username(struct users *u)
{
	struct cli_msg msg;
	char name[64] = {'\0'};

	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);

	if (strlen(name) > 32) {
		vty_output("The length of username should be less than 32!!!\n");
		return -1;
	}

	memset(&msg, 0, sizeof(msg));
	strcpy(msg.user, name);
	msg.type = AAA_NO | AAA_LOGIN_SET;

	return aaa_send_msg(&msg);
}
#endif

int func_hostname(struct users *u)
{
	char name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);
	
	nvram_set("hostname", name);
	syslog(LOG_NOTICE, "[CONFIG-5-HOSTNAME]: The hostname was set to %s, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}


int nfunc_hostname(struct users *u)
{
	nvram_set("hostname","Switch");
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set the hostname to Switch, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

