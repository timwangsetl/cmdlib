/**
 * console / enable
 *
 * Arthor: Yezhong Li
 * date: 2012.3.11
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
#include "aaa.h"
#include "cmdparse.h"
#include "parameter.h"
#include "bcmutils.h"

#include "cli_enable_func.h"

#ifdef CLI_AAA_MODULE
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

static int md5_check(unsigned char *s)
{
	int len = __strlen(s);
	if (len != 32)
		return -1;
	for (; len; len -= 2, s += 2) {
		if (__strtohex(s) == -1)
			return -1;
	}
	return 0;
}

extern struct aaa_sta_info sta_info;

static int secret_set(char *passwd, int length, int level, int is_encrypted)
{
	struct cli_msg msg;

	memset(&msg, 0, sizeof(msg));
	sprintf(msg.user, "$enab%d$", level);

	if (is_encrypted) {
		msg.type = AAA_ENCRYPTED_SECRET | AAA_ENABLE_SET;
		if (md5_check((unsigned char *)passwd)) {
			vty_output("Invalid encrypted password: %s\n", passwd);
			return -1;
		}
	} else {
		msg.type = AAA_UNENCRYPTED_SECRET | AAA_ENABLE_SET;
	}
	
	msg.level = level;

	memcpy(msg.password, passwd, length);
	return aaa_send_msg(&msg);
}

static int passwd_reset(struct users *u)
{
	struct cli_msg msg;

	memset(&msg, 0, sizeof(msg));
	strcpy(msg.user, "$enab16$");
	msg.type = AAA_ENABLE_PASSWD_NO;
	
	return aaa_send_msg(&msg);
}

static int secret_reset(struct users *u)
{
	struct cli_msg msg;
	int level;

	cli_param_get_int(DYNAMIC_PARAM, 0, &level, u);
 
	memset(&msg, 0, sizeof(msg));
	sprintf(msg.user, "$enab%d$", level);
 	
	msg.type = AAA_ENABLE_SECRET_NO;
	
	return aaa_send_msg(&msg);
}

int passwd_set(char *passwd, int length, int level, int is_encrypted)
{
	struct cli_msg msg;
	char *password_encrypt;
	char hash[64] = {0};
	int ret;

	if (level > 0 && level <= 15) {
		vty_output("%% Converting to a secret.  Please use \"enable secret\" in the future.\n");
		ret = secret_set(passwd, length, level, is_encrypted);
		return ret;
	}

	if (level == 0)
		level = 16;

	memset(&msg, 0, sizeof(msg));
	strcpy(msg.user, "$enab16$");

	password_encrypt = nvram_safe_get("password_encryption");

	if (is_encrypted) {
		if (switch_crc((unsigned char *)passwd) || length > 32) {
			vty_output("Invalid encrypted password: %s\n", passwd);
			free(password_encrypt);
			return -1;
		}
		strcpy(hash, passwd);
		msg.type = AAA_ENCRYPTED_PASSWD | AAA_ENABLE_SET;
	} else {
		if (length > 15) {
			vty_output("password: %s, the length should be less 15\n", passwd);
			free(password_encrypt);
			return -1;
		}
		if (atoi(password_encrypt)) {
			switch_encrypted((unsigned char *)passwd, (unsigned char *)hash);
			msg.type = AAA_ENCRYPTED_PASSWD | AAA_ENABLE_SET;
		} else {
			strcpy(hash, passwd);
			msg.type = AAA_UNENCRYPTED_PASSWD | AAA_ENABLE_SET;
		}
	}

	memcpy(msg.password, hash, strlen(hash));

	free(password_encrypt);
	return aaa_send_msg(&msg);
}

int func_passwd_line(struct users *u)
{
	int flag, level,i;
	char *line;

	cli_param_get_int(DYNAMIC_PARAM, 0, &flag, u);
	cli_param_get_int(DYNAMIC_PARAM, 1, &level, u);

	if (level)
		cli_param_get_int(STATIC_PARAM, 1, (int *)&line, u);
	else
		cli_param_get_int(STATIC_PARAM, 0, (int *)&line, u);
	for(i=0;i< strlen(line);i++){
		if(*(line+i)==' '){
			vty_output("The string:%s include special character!!!\n",line);
			return -1;
		}
	}
	return passwd_set(line, strlen(line), level, flag);
}

int nfunc_passwd_line(struct users *u)
{	
	return passwd_reset(u);
}

int func_secret_line(struct users *u)
{
	int flag, level,i;
	char *line;

	cli_param_get_int(DYNAMIC_PARAM, 0, &flag, u);
	cli_param_get_int(DYNAMIC_PARAM, 1, &level, u);

	if (level)
		cli_param_get_int(STATIC_PARAM, 1, (int *)&line, u);
	else {
		level = 15;
		cli_param_get_int(STATIC_PARAM, 0, (int *)&line, u);
	}
	for(i=0;i< strlen(line);i++){
		if(*(line+i)==' '){
			vty_output("The string:%s include special character!!!\n",line);
			return -1;
		}
	}

	return secret_set(line, strlen(line), level, flag);
}

int nfunc_secret_line(struct users *u)
{ 	
	return secret_reset(u);
}
#endif
